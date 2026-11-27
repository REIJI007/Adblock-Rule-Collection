#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-check generated Adblock/DNS/Hosts/domain lists against seven public DNS providers.

Deletion is deliberately conservative: every configured resolver must return
non-truncated NXDOMAIN for both A and AAAA. Any NOERROR response, resolver
disagreement, transport error, SERVFAIL, REFUSED, or rate limit retains the
entry. Wildcards, regular expressions, URL patterns, IP literals, comments,
and unrecognized syntax are not rewritten.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CACHE_VERSION = 3
QUERY_TYPES = {"A": 1, "AAAA": 28}
UNKNOWN_CACHE_SECONDS = 900

# Official DoH endpoints. Quad9's 9.9.9.10 service is intentionally used:
# it is the documented "No Threat Blocking" profile.
DNS_PROVIDERS = {
    "google": {"transport": "doh", "endpoint": "https://dns.google/dns-query"},
    "cloudflare": {"transport": "doh", "endpoint": "https://cloudflare-dns.com/dns-query"},
    "cisco": {"transport": "doh", "endpoint": "https://dns.opendns.com/dns-query"},
    "quad9": {"transport": "doh", "endpoint": "https://dns10.quad9.net/dns-query"},
    "alidns": {"transport": "doh", "endpoint": "https://dns.alidns.com/dns-query"},
    "tencent": {"transport": "doh", "endpoint": "https://doh.pub/dns-query"},
    # Baidu's official public-DNS help page publishes this resolver IP.
    # Its standard DNS protocol is used because an official DoH template
    # is not listed in that public-DNS support page.
    "baidu": {"transport": "udp", "address": "180.76.76.76"},
}

MANAGED_OUTPUTS = {
    "ADBLOCK_RULE_COLLECTION.txt": "adblock",
    "ADBLOCK_RULE_COLLECTION_Lite.txt": "adblock",
    "ADBLOCK_RULE_COLLECTION_DNS.txt": "dns",
    "ADBLOCK_RULE_COLLECTION_DNS_Lite.txt": "dns",
    "ADBLOCK_RULE_COLLECTION_HOST.txt": "hosts",
    "ADBLOCK_RULE_COLLECTION_HOST_Lite.txt": "hosts",
    "ADBLOCK_RULE_COLLECTION_HOST_IPV6.txt": "hosts",
    "ADBLOCK_RULE_COLLECTION_HOST_IPV6_Lite.txt": "hosts",
    "ADBLOCK_RULE_COLLECTION_DOMAIN.txt": "domains",
    "ADBLOCK_RULE_COLLECTION_DOMAIN_Lite.txt": "domains",
}

COMMENT_PREFIXES = ("!", "#", ";", "[", "//")
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z", re.I)
DOMAIN_MODIFIER_RE = re.compile(r"(?i)([$,]domain=)([^,$]+)")
COSMETIC_MARKERS = ("#@?#", "#?#", "#@#", "##", "#$#", "#@%#", "#%#")


class RateLimiter:
    """A per-provider request-start limiter to avoid overwhelming public resolvers."""

    def __init__(self, qps: float) -> None:
        self.interval = 1.0 / qps
        self.lock = threading.Lock()
        self.next_start = 0.0

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            scheduled = max(now, self.next_start)
            self.next_start = scheduled + self.interval
        delay = scheduled - now
        if delay > 0:
            time.sleep(delay)


_RATE_LIMITERS: dict[str, RateLimiter] = {}


def normalize_domain(value: str) -> str | None:
    """Normalize a fully-qualified hostname to lowercase ASCII/IDNA."""
    value = value.strip().rstrip(".").lower()
    if not value or any(char in value for char in "*/\\:@?#"):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253:
        return None
    labels = value.split(".")
    if len(labels) < 2:
        return None
    if any(
        not label or len(label) > 63 or not DOMAIN_LABEL_RE.fullmatch(label)
        for label in labels
    ):
        return None
    return value


def _split_newline(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    if line.endswith("\r"):
        return line[:-1], "\r"
    return line, ""


def _is_comment(line: str) -> bool:
    return not line.strip() or line.lstrip().startswith(COMMENT_PREFIXES)


def _parse_hosts(line: str) -> tuple[list[str], list[str], str] | None:
    """Return (kept-prefix tokens, hostname tokens, comment/newline suffix)."""
    body, newline = _split_newline(line)
    raw = body.split("#", 1)
    data = raw[0].split()
    if len(data) < 2:
        return None
    try:
        ipaddress.ip_address(data[0])
    except ValueError:
        return None
    # Single-label local hostnames (localhost, printer, etc.) are not public DNS
    # candidates and are always retained.
    names = data[1:]
    suffix = (" #" + raw[1]) if len(raw) > 1 else ""
    return [data[0]], names, suffix + newline


def _extract_anchored_domain(line: str) -> str | None:
    """Extract only an explicitly host-anchored ABP/AdGuard domain pattern."""
    body = line[2:] if line.startswith("@@") else line
    if body.startswith("||"):
        pattern = body[2:]
    elif body.startswith("|"):
        pattern = body[1:]
    else:
        return None
    # A path, domain separator, modifier delimiter, or end of string terminates
    # the hostname. Wildcards and URL schemes fail normalize_domain().
    host = re.split(r"[\^/$|]", pattern, maxsplit=1)[0]
    return normalize_domain(host)


def _cosmetic_scope(line: str) -> tuple[int, str, list[tuple[str, str]]] | None:
    """Extract explicit domains from an ABP/AdGuard cosmetic-rule scope."""
    marker = next((m for m in COSMETIC_MARKERS if m in line), None)
    if marker is None:
        return None
    position = line.find(marker)
    scope = line[:position]
    if not scope:
        return None
    parts: list[tuple[str, str]] = []
    for token in scope.split(","):
        token = token.strip()
        if not token:
            return None
        negation = "~" if token.startswith("~") else ""
        name = token[1:] if negation else token
        if name == "*":
            parts.append((negation, "*"))
            continue
        domain = normalize_domain(name)
        if domain is None:
            # An unknown scope token means we cannot safely rewrite the list.
            return None
        parts.append((negation, domain))
    return position, marker, parts


def _domain_modifier_domains(line: str) -> list[str]:
    domains: list[str] = []
    for match in DOMAIN_MODIFIER_RE.finditer(line):
        for token in match.group(2).split("|"):
            name = token.strip()
            if name.startswith("~"):
                name = name[1:]
            domain = normalize_domain(name)
            if domain:
                domains.append(domain)
    return domains


def parse_line(line: str, kind: str) -> tuple[str | None, list[str]]:
    """Return a rewrite strategy and exact DNS names referenced by this entry."""
    body, _ = _split_newline(line)
    value = body.strip()
    if _is_comment(value):
        return None, []
    if kind == "domains":
        domain = normalize_domain(value.split()[0]) if value.split() else None
        return ("single", [domain]) if domain else (None, [])

    if kind == "hosts":
        parsed = _parse_hosts(line)
        if not parsed:
            return None, []
        candidates = [
            domain for host in parsed[1:]
            if (domain := normalize_domain(host)) is not None
        ]
        return ("hosts", candidates) if candidates else (None, [])

    if kind not in {"adblock", "dns"}:
        return None, []

    cosmetic = _cosmetic_scope(value)
    if cosmetic:
        candidates = [name for _, name in cosmetic[2] if name != "*"]
        return ("cosmetic", candidates) if candidates else (None, [])

    candidates = []
    anchored = _extract_anchored_domain(value)
    if anchored:
        candidates.append(anchored)

    # $domain= scopes are explicit DNS hostnames too. They can be removed
    # independently without broadening a rule's scope.
    candidates.extend(_domain_modifier_domains(value))

    # DNS feeds also contain bare FQDN entries. Ordinary Adblock lists do not:
    # a non-anchored token there may be an arbitrary URL substring or regex.
    if kind == "dns" and not candidates:
        bare = value.split("$", 1)[0].split("#", 1)[0].strip()
        domain = normalize_domain(bare)
        if domain:
            candidates.append(domain)

    return ("single" if candidates else None), sorted(set(candidates))


def _rewrite_domain_modifiers(line: str, invalid: set[str]) -> str | None:
    """Remove nonexistent domains from explicit $domain= scope lists."""
    should_drop = False

    def replace(match: re.Match[str]) -> str:
        nonlocal should_drop
        prefix, value = match.group(1), match.group(2)
        tokens = value.split("|")
        parsed = []
        original_positive = 0
        kept_positive = 0
        unknown_positive = False
        for token in tokens:
            token = token.strip()
            negated = token.startswith("~")
            raw = token[1:] if negated else token
            domain = normalize_domain(raw)
            if not negated and domain:
                original_positive += 1
            elif not negated and raw != "*":
                unknown_positive = True
            if domain and domain in invalid:
                continue
            parsed.append(("~" if negated else "") + token.lstrip("~"))
            if not negated and domain:
                kept_positive += 1
        # If all explicit positive scopes vanished, this rule can no longer
        # match a real request. Unknown/wildcard scopes force a fail-open keep.
        if original_positive and kept_positive == 0 and not unknown_positive:
            should_drop = True
        return prefix + "|".join(parsed)

    rewritten = DOMAIN_MODIFIER_RE.sub(replace, line)
    return None if should_drop else rewritten


def rewrite_line(line: str, invalid_domains: set[str], kind: str) -> str | None:
    """Remove confirmed-invalid names while preserving unrelated rule syntax."""
    body, newline = _split_newline(line)
    if _is_comment(body):
        return line
    strategy, candidates = parse_line(line, kind)
    invalid = set(candidates) & invalid_domains
    if not invalid:
        return line

    if strategy == "hosts":
        parsed = _parse_hosts(line)
        if not parsed:
            return line
        prefix, names, suffix_newline = parsed
        kept = [
            name for name in names
            if normalize_domain(name) not in invalid
        ]
        if not kept:
            return None
        suffix = suffix_newline
        if suffix.endswith("\r\n"):
            suffix = suffix[:-2] + "\r\n"
        elif suffix.endswith(("\n", "\r")):
            suffix = suffix[:-1] + suffix[-1]
        # Keep inline comments. Do not remove single-label names such as localhost.
        comment = ""
        raw_body = body.split("#", 1)
        if len(raw_body) > 1:
            comment = " #" + raw_body[1]
        return " ".join(prefix + kept) + comment + newline

    if strategy == "cosmetic":
        scope = _cosmetic_scope(body)
        if not scope:
            return line
        position, marker, parts = scope
        positive = [name for neg, name in parts if not neg and name != "*"]
        kept_parts = [
            (neg, name) for neg, name in parts
            if name == "*" or name not in invalid
        ]
        if positive and not any(not neg and name != "*" for neg, name in kept_parts):
            return None
        new_scope = ",".join(neg + name for neg, name in kept_parts)
        return new_scope + body[position:] + newline

    # Bare DNS entries and pure-domain-list entries are themselves the domain.
    anchored = _extract_anchored_domain(body)
    if kind == "domains":
        return None
    if kind == "dns" and not anchored:
        bare = body.split("$", 1)[0].split("#", 1)[0].strip()
        bare_domain = normalize_domain(bare)
        if bare_domain and bare_domain in invalid:
            return None

    # An invalid primary host anchor makes the complete rule irrelevant.
    if anchored and anchored in invalid:
        return None

    rewritten = _rewrite_domain_modifiers(body, invalid)
    if rewritten is None:
        return None
    return rewritten + newline


def make_dns_query(domain: str, qtype: str) -> tuple[bytes, int]:
    query_id = int.from_bytes(os.urandom(2), "big")
    labels = domain.encode("ascii").split(b".")
    qname = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", QUERY_TYPES[qtype], 1)
    return header + question, query_id


def parse_dns_response(payload: bytes, query_id: int) -> int | None:
    """Return DNS RCODE, rejecting malformed, mismatched, non-response packets."""
    if len(payload) < 12:
        return None
    response_id, flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    if response_id != query_id or not (flags & 0x8000):
        return None
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    if truncated and rcode == 3:
        return None
    return rcode


def _query_doh(provider: str, domain: str, qtype: str, timeout: float) -> int | None:
    packet, query_id = make_dns_query(domain, qtype)
    encoded = base64.urlsafe_b64encode(packet).rstrip(b"=").decode("ascii")
    endpoint = DNS_PROVIDERS[provider]["endpoint"]
    request = urllib.request.Request(
        endpoint + "?dns=" + encoded,
        headers={"Accept": "application/dns-message"},
    )
    for attempt in range(2):
        _RATE_LIMITERS[provider].wait()
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return parse_dns_response(response.read(), query_id)
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt:
                return None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt:
                return None
        time.sleep(0.25 * (attempt + 1))
    return None


def _query_baidu(domain: str, qtype: str, timeout: float) -> int | None:
    packet, query_id = make_dns_query(domain, qtype)
    for attempt in range(2):
        _RATE_LIMITERS["baidu"].wait()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (DNS_PROVIDERS["baidu"]["address"], 53))
                response, _ = sock.recvfrom(4096)
            rcode = parse_dns_response(response, query_id)
            if rcode is not None:
                return rcode
        except (OSError, TimeoutError):
            pass
        if attempt == 0:
            time.sleep(0.25)
    return None


def query_public_dns(provider: str, domain: str, qtype: str, timeout: float) -> int | None:
    try:
        if DNS_PROVIDERS[provider]["transport"] == "udp":
            return _query_baidu(domain, qtype, timeout)
        return _query_doh(provider, domain, qtype, timeout)
    except Exception:
        # Every unexpected resolver-specific error is fail-open.
        return None


def classify_domain(
    domain: str,
    timeout: float,
    query_executor: concurrent.futures.Executor,
) -> dict[str, Any]:
    """Require unanimous NXDOMAIN from all seven resolvers for A and AAAA."""
    future_map = {
        query_executor.submit(query_public_dns, provider, domain, qtype, timeout):
            (provider, qtype)
        for provider in DNS_PROVIDERS
        for qtype in QUERY_TYPES
    }
    provider_codes: dict[str, dict[str, int | None]] = {
        provider: {} for provider in DNS_PROVIDERS
    }
    for future, (provider, qtype) in future_map.items():
        try:
            provider_codes[provider][qtype] = future.result()
        except Exception:
            provider_codes[provider][qtype] = None

    provider_results: dict[str, str] = {}
    for provider, codes in provider_codes.items():
        values = [codes.get("A"), codes.get("AAAA")]
        if 0 in values:
            provider_results[provider] = "valid"
        elif values == [3, 3]:
            provider_results[provider] = "nxdomain"
        else:
            provider_results[provider] = "unknown"

    if "valid" in provider_results.values():
        status = "valid"
    elif all(value == "nxdomain" for value in provider_results.values()):
        status = "nxdomain"
    else:
        status = "unknown"

    return {
        "status": status,
        "providers": provider_results,
        "dns_rcodes": provider_codes,
    }


def _kind_for_path(path: Path) -> str | None:
    return MANAGED_OUTPUTS.get(path.name)


def discover_managed_outputs(root: Path) -> list[Path]:
    return [root / name for name in MANAGED_OUTPUTS if (root / name).is_file()]


def _active_line_count(lines: list[str]) -> int:
    return sum(1 for line in lines if not _is_comment(line))


def update_count_metadata(lines: list[str], kind: str) -> list[str]:
    count = _active_line_count(lines)
    updated = []
    patterns = (
        re.compile(r"^(\s*!?\s*Total rules:\s*)\d+(\s*)$", re.I),
        re.compile(r"^(\s*!?\s*RuleCount:\s*)\d+(\s*)$", re.I),
        re.compile(r"^(\s*#有效域名数目:\s*)\d+(\s*)$"),
    )
    for line in lines:
        body, newline = _split_newline(line)
        replaced = False
        for pattern in patterns:
            match = pattern.fullmatch(body)
            if match:
                body = f"{match.group(1)}{count}{match.group(2)}"
                replaced = True
                break
        updated.append(body + newline if replaced else line)
    return updated


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def load_cache(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {"version": CACHE_VERSION, "domains": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("version") == CACHE_VERSION and isinstance(payload.get("domains"), dict):
            return payload
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        pass
    return {"version": CACHE_VERSION, "domains": {}}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-check generated Adblock, DNS, Hosts, and domain lists."
    )
    parser.add_argument("files", nargs="*", help="managed rule-list paths")
    parser.add_argument(
        "--all-generated", action="store_true",
        help="validate the repository's ten generated subscription files",
    )
    parser.add_argument("--write", action="store_true", help="apply removals; default is dry-run")
    parser.add_argument("--cache", type=Path, help="JSON cache path")
    parser.add_argument("--report", type=Path, help="JSON report path")
    parser.add_argument("--concurrency", type=int, default=12, help="concurrent domain checks (1-24)")
    parser.add_argument("--qps", type=float, default=12.0, help="maximum query starts per provider per second (1-18)")
    parser.add_argument("--timeout", type=float, default=6.0, help="per-query timeout in seconds")
    parser.add_argument("--cache-ttl-hours", type=float, default=24.0, help="cache TTL for valid/NXDOMAIN")
    args = parser.parse_args()

    if not (1 <= args.concurrency <= 24):
        parser.error("--concurrency must be between 1 and 24")
    if not (1 <= args.qps <= 18):
        parser.error("--qps must be between 1 and 18 (Tencent Public DNS documents a 20 QPS per-domain limit)")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout must be > 0 and <= 60")
    if args.cache_ttl_hours <= 0:
        parser.error("--cache-ttl-hours must be greater than zero")

    global _RATE_LIMITERS
    _RATE_LIMITERS = {name: RateLimiter(args.qps) for name in DNS_PROVIDERS}

    if args.all_generated:
        paths = discover_managed_outputs(Path.cwd())
    elif args.files:
        paths = [Path(value).resolve() for value in args.files]
    else:
        parser.error("provide file paths or use --all-generated")

    files: dict[Path, tuple[str, list[str]]] = {}
    candidates: set[str] = set()
    for path in paths:
        kind = _kind_for_path(path)
        if kind is None:
            parser.error(f"unsupported managed output filename: {path.name}")
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines(keepends=True)
        except (OSError, UnicodeError) as exc:
            print(f"Cannot read {path}: {exc}", file=sys.stderr)
            return 2
        files[path] = (kind, lines)
        for line in lines:
            _, domains = parse_line(line, kind)
            candidates.update(domains)

    if not files:
        print("No generated subscription files found.")
        return 0

    cache = load_cache(args.cache)
    cached: dict[str, dict[str, Any]] = {}
    pending: list[str] = []
    now = time.time()
    cache_domains = cache["domains"]
    for domain in sorted(candidates):
        entry = cache_domains.get(domain)
        if not isinstance(entry, dict) or not isinstance(entry.get("result"), dict):
            pending.append(domain)
            continue
        checked_at = entry.get("checked_at")
        status = entry["result"].get("status")
        if not isinstance(checked_at, (int, float)):
            pending.append(domain)
            continue
        ttl = UNKNOWN_CACHE_SECONDS if status == "unknown" else args.cache_ttl_hours * 3600
        if now - checked_at <= ttl:
            cached[domain] = entry["result"]
        else:
            pending.append(domain)

    print(
        f"Files: {len(files)} | candidate domains: {len(candidates)} | "
        f"cache hits: {len(cached)} | to query: {len(pending)}"
    )

    results = dict(cached)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as domain_pool:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.concurrency * len(DNS_PROVIDERS) * 2
        ) as query_pool:
            future_map = {
                domain_pool.submit(classify_domain, domain, args.timeout, query_pool): domain
                for domain in pending
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_map):
                domain = future_map[future]
                try:
                    results[domain] = future.result()
                except Exception as exc:
                    results[domain] = {
                        "status": "unknown",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                completed += 1
                if completed % 100 == 0 or completed == len(future_map):
                    print(f"DNS checked: {completed}/{len(future_map)}")

    for domain in pending:
        cache_domains[domain] = {
            "checked_at": time.time(),
            "result": results[domain],
        }

    invalid = {domain for domain, result in results.items() if result["status"] == "nxdomain"}
    file_summaries: dict[str, Any] = {}
    output_documents: dict[Path, str] = {}
    total_removed = 0
    for path, (kind, lines) in files.items():
        rewritten = []
        removed = 0
        for line in lines:
            replacement = rewrite_line(line, invalid, kind)
            if replacement is None:
                removed += 1
            else:
                rewritten.append(replacement)

        rewritten = update_count_metadata(rewritten, kind)
        before_count = _active_line_count(lines)
        after_count = _active_line_count(rewritten)
        if before_count > 0 and after_count == 0:
            raise RuntimeError(
                f"{path}: DNS validation would remove every active line; "
                "refusing to replace the existing subscription."
            )
        total_removed += removed
        file_summaries[path.name] = {
            "kind": kind,
            "active_lines_before": before_count,
            "active_lines_after": after_count,
            "removed_lines": removed,
        }
        output_documents[path] = "".join(rewritten)

    if args.write:
        for path, document in output_documents.items():
            original = path.read_text(encoding="utf-8-sig")
            if original != document:
                atomic_write(path, document)

    counts = {
        "valid": sum(result["status"] == "valid" for result in results.values()),
        "nxdomain": len(invalid),
        "unknown": sum(result["status"] == "unknown" for result in results.values()),
    }
    report = {
        "policy": {
            "delete_only_if_all_seven_providers_return_nxdomain_for_A_and_AAAA": True,
            "providers": list(DNS_PROVIDERS),
            "unknown_is_fail_open": True,
        },
        "summary": {
            "files_scanned": len(files),
            "candidate_domains": len(candidates),
            "cache_hits": len(cached),
            "queried_domains": len(pending),
            **counts,
            "lines_removed": total_removed,
            "write_mode": args.write,
        },
        "files": file_summaries,
        "results": results,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.cache:
        args.cache.parent.mkdir(parents=True, exist_ok=True)
        args.cache.write_text(
            json.dumps(cache, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    print(
        "Summary: "
        f"valid={counts['valid']}, confirmed_NXDOMAIN={counts['nxdomain']}, "
        f"unknown_kept={counts['unknown']}, removed_lines={total_removed}"
    )
    if not args.write and total_removed:
        print("Dry run only; re-run with --write to apply removals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
