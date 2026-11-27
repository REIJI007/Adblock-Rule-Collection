#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate Adblock output once, immediately after the Main/Lite build.

The five resolvers are unfiltered Google, Cloudflare, Tencent, Alibaba and
AdGuard DNS. Both A (IPv4) and AAAA (IPv6) are queried at every resolver.
A domain is valid if ANY query returns NOERROR (including NODATA). It is
invalid only when NONE of the ten queries returns NOERROR: NXDOMAIN and
query failures both count as unsuccessful answers, per the repository policy.
A small canary check aborts the batch if the entire resolver pool is offline.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CACHE_VERSION = 5
QUERY_TYPES = {"A": 1, "AAAA": 28}

# Only non-filtering public recursive DNS endpoints are used.
# AdGuard explicitly documents the unfiltered endpoint as not blocking any DNS
# requests. Tencent and Alibaba endpoints below are their public DNS services.
DNS_PROVIDERS = {
    "google": {
        "transport": "doh",
        "endpoint": "https://dns.google/dns-query",
    },
    "cloudflare": {
        "transport": "doh",
        "endpoint": "https://cloudflare-dns.com/dns-query",
    },
    "tencent": {
        "transport": "doh",
        "endpoint": "https://doh.pub/dns-query",
    },
    "alidns": {
        "transport": "doh",
        "endpoint": "https://dns.alidns.com/dns-query",
    },
    "adguard_unfiltered": {
        "transport": "doh",
        "endpoint": "https://unfiltered.adguard-dns.com/dns-query",
    },
}

# The validator intentionally accepts only the two upstream compiler outputs.
# DNS/Hosts/domain feeds downstream are derived from these cleaned files and
# must not be checked again.
MANAGED_OUTPUTS = {
    "ADBLOCK_RULE_COLLECTION.txt": "adblock",
    "ADBLOCK_RULE_COLLECTION_Lite.txt": "adblock",
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
    value = value.strip().lower()
    if value.endswith(".."):
        return None
    value = value.rstrip(".")
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


def _extract_generated_exact_regex_domain(line: str) -> str | None:
    """Recognize only this repository compiler's exact-host URL-authority regex.

    Hosts and exact-domain sources are compiled into this anchored pattern,
    rather than a simple ||domain^ rule. Generic/complex regex rules are left
    untouched; only the compiler's fixed wrapper plus an escaped literal
    hostname is eligible for DNS validation.
    """
    body = line[2:] if line.startswith("@@") else line
    prefix = r"/^https?:\/\/(?:[^\/?#@]+@)?"
    suffix = r"(?::[0-9]+)?(?:[\/?#]|$)/"
    if not body.startswith(prefix) or not body.endswith(suffix):
        return None
    escaped_host = body[len(prefix):-len(suffix)]
    # compile_dns_hostname_regex() wraps an exact hostname in one
    # non-capturing group. Accept it only when the inner value is literal.
    if escaped_host.startswith("(?:") and escaped_host.endswith(")"):
        escaped_host = escaped_host[3:-1]
    # re.escape() renders dots as a backslash-dot pair. Reject every other
    # regex operator instead of trying to interpret a general regular expression.
    labels = escaped_host.split(r"\.")
    if not labels or any(
        not re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels
    ):
        return None
    return normalize_domain(".".join(labels))


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
    """Return only positive $domain= scopes; negative scopes must be preserved."""
    domains: list[str] = []
    for match in DOMAIN_MODIFIER_RE.finditer(line):
        for token in match.group(2).split("|"):
            name = token.strip()
            if name.startswith("~"):
                continue
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
            domain for host in parsed[1]
            if (domain := normalize_domain(host)) is not None
        ]
        return ("hosts", candidates) if candidates else (None, [])

    if kind not in {"adblock", "dns"}:
        return None, []

    cosmetic = _cosmetic_scope(value)
    if cosmetic:
        candidates = [
            name for negated, name in cosmetic[2]
            if not negated and name != "*"
        ]
        return ("cosmetic", candidates) if candidates else (None, [])

    candidates = []
    anchored = _extract_anchored_domain(value)
    if anchored:
        candidates.append(anchored)
    exact_regex_domain = _extract_generated_exact_regex_domain(value)
    if exact_regex_domain:
        candidates.append(exact_regex_domain)

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
            if not negated and domain and domain in invalid:
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
            if neg or name == "*" or name not in invalid
        ]
        if positive and not any(not neg and name != "*" for neg, name in kept_parts):
            return None
        new_scope = ",".join(neg + name for neg, name in kept_parts)
        return new_scope + body[position:] + newline

    # Bare DNS entries and pure-domain-list entries are themselves the domain.
    anchored = _extract_anchored_domain(body)
    exact_regex_domain = _extract_generated_exact_regex_domain(body)
    if exact_regex_domain and exact_regex_domain in invalid:
        return None
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


def _skip_dns_name(payload: bytes, offset: int) -> int:
    """Skip a DNS-encoded name, following compression pointers safely."""
    cursor = offset
    resume_offset: int | None = None
    visited: set[int] = set()
    while True:
        if cursor >= len(payload):
            raise ValueError("DNS name extends beyond packet")
        length = payload[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(payload):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | payload[cursor + 1]
            if pointer >= len(payload) or cursor in visited or len(visited) > len(payload):
                raise ValueError("invalid DNS compression pointer")
            visited.add(cursor)
            if resume_offset is None:
                resume_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        if length == 0:
            return resume_offset if resume_offset is not None else cursor + 1
        if length > 63 or cursor + 1 + length > len(payload):
            raise ValueError("invalid or truncated DNS label")
        cursor += length + 1


def parse_dns_response(
    payload: bytes,
    query_id: int,
    qtype: str,
) -> dict[str, Any] | None:
    """Parse a DoH response and collect usable IPs from its Answer section.

    NOERROR alone is not proof of a usable DNS answer. The response must contain
    at least one IN-class A/AAAA RDATA matching the requested record type and
    representing a usable unicast IP address.
    """
    if qtype not in QUERY_TYPES or len(payload) < 12:
        return None
    try:
        response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
            "!HHHHHH", payload[:12]
        )
        if response_id != query_id or not (flags & 0x8000):
            return None
        if flags & 0x0200:
            # A truncated reply cannot be trusted as a complete DNS answer.
            return None

        rcode = flags & 0x000F
        offset = 12
        for _ in range(qdcount):
            offset = _skip_dns_name(payload, offset)
            if offset + 4 > len(payload):
                return None
            offset += 4

        addresses: set[str] = set()
        expected_type = QUERY_TYPES[qtype]
        expected_length = 4 if qtype == "A" else 16
        for _ in range(ancount):
            offset = _skip_dns_name(payload, offset)
            if offset + 10 > len(payload):
                return None
            rrtype, rrclass, _ttl, rdlength = struct.unpack(
                "!HHIH", payload[offset:offset + 10]
            )
            offset += 10
            if offset + rdlength > len(payload):
                return None
            rdata = payload[offset:offset + rdlength]
            offset += rdlength

            if rcode != 0 or rrclass != 1 or rrtype != expected_type:
                continue
            if len(rdata) != expected_length:
                return None
            address = ipaddress.ip_address(rdata)
            # Exclude sinkhole/placeholder and non-host addresses. Private
            # unicast addresses remain valid IP answers; public DNS may serve
            # legitimate private-use records too.
            if (
                address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
            ):
                continue
            addresses.add(str(address))

        return {"rcode": rcode, "addresses": sorted(addresses)}
    except (ValueError, struct.error):
        return None


def _query_doh(
    provider: str,
    domain: str,
    qtype: str,
    timeout: float,
) -> dict[str, Any] | None:
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
                return parse_dns_response(response.read(), query_id, qtype)
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt:
                return None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt:
                return None
        time.sleep(0.25 * (attempt + 1))
    return None


def query_public_dns(
    provider: str,
    domain: str,
    qtype: str,
    timeout: float,
) -> dict[str, Any] | None:
    try:
        return _query_doh(provider, domain, qtype, timeout)
    except Exception:
        # A resolver/API/transport failure provides no usable IP answer.
        return None


def classify_domain(
    domain: str,
    timeout: float,
    query_executor: concurrent.futures.Executor,
) -> dict[str, Any]:
    """Keep a domain only when at least one query returns a usable IP address."""
    future_map = {
        query_executor.submit(query_public_dns, provider, domain, qtype, timeout):
            (provider, qtype)
        for provider in DNS_PROVIDERS
        for qtype in QUERY_TYPES
    }
    provider_responses: dict[str, dict[str, dict[str, Any] | None]] = {
        provider: {} for provider in DNS_PROVIDERS
    }
    for future, (provider, qtype) in future_map.items():
        try:
            provider_responses[provider][qtype] = future.result()
        except Exception:
            provider_responses[provider][qtype] = None

    ip_returning_queries = [
        f"{provider}/{qtype}"
        for provider, responses in provider_responses.items()
        for qtype, response in responses.items()
        if response and response["addresses"]
    ]
    provider_results = {
        provider: (
            "resolved"
            if any(response and response["addresses"] for response in responses.values())
            else "no_usable_ip"
        )
        for provider, responses in provider_responses.items()
    }
    dns_rcodes = {
        provider: {
            qtype: response["rcode"] if response else None
            for qtype, response in responses.items()
        }
        for provider, responses in provider_responses.items()
    }
    dns_addresses = {
        provider: {
            qtype: response["addresses"] if response else []
            for qtype, response in responses.items()
        }
        for provider, responses in provider_responses.items()
    }
    return {
        "status": "valid" if ip_returning_queries else "invalid",
        "providers": provider_results,
        "dns_rcodes": dns_rcodes,
        "dns_addresses": dns_addresses,
        "ip_returning_queries": ip_returning_queries,
    }


def verify_resolver_pool(
    timeout: float,
    query_executor: concurrent.futures.Executor,
) -> None:
    """Abort unless the known-good example.com canary returns a usable IP."""
    checks = [
        query_executor.submit(query_public_dns, provider, "example.com", qtype, timeout)
        for provider in DNS_PROVIDERS
        for qtype in QUERY_TYPES
    ]
    responses = [future.result() for future in checks]
    if not any(response and response["addresses"] for response in responses):
        raise RuntimeError(
            "DNS validation aborted: none of the five resolvers returned a usable "
            "IP address for the example.com A/AAAA canary. Existing Adblock output "
            "was not modified."
        )

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
        description="Validate generated Main/Lite Adblock lists against five unfiltered public DNS resolvers."
    )
    parser.add_argument("files", nargs="*", help="ADBLOCK_RULE_COLLECTION.txt and/or its Lite output")
    parser.add_argument(
        "--both-adblock", action="store_true",
        help="validate both generated Adblock output files",
    )
    parser.add_argument("--write", action="store_true", help="apply removals; default is dry-run")
    parser.add_argument("--cache", type=Path, help="JSON cache path")
    parser.add_argument("--report", type=Path, help="JSON report path")
    parser.add_argument("--concurrency", type=int, default=12, help="concurrent domain checks (1-24)")
    parser.add_argument("--qps", type=float, default=18.0, help="maximum query starts per provider per second (1-18)")
    parser.add_argument("--timeout", type=float, default=6.0, help="per-query timeout in seconds")
    parser.add_argument("--cache-ttl-hours", type=float, default=0.25, help="cache TTL in hours (default: 15 minutes)")
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

    if args.both_adblock:
        paths = discover_managed_outputs(Path.cwd())
    elif args.files:
        paths = [Path(value).resolve() for value in args.files]
    else:
        parser.error("provide an Adblock output path or use --both-adblock")

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
        if not isinstance(checked_at, (int, float)):
            pending.append(domain)
            continue
        ttl = args.cache_ttl_hours * 3600
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
            if candidates:
                verify_resolver_pool(args.timeout, query_pool)
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
                    # An internal validator error is not a DNS result. Abort
                    # before writing rather than silently retaining or deleting
                    # a domain on a broken classification path.
                    raise RuntimeError(
                        f"internal error while classifying {domain}: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                completed += 1
                if completed % 100 == 0 or completed == len(future_map):
                    print(f"DNS checked: {completed}/{len(future_map)}")

    for domain in pending:
        cache_domains[domain] = {
            "checked_at": time.time(),
            "result": results[domain],
        }

    invalid = {domain for domain, result in results.items() if result["status"] == "invalid"}
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
        "invalid": len(invalid),
    }
    report = {
        "policy": {
            "providers": list(DNS_PROVIDERS),
            "query_types": ["A", "AAAA"],
            "valid_if_any_A_or_AAAA_answer_contains_usable_unicast_ip": True,
            "invalid_if_no_query_returns_a_usable_ip_address": True,
            "noerror_NODATA_counts_as_valid": False,
            "CNAME_without_final_A_or_AAAA_answer_counts_as_valid": False,
            "usable_ip_policy": "exclude unspecified, multicast, loopback, link-local and reserved addresses",
            "resolver_pool_canary": "example.com A/AAAA; abort unless a resolver returns a usable IP address",
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
        f"valid={counts['valid']}, invalid={counts['invalid']}, "
        f"removed_lines={total_removed}"
    )
    if not args.write and total_removed:
        print("Dry run only; re-run with --write to apply removals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
