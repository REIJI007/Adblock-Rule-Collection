#!/usr/bin/env python3
"""Conservatively remove adblock entries whose domains are confirmed NXDOMAIN.

Only public DNS-over-HTTPS resolvers are used. A domain is removed only when
both configured providers return NXDOMAIN for both A and AAAA queries.
Timeouts, SERVFAIL, rate limits, and resolver disagreement are fail-open.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DNS_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}
QUERY_TYPES = ("A", "AAAA")
DEFAULT_CONCURRENCY = 24
DEFAULT_TIMEOUT = 6.0
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
RULE_DOMAIN_RE = re.compile(
    r"^(?:@@)?\|\|(?P<host>[^/^$|]+)(?:\^|/|\$|$)", re.IGNORECASE
)
PLAIN_DOMAIN_RE = re.compile(
    r"^(?:[A-Z0-9-]+\.)+[A-Z0-9-]+\.?$", re.IGNORECASE
)
SUPPORTED_EXTENSIONS = {
    ".txt", ".list", ".adblock", ".conf", ".hosts", ".rules", ".dat"
}
EXCLUDED_DIRS = {
    ".git", ".github", ".venv", "venv", "node_modules", "__pycache__",
    "tests", "test", "docs", "examples", "assets", "dist", "build"
}
EXCLUDED_PREFIXES = (
    "readme", "license", "changelog", "contributing", "requirements",
    "dns-validation-report",
)


def normalize_domain(value: str) -> str | None:
    """Return an ASCII/IDNA FQDN, or None for non-domain values."""
    value = value.strip().rstrip(".").lower()
    if not value or "*" in value or "/" in value or ":" in value:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_name) > 253 or "." not in ascii_name:
        return None
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return ascii_name


def parse_line(line: str) -> tuple[str | None, list[str]]:
    """Recognize hosts-file, Adblock Plus domain, and bare-domain entries."""
    body = line.rstrip("\r\n").strip()
    if not body or body.startswith(("!", "#", ";", "[", "//")):
        return None, []

    tokens = body.split()
    if len(tokens) >= 2:
        try:
            ipaddress.ip_address(tokens[0])
            comment_at = next(
                (i for i, token in enumerate(tokens[1:], 1)
                 if token.startswith(("#", "!"))),
                len(tokens),
            )
            domains = [
                d for token in tokens[1:comment_at]
                if (d := normalize_domain(token)) is not None
            ]
            if domains:
                return "hosts", domains
        except ValueError:
            pass

    match = RULE_DOMAIN_RE.match(body)
    if match:
        domain = normalize_domain(match.group("host"))
        return ("single", [domain]) if domain else (None, [])

    domain = normalize_domain(body)
    if domain and PLAIN_DOMAIN_RE.fullmatch(body):
        return "single", [domain]
    return None, []


def rewrite_line(line: str, invalid_domains: set[str]) -> str | None:
    """Remove only confirmed-invalid domain tokens; preserve all other syntax."""
    kind, domains = parse_line(line)
    if not domains:
        return line
    invalid = {domain for domain in domains if domain in invalid_domains}
    if not invalid:
        return line

    if kind == "single":
        return None

    newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
    body = line.rstrip("\r\n")
    tokens = body.split()
    comment_at = next(
        (i for i, token in enumerate(tokens[1:], 1)
         if token.startswith(("#", "!"))),
        len(tokens),
    )
    kept = [
        token for token in tokens[1:comment_at]
        if (normalize_domain(token) not in invalid)
    ]
    if not kept:
        return None
    suffix = tokens[comment_at:]
    return " ".join([tokens[0], *kept, *suffix]) + newline


def discover_rule_files(root: Path) -> list[Path]:
    """Find likely rule-list files while excluding code, docs, and build trees."""
    found: list[Path] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for filename in files:
            path = Path(current) / filename
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if filename.lower().startswith(EXCLUDED_PREFIXES):
                continue
            found.append(path)
    return sorted(found)


def query_doh(
    provider: str, domain: str, qtype: str, timeout: float
) -> dict[str, Any] | None:
    """Query a public DoH JSON endpoint; return None on transport/API failure."""
    endpoint = DNS_PROVIDERS[provider]
    query = urllib.parse.urlencode({"name": domain, "type": qtype})
    url = f"{endpoint}?{query}"
    headers = {
        "Accept": "application/dns-json",
        "User-Agent": "Adblock-Rule-Collection-DNS-Validator/1.0",
    }
    for attempt in range(2):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            status = payload.get("Status")
            if isinstance(status, int):
                return payload
            return None
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP_CODES or attempt == 1:
                return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            if attempt == 1:
                return None
        time.sleep(0.25 * (attempt + 1))
    return None


def classify_domain(domain: str, timeout: float) -> dict[str, Any]:
    """Classify as valid, nxdomain, or unknown using two independent providers.

    NOERROR (Status=0), including NODATA, is evidence that the queried name
    exists. NXDOMAIN is accepted only when both A and AAAA queries from both
    providers agree. All other outcomes are unknown and must be retained.
    """
    provider_results: dict[str, str] = {}
    statuses: dict[str, list[int | None]] = {}
    for provider in DNS_PROVIDERS:
        provider_statuses: list[int | None] = []
        for qtype in QUERY_TYPES:
            response = query_doh(provider, domain, qtype, timeout)
            status = response.get("Status") if response else None
            provider_statuses.append(status if isinstance(status, int) else None)
        statuses[provider] = provider_statuses
        if 0 in provider_statuses:
            provider_results[provider] = "valid"
        elif provider_statuses == [3, 3]:
            provider_results[provider] = "nxdomain"
        else:
            provider_results[provider] = "unknown"

    if "valid" in provider_results.values():
        result = "valid"
    elif all(value == "nxdomain" for value in provider_results.values()):
        result = "nxdomain"
    else:
        result = "unknown"
    return {
        "status": result,
        "providers": provider_results,
        "dns_status_codes": statuses,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove only domains confirmed NXDOMAIN by public DNS."
    )
    parser.add_argument(
        "files", nargs="*", help="Rule files to validate (default: use --all)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="discover supported rule files under the current directory"
    )
    parser.add_argument(
        "--write", action="store_true",
        help="write filtered files; without this flag the command is a dry run"
    )
    parser.add_argument(
        "--report", type=Path,
        help="optional JSON report path"
    )
    parser.add_argument(
        "--cache", type=Path,
        help="optional JSON cache file for previously checked domains"
    )
    parser.add_argument(
        "--cache-ttl-hours", type=float, default=24.0,
        help="cache lifetime for valid/NXDOMAIN results (default: 24 hours)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
        help=f"maximum concurrent domain checks (default: {DEFAULT_CONCURRENCY})"
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"per-request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    args = parser.parse_args()

    if args.concurrency < 1 or args.concurrency > 100:
        parser.error("--concurrency must be between 1 and 100")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout must be greater than 0 and at most 60 seconds")

    root = Path.cwd()
    if args.all:
        files = discover_rule_files(root)
    elif args.files:
        files = [Path(name).resolve() for name in args.files]
    else:
        parser.error("provide file paths or use --all")

    files = [path for path in files if path.is_file()]
    if not files:
        print("No supported rule files found.", file=sys.stderr)
        return 2

    file_lines: dict[Path, list[str]] = {}
    domains: set[str] = set()
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines(keepends=True)
        except (OSError, UnicodeError) as exc:
            print(f"Skipping unreadable file {path}: {exc}", file=sys.stderr)
            continue
        file_lines[path] = lines
        for line in lines:
            _, candidates = parse_line(line)
            domains.update(candidates)

    print(f"Files: {len(file_lines)} | unique domains: {len(domains)}")
    if args.cache_ttl_hours <= 0:
        parser.error("--cache-ttl-hours must be greater than zero")

    # Cached transport failures expire quickly; conclusive results live longer.
    cache_entries: dict[str, dict[str, Any]] = {}
    cached_results: dict[str, dict[str, Any]] = {}
    now = time.time()
    if args.cache and args.cache.is_file():
        try:
            loaded_cache = json.loads(args.cache.read_text(encoding="utf-8"))
            if isinstance(loaded_cache, dict):
                cache_entries = loaded_cache
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("Ignoring unreadable DNS cache.", file=sys.stderr)

    for domain in domains:
        entry = cache_entries.get(domain)
        if not isinstance(entry, dict) or not isinstance(entry.get("result"), dict):
            continue
        checked_at = entry.get("checked_at")
        status = entry["result"].get("status")
        if not isinstance(checked_at, (int, float)):
            continue
        ttl = 900 if status == "unknown" else args.cache_ttl_hours * 3600
        if now - checked_at <= ttl:
            cached_results[domain] = entry["result"]

    results: dict[str, dict[str, Any]] = dict(cached_results)
    pending_domains = sorted(domains - set(cached_results))
    print(f"DNS cache hits: {len(cached_results)} | queries required: {len(pending_domains)}")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.concurrency
    ) as executor:
        future_map = {
            executor.submit(classify_domain, domain, args.timeout): domain
            for domain in pending_domains
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            domain = future_map[future]
            try:
                results[domain] = future.result()
            except Exception as exc:  # fail-open on an unexpected per-domain error
                results[domain] = {
                    "status": "unknown",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            completed += 1
            if completed % 100 == 0 or completed == len(future_map):
                print(f"DNS checked: {completed}/{len(future_map)}")

    if args.cache:
        for domain, result in results.items():
            if domain not in cached_results:
                cache_entries[domain] = {"checked_at": time.time(), "result": result}
        args.cache.parent.mkdir(parents=True, exist_ok=True)
        args.cache.write_text(
            json.dumps(cache_entries, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

    invalid_domains = {
        domain for domain, result in results.items()
        if result["status"] == "nxdomain"
    }
    modified_files = 0
    removed_lines = 0
    for path, lines in file_lines.items():
        rewritten: list[str] = []
        removed = 0
        for line in lines:
            replacement = rewrite_line(line, invalid_domains)
            if replacement is None:
                removed += 1
            else:
                rewritten.append(replacement)
        if removed:
            removed_lines += removed
            modified_files += 1
            if args.write:
                path.write_text("".join(rewritten), encoding="utf-8")

    counts = {
        "valid": sum(r["status"] == "valid" for r in results.values()),
        "nxdomain": len(invalid_domains),
        "unknown": sum(r["status"] == "unknown" for r in results.values()),
    }
    report = {
        "summary": {
            "files_scanned": len(file_lines),
            "unique_domains": len(domains),
            **counts,
            "lines_to_remove": removed_lines,
            "files_to_modify": modified_files,
            "write_mode": args.write,
        },
        "invalid_domains": sorted(invalid_domains),
        "results": results,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    print(
        "Summary: "
        f"valid={counts['valid']}, "
        f"confirmed_NXDOMAIN={counts['nxdomain']}, "
        f"unknown_kept={counts['unknown']}, "
        f"lines_removed={removed_lines}, "
        f"files_modified={modified_files}"
    )
    if not args.write and removed_lines:
        print("Dry run only. Re-run with --write to apply the removals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
