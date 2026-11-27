#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用两个公共 DNS-over-HTTPS 解析器验证 DOMAIN 订阅中的主机名。

只有取得 A、AAAA 或 CNAME 正向解析结果的域名才会进入订阅。
两个解析器一致确认 NXDOMAIN，或一致确认 A/AAAA 均无地址记录时，才会标记为无效。
超时、SERVFAIL 和解析器结果不一致属于不确定状态：新域名暂不发布，已有有效记录则保留。
SQLite 缓存用于跨工作流运行增量扫描，避免每 20 分钟重复查询全部域名。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
}
POSITIVE_TYPES = {"A": {1, 5}, "AAAA": {28, 5}}
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\Z", re.IGNORECASE)
CACHE_MARKER = "#DNS验证缓存版本: 1"


class RateLimiter:
    """限制所有 DoH 请求的总速率，避免对公共解析器造成突发流量。"""

    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than zero")
        self.interval = 1.0 / requests_per_second
        self.lock = threading.Lock()
        self.next_request_at = 0.0

    def acquire(self) -> None:
        with self.lock:
            now = time.monotonic()
            scheduled_at = max(now, self.next_request_at)
            self.next_request_at = scheduled_at + self.interval
        delay = scheduled_at - now
        if delay > 0:
            time.sleep(delay)


def canonical_domain(value: str) -> str | None:
    """规范化并校验单个 DNS 主机名；不接受 IP、通配符或单标签名称。"""
    if not value or value != value.strip() or "*" in value:
        return None
    if value.endswith(".."):
        return None
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253 or any(ch in value for ch in "/\\\\:@?#"):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    labels = value.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None

    ascii_labels: list[str] = []
    try:
        for label in labels:
            encoded = label.encode("idna").decode("ascii").lower()
            if len(encoded) > 63 or not DOMAIN_LABEL_RE.fullmatch(encoded):
                return None
            ascii_labels.append(encoded)
    except UnicodeError:
        return None

    result = ".".join(ascii_labels)
    return result if len(result) <= 253 else None


def response_state(payload: object, query_type: str) -> str:
    """将 DoH JSON 响应归类为 positive、nxdomain、nodata 或 error。"""
    if not isinstance(payload, dict):
        return "error"
    status = payload.get("Status")
    if status == 3:
        return "nxdomain"
    if status != 0:
        return "error"

    answers = payload.get("Answer") or []
    if not isinstance(answers, list):
        return "error"
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        try:
            record_type = int(answer.get("type", -1))
        except (TypeError, ValueError):
            continue
        if record_type in POSITIVE_TYPES[query_type] and answer.get("data"):
            return "positive"
    return "nodata"


def query_dns(
    domain: str,
    query_type: str,
    resolver_url: str,
    limiter: RateLimiter,
    timeout: float = 6.0,
) -> str:
    """向指定公共解析器发送一次 DoH JSON 查询；网络异常一律返回 error。"""
    query = urllib.parse.urlencode({"name": domain, "type": query_type})
    separator = "&" if "?" in resolver_url else "?"
    request = urllib.request.Request(
        resolver_url + separator + query,
        headers={
            "Accept": "application/dns-json",
            "User-Agent": "Adblock-Rule-Collection-DNS-Validator/1.0",
        },
    )
    try:
        limiter.acquire()
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(65536).decode("utf-8"))
        return response_state(payload, query_type)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError):
        return "error"


QueryFunction = Callable[[str, str, str], str]


def verify_domain(domain: str, query: QueryFunction) -> tuple[str, str]:
    """返回 (valid|invalid|pending, reason)。

    两个解析器均确认 NXDOMAIN 才判定不存在；A/AAAA 均在两个解析器上
    返回 NOERROR 但无地址/CNAME 记录时，判定为没有可用地址记录。
    """
    if not canonical_domain(domain):
        return "invalid", "invalid_hostname"

    a_results = [query(domain, "A", url) for url in RESOLVERS.values()]
    if "positive" in a_results:
        return "valid", "a_or_cname_record"
    if all(result == "nxdomain" for result in a_results):
        return "invalid", "confirmed_nxdomain"

    aaaa_results = [query(domain, "AAAA", url) for url in RESOLVERS.values()]
    if "positive" in aaaa_results:
        return "valid", "aaaa_or_cname_record"
    if all(result == "nodata" for result in a_results + aaaa_results):
        return "invalid", "no_a_aaaa_or_cname_records"

    return "pending", "dns_inconclusive"


def read_candidates(path: Path) -> tuple[set[str], int]:
    candidates: set[str] = set()
    malformed = 0
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        domain = canonical_domain(line)
        if domain is None:
            malformed += 1
            continue
        candidates.add(domain)
    return candidates, malformed


def ensure_cache_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_cache (
            host TEXT PRIMARY KEY,
            status TEXT NOT NULL CHECK(status IN ('valid', 'invalid', 'pending')),
            checked_at INTEGER NOT NULL,
            next_check_at INTEGER NOT NULL,
            reason TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dns_cache_next_check "
        "ON dns_cache(next_check_at, status)"
    )


def update_cache(
    connection: sqlite3.Connection,
    host: str,
    status: str,
    reason: str,
    now: int,
    ttl_seconds: int,
    retry_seconds: int,
) -> None:
    existing = connection.execute(
        "SELECT status FROM dns_cache WHERE host = ?", (host,)
    ).fetchone()

    if status in {"valid", "invalid"}:
        connection.execute(
            """
            INSERT INTO dns_cache(host, status, checked_at, next_check_at, reason)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                status = excluded.status,
                checked_at = excluded.checked_at,
                next_check_at = excluded.next_check_at,
                reason = excluded.reason
            """,
            (host, status, now, now + ttl_seconds, reason),
        )
    elif existing is None:
        connection.execute(
            """
            INSERT INTO dns_cache(host, status, checked_at, next_check_at, reason)
            VALUES (?, 'pending', 0, ?, ?)
            """,
            (host, now + retry_seconds, reason),
        )
    else:
        # 解析器暂时异常时保留既有的 valid/invalid 结论，避免把网络故障当成域名失效。
        connection.execute(
            "UPDATE dns_cache SET next_check_at = ?, "
            "reason = CASE WHEN status = 'pending' THEN ? ELSE reason END "
            "WHERE host = ?",
            (now + retry_seconds, reason, host),
        )


def rewrite_domain_file(path: Path, valid_domains: set[str]) -> int:
    """原样保留注释头部，只输出已确认有效的域名并更新计数。"""
    source_lines = path.read_text(encoding="utf-8-sig").splitlines()
    output_lines: list[str] = []
    retained = 0
    count_header_seen = False
    marker_seen = False

    for raw_line in source_lines:
        line = raw_line.strip()
        if line.startswith("#有效域名数目:"):
            output_lines.append("#有效域名数目: 0")
            count_header_seen = True
        elif line.startswith("#DNS验证缓存版本:"):
            output_lines.append(CACHE_MARKER)
            marker_seen = True
        elif not line or line.startswith("#"):
            output_lines.append(raw_line)
        else:
            domain = canonical_domain(line)
            if domain and domain in valid_domains:
                output_lines.append(domain)
                retained += 1

    if not count_header_seen:
        output_lines.insert(0, "#有效域名数目: 0")
    if not marker_seen:
        insert_at = 1 if output_lines else 0
        output_lines.insert(insert_at, CACHE_MARKER)

    output_lines = [
        f"#有效域名数目: {retained}" if item == "#有效域名数目: 0" else item
        for item in output_lines
    ]
    path.write_text("\\n".join(output_lines) + "\\n", encoding="utf-8")
    return retained


def run_validation(
    files: list[Path],
    cache_path: Path,
    report_path: Path,
    batch_size: int = 10000,
    workers: int = 48,
    qps: float = 60.0,
    ttl_days: int = 30,
    retry_hours: int = 2,
) -> dict[str, object]:
    if batch_size < 1 or workers < 1 or ttl_days < 1 or retry_hours < 1:
        raise ValueError("batch-size, workers, ttl-days and retry-hours must be positive")
    if not files:
        raise ValueError("at least one domain list file is required")
    for path in files:
        if not path.is_file():
            raise FileNotFoundError(f"domain list not found: {path}")

    marker_present = any(
        CACHE_MARKER in path.read_text(encoding="utf-8-sig")
        for path in files
    )
    cache_existed = cache_path.is_file()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(cache_path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=NORMAL")
    ensure_cache_schema(connection)

    try:
        cached_rows = connection.execute("SELECT COUNT(*) FROM dns_cache").fetchone()[0]
        if marker_present and (not cache_existed or cached_rows == 0):
            raise RuntimeError(
                "DNS validation cache is missing or empty although the output lists "
                "already contain the DNS cache marker. Refusing to publish a partial list; "
                "restore the Actions cache or remove the marker only for an intentional rebuild."
            )

        candidates: set[str] = set()
        malformed = 0
        for path in files:
            file_candidates, file_malformed = read_candidates(path)
            candidates.update(file_candidates)
            malformed += file_malformed
        if not candidates:
            raise RuntimeError("no valid candidate domains were found")

        connection.execute(
            "CREATE TEMP TABLE candidates(host TEXT PRIMARY KEY) WITHOUT ROWID"
        )
        connection.executemany(
            "INSERT OR IGNORE INTO candidates(host) VALUES (?)",
            ((host,) for host in candidates),
        )

        now = int(time.time())
        ttl_seconds = ttl_days * 86400
        retry_seconds = retry_hours * 3600
        due_hosts = [
            row[0]
            for row in connection.execute(
                """
                SELECT c.host
                FROM candidates AS c
                LEFT JOIN dns_cache AS d ON d.host = c.host
                WHERE d.host IS NULL OR d.next_check_at <= ?
                ORDER BY
                    CASE
                        WHEN d.host IS NULL THEN 0
                        WHEN d.status = 'pending' THEN 1
                        ELSE 2
                    END,
                    COALESCE(d.next_check_at, 0),
                    c.host
                LIMIT ?
                """,
                (now, batch_size),
            )
        ]

        limiter = RateLimiter(qps)

        def check_one(host: str) -> tuple[str, str, str]:
            def query(name: str, query_type: str, resolver_url: str) -> str:
                return query_dns(name, query_type, resolver_url, limiter)

            status, reason = verify_domain(host, query)
            return host, status, reason

        processed_counts = {"valid": 0, "invalid": 0, "pending": 0}
        if due_hosts:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                results = list(executor.map(check_one, due_hosts))
            for host, status, reason in results:
                update_cache(
                    connection, host, status, reason, now, ttl_seconds, retry_seconds
                )
                processed_counts[status] += 1
            connection.commit()

        valid_domains = {
            row[0]
            for row in connection.execute(
                """
                SELECT c.host
                FROM candidates AS c
                JOIN dns_cache AS d ON d.host = c.host
                WHERE d.status = 'valid'
                """
            )
        }
        cached_counts = {
            status: count
            for status, count in connection.execute(
                """
                SELECT d.status, COUNT(*)
                FROM candidates AS c
                JOIN dns_cache AS d ON d.host = c.host
                GROUP BY d.status
                """
            )
        }
        for status in ("valid", "invalid", "pending"):
            cached_counts.setdefault(status, 0)

        retained_by_file = {
            str(path): rewrite_domain_file(path, valid_domains) for path in files
        }

        report: dict[str, object] = {
            "candidate_domains": len(candidates),
            "malformed_entries": malformed,
            "batch_limit": batch_size,
            "processed_this_run": len(due_hosts),
            "processed_results": processed_counts,
            "cached_status": cached_counts,
            "confirmed_valid_candidates": len(valid_domains),
            "retained_by_file": retained_by_file,
            "resolvers": list(RESOLVERS.keys()),
            "record_types": ["A", "AAAA", "CNAME"],
            "cache_ttl_days": ttl_days,
            "pending_retry_hours": retry_hours,
            "policy": (
                "Publish only domains with a positive A, AAAA or CNAME response. "
                "Remove only consensus NXDOMAIN or consensus A/AAAA NODATA. "
                "Keep prior confirmed status on transient or conflicting DNS results."
            ),
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\\n",
            encoding="utf-8",
        )
        return report
    finally:
        connection.close()


def run_self_tests() -> None:
    assert canonical_domain("Example.COM.") == "example.com"
    assert canonical_domain("例え.テスト") == "xn--r8jz45g.xn--zckzah"
    assert canonical_domain("127.0.0.1") is None
    assert canonical_domain("*.example.com") is None
    assert canonical_domain("localhost") is None
    assert response_state({"Status": 3}, "A") == "nxdomain"
    assert response_state({"Status": 0, "Answer": []}, "A") == "nodata"
    assert response_state(
        {"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.1"}]}, "A"
    ) == "positive"

    def make_query(responses: dict[tuple[str, str], str]) -> QueryFunction:
        def query(domain: str, query_type: str, resolver_url: str) -> str:
            resolver = "cloudflare" if "cloudflare" in resolver_url else "google"
            return responses[(query_type, resolver)]
        return query

    valid_a = {
        ("A", "cloudflare"): "positive",
        ("A", "google"): "positive",
    }
    assert verify_domain("example.com", make_query(valid_a)) == (
        "valid", "a_or_cname_record"
    )

    nxdomain = {
        ("A", "cloudflare"): "nxdomain",
        ("A", "google"): "nxdomain",
    }
    assert verify_domain("example.com", make_query(nxdomain)) == (
        "invalid", "confirmed_nxdomain"
    )

    ipv6_only = {
        ("A", "cloudflare"): "nodata",
        ("A", "google"): "nodata",
        ("AAAA", "cloudflare"): "positive",
        ("AAAA", "google"): "positive",
    }
    assert verify_domain("example.com", make_query(ipv6_only)) == (
        "valid", "aaaa_or_cname_record"
    )

    no_address = {
        ("A", "cloudflare"): "nodata",
        ("A", "google"): "nodata",
        ("AAAA", "cloudflare"): "nodata",
        ("AAAA", "google"): "nodata",
    }
    assert verify_domain("example.com", make_query(no_address)) == (
        "invalid", "no_a_aaaa_or_cname_records"
    )

    inconclusive = {
        ("A", "cloudflare"): "error",
        ("A", "google"): "nxdomain",
        ("AAAA", "cloudflare"): "error",
        ("AAAA", "google"): "nodata",
    }
    assert verify_domain("example.com", make_query(inconclusive)) == (
        "pending", "dns_inconclusive"
    )
    print("Passed 9 DNS validator regression checks.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate domain-only blocklists using public DNS resolvers."
    )
    parser.add_argument("files", nargs="*", help="Domain list files to validate")
    parser.add_argument(
        "--cache", type=Path, default=Path(".cache/dns-domain-validation.sqlite3")
    )
    parser.add_argument(
        "--report", type=Path, default=Path("dns-domain-validation-report.json")
    )
    parser.add_argument("--batch-size", type=int, default=10000)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--qps", type=float, default=60.0)
    parser.add_argument("--ttl-days", type=int, default=30)
    parser.add_argument("--retry-hours", type=int, default=2)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        run_self_tests()
        return 0
    if not args.files:
        parser.error("at least one domain list file is required")

    try:
        report = run_validation(
            files=[Path(item) for item in args.files],
            cache_path=args.cache,
            report_path=args.report,
            batch_size=args.batch_size,
            workers=args.workers,
            qps=args.qps,
            ttl_days=args.ttl_days,
            retry_hours=args.retry_hours,
        )
    except Exception as error:
        print(f"DNS validation failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
