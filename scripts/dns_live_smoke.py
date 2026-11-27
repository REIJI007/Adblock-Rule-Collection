#!/usr/bin/env python3
"""Live smoke test for all configured IP-pinned DoH resolver endpoints.

This script is intentionally separate from unit tests. It sends only a small
example.com A/AAAA canary set and never edits subscription files.
"""
from __future__ import annotations

import concurrent.futures
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dns_domain_validator as validator  # noqa: E402


def main() -> int:
    timeout = 10.0
    validator._RATE_LIMITERS = {
        provider: validator.RateLimiter(0.25)
        for provider in validator.DNS_PROVIDERS
    }

    query_map = {}
    with concurrent.futures.ThreadPoolExecutor(\n        max_workers=len(validator.DNS_PROVIDERS) * len(validator.QUERY_TYPES)\n    ) as executor:
        for provider in validator.DNS_PROVIDERS:
            for qtype in validator.QUERY_TYPES:
                future = executor.submit(
                    validator.query_public_dns,
                    provider,
                    "example.com",
                    qtype,
                    timeout,
                )
                query_map[future] = (provider, qtype)

        results = {
            provider: {} for provider in validator.DNS_PROVIDERS
        }
        for future, (provider, qtype) in query_map.items():
            try:
                results[provider][qtype] = future.result()
            except Exception as error:
                results[provider][qtype] = None
                print(
                    f"{provider}/{qtype}: unexpected {type(error).__name__}: {error}",
                    file=sys.stderr,
                )

    report = {
        "canary": "example.com",
        "transport": "DoH over HTTPS to numeric bootstrap IP; TLS SNI/Host validation enabled",
        "checked_at": int(time.time()),
        "providers": {},
    }

    healthy = set()
    for provider, responses in results.items():
        normalized = {}
        for qtype in validator.QUERY_TYPES:
            response = responses.get(qtype)
            normalized[qtype] = {
                "rcode": response.get("rcode") if response else None,
                "addresses": response.get("addresses", []) if response else [],
                "ttl": response.get("ttl") if response else None,
            }

        has_ip = any(value["addresses"] for value in normalized.values())
        if has_ip:
            healthy.add(provider)
        report["providers"][provider] = {
            "status": "healthy" if has_ip else "no_usable_canary_ip",
            "queries": normalized,
        }

    report["summary"] = {
        "configured_providers": len(validator.DNS_PROVIDERS),
        "healthy_providers": len(healthy),
        "healthy_names": sorted(healthy),
        "minimum_required": validator.MIN_HEALTHY_RESOLVERS,
    }

    report_path = ROOT / "dns-live-smoke-report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    for provider, data in report["providers"].items():
        a = data["queries"]["A"]["addresses"]
        aaaa = data["queries"]["AAAA"]["addresses"]
        print(
            f"{provider}: {data['status']} | "
            f"A={','.join(a) if a else '-'} | "
            f"AAAA={','.join(aaaa) if aaaa else '-'}"
        )

    print(
        f"Healthy resolvers: {len(healthy)}/{len(validator.DNS_PROVIDERS)} "
        f"(minimum {validator.MIN_HEALTHY_RESOLVERS})"
    )
    if len(healthy) < validator.MIN_HEALTHY_RESOLVERS:
        print(
            "Live DoH smoke test failed: fewer than the required number of "
            "resolvers returned a usable canary IP.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
