#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate Adblock output once, immediately after the Main/Lite build.

The resolver pool contains Google, Cloudflare and AdGuard Non-filtering DNS.
Both A (IPv4) and AAAA (IPv6) are queried at every resolver. A domain is
valid only when an Answer-section A/AAAA record on the queried hostname or
its CNAME chain contains a usable IP address. Negative classification requires
a healthy resolver quorum and repeated independent no-address observations.
A canary check aborts the batch if the resolver pool is unhealthy.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import urllib.error
from pathlib import Path
from typing import Any

CACHE_VERSION = 7
MIN_HEALTHY_RESOLVERS = 3
NEGATIVE_CONFIRMATIONS_REQUIRED = 3
NEGATIVE_CONFIRMATION_INTERVAL_SECONDS = 15 * 60
NEGATIVE_CONFIRMATION_WINDOW_SECONDS = 24 * 60 * 60
QUERY_TYPES = {"A": 1, "AAAA": 28}

# All resolver traffic uses RFC 8484 DoH. Connections are made directly to
# numeric resolver IPs; the original service hostname is retained for HTTP
# Host, TLS SNI and certificate hostname verification.
DNS_PROVIDERS = {
    "google": {
        "transport": "doh",
        "tls_server_name": "dns.google",
        "path": "/dns-query",
        "bootstrap_ipv4": ["8.8.8.8", "8.8.4.4"],
        "bootstrap_ipv6": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    },
    "cloudflare": {
        "transport": "doh",
        "tls_server_name": "cloudflare-dns.com",
        "path": "/dns-query",
        "bootstrap_ipv4": ["1.1.1.1", "1.0.0.1"],
        "bootstrap_ipv6": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
    },
    "adguard_unfiltered": {
        "transport": "doh",
        "tls_server_name": "unfiltered.adguard-dns.com",
        "path": "/dns-query",
        "bootstrap_ipv4": ["94.140.14.140", "94.140.14.141"],
        "bootstrap_ipv6": ["2a10:50c0::1:ff", "2a10:50c0::2:ff"],
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
    """Return only DNS names that are actual blocked targets.

    Positive/negative $domain= values and cosmetic-rule scopes describe where
    a rule applies; they are not the hostname being blocked and must not be
    DNS-pruned independently.
    """
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

    # Cosmetic scopes are contextual website selectors, not blocked hosts.
    if any(marker in value for marker in COSMETIC_MARKERS):
        return None, []

    candidates: list[str] = []
    anchored = _extract_anchored_domain(value)
    if anchored:
        candidates.append(anchored)
    exact_regex_domain = _extract_generated_exact_regex_domain(value)
    if exact_regex_domain:
        candidates.append(exact_regex_domain)

    # $domain= modifier scopes are deliberately excluded here. Only the
    # primary anchored hostname (the actual blocked request target) is tested.
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
    """Remove confirmed-invalid target hosts without changing rule scopes."""
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
        prefix, names, _suffix_newline = parsed
        kept = [
            name for name in names
            if normalize_domain(name) not in invalid
        ]
        if not kept:
            return None
        raw_body = body.split("#", 1)
        comment = (" #" + raw_body[1]) if len(raw_body) > 1 else ""
        return " ".join(prefix + kept) + comment + newline

    # Domain-list, anchored Adblock, exact generated host-regex and bare DNS
    # entries are removed as a whole when their actual target is invalid.
    # Website scopes ($domain= and cosmetic scopes) are never rewritten.
    return None

def make_dns_query(domain: str, qtype: str) -> tuple[bytes, int]:
    query_id = int.from_bytes(os.urandom(2), "big")
    labels = domain.encode("ascii").split(b".")
    qname = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", QUERY_TYPES[qtype], 1)
    return header + question, query_id


def _read_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name, safely handling RFC 1035 compression pointers."""
    cursor = offset
    resume_offset: int | None = None
    labels: list[str] = []
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
            end = resume_offset if resume_offset is not None else cursor + 1
            return ".".join(labels).lower(), end
        if length > 63 or cursor + 1 + length > len(payload):
            raise ValueError("invalid or truncated DNS label")
        try:
            labels.append(payload[cursor + 1:cursor + 1 + length].decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII DNS wire label") from exc
        cursor += length + 1


def _is_usable_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject special-purpose sinkhole/non-host addresses; private unicast is allowed."""
    return not (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


def parse_dns_response(
    payload: bytes,
    query_id: int,
    qtype: str,
    query_domain: str,
) -> dict[str, Any] | None:
    """Parse a DoH response and validate address records on the queried CNAME chain."""
    if qtype not in QUERY_TYPES or len(payload) < 12:
        return None
    expected_type = QUERY_TYPES[qtype]
    expected_length = 4 if qtype == "A" else 16
    normalized_query = normalize_domain(query_domain)
    if not normalized_query:
        return None

    try:
        response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
            "!HHHHHH", payload[:12]
        )
        if response_id != query_id or not (flags & 0x8000) or flags & 0x0200:
            return None
        if qdcount != 1:
            return None

        question_name, offset = _read_dns_name(payload, 12)
        if offset + 4 > len(payload):
            return None
        question_type, question_class = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        if question_name != normalized_query or question_type != expected_type or question_class != 1:
            return None

        rcode = flags & 0x000F
        records: list[dict[str, Any]] = []
        for _ in range(ancount):
            owner, offset = _read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                return None
            rrtype, rrclass, ttl, rdlength = struct.unpack(
                "!HHIH", payload[offset:offset + 10]
            )
            offset += 10
            rdata_offset = offset
            rdata_end = offset + rdlength
            if rdata_end > len(payload):
                return None
            rdata = payload[rdata_offset:rdata_end]
            record: dict[str, Any] = {
                "owner": owner,
                "type": rrtype,
                "class": rrclass,
                "ttl": ttl,
            }
            if rrtype == 5 and rrclass == 1:
                cname_target, consumed = _read_dns_name(payload, rdata_offset)
                if consumed > rdata_end:
                    return None
                record["target"] = cname_target
            elif rrtype == expected_type and rrclass == 1 and rcode == 0:
                if len(rdata) != expected_length:
                    return None
                address = ipaddress.ip_address(rdata)
                record["address"] = str(address) if _is_usable_address(address) else None
            records.append(record)
            offset = rdata_end

        if rcode != 0:
            return {"rcode": rcode, "addresses": [], "ttl": None, "cname_chain": []}

        # Only accept an address owned by the queried name or by a target reached
        # through its CNAME chain. Unrelated A/AAAA records in Answer do not count.
        current = normalized_query
        visited_names = {current}
        chain: list[str] = [current]
        ttls: list[int] = []
        for _hop in range(9):
            cname_records = [
                record for record in records
                if record["owner"] == current
                and record["type"] == 5
                and record["class"] == 1
            ]
            if cname_records:
                targets = {record.get("target") for record in cname_records}
                if len(targets) != 1 or None in targets:
                    return {"rcode": rcode, "addresses": [], "ttl": None, "cname_chain": chain}
                target = next(iter(targets))
                if target in visited_names:
                    return {"rcode": rcode, "addresses": [], "ttl": None, "cname_chain": chain}
                visited_names.add(target)
                chain.append(target)
                ttls.extend(int(record["ttl"]) for record in cname_records)
                current = target
                continue

            matching = [
                record for record in records
                if record["owner"] == current
                and record["type"] == expected_type
                and record["class"] == 1
                and record.get("address")
            ]
            addresses = sorted({record["address"] for record in matching})
            if addresses:
                ttls.extend(int(record["ttl"]) for record in matching)
                return {
                    "rcode": rcode,
                    "addresses": addresses,
                    "ttl": min(ttls) if ttls else None,
                    "cname_chain": chain,
                }
            return {"rcode": rcode, "addresses": [], "ttl": None, "cname_chain": chain}

        return {"rcode": rcode, "addresses": [], "ttl": None, "cname_chain": chain}
    except (ValueError, struct.error):
        return None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a numeric IP while verifying the DNS TLS name."""

    def __init__(
        self,
        host: str,
        *,
        bootstrap_ip: str,
        tls_server_name: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(host, **kwargs)
        self.bootstrap_ip = bootstrap_ip
        self.tls_server_name = tls_server_name

    def connect(self) -> None:
        if self._tunnel_host:
            raise OSError("HTTPS proxy tunneling is not supported by pinned DoH transport")
        raw_socket = socket.create_connection(
            (self.bootstrap_ip, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.tls_server_name,
            )
        except Exception:
            raw_socket.close()
            raise


_BOOTSTRAP_ROTATION: dict[str, int] = {}
_BOOTSTRAP_ROTATION_LOCK = threading.Lock()


def _doh_url(bootstrap_ip: str, path: str, encoded_query: str) -> str:
    address = ipaddress.ip_address(bootstrap_ip)
    authority = f"[{address}]" if address.version == 6 else str(address)
    return f"https://{authority}{path}?dns={encoded_query}"


def _ordered_bootstrap_ips(provider: str) -> list[str]:
    config = DNS_PROVIDERS[provider]
    ipv4 = list(config.get("bootstrap_ipv4", []))
    ipv6 = list(config.get("bootstrap_ipv6", []))

    with _BOOTSTRAP_ROTATION_LOCK:
        start = _BOOTSTRAP_ROTATION.get(provider, 0)
        if ipv4:
            _BOOTSTRAP_ROTATION[provider] = (start + 1) % len(ipv4)
    if ipv4:
        ipv4 = ipv4[start:] + ipv4[:start]
    return ipv4 + ipv6


def _query_doh(
    provider: str,
    domain: str,
    qtype: str,
    timeout: float,
) -> dict[str, Any] | None:
    packet, query_id = make_dns_query(domain, qtype)
    encoded = base64.urlsafe_b64encode(packet).rstrip(b"=").decode("ascii")
    config = DNS_PROVIDERS[provider]
    addresses = _ordered_bootstrap_ips(provider)

    # The HTTPS URL authority is the numeric bootstrap IP. We construct the
    # HTTP request explicitly so exactly one Host header is sent; TLS SNI and
    # certificate hostname verification continue to use the provider name.
    request_target = f'{config["path"]}?dns={encoded}'
    for attempt, bootstrap_ip in enumerate(addresses[:3]):
        connection: _PinnedHTTPSConnection | None = None
        _RATE_LIMITERS[provider].wait()
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = _PinnedHTTPSConnection(
                bootstrap_ip,
                bootstrap_ip=bootstrap_ip,
                tls_server_name=config["tls_server_name"],
                timeout=timeout,
                context=context,
            )
            connection.putrequest(
                "GET",
                request_target,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", config["tls_server_name"])
            connection.putheader("Accept", "application/dns-message")
            connection.putheader("Connection", "close")
            connection.endheaders()
            response = connection.getresponse()

            if response.status == 429:
                # Respect provider-side throttling rather than switching IPs
                # to evade a rate limit.
                retry_after = response.getheader("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(min(int(retry_after), 10))
                return None
            if response.status in {500, 502, 503, 504} and attempt < 2:
                time.sleep(0.2 * (attempt + 1))
                continue
            if response.status != 200:
                return None

            content_type = (
                response.getheader("Content-Type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )
            if content_type not in {"application/dns-message", "application/octet-stream"}:
                return None
            return parse_dns_response(response.read(), query_id, qtype, domain)
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException):
            if attempt >= 2:
                return None
            time.sleep(0.2 * (attempt + 1))
        finally:
            if connection is not None:
                connection.close()
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
        # A resolver/API/transport failure provides no usable DNS result.
        return None


def classify_domain(
    domain: str,
    timeout: float,
    query_executor: concurrent.futures.Executor,
    healthy_providers: set[str] | None = None,
    min_healthy_resolvers: int = MIN_HEALTHY_RESOLVERS,
) -> dict[str, Any]:
    """Classify without treating transport failure as proof of no DNS address."""
    if healthy_providers is None:
        healthy_providers = set(DNS_PROVIDERS)
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
        if response and response.get("addresses")
    ]
    if ip_returning_queries:
        status = "valid"
    elif len(healthy_providers) < min_healthy_resolvers:
        status = "temporary_failure"
    else:
        healthy_results = [
            response
            for provider in healthy_providers
            for response in provider_responses.get(provider, {}).values()
        ]
        # NXDOMAIN and NOERROR-without-address are complete DNS answers.
        # SERVFAIL, REFUSED, malformed replies and timeouts remain temporary.
        if (
            len(healthy_results) != len(healthy_providers) * len(QUERY_TYPES)
            or any(
                response is None or response.get("rcode") not in {0, 3}
                for response in healthy_results
            )
        ):
            status = "temporary_failure"
        else:
            status = "no_address"

    provider_results = {
        provider: (
            "resolved"
            if any(response and response.get("addresses") for response in responses.values())
            else "no_address"
            if provider in healthy_providers and all(
                response is not None and response.get("rcode") in {0, 3}
                for response in responses.values()
            ) and len(responses) == len(QUERY_TYPES)
            else "unhealthy_or_failed"
        )
        for provider, responses in provider_responses.items()
    }
    return {
        "status": status,
        "providers": provider_results,
        "healthy_providers": sorted(healthy_providers),
        "dns_rcodes": {
            provider: {
                qtype: response["rcode"] if response else None
                for qtype, response in responses.items()
            }
            for provider, responses in provider_responses.items()
        },
        "dns_addresses": {
            provider: {
                qtype: response["addresses"] if response else []
                for qtype, response in responses.items()
            }
            for provider, responses in provider_responses.items()
        },
        "dns_ttls": {
            provider: {
                qtype: response.get("ttl") if response else None
                for qtype, response in responses.items()
            }
            for provider, responses in provider_responses.items()
        },
        "ip_returning_queries": ip_returning_queries,
    }


def verify_resolver_pool(
    timeout: float,
    query_executor: concurrent.futures.Executor,
    min_healthy_resolvers: int = MIN_HEALTHY_RESOLVERS,
) -> set[str]:
    """Return individually healthy resolvers; abort if the healthy quorum is too small."""
    checks = {
        query_executor.submit(query_public_dns, provider, "example.com", qtype, timeout):
            (provider, qtype)
        for provider in DNS_PROVIDERS
        for qtype in QUERY_TYPES
    }
    responses: dict[str, dict[str, dict[str, Any] | None]] = {
        provider: {} for provider in DNS_PROVIDERS
    }
    for future, (provider, qtype) in checks.items():
        try:
            responses[provider][qtype] = future.result()
        except Exception:
            responses[provider][qtype] = None

    healthy = {
        provider
        for provider, answers in responses.items()
        if any(answer and answer.get("addresses") for answer in answers.values())
    }
    if len(healthy) < min_healthy_resolvers:
        details = {
            provider: {
                qtype: answer.get("rcode") if answer else None
                for qtype, answer in answers.items()
            }
            for provider, answers in responses.items()
        }
        raise RuntimeError(
            "DNS validation aborted: only "
            f"{len(healthy)}/{len(DNS_PROVIDERS)} resolvers passed the example.com "
            f"A/AAAA IP-answer canary; at least {min_healthy_resolvers} are required. "
            f"Canary RCODEs: {details}. Existing Adblock outputs were not modified."
        )
    return healthy


def apply_negative_confirmation(
    result: dict[str, Any],
    previous_result: dict[str, Any] | None,
    now: float | None = None,
) -> dict[str, Any]:
    """Require three independent no-address observations before destructive removal."""
    timestamp = time.time() if now is None else now
    previous_observations = (
        previous_result.get("negative_observations", [])
        if isinstance(previous_result, dict)
        else []
    )
    observations = [
        float(value) for value in previous_observations
        if isinstance(value, (int, float))
        and timestamp - float(value) <= NEGATIVE_CONFIRMATION_WINDOW_SECONDS
        and float(value) <= timestamp
    ]

    if result["status"] == "valid":
        result["negative_observations"] = []
        return result

    if result["status"] == "no_address":
        if not observations or timestamp - observations[-1] >= NEGATIVE_CONFIRMATION_INTERVAL_SECONDS:
            observations.append(timestamp)
        if (
            len(observations) >= NEGATIVE_CONFIRMATIONS_REQUIRED
            and observations[-1] - observations[0] >= 2 * NEGATIVE_CONFIRMATION_INTERVAL_SECONDS
        ):
            result["status"] = "invalid"
        else:
            result["status"] = "pending_confirmation"
    elif result["status"] == "temporary_failure":
        # A failed round neither confirms nor erases prior negative evidence.
        pass

    result["negative_observations"] = observations
    return result


def result_cache_ttl(result: dict[str, Any], maximum_ttl_seconds: int) -> int:
    """Use answer TTLs for positive answers and short rechecks for negative states."""
    status = result.get("status")
    if status == "temporary_failure":
        return 0
    if status in {"no_address", "pending_confirmation", "invalid"}:
        return min(15 * 60, maximum_ttl_seconds)

    values = [
        int(ttl)
        for provider_values in result.get("dns_ttls", {}).values()
        for ttl in provider_values.values()
        if isinstance(ttl, (int, float)) and ttl > 0
    ]
    if not values:
        return min(60, maximum_ttl_seconds)
    return min(min(values), maximum_ttl_seconds)



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
        description=(
            "Validate generated Main/Lite Adblock lists against three unfiltered "
            "public DNS-over-HTTPS resolvers."
        )
    )
    parser.add_argument("files", nargs="*", help="ADBLOCK_RULE_COLLECTION.txt and/or its Lite output")
    parser.add_argument(
        "--both-adblock", action="store_true",
        help="validate both generated Adblock output files using one shared domain set",
    )
    parser.add_argument("--write", action="store_true", help="apply removals; default is dry-run")
    parser.add_argument("--cache", type=Path, help="JSON cache/state path")
    parser.add_argument("--report", type=Path, help="JSON report path")
    parser.add_argument("--concurrency", type=int, default=12, help="concurrent domain checks (1-24)")
    parser.add_argument("--qps", type=float, default=15.0, help="maximum query starts per resolver per second (1-18)")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-query timeout in seconds")
    parser.add_argument(
        "--cache-ttl-hours", type=float, default=6.0,
        help="maximum positive-answer cache TTL in hours; actual DNS TTL may shorten it",
    )
    parser.add_argument(
        "--min-healthy-resolvers", type=int, default=MIN_HEALTHY_RESOLVERS,
        help=f"minimum healthy resolvers required before confirming no-address (default: {MIN_HEALTHY_RESOLVERS})",
    )
    parser.add_argument(
        "--max-removal-ratio", type=float, default=0.20,
        help="abort without writing if DNS would remove more than this fraction of active lines (0-1)",
    )
    args = parser.parse_args()

    if not (1 <= args.concurrency <= 24):
        parser.error("--concurrency must be between 1 and 24")
    if not (1 <= args.qps <= 18):
        parser.error("--qps must be between 1 and 18")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout must be > 0 and <= 60")
    if args.cache_ttl_hours <= 0:
        parser.error("--cache-ttl-hours must be greater than zero")
    if not (1 <= args.min_healthy_resolvers <= len(DNS_PROVIDERS)):
        parser.error(f"--min-healthy-resolvers must be between 1 and {len(DNS_PROVIDERS)}")
    if not (0 <= args.max_removal_ratio <= 1):
        parser.error("--max-removal-ratio must be between 0 and 1")

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
    cache_domains = cache["domains"]
    cached: dict[str, dict[str, Any]] = {}
    previous_results: dict[str, dict[str, Any] | None] = {}
    pending: list[str] = []
    now = time.time()
    maximum_ttl_seconds = int(args.cache_ttl_hours * 3600)

    for domain in sorted(candidates):
        entry = cache_domains.get(domain)
        previous_result = entry.get("result") if isinstance(entry, dict) else None
        previous_results[domain] = previous_result if isinstance(previous_result, dict) else None
        if not isinstance(entry, dict) or not isinstance(previous_result, dict):
            pending.append(domain)
            continue
        checked_at = entry.get("checked_at")
        if not isinstance(checked_at, (int, float)):
            pending.append(domain)
            continue
        ttl = result_cache_ttl(previous_result, maximum_ttl_seconds)
        if ttl > 0 and now - checked_at <= ttl:
            cached[domain] = previous_result
        else:
            pending.append(domain)

    print(
        f"Files: {len(files)} | unique target hosts: {len(candidates)} | "
        f"cache hits: {len(cached)} | to query: {len(pending)}"
    )

    results = dict(cached)
    healthy_providers: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as domain_pool:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.concurrency * len(DNS_PROVIDERS) * 2
        ) as query_pool:
            if pending:
                healthy_providers = verify_resolver_pool(
                    args.timeout,
                    query_pool,
                    args.min_healthy_resolvers,
                )
                print(
                    "Healthy DoH resolvers: "
                    + ", ".join(sorted(healthy_providers))
                    + f" ({len(healthy_providers)}/{len(DNS_PROVIDERS)})"
                )

            future_map = {
                domain_pool.submit(
                    classify_domain,
                    domain,
                    args.timeout,
                    query_pool,
                    healthy_providers,
                    args.min_healthy_resolvers,
                ): domain
                for domain in pending
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_map):
                domain = future_map[future]
                try:
                    fresh_result = future.result()
                    results[domain] = apply_negative_confirmation(
                        fresh_result,
                        previous_results.get(domain),
                    )
                except Exception as exc:
                    # Internal errors abort the run; they must never become
                    # negative DNS evidence or cause a destructive rewrite.
                    raise RuntimeError(
                        f"internal error while classifying {domain}: "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc
                completed += 1
                if completed % 100 == 0 or completed == len(future_map):
                    print(f"DNS checked: {completed}/{len(future_map)}")

    checked_at = time.time()
    for domain in pending:
        cache_domains[domain] = {
            "checked_at": checked_at,
            "result": results[domain],
        }

    # Keep the cache bounded to names still referenced by the current outputs.
    cache["domains"] = {
        domain: cache_domains[domain]
        for domain in candidates
        if domain in cache_domains
    }

    invalid = {
        domain for domain, result in results.items()
        if result.get("status") == "invalid"
    }
    file_summaries: dict[str, Any] = {}
    output_documents: dict[Path, str] = {}
    total_removed = 0
    quality_issues: list[str] = []

    for path, (kind, lines) in files.items():
        rewritten: list[str] = []
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
        ratio = removed / before_count if before_count else 0.0
        if before_count > 0 and after_count == 0:
            quality_issues.append(
                f"{path.name}: DNS validation would remove every active line"
            )
        if ratio > args.max_removal_ratio:
            quality_issues.append(
                f"{path.name}: proposed removal ratio {ratio:.2%} exceeds "
                f"the configured {args.max_removal_ratio:.2%} safety limit"
            )
        total_removed += removed
        file_summaries[path.name] = {
            "kind": kind,
            "active_lines_before": before_count,
            "active_lines_after": after_count,
            "removed_lines": removed,
            "removal_ratio": round(ratio, 6),
        }
        output_documents[path] = "".join(rewritten)

    status_counts = {
        status: sum(result.get("status") == status for result in results.values())
        for status in (
            "valid",
            "pending_confirmation",
            "invalid",
            "temporary_failure",
        )
    }
    report = {
        "policy": {
            "providers": list(DNS_PROVIDERS),
            "transport": "DoH only",
            "query_types": ["A", "AAAA"],
            "valid_if_any_query_returns_usable_chain_ip": True,
            "negative_requires_three_observations_over_at_least_30_minutes": True,
            "temporary_failures_are_not_negative_evidence": True,
            "minimum_healthy_resolvers_for_negative_confirmation": args.min_healthy_resolvers,
            "target_host_only": "Adblock $domain= and cosmetic scopes are not treated as blocked targets",
            "cname": "follow Answer-section CNAME chain; only chain-owned A/AAAA addresses count",
        },
        "health": {
            "healthy_resolvers": sorted(healthy_providers),
            "healthy_count": len(healthy_providers),
        },
        "summary": {
            "files_scanned": len(files),
            "candidate_target_hosts": len(candidates),
            "cache_hits": len(cached),
            "queried_domains": len(pending),
            **status_counts,
            "lines_removed": total_removed,
            "write_mode": args.write,
            "quality_issues": quality_issues,
        },
        "files": file_summaries,
        "results": results,
    }

    # Reports and cache are saved even when the safety gate blocks file writes.
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

    if quality_issues:
        for issue in quality_issues:
            print(f"QUALITY GATE: {issue}", file=sys.stderr)
        print("Safety gate blocked all Adblock file writes.", file=sys.stderr)
        return 3

    if args.write:
        for path, document in output_documents.items():
            original = path.read_text(encoding="utf-8-sig")
            if original != document:
                atomic_write(path, document)

    print(
        "Summary: "
        f"valid={status_counts['valid']}, "
        f"pending_confirmation={status_counts['pending_confirmation']}, "
        f"invalid={status_counts['invalid']}, "
        f"temporary_failure={status_counts['temporary_failure']}, "
        f"removed_lines={total_removed}"
    )
    if not args.write and total_removed:
        print("Dry run only; re-run with --write to apply removals.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
