# -*- coding: utf-8 -*-
"""Compile heterogeneous upstream blocklists into one AdGuard browser filter.

Important contract:
- Native Adblock/AdGuard filter rules are preserved, except safe normalization of
  simple domain-anchored rules and exact duplicate removal.
- Hosts entries and domains-only entries are translated to exact-host URL regexes
  instead of broad ||domain^ rules, which would include subdomains.
- DNS-only semantics that cannot be expressed by a browser filter are reported.
  By default, any such rule aborts publication; --allow-lossy is an explicit
  escape hatch and is recorded in the JSON report.
- Existing output is replaced atomically only after compilation passes.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

OUTPUT_DEFAULT = "ADBLOCK_RULE_COLLECTION.txt"
REPORT_DEFAULT = "ADBLOCK_RULE_COLLECTION.semantic-report.json"
FETCH_WORKERS = 12
FETCH_TIMEOUT_SECONDS = 18

# These are actual filter operators, not comment prefixes.
VALID_HASH_RULE_PREFIXES = (
    "##", "#@#", "#$#", "#$@#", "#?#", "#@?#", "#%#", "#@%#",
)
COMMENT_PREFIXES = ("!",)
FILTER_DIRECTIVE_RE = re.compile(
    r"^!#(?:if|else|endif|include|safari_cb_affinity|pragma)\b",
    re.IGNORECASE,
)
# These hostnames are system loopback aliases, not advertising/tracker hosts.
# A hosts blocklist often carries these default mappings for compatibility.
SYSTEM_HOST_ALIASES = {
    "localhost",
    "localhost.localdomain",
    "localhost4",
    "localhost6",
    "ip6-localhost",
    "ip6-loopback",
}
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z", re.IGNORECASE)
HOSTS_LINE_RE = re.compile(r"^\s*(\S+)\s+(.+?)\s*$")

# Explicit overrides for user-added sources whose format cannot be inferred safely.
# Example: SOURCE_FORMAT_OVERRIDES["https://example.org/domains.txt"] = "domains"
# "domains" uses normal domain-blocklist scope (the domain and its subdomains).
# Use "domains-exact" only when the source contract says entries match one hostname
# without extending to descendants. A bare-domain line alone does not encode scope.
# Allowed values: adblock, hosts, domains, domains-exact, dns, cname.
SOURCE_FORMAT_OVERRIDES: dict[str, str] = {}
SUPPORTED_SOURCE_KINDS = {
    "adblock", "hosts", "domains", "domains-exact", "dns", "cname", "exclusions"
}

# AdGuard preprocessor conditions are platform-dependent. The output is one
# target-specific browser filter, not a multi-platform FiltersRegistry build.
KNOWN_CONDITION_FLAGS = {
    "adguard", "adguard_app_windows", "adguard_app_mac", "adguard_app_android",
    "adguard_app_ios", "adguard_app_cli", "adguard_ext_safari",
    "adguard_ext_chromium", "adguard_ext_chromium_mv3", "adguard_ext_firefox",
    "adguard_ext_edge", "adguard_ext_edge_mv3", "adguard_ext_opera",
    "adguard_ext_opera_mv3", "adguard_ext_android_cb", "ext_ublock",
    "ext_ubol", "ext_abp", "ext_safari", "env_mobile", "env_safari", "env_chromium",
    "env_firefox", "env_edge", "env_mv3", "cap_html_filtering", "cap_ipaddress",
    "cap_user_stylesheet",
}
TARGET_PROFILES = {
    # chromium means the AdGuard Chromium MV2 profile; use chromium-mv3 for MV3.
    "chromium": {
        "adguard": True, "adguard_ext_chromium": True, "env_chromium": True,
        "cap_user_stylesheet": True,
    },
    "chromium-mv3": {
        "adguard": True, "adguard_ext_chromium_mv3": True, "env_chromium": True,
        "cap_user_stylesheet": True,
    },
    "firefox": {
        "adguard": True, "adguard_ext_firefox": True, "env_firefox": True,
        "cap_user_stylesheet": True,
    },
    "safari": {
        "adguard": True, "adguard_ext_safari": True, "env_safari": True,
    },
    "generic": {"adguard": True},
}
# Source families whose semantics belong to a DNS-aware engine, not a browser URL
# filter. They are explicitly reported as out of target scope rather than being
# reinterpreted as browser rules or making an otherwise valid browser build fail.
BROWSER_TARGET_EXCLUDED_SOURCE_REASONS = {
    "dns": (
        "DNS filtering rules depend on DNS-resolution semantics and belong in a DNS "
        "filter output, not an AdGuard browser request-filter list."
    ),
    "cname": (
        "CNAME-chain rules require DNS-aware request inspection; a static browser "
        "filter cannot preserve that source-level behavior."
    ),
}
MAX_INCLUDE_DEPTH = 12
ADGUARD_SDNS_CONFIGURATION_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/configuration.json"
)

# These are known non-portable uBlock Origin operators, not ordinary ABP rules.
# Do not silently publish them as if AdGuard had identical behavior.
NON_PORTABLE_NATIVE_PATTERNS = (
    # AdGuard has its own scriptlet syntax (#%#//scriptlet(...)); uBO's +js()
    # must not be passed through as though the two syntaxes were interchangeable.
    # These procedural operators are not part of AdGuard's documented Extended CSS.
    (re.compile(r":matches-path\s*\(", re.IGNORECASE), "uBlock procedural operator :matches-path() has no verified AdGuard equivalent"),
    (re.compile(r":remove-(?:attr|class)\s*\(", re.IGNORECASE), "uBlock procedural DOM-removal operator has no verified AdGuard equivalent"),
)
DNS_ONLY_MODIFIER_RE = re.compile(r"(?:\$|,)(?:client|dnstype|dnsrewrite|ctag|network)(?:=|,|$)", re.IGNORECASE)

class CompilationError(RuntimeError):
    pass

@dataclass(frozen=True)
class Source:
    url: str
    kind: str

@dataclass
class SourceSummary:
    url: str
    kind: str
    status: str = "pending"
    input_lines: int = 0
    emitted_rules: int = 0
    duplicate_rules: int = 0
    ignored_comments: int = 0
    unsupported_lines: int = 0
    ignored_system_mappings: int = 0
    excluded_by_metadata: int = 0
    input_lines_skipped_by_target: int = 0
    target_skip_reason: str | None = None
    target_excluded_rules: int = 0
    metadata_patterns: int = 0
    error: str | None = None

@dataclass
class CompileState:
    # A set avoids retaining millions of redundant source-line objects for rules
    # already deduplicated into the final output.
    records: set[str] = field(default_factory=set)
    issues: list[dict[str, object]] = field(default_factory=list)
    target_exclusions: list[dict[str, object]] = field(default_factory=list)
    summaries: dict[str, SourceSummary] = field(default_factory=dict)

def classify_source(url: str) -> str:
    """Explicit source-family adapter for the curated upstream manifest.

    Unknown source families fail closed. Add a format mapping here before adding
    a new upstream; do not infer format from the downloaded line contents.
    """
    override = SOURCE_FORMAT_OVERRIDES.get(url)
    if override is not None:
        if override not in SUPPORTED_SOURCE_KINDS:
            raise CompilationError(
                f"Invalid source-format override {override!r} for {url!r}; "
                f"expected one of {sorted(SUPPORTED_SOURCE_KINDS)}"
            )
        return override

    parsed = urllib.parse.urlparse(url)
    lowered = url.lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    basename = path.rsplit("/", 1)[-1]

    # The *justdomains convention denotes a domain-only feed. Unlike native
    # Adblock rules, each bare entry needs the domain-list adapter.
    if basename.endswith("_justdomains.txt"):
        return "domains"

    if lowered == "https://adaway.org/hosts.txt":
        return "hosts"

    # In AdGuardSDNSFilter, exclusions.txt is metadata consumed by the hostlist
    # compiler to remove matching source rules; it is not an active blocklist.
    if (
        hostname == "raw.githubusercontent.com"
        and path.startswith("/adguardteam/adguardsdnsfilter/")
        and path.endswith("/filters/exclusions.txt")
    ):
        return "exclusions"

    if (
        "adguardteam/adguardsdnsfilter/" in lowered
        or "filter_15_dnsfilter/" in lowered
        or (hostname == "malware-filter.gitlab.io" and basename.endswith("-agh.txt"))
    ):
        return "dns"

    if hostname == "adguardteam.github.io" and path.startswith("/cname-trackers/data/"):
        # The CNAME-tracker project publishes two semantically different families:
        # disguised tracker hostnames are ordinary browser-blocking rules, whereas
        # original trackers and microsites require CNAME-aware DNS inspection.
        if (
            "/data/microsites/" in path
            or "/data/combined_original_trackers" in path
            or "/data/combined_disguised_microsites" in path
        ):
            return "cname"
        if path.endswith("_justdomains.txt"):
            return "domains"
        if (
            any(part in path for part in (
                "/data/ads/",
                "/data/clickthroughs/",
                "/data/trackers/",
                "/data/mail_trackers/",
            ))
            or "/data/combined_disguised_" in path
        ):
            return "adblock"

    if "adguardteam/cname-trackers/" in lowered:
        # Original trackers and microsites require DNS/CNAME-aware inspection,
        # including their justdomains variants.
        if (
            "/data/combined_original_trackers" in path
            or "/data/combined_disguised_microsites" in path
        ):
            return "cname"
        if path.endswith("_justdomains.txt"):
            return "domains"
        # The combined_disguised_* files with Adblock syntax remain native rules.
        return "adblock"

    # Known raw GitHub repositories that publish browser Adblock-compatible rules.
    raw_repo = ""
    if hostname == "raw.githubusercontent.com":
        segments = [segment for segment in path.split("/") if segment]
        if len(segments) >= 2:
            raw_repo = "/".join(segments[:2]).lower()
    native_repositories = {
        "easylist/easylist",
        "adguardteam/adguardfilters",
        "adguardteam/filtersregistry",
        "ublockorigin/uassets",
        "easylist/antiadblockfilters",
        "easylist/easylistchina",
    }
    if raw_repo in native_repositories:
        return "adblock"

    # Other known native browser-filter hosts in this curated manifest.
    if hostname in {
        "filters.adavoid.org",
        "easylist.to",
        "secure.fanboy.co.nz",
        "adguardteam.github.io",
    }:
        return "adblock"
    if hostname == "malware-filter.gitlab.io":
        return "adblock"

    raise CompilationError(
        f"No source-format mapping for {url!r}; classify this source explicitly "
        "before adding it to the upstream manifest."
    )

def build_sources(urls: Iterable[str]) -> list[Source]:
    sources = [Source(url=url, kind=classify_source(url)) for url in urls]
    if len({s.url for s in sources}) != len(sources):
        raise CompilationError("The upstream manifest contains duplicate URLs")
    return sources

def canonical_hostname(value: str, *, allow_single_label: bool = True) -> str | None:
    """Return validated lowercase ASCII/IDNA hostname, or None.

    A single-label name is permitted for hosts files; callers may separately
    enforce fully-qualified names where their source format requires that.
    IP literals, wildcards, URL syntax and empty labels are not hostnames here.
    """
    if not value or value != value.strip() or "*" in value:
        return None
    if value.endswith(".."):
        return None
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253 or any(ch in value for ch in "/\\:@?#"):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    labels = value.split(".")
    if (not allow_single_label and len(labels) < 2) or any(not label for label in labels):
        return None
    ascii_labels: list[str] = []
    try:
        for label in labels:
            ascii_label = label.encode("idna").decode("ascii").lower()
            if len(ascii_label) > 63 or not DOMAIN_LABEL_RE.fullmatch(ascii_label):
                return None
            ascii_labels.append(ascii_label)
    except UnicodeError:
        return None
    normalized = ".".join(ascii_labels)
    if len(normalized) > 253:
        return None
    return normalized

def is_comment_or_header(line: str) -> bool:
    if not line:
        return True
    if line.startswith(COMMENT_PREFIXES):
        return True
    if line.startswith("["):
        return True
    if line.startswith("#") and not line.startswith(VALID_HASH_RULE_PREFIXES):
        return True
    return False

def canonical_host_or_ipv4(value: str, *, allow_single_label: bool = False) -> str | None:
    """Canonicalize a hostname or IPv4 literal used in a network filter rule."""
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            return str(address)
        return None
    except ValueError:
        return canonical_hostname(value, allow_single_label=allow_single_label)

def exact_hostname_regex_rule(hostname: str, *, exception: bool = False) -> str:
    """Compile an exact host block into an AdGuard URL-regex rule.

    This intentionally does not use ||host^, because that rule includes all
    subdomains. Scope is browser HTTP(S) URLs with this exact authority host.
    """
    domain = canonical_host_or_ipv4(hostname)
    if not domain:
        raise CompilationError(f"invalid exact hostname: {hostname!r}")
    escaped = re.escape(domain)
    # The slashes are escaped because slash delimits an AdGuard regex rule.
    body = (
        r"^https?:\/\/(?:[^\/?#@]+@)?"
        + escaped
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + body + "/"

def normalize_native_domain_rule(line: str) -> str:
    """Normalize only simple domain-anchored rules; keep all other syntax intact."""
    match = re.fullmatch(r"(?P<exception>@@)?(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^(?P<tail>\$.*)?", line)
    if not match:
        return line
    hostname = canonical_host_or_ipv4(match.group("host"), allow_single_label=False)
    if not hostname:
        # Native upstream filter syntax is already the target grammar. If a
        # source uses a legal-but-non-hostname token, preserve its original form
        # rather than inventing a different rule or rejecting it on our own
        # narrower hostname validator.
        return line
    return (
        (match.group("exception") or "")
        + match.group("anchor")
        + hostname
        + "^"
        + (match.group("tail") or "")
    )

def detect_nonportable_native_rule(line: str) -> str | None:
    if DNS_ONLY_MODIFIER_RE.search(line):
        return "DNS-only modifier cannot be represented safely in an AdGuard browser filter"
    for pattern, explanation in NON_PORTABLE_NATIVE_PATTERNS:
        if pattern.search(line):
            return explanation
    return None

def canonical_wildcard_hostname_mask(value: str) -> str | None:
    """Validate and lowercase a DNS hostname mask with simple '*' wildcards."""
    if not value or value != value.strip() or len(value) > 253:
        return None
    if not re.fullmatch(r"[A-Za-z0-9*.-]+", value):
        return None
    labels = value.lower().split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None
    for label in labels:
        if "*" not in label:
            if not DOMAIN_LABEL_RE.fullmatch(label):
                return None
        else:
            # Literal characters adjacent to a wildcard must not force an
            # impossible leading/trailing hyphen in every matching DNS label.
            if not re.fullmatch(r"[a-z0-9*-]+", label):
                return None
            if label.startswith("-") or label.endswith("-"):
                return None
    return value.lower()

def split_modifiers(modifier_text: str) -> list[str]:
    """Split modifiers on commas outside quoted values."""
    result: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(modifier_text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == ",":
            result.append(modifier_text[start:index].strip())
            start = index + 1
    if quote:
        raise CompilationError("unterminated quoted modifier")
    result.append(modifier_text[start:].strip())
    if any(not token for token in result):
        raise CompilationError("empty modifier in rule")
    return result

def find_regex_rule_end(body: str) -> int | None:
    """Return the index of the closing slash in a slash-delimited regex rule."""
    if not body.startswith("/"):
        return None
    escaped = False
    for index in range(1, len(body)):
        char = body[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == "/":
            return index
    return None

def compile_dns_hostname_regex(regex_body: str, *, exception: bool = False) -> str | None:
    """Wrap a conservative, anchored hostname regex in an HTTP(S) URL matcher."""
    if not (regex_body.startswith("^") and regex_body.endswith("$")):
        return None
    inner = regex_body[1:-1]
    if not inner or "/" in inner or any(token in inner for token in ("(?=", "(?!", "(?<=", "(?<!", "(?P", "\\k<")):
        return None
    # Only the common JavaScript/Python-compatible regex subset is translated.
    # Non-capturing groups are allowed; other special group forms are rejected.
    if re.search(r"\(\?(?!:)", inner):
        return None
    check_inner = inner.replace("(?:", "")
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "._*+?()|\\[]{}^-"
    )
    if any(char not in allowed for char in check_inner):
        return None
    try:
        re.compile(inner)
    except re.error:
        return None
    url_pattern = (
        r"^https?:\/\/(?:[^\/?#@]+@)?(?:"
        + inner
        + r")(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + url_pattern + "/"

def compile_dns_rule(line: str) -> str:
    """Translate only DNS rule forms whose browser-filter meaning is provable."""
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("@@"):
        raise CompilationError("misplaced DNS exception marker")

    # Regex delimiters must be processed before '$' modifiers because '$' may
    # also be the regex end-anchor.
    if body.startswith("/"):
        closing = find_regex_rule_end(body)
        if closing is None:
            raise CompilationError("malformed slash-delimited DNS regex")
        regex_body = body[1:closing]
        tail = body[closing + 1:]
        regex_modifiers: list[str] = []
        if tail:
            if not tail.startswith("$"):
                raise CompilationError("unexpected text after DNS regex")
            regex_modifiers = split_modifiers(tail[1:])

        normalized_regex_modifiers: list[str] = []
        for token in regex_modifiers:
            key, separator, value = token.partition("=")
            key = key.strip().lower()
            if key in {"important", "badfilter"} and not separator:
                normalized_regex_modifiers.append(key)
            else:
                raise CompilationError(
                    f"DNS-only or unsupported modifier on regex rule: {token}"
                )

        # A regex explicitly matching a URL scheme already has URL scope, so
        # preserving its original pattern retains the target matcher semantics.
        # Some DNS feeds use a literal "https?:" regex prefix and escaped
        # slashes. Detect that textual URL-scope form before treating the regex
        # as a hostname matcher.
        has_url_scope = (
            "https?:" in regex_body.lower()
            or "http?:" in regex_body.lower()
            or re.search(r"https?\s*:", regex_body, re.IGNORECASE) is not None
        )
        if has_url_scope:
            translated = ("@@" if exception else "") + "/" + regex_body + "/"
        else:
            translated = compile_dns_hostname_regex(regex_body, exception=exception)
            if translated is None:
                raise CompilationError(
                    "DNS hostname regex cannot be proven equivalent as a browser URL regex"
                )

        if normalized_regex_modifiers:
            translated += "$" + ",".join(normalized_regex_modifiers)
        return translated

    parts = body.split("$", 1)
    pattern = parts[0]
    modifier_text = parts[1] if len(parts) == 2 else None

    modifiers: list[str] = []
    if modifier_text is not None:
        modifiers = split_modifiers(modifier_text)
        normalized_modifiers: list[str] = []
        for token in modifiers:
            key, separator, value = token.partition("=")
            key_lower = key.strip().lower()
            if key_lower in ("important", "badfilter"):
                if separator:
                    raise CompilationError(f"{key_lower} modifier must not have a value")
                normalized_modifiers.append(key_lower)
            elif key_lower == "denyallow" and separator:
                entries = value.split("|")
                normalized_entries = [
                    canonical_hostname(entry, allow_single_label=False)
                    for entry in entries
                ]
                if any(entry is None for entry in normalized_entries):
                    raise CompilationError("invalid domain in denyallow modifier")
                normalized_modifiers.append(
                    "denyallow=" + "|".join(
                        entry for entry in normalized_entries if entry
                    )
                )
            else:
                raise CompilationError(
                    f"DNS-only or unverified modifier cannot be represented safely in a browser filter: {token}"
                )
        modifiers = normalized_modifiers

    # A bare domain/IP in a domains-only DNS list is an exact-host rule, not a
    # subtree rule. The URL-regex wrapper preserves that narrower scope.
    if (
        not pattern.startswith(("||", "|"))
        and not any(ch in pattern for ch in "*^/")
    ):
        try:
            ipaddress.ip_address(pattern)
        except ValueError:
            pass
        else:
            raise CompilationError(
                "bare IP in AdGuard DNS syntax matches CNAME targets resolving to that IP; "
                "an AdGuard browser filter cannot preserve DNS-resolution semantics"
            )
        hostname = canonical_hostname(pattern, allow_single_label=False)
        if hostname:
            translated = exact_hostname_regex_rule(hostname, exception=exception)
            return translated + ("$" + ",".join(modifiers) if modifiers else "")
        raise CompilationError(f"unsupported DNS domain or address rule: {pattern}")

    # A trailing hostname-end anchor is not the same as a URL-end anchor.
    exact_pipe = re.fullmatch(
        r"(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^?\|",
        pattern,
    )
    if exact_pipe:
        raw_hostname = exact_pipe.group("host")
        try:
            ipaddress.ip_address(raw_hostname)
        except ValueError:
            pass
        else:
            raise CompilationError(
                "IP-based DNS rules may match CNAME resolution results, not browser URL hosts"
            )
        hostname = canonical_hostname(raw_hostname, allow_single_label=False)
        if not hostname:
            raise CompilationError(f"invalid exact DNS hostname: {pattern}")
        translated = exact_hostname_regex_rule(hostname, exception=exception)
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # A leading-dot hostname mask selects subdomains but not the apex. Convert
    # it to a domain-anchored wildcard instead of an unanchored URL substring.
    leading_dot = re.fullmatch(r"\.([A-Za-z0-9.-]+)\^", pattern)
    if leading_dot:
        hostname = canonical_hostname(
            leading_dot.group(1), allow_single_label=False
        )
        if not hostname:
            raise CompilationError(f"invalid leading-dot DNS hostname mask: {pattern}")
        translated = (
            ("@@" if exception else "") + "||*." + hostname + "^"
        )
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # Host-start masks without a separator/end anchor already use the same
    # leading-host operator in AdGuard browser filters. Preserve their prefix
    # semantics, including partial final labels.
    if re.fullmatch(r"\|\|[A-Za-z0-9*.-]+", pattern):
        translated = ("@@" if exception else "") + pattern.lower()
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # A single leading pipe with '^' means exact hostname in DNS scope. It must
    # not become an entire-URL-start anchor in browser scope.
    exact_match = re.fullmatch(r"\|([^|^*/$]+)\^", pattern)
    if exact_match:
        hostname = canonical_host_or_ipv4(
            exact_match.group(1), allow_single_label=False
        )
        if not hostname:
            raise CompilationError(f"invalid exact DNS hostname: {pattern}")
        translated = exact_hostname_regex_rule(hostname, exception=exception)
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # Standard hostname-subtree rules and simple hostname wildcards.
    subtree_match = re.fullmatch(r"\|\|([^|^/$]+)\^", pattern)
    if subtree_match:
        raw_mask = subtree_match.group(1)
        if "*" in raw_mask:
            hostname_mask = canonical_wildcard_hostname_mask(raw_mask)
            if not hostname_mask:
                raise CompilationError(f"invalid DNS wildcard hostname mask: {pattern}")
            translated = ("@@" if exception else "") + "||" + hostname_mask + "^"
        else:
            if re.fullmatch(r"(?:[0-9]{1,3}\.){1,3}[0-9]{0,3}\.?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}", raw_mask):
                raise CompilationError(
                    "IP-like DNS masks can refer to CNAME/IP semantics and cannot be "
                    "safely translated into browser URL-host rules"
                )
            hostname = canonical_hostname(raw_mask, allow_single_label=False)
            if hostname:
                translated = ("@@" if exception else "") + "||" + hostname + "^"
            elif re.fullmatch(r"[A-Za-z0-9_.-]+", raw_mask):
                # Preserve source-valid hostname labels that are not accepted by
                # the strict IDNA hostname normalizer, without broadening them.
                translated = ("@@" if exception else "") + "||" + raw_mask.lower() + "^"
            else:
                raise CompilationError(f"invalid DNS hostname mask: {pattern}")
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    raise CompilationError(f"DNS rule pattern cannot be translated losslessly: {pattern}")

def compile_hosts_line(line: str, *, category: str = "hosts") -> tuple[list[str], str]:
    body = line.split("#", 1)[0].strip()
    if not body:
        return [], "comment"
    parts = body.split()
    try:
        address = ipaddress.ip_address(parts[0])
    except (ValueError, IndexError):
        raise CompilationError("not a valid hosts mapping")
    if len(parts) < 2:
        raise CompilationError("hosts mapping has no hostname")

    # Ordinary hosts address mappings are DNS resolution overrides, not blocks.
    # Do not rewrite arbitrary A/AAAA mappings as browser request blocks.
    if not (address.is_unspecified or address.is_loopback):
        raise CompilationError(
            f"hosts address {address} is a name-to-IP mapping, not a block; "
            "it cannot be represented by a browser blocking rule"
        )

    output: list[str] = []
    ignored_system_alias = False
    for original_host in parts[1:]:
        hostname = canonical_hostname(original_host)
        if not hostname:
            raise CompilationError(f"invalid hosts alias: {original_host}")
        if hostname in SYSTEM_HOST_ALIASES:
            ignored_system_alias = True
            continue
        output.append(exact_hostname_regex_rule(hostname))

    if ignored_system_alias and not output:
        return [], "system-host-mapping"
    if ignored_system_alias:
        return output, category + "-with-system-alias"
    return output, category

def compile_domain_line(line: str) -> str:
    """Compile a normal domain-blocklist entry for the domain and its subdomains.

    This preserves the repository's established bare-domain contract (||domain^).
    Source formats that explicitly promise exact-host-only matching must use the
    separate domains-exact adapter instead.
    """
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid domains-only entry: {candidate!r}")
    return "||" + hostname + "^"

def compile_domain_exact_line(line: str) -> str:
    """Compile a bare domain that blocks only this exact hostname."""
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid exact-host domains entry: {candidate!r}")
    return exact_hostname_regex_rule(hostname)

def compile_line(kind: str, raw_line: str) -> tuple[list[str], str]:
    line = raw_line.strip()
    if FILTER_DIRECTIVE_RE.match(line):
        raise CompilationError(
            "filter preprocessor directive must be evaluated or expanded before compilation; "
            "it cannot be silently discarded"
        )
    if is_comment_or_header(line):
        return [], "comment"

    if kind == "adblock":
        reason = detect_nonportable_native_rule(line)
        if reason:
            raise CompilationError(reason)
        # Native browser filter rules already use the target rule language.
        # Only normalize the domain token in simple domain-anchored rules.
        return [normalize_native_domain_rule(line)], "native"

    if kind == "hosts":
        return compile_hosts_line(line)

    if kind == "domains":
        return [compile_domain_line(line)], "domains"

    if kind == "domains-exact":
        return [compile_domain_exact_line(line)], "domains-exact"

    if kind == "cname":
        raise CompilationError(
            "this source requires CNAME-chain inspection; a static AdGuard browser "
            "filter cannot preserve that source-level behavior"
        )

    if kind == "exclusions":
        raise CompilationError(
            "this is an exclusion selector file, not an active blocklist; it must be "
            "applied to its designated source group rather than emitted as rules"
        )

    if kind == "dns":
        # DNS/domain-list formats permit inline comments after whitespace. A
        # hostname cannot legally contain '#', so removing this suffix is safe.
        line = line.split("#", 1)[0].strip()
        if not line:
            return [], "comment"
        # DNS lists can contain either Adblock-style host rules or hosts entries.
        fields = line.split()
        looks_like_hosts = False
        if len(fields) >= 2:
            try:
                ipaddress.ip_address(fields[0])
                looks_like_hosts = True
            except ValueError:
                pass
        if looks_like_hosts:
            return compile_hosts_line(line, category="hosts-in-dns")
        return [compile_dns_rule(line)], "dns"

    raise CompilationError(f"unknown source format: {kind}")

def fetch_source(source: Source) -> tuple[Source, str]:
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "Adblock-Rule-Collection-SemanticCompiler/1.0"},
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise CompilationError(f"HTTP status {status}")
        data = response.read()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise CompilationError(f"upstream is not valid UTF-8: {error}") from error
    return source, text

def add_issue(state: CompileState, summary: SourceSummary, line_number: int, original: str, reason: str) -> None:
    summary.unsupported_lines += 1
    state.issues.append({
        "source": summary.url,
        "format": summary.kind,
        "line": line_number,
        "rule": original[:500],
        "reason": reason,
    })

@dataclass(frozen=True)
class ExpandedLine:
    source: Source
    line_number: int
    text: str

def target_condition_flags(target: str) -> dict[str, bool]:
    if target not in TARGET_PROFILES:
        raise CompilationError(f"unknown AdGuard target profile: {target}")
    flags = {name: False for name in KNOWN_CONDITION_FLAGS}
    flags.update(TARGET_PROFILES[target])
    return flags

def evaluate_filter_condition(expression: str, flags: dict[str, bool]) -> bool:
    """Evaluate AdGuard !#if expressions with !, &&, || and parentheses."""
    tokens: list[str] = []
    cursor = 0
    while cursor < len(expression):
        if expression[cursor].isspace():
            cursor += 1
            continue
        match = re.match(r"&&|\|\||[!()]|[A-Za-z_][A-Za-z0-9_]*", expression[cursor:])
        if not match:
            raise CompilationError(
                f"unsupported token in filter condition near {expression[cursor:]!r}"
            )
        tokens.append(match.group(0))
        cursor += len(match.group(0))

    if not tokens:
        raise CompilationError("empty filter preprocessor condition")
    index = 0

    def parse_primary() -> bool:
        nonlocal index
        if index >= len(tokens):
            raise CompilationError("unexpected end of filter condition")
        token = tokens[index]
        if token == "!":
            index += 1
            return not parse_primary()
        if token == "(":
            index += 1
            result = parse_or()
            if index >= len(tokens) or tokens[index] != ")":
                raise CompilationError("missing ')' in filter condition")
            index += 1
            return result
        if token in {"&&", "||", ")"}:
            raise CompilationError(f"unexpected operator {token!r} in filter condition")
        if token.lower() == "true":
            index += 1
            return True
        if token.lower() == "false":
            index += 1
            return False
        if token not in flags:
            raise CompilationError(f"unknown AdGuard preprocessor flag: {token}")
        index += 1
        return flags[token]

    def parse_and() -> bool:
        nonlocal index
        result = parse_primary()
        while index < len(tokens) and tokens[index] == "&&":
            index += 1
            rhs = parse_primary()
            result = result and rhs
        return result

    def parse_or() -> bool:
        nonlocal index
        result = parse_and()
        while index < len(tokens) and tokens[index] == "||":
            index += 1
            rhs = parse_and()
            result = result or rhs
        return result

    result = parse_or()
    if index != len(tokens):
        raise CompilationError(f"unexpected token {tokens[index]!r} in filter condition")
    return result

def same_origin(left: str, right: str) -> bool:
    a = urllib.parse.urlparse(left)
    b = urllib.parse.urlparse(right)
    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and a.port == b.port
    )

def allow_preprocessor_include(parent_url: str, include_url: str) -> bool:
    """Allow same-origin includes plus a narrow official AdGuard CNAME include path."""
    if same_origin(parent_url, include_url):
        return True
    parent = urllib.parse.urlparse(parent_url)
    included = urllib.parse.urlparse(include_url)
    return (
        parent.scheme.lower() == "https"
        and (parent.hostname or "").lower() == "raw.githubusercontent.com"
        and parent.path.lower().startswith("/adguardteam/adguardfilters/")
        and included.scheme.lower() == "https"
        and (included.hostname or "").lower() == "adguardteam.github.io"
        and included.path.lower().startswith("/cname-trackers/data/")
    )

def expand_filter_preprocessor(
    source: Source,
    text: str,
    target: str,
    cache: dict[str, tuple[Source, str]],
    stack: tuple[str, ...] = (),
) -> list[ExpandedLine]:
    """Expand same-origin !#include directives and evaluate platform conditions."""
    if len(stack) >= MAX_INCLUDE_DEPTH:
        raise CompilationError(f"preprocessor include depth exceeds {MAX_INCLUDE_DEPTH}")
    if source.url in stack:
        cycle = " -> ".join((*stack, source.url))
        raise CompilationError(f"recursive !#include cycle: {cycle}")

    flags = target_condition_flags(target)
    # Each frame contains the parent activation state, condition value, and else state.
    frames: list[dict[str, bool]] = []
    active = True
    output: list[ExpandedLine] = []

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()

        if_match = re.fullmatch(r"!#if\s+(.+)", line)
        if if_match:
            condition_value = evaluate_filter_condition(if_match.group(1), flags)
            frames.append({
                "parent_active": active,
                "condition": condition_value,
                "seen_else": False,
            })
            active = active and condition_value
            continue

        if re.fullmatch(r"!#else", line):
            if not frames:
                raise CompilationError(f"{source.url}:{line_number}: !#else without !#if")
            frame = frames[-1]
            if frame["seen_else"]:
                raise CompilationError(f"{source.url}:{line_number}: duplicate !#else")
            frame["seen_else"] = True
            active = frame["parent_active"] and not frame["condition"]
            continue

        if re.fullmatch(r"!#endif", line):
            if not frames:
                raise CompilationError(f"{source.url}:{line_number}: !#endif without !#if")
            frame = frames.pop()
            active = frame["parent_active"]
            continue

        affinity_begin = re.fullmatch(r"!#safari_cb_affinity\(([^)]*)\)", line)
        if affinity_begin:
            if not active:
                continue
            if target == "safari":
                raise CompilationError(
                    f"{source.url}:{line_number}: Safari content-blocker affinity "
                    "cannot be preserved in one flat filter file"
                )
            # Affinity only partitions Safari content blockers; for non-Safari
            # targets the enclosed rules remain active but the metadata is removed.
            continue

        if re.fullmatch(r"!#safari_cb_affinity", line):
            if not active:
                continue
            if target == "safari":
                raise CompilationError(
                    f"{source.url}:{line_number}: Safari content-blocker affinity "
                    "cannot be preserved in one flat filter file"
                )
            continue

        include_match = re.fullmatch(r"!#include\s+(.+)", line)
        if include_match:
            if not active:
                continue
            include_path = include_match.group(1).strip()
            if len(include_path) >= 2 and include_path[0] == include_path[-1] and include_path[0] in {"'", '"'}:
                include_path = include_path[1:-1]
            include_url = urllib.parse.urljoin(source.url, include_path)
            parsed_include = urllib.parse.urlparse(include_url)
            if parsed_include.scheme not in {"https", "http"} or not parsed_include.hostname:
                raise CompilationError(f"{source.url}:{line_number}: invalid !#include target {include_path!r}")
            if not allow_preprocessor_include(source.url, include_url):
                raise CompilationError(
                    f"{source.url}:{line_number}: cross-origin !#include is not allowlisted: {include_url}"
                )
            if include_url not in cache:
                try:
                    include_kind = classify_source(include_url)
                except CompilationError:
                    # Includes are fragments of their parent filter; absent an
                    # explicit source override, they inherit the parent's syntax.
                    include_kind = source.kind
                included_source = Source(include_url, include_kind)
                _, included_text = fetch_source(included_source)
                cache[include_url] = (included_source, included_text)
            included_source, included_text = cache[include_url]
            output.extend(
                expand_filter_preprocessor(
                    included_source,
                    included_text,
                    target,
                    cache,
                    (*stack, source.url),
                )
            )
            continue

        if line.startswith(("!#if", "!#else", "!#endif", "!#include")):
            if active:
                raise CompilationError(
                    f"{source.url}:{line_number}: malformed preprocessor directive: {line}"
                )
            continue

        if active:
            output.append(ExpandedLine(source, line_number, raw_line))

    if frames:
        raise CompilationError(f"{source.url}: unterminated !#if block")
    return output

@dataclass(frozen=True)
class ExclusionMatcher:
    kind: str
    value: str | re.Pattern[str]

    def matches(self, line: str) -> bool:
        if self.kind == "substring":
            return str(self.value) in line
        if self.kind in {"wildcard", "regex"}:
            assert isinstance(self.value, re.Pattern)
            return self.value.search(line) is not None
        raise AssertionError(f"unknown exclusion matcher kind: {self.kind}")

def parse_hostlist_exclusion_patterns(text: str) -> list[ExclusionMatcher]:
    """Mirror AdGuard HostlistCompiler exclusion wildcard semantics.

    - Plain text: case-sensitive substring match against the original rule.
    - * wildcard: case-insensitive whole-line wildcard match.
    - /regex/: case-insensitive, multiline regex search.
    """
    result: list[ExclusionMatcher] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        pattern = raw.strip()
        if not pattern or is_comment_or_header(pattern) or pattern in seen:
            continue
        seen.add(pattern)
        if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
            try:
                result.append(
                    ExclusionMatcher("regex", re.compile(pattern[1:-1], re.IGNORECASE | re.MULTILINE))
                )
            except re.error as error:
                raise CompilationError(
                    f"invalid exclusion regex {pattern!r}: {error}"
                ) from error
        elif "*" in pattern:
            parts = re.split(r"\*+", pattern)
            wildcard_regex = r"^" + r"[\s\S]*".join(re.escape(part) for part in parts) + r"$"
            result.append(
                ExclusionMatcher("wildcard", re.compile(wildcard_regex, re.IGNORECASE))
            )
        else:
            result.append(ExclusionMatcher("substring", pattern))
    return result

def load_adguard_dns_exclusion_map(
    fetched: list[tuple[Source, str]],
) -> tuple[dict[str, list[ExclusionMatcher]], dict[str, int], str | None]:
    """Load AdGuardSDNSFilter's source-to-exclusion relationships.

    The exclusion file is not a blocklist. Its patterns are only applied to the
    exact input sources that configuration.json declares to use them.
    """
    exclusion_sources = {
        source.url: text
        for source, text in fetched
        if source.kind == "exclusions"
    }
    if not exclusion_sources:
        return {}, {}, None

    try:
        _, config_text = fetch_source(
            Source(ADGUARD_SDNS_CONFIGURATION_URL, "source-metadata")
        )
        configuration = json.loads(config_text)
    except Exception as error:
        raise CompilationError(
            f"unable to load AdGuardSDNSFilter source metadata: {error}"
        ) from error

    manifest_urls = {source.url for source, _ in fetched}
    source_to_exclusion_urls: dict[str, list[str]] = {}
    for entry in configuration.get("sources", []):
        source_url = entry.get("source")
        refs = entry.get("exclusions_sources") or []
        if not source_url or source_url not in manifest_urls or not refs:
            continue
        resolved = [
            urllib.parse.urljoin(ADGUARD_SDNS_CONFIGURATION_URL, ref)
            for ref in refs
        ]
        source_to_exclusion_urls[source_url] = resolved

    exclusion_patterns_by_url: dict[str, list[ExclusionMatcher]] = {}
    pattern_counts_by_metadata_url: dict[str, int] = {}
    available_texts = dict(exclusion_sources)

    for refs in source_to_exclusion_urls.values():
        for exclusion_url in refs:
            if exclusion_url in exclusion_patterns_by_url:
                continue
            if exclusion_url not in available_texts:
                try:
                    _, exclusion_text = fetch_source(Source(exclusion_url, "exclusions"))
                    available_texts[exclusion_url] = exclusion_text
                except Exception as error:
                    raise CompilationError(
                        f"unable to load required exclusion source {exclusion_url}: {error}"
                    ) from error
            patterns = parse_hostlist_exclusion_patterns(available_texts[exclusion_url])
            exclusion_patterns_by_url[exclusion_url] = patterns
            pattern_counts_by_metadata_url[exclusion_url] = len(patterns)

    patterns_by_source: dict[str, list[ExclusionMatcher]] = {}
    for source_url, refs in source_to_exclusion_urls.items():
        patterns_by_source[source_url] = [
            pattern
            for exclusion_url in refs
            for pattern in exclusion_patterns_by_url.get(exclusion_url, [])
        ]

    return patterns_by_source, pattern_counts_by_metadata_url, ADGUARD_SDNS_CONFIGURATION_URL

def compile_fetched_sources(
    fetched: list[tuple[Source, str]],
    target: str,
    source_exclusions: dict[str, list[ExclusionMatcher]] | None = None,
    metadata_pattern_counts: dict[str, int] | None = None,
    metadata_config_url: str | None = None,
) -> CompileState:
    state = CompileState()
    source_exclusions = source_exclusions or {}
    metadata_pattern_counts = metadata_pattern_counts or {}
    cache: dict[str, tuple[Source, str]] = {
        source.url: (source, text) for source, text in fetched
    }

    expanded_lines: list[ExpandedLine] = []
    for source, text in fetched:
        summary = SourceSummary(
            url=source.url,
            kind=source.kind,
            status="ok",
            input_lines=len(text.splitlines()),
        )
        state.summaries[source.url] = summary

        # Exclusion selector files are metadata for a DNS-list compiler, never
        # active browser blocking rules.
        if source.kind == "exclusions":
            summary.status = "consumed-as-metadata"
            summary.target_skip_reason = (
                "This file contains upstream exclusion metadata, not active filter rules."
            )
            continue

        # A DNS blocklist is not interchangeable with a browser request filter:
        # e.g. a DNS IP rule can block a hostname because its resolution points
        # to that IP, while a browser rule sees only the request URL. CNAME lists
        # likewise require DNS-aware request inspection. Keep these families out
        # of this target and make the exclusion visible in the report.
        if source.kind in BROWSER_TARGET_EXCLUDED_SOURCE_REASONS:
            summary.status = "skipped-target-mismatch"
            summary.target_skip_reason = BROWSER_TARGET_EXCLUDED_SOURCE_REASONS[source.kind]
            summary.input_lines_skipped_by_target = sum(
                1
                for raw in text.splitlines()
                if raw.strip() and not is_comment_or_header(raw.strip())
            )
            continue

        try:
            expanded_lines.extend(
                expand_filter_preprocessor(source, text, target, cache)
            )
        except Exception as error:
            summary.status = "preprocessor-error"
            summary.error = f"{type(error).__name__}: {error}"
            state.issues.append({
                "source": source.url,
                "format": source.kind,
                "line": None,
                "rule": "<filter preprocessor>",
                "reason": summary.error,
            })

    # Files referenced through !#include may not be in the original manifest.
    for source_url, (source, text) in cache.items():
        if source_url not in state.summaries:
            state.summaries[source_url] = SourceSummary(
                url=source.url,
                kind=source.kind,
                status="included",
                input_lines=len(text.splitlines()),
            )

    # Exclusion files are metadata. Their patterns are applied only to the
    # upstream source URLs explicitly linked to them in AdGuard's configuration.
    for source, _ in fetched:
        if source.kind == "exclusions":
            summary = state.summaries[source.url]
            summary.status = "consumed-as-metadata"
            summary.metadata_patterns = metadata_pattern_counts.get(source.url, 0)
    if metadata_config_url:
        state.summaries[metadata_config_url] = SourceSummary(
            url=metadata_config_url,
            kind="source-metadata",
            status="loaded",
            metadata_patterns=sum(metadata_pattern_counts.values()),
        )

    for expanded in expanded_lines:
        source = expanded.source
        summary = state.summaries[source.url]
        raw_rule = expanded.text.rstrip("\r\n")
        line = raw_rule.strip()

        # An included fragment can be classified independently of its parent
        # source. Apply the same target boundary to it as to manifest sources.
        if source.kind in BROWSER_TARGET_EXCLUDED_SOURCE_REASONS:
            summary.status = "skipped-target-mismatch"
            summary.target_skip_reason = BROWSER_TARGET_EXCLUDED_SOURCE_REASONS[source.kind]
            if line and not is_comment_or_header(line):
                summary.input_lines_skipped_by_target += 1
            continue
        if source.kind == "exclusions":
            summary.status = "consumed-as-metadata"
            summary.target_skip_reason = (
                "This file contains upstream exclusion metadata, not active filter rules."
            )
            continue
        if not is_comment_or_header(line):
            matched_exclusions = source_exclusions.get(source.url, [])
            if any(pattern.matches(raw_rule) for pattern in matched_exclusions):
                summary.excluded_by_metadata += 1
                continue
        # Some well-understood source rules have no equivalent in the selected
        # AdGuard browser target. Do not silently rewrite them or fail an entire
        # million-rule build because of a known engine mismatch: exclude each
        # such rule explicitly, including its source and reason, in the audit.
        # Unknown in-scope conversion failures below remain strict errors.
        target_exclusion_reason = (
            detect_nonportable_native_rule(line)
            if source.kind == "adblock" and line and not is_comment_or_header(line)
            else None
        )
        if target_exclusion_reason:
            summary.target_excluded_rules += 1
            state.target_exclusions.append({
                "source": source.url,
                "format": source.kind,
                "line": expanded.line_number,
                "rule": line[:500],
                "reason": target_exclusion_reason,
            })
            continue

        try:
            translated, category = compile_line(source.kind, line)
        except CompilationError as error:
            add_issue(state, summary, expanded.line_number, line, str(error))
            continue

        if category == "comment":
            summary.ignored_comments += 1
        if category == "system-host-mapping" or category.endswith("-with-system-alias"):
            summary.ignored_system_mappings += 1

        for output_rule in translated:
            if output_rule in state.records:
                summary.duplicate_rules += 1
            else:
                state.records.add(output_rule)
                summary.emitted_rules += 1

    return state

def build_report(state: CompileState, *, source_failures: list[dict[str, str]], output_path: str, target: str) -> dict[str, object]:
    source_summaries = []
    for summary in state.summaries.values():
        source_summaries.append({
            "url": summary.url,
            "format": summary.kind,
            "status": summary.status,
            "input_lines": summary.input_lines,
            "unique_rules_emitted": summary.emitted_rules,
            "duplicates": summary.duplicate_rules,
            "comments_or_headers": summary.ignored_comments,
            "ignored_system_mappings": summary.ignored_system_mappings,
            "excluded_by_upstream_metadata": summary.excluded_by_metadata,
            "input_lines_skipped_by_target": summary.input_lines_skipped_by_target,
            "target_skip_reason": summary.target_skip_reason,
            "target_excluded_rules": summary.target_excluded_rules,
            "metadata_patterns": summary.metadata_patterns,
            "unsupported_lines": summary.unsupported_lines,
            "error": summary.error,
        })
    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": f"AdGuard browser filter syntax ({target})",
        "output": output_path,
        "unique_rule_count": len(state.records),
        "source_count": len(source_summaries) + len(source_failures),
        "source_summaries": source_summaries,
        "source_failures": source_failures,
        "sources_skipped_by_target": sum(
            1 for summary in state.summaries.values()
            if summary.status == "skipped-target-mismatch"
        ),
        "input_lines_skipped_by_target": sum(
            summary.input_lines_skipped_by_target
            for summary in state.summaries.values()
        ),
        "target_excluded_rule_count": len(state.target_exclusions),
        "target_exclusions": state.target_exclusions,
        "unsupported_count": len(state.issues),
        "unsupported_rules": state.issues,
        "semantic_guarantee": (
            "Native browser-compatible rules are preserved as Adblock-compatible syntax; "
            "hosts and domains-only entries become exact-host HTTP(S) URL regex rules; "
            "DNS and CNAME source families are explicitly excluded from the browser target. "
            "Known non-portable rules are excluded individually with source-line diagnostics; "
            "unknown in-scope conversion failures still fail strict compilation. All exclusions "
            "are visible in the report. This is not a proof for arbitrary regex or "
            "engine-specific rules."
        ),
    }

def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=str(path.parent),
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    )
    temp_name = handle.name
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise

def run_regression_tests() -> None:
    tests: list[tuple[str, object, object]] = []

    def check(name: str, actual: object, expected: object) -> None:
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")
        tests.append((name, actual, expected))

    check("IDNA and lowercase", canonical_hostname("BÜCHER.Example"), "xn--bcher-kva.example")
    exclusion_matchers = parse_hostlist_exclusion_patterns(
        "! comment\n||excluded.example^\n*track*\n/ads\\.example/\n"
    )
    check("plain exclusion uses case-sensitive substring semantics",
          exclusion_matchers[0].matches("||excluded.example^"), True)
    check("wildcard exclusion matches a whole rule case-insensitively",
          exclusion_matchers[1].matches("||TRACK.example^"), True)
    check("regex exclusion is searched case-insensitively",
          exclusion_matchers[2].matches("||ads.example^"), True)
    check("exclusion patterns do not match unrelated rules",
          any(pattern.matches("||safe.example^") for pattern in exclusion_matchers), False)
    check("AdAway is classified as hosts", classify_source("https://adaway.org/hosts.txt"), "hosts")
    check("CNAME disguised ads use ordinary browser syntax", classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt"), "adblock")
    check("CNAME original trackers require CNAME-aware scanning", classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt"), "cname")
    check("AdGuardSDNSFilter exclusions are metadata, not block rules",
          classify_source("https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt"),
          "exclusions")
    check("Chromium MV2 preprocessor condition evaluates true",
          evaluate_filter_condition("adguard && adguard_ext_chromium && !adguard_ext_safari", target_condition_flags("chromium")), True)
    check("Chromium MV3 gets the MV3 condition, not the MV2 condition",
          evaluate_filter_condition("adguard_ext_chromium_mv3 && !adguard_ext_chromium", target_condition_flags("chromium-mv3")), True)
    check("uBlock-only conditions are false for AdGuard output",
          evaluate_filter_condition("ext_ublock || ext_ubol || ext_abp", target_condition_flags("chromium-mv3")), False)
    check("literal false preprocessor condition is evaluated", evaluate_filter_condition("false", target_condition_flags("chromium-mv3")), False)
    check("unsupported capability flag is false for AdGuard output", evaluate_filter_condition("cap_ipaddress", target_condition_flags("chromium-mv3")), False)
    check("Safari-only flag is false for Chromium MV3", evaluate_filter_condition("ext_safari", target_condition_flags("chromium-mv3")), False)
    check("Chromium environment condition is true",
          evaluate_filter_condition("env_chromium && !env_mobile", target_condition_flags("chromium-mv3")), True)
    check("Chromium MV3 exposes the user stylesheet capability",
          evaluate_filter_condition("cap_user_stylesheet", target_condition_flags("chromium-mv3")), True)
    check("Safari does not inherit the Chromium stylesheet capability",
          evaluate_filter_condition("cap_user_stylesheet", target_condition_flags("safari")), False)
    check("AdGuard CNAME include from an official filter source is allowlisted",
          allow_preprocessor_include(
              "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
              "https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt",
          ), True)
    check("disguised CNAME ad-domain lists keep ordinary browser-filter semantics",
          classify_source("https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt"),
          "adblock")
    check("CNAME justdomains feeds use the domain-list adapter",
          classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads_justdomains.txt"),
          "domains")
    check("original CNAME tracker justdomains remains DNS-aware",
          classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers_justdomains.txt"),
          "cname")
    check("disguised microsite list requires DNS-aware inspection",
          classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt"),
          "cname")
    check("CNAME microsite lists retain DNS-aware semantics",
          classify_source("https://adguardteam.github.io/cname-trackers/data/microsites/example.txt"),
          "cname")
    check("arbitrary cross-origin preprocessor include is rejected",
          allow_preprocessor_include(
              "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
              "https://evil.example/list.txt",
          ), False)
    check("Chromium preprocessor excludes Safari-only rules",
          evaluate_filter_condition("adguard_ext_safari", target_condition_flags("chromium")), False)
    conditional_source = Source("https://example.com/filter.txt", "adblock")
    conditional_text = "!#if (adguard_ext_chromium)\n||chromium.example^\n!#else\n||other.example^\n!#endif\n"
    conditional_lines = expand_filter_preprocessor(
        conditional_source,
        conditional_text,
        "chromium",
        {conditional_source.url: (conditional_source, conditional_text)},
    )
    check("preprocessor selects only active target rules",
          [line.text.strip() for line in conditional_lines],
          ["||chromium.example^"])
    check("AdGuard DNS filter is classified as DNS", classify_source("https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt"), "dns")
    check("CNAME tracker list is isolated as source-level semantics", classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt"), "cname")
    try:
        compile_line("cname", "||tracker.example.com^")
    except CompilationError:
        tests.append(("CNAME syntax cannot be compiled as an ordinary browser rule", True, True))
    else:
        raise AssertionError("CNAME-scanner semantics must not be changed to ordinary URL blocking")

    dns_source = Source("https://example.invalid/dns-list.txt", "dns")
    dns_state = compile_fetched_sources(
        [(dns_source, "||ads.example^\n203.0.113.7$network\n")],
        "chromium-mv3",
    )
    check("DNS-only sources do not leak into browser rules", len(dns_state.records), 0)
    check("DNS-only sources are reported as target exclusions",
          dns_state.summaries[dns_source.url].status, "skipped-target-mismatch")
    check("DNS-only source rules are counted in the audit",
          dns_state.summaries[dns_source.url].input_lines_skipped_by_target, 2)
    check("target-excluded DNS rules do not fail browser compilation", len(dns_state.issues), 0)

    native_source = Source("https://example.invalid/native-rules.txt", "adblock")
    native_state = compile_fetched_sources(
        [(native_source, "||37.1.213.100^$network\nexample.com##.ad:remove-class(foo)\n")],
        "chromium-mv3",
    )
    check("known nonportable native rules do not get rewritten", len(native_state.records), 0)
    check("known nonportable native rules are audited as target exclusions",
          len(native_state.target_exclusions), 2)
    check("known nonportable native rules do not masquerade as unknown compiler errors",
          len(native_state.issues), 0)

    cname_source = Source("https://example.invalid/cname-list.txt", "cname")
    cname_state = compile_fetched_sources(
        [(cname_source, "||tracker.example.com^\n")],
        "chromium-mv3",
    )
    check("CNAME-only source is audited outside browser target",
          cname_state.summaries[cname_source.url].status, "skipped-target-mismatch")
    check("CNAME-only source does not cause false conversion", len(cname_state.records), 0)
    check("CNAME-only source does not become an unsupported-rule error", len(cname_state.issues), 0)

    mixed_sources = [
        (Source("https://example.invalid/hosts.txt", "hosts"), "0.0.0.0 Ads.Example.com\n"),
        (Source("https://example.invalid/domains.txt", "domains"), "Tracker.Example.net\n"),
        (Source("https://example.invalid/adblock.txt", "adblock"), "||Ads.Example.com^\n"),
    ]
    mixed_state = compile_fetched_sources(mixed_sources, "chromium-mv3")
    check("hosts, domain-only, and native Adblock sources compile together",
          len(mixed_state.issues), 0)
    check("native Adblock rules keep their native semantics",
          "||ads.example.com^" in mixed_state.records, True)
    check("hosts source keeps exact-host scope",
          exact_hostname_regex_rule("ads.example.com") in mixed_state.records, True)
    check("domains-only source keeps domain-and-subdomain scope",
          "||tracker.example.net^" in mixed_state.records, True)

    try:
        classify_source("https://example.invalid/new-list.txt")
    except CompilationError:
        tests.append(("unknown source format rejected", True, True))
    else:
        raise AssertionError("unknown source format must not silently default to Adblock")
    override_url = "https://example.invalid/domains.txt"
    SOURCE_FORMAT_OVERRIDES[override_url] = "domains"
    try:
        check("explicit override enables a domains-only source", classify_source(override_url), "domains")
    finally:
        del SOURCE_FORMAT_OVERRIDES[override_url]
    exact_override_url = "https://example.invalid/domains-exact.txt"
    SOURCE_FORMAT_OVERRIDES[exact_override_url] = "domains-exact"
    try:
        check("explicit override enables an exact-host domains source",
              classify_source(exact_override_url), "domains-exact")
    finally:
        del SOURCE_FORMAT_OVERRIDES[exact_override_url]
    check("plain domain-list entries block the domain and its subdomains",
          compile_line("domains", "Example.COM")[0],
          ["||example.com^"])
    check("exact-host domain-list entries do not expand to subdomains",
          compile_line("domains-exact", "Example.COM")[0],
          [exact_hostname_regex_rule("example.com")])
    check("baseline localhost mapping is not emitted as an ad block", compile_line("hosts", "127.0.0.1 localhost")[0], [])
    check("mixed hosts mapping skips localhost but retains the block alias",
          compile_line("hosts", "127.0.0.1 localhost ads.example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("host record preserves exact-host scope", compile_line("hosts", "0.0.0.0 Ads.Example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("domain-only preserves exact-host scope", compile_line("domains", "Ads.Example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("DNS subtree rule preserves subtree", compile_line("dns", "||Ads.Example.com^")[0],
          ["||ads.example.com^"])
    check("DNS wildcard hostname mask is preserved", compile_line("dns", "||MobileAnalytics.*.AmazonAWS.com^")[0],
          ["||mobileanalytics.*.amazonaws.com^"])
    check("DNS exception preserves exception", compile_line("dns", "@@||Ads.Example.com^")[0],
          ["@@||ads.example.com^"])
    check("DNS inline comment is ignored", compile_line("dns", "example.com # source note")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("DNS exact end anchor is preserved as exact-host regex", compile_line("dns", "@@||example.com^|")[0],
          [r"@@/^https?:\/\/(?:[^\/?#@]+@)?example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("DNS partial domain anchor keeps prefix semantics", compile_line("dns", "||advertising.civitai.")[0],
          ["||advertising.civitai."])
    check("DNS leading-dot mask excludes apex", compile_line("dns", ".example.com^")[0],
          ["||*.example.com^"])
    check("anchored DNS hostname regex compiles to URL authority regex",
          compile_line("dns", "/^(?:\\w+\\.)*minepi\\.com$/")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?(?:(?:\w+\.)*minepi\.com)(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("URL-scoped regex remains a URL-scoped regex", compile_line("dns", r"/(https?:\/\/)213\.32\.115\..{100,}/")[0],
          [r"/(https?:\/\/)213\.32\.115\..{100,}/"])
    check("Adblock badfilter remains explicit", compile_line("adblock", "||Ads.Example.com^$badfilter")[0],
          ["||ads.example.com^$badfilter"])
    check("cosmetic rules are retained", compile_line("adblock", "example.com##.ad")[0],
          ["example.com##.ad"])
    check("comments are not emitted", compile_line("adblock", "! comment")[0], [])
    try:
        compile_line("adblock", "!#if ext_ublock")
    except CompilationError:
        tests.append(("filter preprocessor directives are not silently dropped", True, True))
    else:
        raise AssertionError("filter preprocessor directives must be evaluated or reported")
    try:
        compile_line("hosts", "192.0.2.10 ads.example.com")
    except CompilationError:
        tests.append(("non-block hosts mapping rejected", True, True))
    else:
        raise AssertionError("non-block hosts mapping must not be rewritten as a block")
    try:
        compile_line("dns", "||example.com^$dnstype=A")
    except CompilationError:
        tests.append(("DNS-only dnstype rejected", True, True))
    else:
        raise AssertionError("DNS-only dnstype must not be silently discarded")
    check("AdGuard Extended CSS :has-text is preserved", compile_line("adblock", "example.com#?#div:has-text(ad)")[0],
          ["example.com#?#div:has-text(ad)"])
    check("AdGuard Extended CSS :matches-css is preserved", compile_line("adblock", "example.com#?#div:matches-css(width: 1px)")[0],
          ["example.com#?#div:matches-css(width: 1px)"])
    check("AdGuard accepts uBO-compatible +js syntax", compile_line("adblock", "example.com##+js(no-such-scriptlet)")[0],
          ["example.com##+js(no-such-scriptlet)"])
    check("native IPv4 host rules are preserved", compile_line("adblock", "||37.1.213.100^")[0],
          ["||37.1.213.100^"])
    try:
        compile_line("adblock", "||37.1.213.100^$network")
    except CompilationError:
        tests.append(("network modifier rejected for browser target", True, True))
    else:
        raise AssertionError("the app-only $network modifier must not be published to a browser filter")
    try:
        compile_line("dns", "||37.1.213.100^")
    except CompilationError:
        tests.append(("IP-like DNS hostname matcher rejected as ambiguous", True, True))
    else:
        raise AssertionError("IP-like DNS rules must not be converted to URL-host blockers")
    try:
        compile_line("dns", "37.1.213.100")
    except CompilationError:
        tests.append(("bare DNS IP/CNAME rule rejected", True, True))
    else:
        raise AssertionError("bare DNS IP semantics must not be rewritten as URL-host semantics")
    try:
        compile_line("adblock", "||example.com^$dnstype=A")
    except CompilationError:
        tests.append(("DNS-only modifier rejected in native list", True, True))
    else:
        raise AssertionError("DNS-only modifiers must not be silently published as browser rules")
    configured_sources = build_sources(urls)
    check("all configured upstreams have an explicit format family", len(configured_sources), len(urls))
    check("manifest covers the required input and metadata families",
          sorted({source.kind for source in configured_sources}),
          ["adblock", "cname", "dns", "exclusions", "hosts"])
    print(f"Passed {len(tests)} semantic regression checks.")

def main() -> int:
    parser = argparse.ArgumentParser(description="Compile upstream blocklists into an AdGuard browser filter with explicit semantic-loss reporting.")
    parser.add_argument("--target", choices=sorted(TARGET_PROFILES), default="chromium-mv3", help="AdGuard target profile (default: chromium-mv3)")
    parser.add_argument("--output", default=OUTPUT_DEFAULT, help=f"compiled filter path (default: {OUTPUT_DEFAULT})")
    parser.add_argument("--report", default=REPORT_DEFAULT, help=f"JSON compilation report (default: {REPORT_DEFAULT})")
    parser.add_argument("--allow-lossy", action="store_true", help="explicitly publish only translatable rules; report all omitted rules")
    parser.add_argument("--allow-source-failures", action="store_true", help="explicitly allow publishing without sources that failed to download")
    parser.add_argument("--self-test", action="store_true", help="run built-in regression tests without downloading upstreams")
    args = parser.parse_args()

    if args.self_test:
        run_regression_tests()
        return 0

    try:
        sources = build_sources(urls)
    except CompilationError as error:
        print(f"ABORTED: invalid upstream manifest: {error}", file=sys.stderr)
        return 2
    state = CompileState()
    fetched: list[tuple[Source, str]] = []
    source_failures: list[dict[str, str]] = []
    print(f"Fetching {len(sources)} upstream sources with {FETCH_WORKERS} workers...", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
        future_map = {executor.submit(fetch_source, source): source for source in sources}
        for future in concurrent.futures.as_completed(future_map):
            source = future_map[future]
            try:
                fetched.append(future.result())
            except Exception as error:
                message = f"{type(error).__name__}: {error}"
                source_failures.append({"url": source.url, "format": source.kind, "error": message})
                print(f"[FETCH FAILED] {source.kind}: {source.url}: {message}", file=sys.stderr)

    # Deterministic processing order, independent of network completion order.
    fetched.sort(key=lambda item: sources.index(item[0]))

    # This generator produces an AdGuard browser filter. DNS-specific exclusion
    # metadata is consumed by a DNS-list compiler, not by this output target.
    # compile_fetched_sources records DNS/CNAME families as target exclusions.
    state = compile_fetched_sources(fetched, args.target)
    state.issues.sort(key=lambda issue: (str(issue["source"]), int(issue.get("line") or 0)))
    report = build_report(state, source_failures=source_failures, output_path=args.output, target=args.target)
    report_path = Path(args.report)
    output_path = Path(args.output)

    # Always retain an audit report, even when strict mode prevents publication.
    atomic_write_text(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    if source_failures and not args.allow_source_failures:
        print(
            f"ABORTED: {len(source_failures)} source(s) failed. Existing output was not changed. "
            f"Review {report_path}. Use --allow-source-failures only for an intentional partial build.",
            file=sys.stderr,
        )
        return 2

    if state.issues and not args.allow_lossy:
        print(
            f"ABORTED: {len(state.issues)} rule(s) could not be translated with proven semantics. "
            f"Existing output was not changed. Review {report_path}.",
            file=sys.stderr,
        )
        for issue in state.issues[:15]:
            print(
                f"  {issue['source']}:{issue['line']}: {issue['reason']} :: {issue['rule']}",
                file=sys.stderr,
            )
        return 2

    rules = sorted(state.records)
    if not rules:
        print("ABORTED: compilation produced zero rules; existing output was not changed.", file=sys.stderr)
        return 2

    timestamp = dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    header = [
        "! Title: Adblock-Rule-Collection",
        "! Description: Semantically compiled upstream rules for AdGuard browser filtering",
        "! Target: " + args.target,
        "! Homepage: https://github.com/REIJI007/Adblock-Rule-Collection",
        "! LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL%203.0",
        "! LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA%204.0",
        "! Generated: " + timestamp,
        "! RuleCount: " + str(len(rules)),
        "! CompileReport: " + report_path.name,
    ]
    if source_failures or state.issues or state.target_exclusions:
        header.append("! WARNING: Some source rules were excluded for target incompatibility or compilation errors; see the JSON report.")
    document = "\n".join(header) + "\n\n" + "\n".join(rules) + "\n"
    atomic_write_text(output_path, document)

    print(f"Published {len(rules)} unique rules to {output_path}")
    print(
        f"Sources: {len(fetched)}/{len(sources)}; "
        f"target-excluded rules: {len(state.target_exclusions)}; "
        f"unsupported lines: {len(state.issues)}; source failures: {len(source_failures)}"
    )
    print(f"Report: {report_path}")
    return 0

urls = [
	"https://adaway.org/hosts.txt",
	"https://filters.adavoid.org/ultimate-ad-filter.txt",
	"https://filters.adavoid.org/ultimate-privacy-filter.txt",
	"https://filters.adavoid.org/ultimate-security-filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/annoyances.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/self-promo.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/tweaks.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/banner_sizes.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/content_blocker.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/specific_app.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/specific_web.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/popups.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/social_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/cryptominers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
	"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_101_EasyList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_118_EasyPrivacy/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_122_FanboysAnnoyances/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_123_FanboysSocialBlockingList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_201_WebAnnoyancesUltralist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_204_PeterLowesList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_207_AdblockWarningRemovalList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_208_Online_Malicious_URL_Blocklist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_209_ADgkMobileChinalist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_210_Spam404/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_211_AntiAdblockKillerReek/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_219_ChinaListAndEasyList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_220_CJXsAnnoyanceList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_228_xinggsf/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_229_IdontCareAboutCookies/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_239_FanboyAntifonts/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_240_BarbBlock/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_241_FanboyCookiemonster/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_242_NoCoin/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_255_Phishing_URL_Blocklist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_256_Scam_Blocklist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_257_uBlock_Origin_Badware_risks/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_259_Dandelion_Sprout's_Anti-Malware_List/filter.txt",
	"https://easylist.to/easylist/easylist.txt",
	"https://easylist.to/easylist/easyprivacy.txt",
	"https://easylist.to/easylist/fanboy-social.txt",
	"https://secure.fanboy.co.nz/fanboy-annoyance.txt",
	"https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_dimensions.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_dimensions.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_hide_abp.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general_emailtrackers.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_abp.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_a8net.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_acton.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_ad-ebis.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_adobe.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_at-internet.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_branch.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_commanders-act.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_criteo.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_dataunlocker.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_eulerian.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_ingenious-technologies.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_keyade.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_lead-forensics.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_np6.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_oracle.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_otto.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_plausible.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_tracedock.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_webtrekk.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_wizaly.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_perimeterx.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_mining.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_notifications.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_ai_suggestions.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_antifonts.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_chatapps_third-party.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_international_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_international_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_sounds_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_chinese.txt",
	"https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_english.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-general.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy-removeparam.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/legacy.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/ubol-filters.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/ubo-link-shorteners.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easyprivacy.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-ai.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-annoyances.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-chat.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-cookies.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-newsletters.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-notifications.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-social.txt",
	"https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
	"https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
	"https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt",
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
	"https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt",
	"https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt",
	"https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt",
	"https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt"
]

if __name__ == "__main__":
    raise SystemExit(main())
