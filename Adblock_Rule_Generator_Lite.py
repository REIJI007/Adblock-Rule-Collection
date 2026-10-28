# -*- coding: utf-8 -*-
"""将多个上游过滤列表编译为 AdGuard 网络过滤规则。

默认以 AdGuard for Windows 桌面过滤引擎为目标；符合网络过滤语法的原生规则（包括 DNS/CNAME 来源中的规则）尽量原样保留，其他可安全转换的条目按目标语义转换。
无法证明兼容的规则会记录在审计报告中；严格模式失败时不会覆盖旧产物。
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

OUTPUT_DEFAULT = "ADBLOCK_RULE_COLLECTION_Lite.txt"
REPORT_DEFAULT = "ADBLOCK_RULE_COLLECTION_Lite.semantic-report.json"
DEFAULT_TARGET = "adguard-windows"
FETCH_WORKERS = 12
FETCH_TIMEOUT_SECONDS = 18

# 这些是过滤操作符，不是注释前缀。
VALID_HASH_RULE_PREFIXES = (
    "##", "#@#", "#$#", "#$@#", "#?#", "#@?#", "#%#", "#@%#",
)
COMMENT_PREFIXES = ("!",)
FILTER_DIRECTIVE_RE = re.compile(
    r"^!#(?:if|else|endif|include|safari_cb_affinity|pragma)\b",
    re.IGNORECASE,
)
# 这些是系统回环别名，不是广告或跟踪域名。

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

# 无法可靠识别的自定义来源，需在此显式指定格式。

# domains 匹配域名及其子域；domains-exact 只匹配该主机名。

# 可选来源格式：adblock、hosts、domains、domains-exact、dns、cname。
SOURCE_FORMAT_OVERRIDES: dict[str, str] = {}
SUPPORTED_SOURCE_KINDS = {
    "adblock", "hosts", "domains", "domains-exact", "dns", "cname", "exclusions"
}

# 条件指令按目标平台求值；输出仅面向指定的浏览器配置。

KNOWN_CONDITION_FLAGS = {
    "adguard", "adguard_app_windows", "adguard_app_mac", "adguard_app_android",
    "adguard_app_ios", "adguard_app_cli", "adguard_ext_safari",
    "adguard_ext_chromium", "adguard_ext_chromium_mv3", "adguard_ext_firefox",
    "adguard_ext_edge", "adguard_ext_edge_mv3", "adguard_ext_opera",
    "adguard_ext_opera_mv3", "adguard_ext_android_cb", "ext_ublock",
    "ext_ubol", "ext_abp", "ext_safari", "env_mobile", "env_safari", "env_chromium",
    "env_firefox", "env_edge", "env_mv3", "env_legacy",
    "cap_html_filtering", "cap_ipaddress", "cap_user_stylesheet",
}
TARGET_PROFILES = {
    # 目标为 AdGuard for Windows 桌面过滤引擎，而非浏览器扩展。
    "adguard-windows": {
        "adguard": True,
        "adguard_app_windows": True,
        "cap_html_filtering": True,
        "cap_ipaddress": True,
    },
    # chromium 对应 Chromium MV2；MV3 请使用 chromium-mv3。
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
# DNS/CNAME 来源逐条编译：已符合网络过滤语法的规则原样保留；
# DNS 专用修饰符无法在网络过滤层复现时，按目标兼容性规则单独排除并审计。
MAX_INCLUDE_DEPTH = 12
ADGUARD_SDNS_CONFIGURATION_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/configuration.json"
)

# 已知与目标引擎不兼容的 uBlock Origin 操作不能直接透传。

NON_PORTABLE_NATIVE_PATTERNS = (
    # AdGuard 与 uBlock Origin 的脚本规则语法不同，不能视为等价。

    (re.compile(r":matches-path\s*\(", re.IGNORECASE), "uBlock procedural operator :matches-path() has no verified AdGuard equivalent"),
    (re.compile(r":remove-(?:attr|class)\s*\(", re.IGNORECASE), "uBlock procedural DOM-removal operator has no verified AdGuard equivalent"),
)
DNS_ONLY_MODIFIER_RE = re.compile(r"(?:\$|,)(?:client|dnstype|dnsrewrite|ctag)(?:=|,|$)", re.IGNORECASE)
NETWORK_ONLY_MODIFIER_RE = re.compile(r"(?:\$|,)network(?:=|,|$)", re.IGNORECASE)

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
    # 使用集合去重，避免在内存中保留大量重复规则。

    records: set[str] = field(default_factory=set)
    issues: list[dict[str, object]] = field(default_factory=list)
    target_exclusions: list[dict[str, object]] = field(default_factory=list)
    summaries: dict[str, SourceSummary] = field(default_factory=dict)

def classify_source(url: str) -> str:
    """按显式清单识别上游格式；未知来源默认拒绝。"""
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

    if lowered == "https://adaway.org/hosts.txt":
        return "hosts"

    # exclusions.txt 是来源排除元数据，不是实际拦截规则。

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
        # CNAME 来源需区分：disguised 列表可用于浏览器；original 和 microsites 需要 DNS 感知。

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
        raise CompilationError(
            f"Unknown AdGuard CNAME tracker source family: {url!r}"
        )

    if "adguardteam/cname-trackers/" in lowered:
        # original 跟踪器和 microsites（含 justdomains 版本）需要 DNS/CNAME 感知。

        if (
            "/data/combined_original_trackers" in path
            or "/data/combined_disguised_microsites" in path
        ):
            return "cname"
        if path.endswith("_justdomains.txt"):
            return "domains"

        return "adblock"

    # 除 CNAME 特例外，*_justdomains.txt 按纯域名列表处理。

    if basename.endswith("_justdomains.txt"):
        return "domains"

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
    """校验并规范化主机名；是否允许单标签由调用方决定，非法值返回 None。"""
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
    """规范化网络规则中的主机名或 IPv4 地址。"""
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            return str(address)
        return None
    except ValueError:
        return canonical_hostname(value, allow_single_label=allow_single_label)

def exact_hostname_regex_rule(
    hostname: str,
    *,
    exception: bool = False,
    match_case: bool = False,
) -> str:
    """Generate an exact-host URL regex, scoped to a hierarchical URL authority."""
    domain = canonical_host_or_ipv4(hostname)
    if not domain:
        raise CompilationError(f"invalid exact hostname: {hostname!r}")
    if match_case:
        candidate = hostname[:-1] if hostname.endswith(".") else hostname
        try:
            ipaddress.ip_address(candidate)
            domain = candidate
        except ValueError:
            validated = canonical_hostname(candidate, allow_single_label=False)
            if not validated:
                raise CompilationError(f"invalid exact hostname: {hostname!r}")
            domain = candidate if candidate.isascii() else validated
    escaped = re.escape(domain)
    body = (
        r"^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?"
        + escaped
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + body + "/"
def normalize_native_domain_rule(line: str) -> str:
    """仅规范化简单域名锚定规则，其余语法保持原样。"""
    # 原生浏览器规则中的裸 IPv4 规范化为主机锚定规则。
    # DNS 来源由专用适配器处理，避免误按浏览器语义转换。

    # A bare IPv4-looking string is still an unanchored URL-pattern rule.
    # Do not infer hostname anchoring from its textual shape.

    match = re.fullmatch(r"(?P<exception>@@)?(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^(?P<tail>\$.*)?", line)
    if not match:
        return line
    hostname = canonical_host_or_ipv4(match.group("host"), allow_single_label=False)
    if not hostname:
        # 遇到无法按主机名规范化但可能合法的上游语法时，保留原规则，避免改变匹配范围。

        return line
    tail = match.group("tail") or ""
    match_case = re.search(r"(?:^|,)\s*match-case(?:,|$)", tail, re.IGNORECASE) is not None
    output_hostname = match.group("host") if match_case and match.group("host").isascii() else hostname
    return (
        (match.group("exception") or "")
        + match.group("anchor")
        + output_hostname
        + "^"
        + tail
    )

def detect_nonportable_native_rule(
    line: str,
    target: str = "generic",
    source_url: str | None = None,
) -> str | None:
    if DNS_ONLY_MODIFIER_RE.search(line):
        return "DNS-only modifier cannot be represented safely in an AdGuard network filter"
    if target != "adguard-windows" and NETWORK_ONLY_MODIFIER_RE.search(line):
        return "AdGuard application-only $network modifier is not supported by this target"
    for pattern, explanation in NON_PORTABLE_NATIVE_PATTERNS:
        if pattern.search(line):
            return explanation

    # AdGuard documents some extended CSS operators also used by uBO. Reject
    # only operators whose semantics have no verified AdGuard equivalent.
    if source_url:
        parsed = urllib.parse.urlparse(source_url)
        path = parsed.path.lower()
        is_ublock_core = (
            (parsed.hostname or "").lower() == "raw.githubusercontent.com"
            and path.startswith("/ublockorigin/uassets/")
            and "/filters/" in path
        )
        if is_ublock_core:
            ublock_only_patterns = (
                (re.compile(r":has-text\s*\(", re.IGNORECASE),
                 "uBlock Origin :has-text() has no verified AdGuard equivalent"),
                (re.compile(r":matches-prop\s*\(", re.IGNORECASE),
                 "uBlock Origin :matches-prop() is not the AdGuard :matches-property() operator"),
                (re.compile(r":matches-media\s*\(", re.IGNORECASE),
                 "uBlock Origin :matches-media() has no verified AdGuard equivalent"),
                (re.compile(r":min-text-length\s*\(", re.IGNORECASE),
                 "uBlock Origin :min-text-length() has no verified AdGuard equivalent"),
                (re.compile(r":others\s*\(", re.IGNORECASE),
                 "uBlock Origin :others() has no verified AdGuard equivalent"),
                (re.compile(r":watch-attr\s*\(", re.IGNORECASE),
                 "uBlock Origin :watch-attr() has no verified AdGuard equivalent"),
                (re.compile(r"##\s*\+js\s*\(", re.IGNORECASE),
                 "uBlock Origin scriptlet name/arguments are not assumed portable to AdGuard"),
                (re.compile(r"\$cname(?:=|,|$)", re.IGNORECASE),
                 "uBlock Origin $cname requires CNAME-aware request matching"),
            )
            for pattern, explanation in ublock_only_patterns:
                if pattern.search(line):
                    return explanation
    return None
def canonical_wildcard_hostname_mask(value: str) -> str | None:
    """校验并转为小写的 DNS 主机名通配模式。"""
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
            # 通配符标签校验不能误拒绝有效的首尾字符。

            if not re.fullmatch(r"[a-z0-9*-]+", label):
                return None
            if label.startswith("-") or label.endswith("-"):
                return None
    return value.lower()

def split_modifiers(modifier_text: str) -> list[str]:
    """按引号外的逗号拆分规则修饰符。"""
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
    """返回斜杠分隔正则中结束斜杠的位置。"""
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
    """Translate a DNS hostname regex into URL-authority syntax conservatively."""
    if not regex_body or "/" in regex_body:
        return None
    if any(token in regex_body for token in ("(?=", "(?!", "(?<=", "(?<!", "(?P", "\\k<")):
        return None
    if re.search(r"\\[sSDW]", regex_body) or re.search(r"\(\?(?!:)", regex_body):
        return None

    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "._*+?()|\\[]{}^-"
    )
    if any(char not in allowed for char in regex_body):
        return None
    try:
        re.compile(regex_body)
    except re.error:
        return None

    starts_anchored = regex_body.startswith("^")
    ends_anchored = regex_body.endswith("$") and not regex_body.endswith(r"\$")
    core = regex_body[1:] if starts_anchored else regex_body
    if ends_anchored:
        core = core[:-1]

    escaped = False
    in_class = False
    class_content = ""
    rewritten: list[str] = []
    for char in core:
        if escaped:
            rewritten.append("\\" + char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[" and not in_class:
            in_class = True
            class_content = ""
            rewritten.append(char)
            continue
        if char == "]" and in_class:
            if class_content.startswith("^"):
                return None
            in_class = False
            rewritten.append(char)
            continue
        if in_class:
            class_content += char
            rewritten.append(char)
            continue
        if char in "^$":
            return None
        if char == ".":
            # DNS regex wildcards must never match URL paths or query strings.
            rewritten.append(r"[A-Za-z0-9._-]")
        else:
            rewritten.append(char)
    if escaped or in_class:
        return None

    host_chars = r"[A-Za-z0-9._-]*"
    host_pattern = (
        ("" if starts_anchored else host_chars)
        + "".join(rewritten)
        + ("" if ends_anchored else host_chars)
    )
    url_pattern = (
        r"^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?"
        + host_pattern
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + url_pattern + "/"
def compile_dns_rule(line: str) -> str:
    """Translate AdGuard DNS rules to URL rules without changing the match subject."""
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("@@"):
        raise CompilationError("misplaced DNS exception marker")

    # Parse slash-delimited expressions before looking for modifier separators.
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
            if key in {"important", "badfilter", "match-case"} and not separator:
                normalized_regex_modifiers.append(key)
            else:
                raise CompilationError(
                    f"DNS-only or unsupported modifier on regex rule: {token}"
                )

        # If the regex explicitly targets a URL, keep it as a URL regex. Otherwise
        # compile it against the hostname only and enforce authority boundaries.
        has_url_scope = re.search(r"https?\s*:", regex_body, re.IGNORECASE) is not None
        if has_url_scope:
            translated = ("@@" if exception else "") + "/" + regex_body + "/"
        else:
            translated = compile_dns_hostname_regex(regex_body, exception=exception)
            if translated is None:
                raise CompilationError(
                    "DNS hostname regex cannot be safely scoped to URL authority"
                )
        if normalized_regex_modifiers:
            translated += "$" + ",".join(normalized_regex_modifiers)
        return translated

    parts = body.split("$", 1)
    pattern = parts[0]
    modifier_text = parts[1] if len(parts) == 2 else None
    modifiers: list[str] = []
    if modifier_text is not None:
        parsed_modifiers = split_modifiers(modifier_text)
        normalized_modifiers: list[str] = []
        for token in parsed_modifiers:
            key, separator, value = token.partition("=")
            key_lower = key.strip().lower()
            if key_lower in ("important", "badfilter", "match-case"):
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

    case_sensitive = "match-case" in modifiers

    def append_modifiers(rule: str) -> str:
        return rule + ("$" + ",".join(modifiers) if modifiers else "")

    # A bare hostname in DNS syntax matches that host only, not its subdomains.
    if (
        not pattern.startswith(("||", "|", "."))
        and not any(ch in pattern for ch in "*^/")
        and not pattern.startswith("://")
    ):
        try:
            ipaddress.ip_address(pattern)
        except ValueError:
            pass
        else:
            raise CompilationError(
                "bare IP in AdGuard DNS syntax can match CNAME targets; "
                "an AdGuard network filter cannot preserve DNS-resolution semantics"
            )
        hostname = canonical_hostname(pattern, allow_single_label=False)
        if hostname:
            output_hostname = pattern.rstrip(".") if case_sensitive and pattern.isascii() else hostname
            return append_modifiers(exact_hostname_regex_rule(
                output_hostname, exception=exception, match_case=case_sensitive
            ))
        raise CompilationError(f"unsupported DNS domain or address rule: {pattern}")

    # Wildcard-TLD shorthand is DNS-specific: example.TLD denotes all TLDs.
    tld_match = re.fullmatch(r"\|\|(?P<prefix>[A-Za-z0-9.-]+)\.TLD\^", pattern, re.IGNORECASE)
    if tld_match:
        prefix = tld_match.group("prefix")
        normalized_prefix = canonical_hostname(prefix, allow_single_label=False)
        if not normalized_prefix:
            raise CompilationError(f"invalid wildcard-TLD hostname: {pattern}")
        output_prefix = prefix if case_sensitive and prefix.isascii() else normalized_prefix
        return append_modifiers(("@@" if exception else "") + "||" + output_prefix + ".*^")

    # DNS scheme-prefix syntax: ://example. matches hostnames beginning example.
    scheme_prefix = re.fullmatch(r"://([A-Za-z0-9.-]+)\.", pattern)
    if scheme_prefix:
        prefix = scheme_prefix.group(1)
        normalized_prefix = canonical_hostname(prefix, allow_single_label=False)
        if not normalized_prefix:
            raise CompilationError(f"invalid DNS scheme-prefix pattern: {pattern}")
        output_prefix = prefix if case_sensitive and prefix.isascii() else normalized_prefix
        return append_modifiers(("@@" if exception else "") + "||" + output_prefix + ".*^")

    # A leading dot matches subdomains only, not the root host.
    leading_dot = re.fullmatch(r"\.([A-Za-z0-9.-]+)\^?", pattern)
    if leading_dot:
        hostname = canonical_hostname(leading_dot.group(1), allow_single_label=False)
        if not hostname:
            raise CompilationError(f"invalid leading-dot DNS hostname mask: {pattern}")
        output_hostname = leading_dot.group(1) if case_sensitive and leading_dot.group(1).isascii() else hostname
        return append_modifiers(("@@" if exception else "") + "||*." + output_hostname + "^")

    # Prefix masks without an end marker retain their prefix semantics.
    if re.fullmatch(r"\|\|[A-Za-z0-9*.-]+", pattern):
        output = pattern if case_sensitive else pattern.lower()
        return append_modifiers(("@@" if exception else "") + output)

    # A hostname ending with a pipe is an exact-host match in DNS syntax, not
    # an end-of-URL anchor.
    exact_pipe = re.fullmatch(r"(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^?\|", pattern)
    if exact_pipe:
        raw_hostname = exact_pipe.group("host")
        if re.search(r"\.TLD$", raw_hostname, re.IGNORECASE):
            base = raw_hostname[:-4]
            normalized_base = canonical_hostname(base, allow_single_label=False)
            if not normalized_base:
                raise CompilationError(f"invalid exact wildcard-TLD hostname: {pattern}")
            output_base = base if case_sensitive and base.isascii() else normalized_base
            url_pattern = (
                r"^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?"
                + re.escape(output_base)
                + r"\.[A-Za-z0-9-]+(?::[0-9]+)?(?:[\/?#]|$)"
            )
            return append_modifiers(("@@" if exception else "") + "/" + url_pattern + "/")
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
        output_hostname = raw_hostname if case_sensitive and raw_hostname.isascii() else hostname
        return append_modifiers(exact_hostname_regex_rule(
            output_hostname, exception=exception, match_case=case_sensitive
        ))

    # Single pipe before the hostname anchors the host itself, not the full URL.
    exact_match = re.fullmatch(r"\|([^|^*/$]+)\^", pattern)
    if exact_match:
        raw_hostname = exact_match.group(1)
        hostname = canonical_host_or_ipv4(raw_hostname, allow_single_label=False)
        if not hostname:
            raise CompilationError(f"invalid exact DNS hostname: {pattern}")
        output_hostname = raw_hostname if case_sensitive and raw_hostname.isascii() else hostname
        return append_modifiers(exact_hostname_regex_rule(
            output_hostname, exception=exception, match_case=case_sensitive
        ))

    # Standard subtree and wildcard host masks.
    subtree_match = re.fullmatch(r"\|\|([^|^/$]+)\^", pattern)
    if subtree_match:
        raw_mask = subtree_match.group(1)
        if "*" in raw_mask:
            hostname_mask = canonical_wildcard_hostname_mask(raw_mask)
            if not hostname_mask:
                raise CompilationError(f"invalid DNS wildcard hostname mask: {pattern}")
            output_mask = raw_mask if case_sensitive and raw_mask.isascii() else hostname_mask
            return append_modifiers(("@@" if exception else "") + "||" + output_mask + "^")

        if re.fullmatch(r"(?:[0-9]{1,3}\.){1,3}[0-9]{0,3}\.?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}", raw_mask):
            raise CompilationError(
                "IP-like DNS masks can refer to CNAME/IP semantics and cannot be safely translated"
            )

        hostname = canonical_hostname(raw_mask, allow_single_label=False)
        if not hostname and "." not in raw_mask and re.fullmatch(r"[A-Za-z0-9-]{1,63}", raw_mask):
            # In DNS syntax, ||com^ means the .com TLD and its descendants.
            tld = raw_mask if case_sensitive else raw_mask.lower()
            return append_modifiers(("@@" if exception else "") + "||*." + tld + "^")
        if hostname:
            output_hostname = raw_mask if case_sensitive and raw_mask.isascii() else hostname
            return append_modifiers(("@@" if exception else "") + "||" + output_hostname + "^")
        if re.fullmatch(r"[A-Za-z0-9_.-]+", raw_mask):
            # Preserve an upstream label that this validator cannot canonicalize;
            # strict mode and reports still surface any downstream incompatibility.
            output_mask = raw_mask if case_sensitive else raw_mask.lower()
            return append_modifiers(("@@" if exception else "") + "||" + output_mask + "^")
        raise CompilationError(f"invalid DNS hostname mask: {pattern}")

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

    # 普通 Hosts 地址映射是 DNS 指向，不等同于浏览器拦截规则。

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
    """将纯域名条目编译为匹配该域名及其子域的规则。"""
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid domains-only entry: {candidate!r}")
    return "||" + hostname + "^"

def compile_domain_exact_line(line: str) -> str:
    """将裸域名编译为仅匹配该主机名的规则。"""
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid exact-host domains entry: {candidate!r}")
    return exact_hostname_regex_rule(hostname)

def looks_like_native_network_filter_rule(
    line: str,
    source_kind: str = "adblock",
) -> bool:
    """Recognize rules safe to pass through as browser network-filter syntax.

    DNS/CNAME lists use hostname matching, not URL matching. Host patterns in
    those sources must use the DNS adapter; only explicit cosmetic rules and
    explicit URL-scoped regexes are passed through.
    """
    candidate = line.strip()
    if not candidate:
        return False

    if source_kind in {"dns", "cname"}:
        if any(operator in candidate for operator in VALID_HASH_RULE_PREFIXES):
            return True
        if candidate.startswith("/"):
            closing = find_regex_rule_end(candidate)
            if closing is None:
                return False
            regex_body = candidate[1:closing]
            return re.search(r"https?\s*:", regex_body, re.IGNORECASE) is not None
        if candidate.startswith(("-", "*")) and re.fullmatch(r"\S*[\^|*]\S*", candidate):
            return True
        return False

    if candidate.startswith("/"):
        closing = find_regex_rule_end(candidate)
        if closing is None:
            return False
        return True

    if any(operator in candidate for operator in VALID_HASH_RULE_PREFIXES):
        return True
    if candidate.startswith(("||", "@@||", "|", "@@|")):
        return True
    if "://" in candidate:
        return True
    if re.fullmatch(r"\S*[\^|*]\S*", candidate):
        return True
    if candidate.startswith("."):
        return False

    if re.fullmatch(r"\S+", candidate):
        try:
            ipaddress.ip_address(candidate)
            return False
        except ValueError:
            return canonical_hostname(candidate, allow_single_label=False) is None
    return False
def compile_line(kind: str, raw_line: str, target: str = "generic") -> tuple[list[str], str]:
    line = raw_line.strip()
    if FILTER_DIRECTIVE_RE.match(line):
        raise CompilationError(
            "filter preprocessor directive must be evaluated or expanded before compilation; "
            "it cannot be silently discarded"
        )
    if is_comment_or_header(line):
        return [], "comment"

    if kind == "adblock":
        reason = detect_nonportable_native_rule(line, target)
        if reason:
            raise CompilationError(reason)
        # 原生规则保留目标语法；规范化简单域名锚点和裸 IPv4。

        return [normalize_native_domain_rule(line)], "native"

    if kind == "hosts":
        return compile_hosts_line(line)

    if kind == "domains":
        return [compile_domain_line(line)], "domains"

    if kind == "domains-exact":
        return [compile_domain_exact_line(line)], "domains-exact"

    if kind == "cname":
        # CNAME 来源的常规规则本身通常就是标准 AdGuard 网络过滤语法。
        # 原样纳入可增加直接匹配覆盖，但不能因此声称已实现 DNS CNAME 链检查。
        reason = detect_nonportable_native_rule(line, target)
        if reason:
            raise CompilationError(reason)
        if looks_like_native_network_filter_rule(line, source_kind=kind):
            return [line], "native-cname"
        # 非原生条目只在能够保守转换时才纳入；无法证明等价时交给严格审计阻止发布。
        return [compile_dns_rule(line)], "cname-converted"

    if kind == "exclusions":
        raise CompilationError(
            "this is an exclusion selector file, not an active blocklist; it must be "
            "applied to its designated source group rather than emitted as rules"
        )

    if kind == "dns":
        # Preserve a complete rule first: '#' can be part of a regex or a cosmetic
        # operator, so only strip inline comments from non-native DNS entries.
        if looks_like_native_network_filter_rule(line, source_kind=kind):
            reason = detect_nonportable_native_rule(line, target)
            if reason:
                raise CompilationError(reason)
            return [line], "native-dns"

        # Plain DNS entries may contain trailing source comments.
        line = line.split("#", 1)[0].strip()
        if not line:
            return [], "comment"
        # DNS 列表可能混有 Adblock 规则或 Hosts 映射，分别处理。
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
        # 已经是网络过滤规则语法的 DNS 来源条目保持原文；非原生 DNS 表达式
        # 才尝试转换为网络过滤语法。DNS 专用修饰符不在此处被静默丢弃。
        if looks_like_native_network_filter_rule(line, source_kind=kind):
            reason = detect_nonportable_native_rule(line, target)
            if reason:
                raise CompilationError(reason)
            return [line], "native-dns"
        return [compile_dns_rule(line)], "dns-converted"

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
    """计算 AdGuard 的 !#if 条件表达式。"""
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
    """仅允许同源 include，以及指定的 AdGuard CNAME 跨域路径。"""
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
    """展开 include 指令，并按目标平台计算条件。"""
    if len(stack) >= MAX_INCLUDE_DEPTH:
        raise CompilationError(f"preprocessor include depth exceeds {MAX_INCLUDE_DEPTH}")
    if source.url in stack:
        cycle = " -> ".join((*stack, source.url))
        raise CompilationError(f"recursive !#include cycle: {cycle}")

    flags = target_condition_flags(target)
    # 每层条件记录父级状态、条件结果和 else 状态。
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
            # affinity 只影响 Safari 内容拦截器；其他目标移除该元数据。

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
                    # 同源 include 可作为语法片段；跨域 include 必须显式识别格式，不能猜测。

                    if not same_origin(source.url, include_url):
                        raise
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
    """按 AdGuard HostlistCompiler 的规则匹配排除项：文本、通配符和正则。"""
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
    """读取 AdGuard SDNSFilter 的来源与排除规则关联；只对配置指定的来源生效。"""
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

def compile_sources_with_metadata(
    fetched: list[tuple[Source, str]],
    target: str,
    metadata_loader=None,
    *,
    require_metadata: bool = False,
) -> tuple[CompileState, dict[str, int], str | None]:
    """Compile with source-scoped upstream exclusions; fail closed if required metadata is absent."""
    if require_metadata and not any(source.kind == "exclusions" for source, _ in fetched):
        raise CompilationError(
            "required source-exclusion metadata source was not fetched; refusing to compile without it"
        )

    loader = metadata_loader or load_adguard_dns_exclusion_map
    source_exclusions, metadata_pattern_counts, metadata_config_url = loader(fetched)
    state = compile_fetched_sources(
        fetched,
        target,
        source_exclusions=source_exclusions,
        metadata_pattern_counts=metadata_pattern_counts,
        metadata_config_url=metadata_config_url,
    )
    return state, metadata_pattern_counts, metadata_config_url


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

        # 排除选择器是 DNS 列表编译的元数据，不是浏览器拦截规则。

        if source.kind == "exclusions":
            summary.status = "consumed-as-metadata"
            summary.target_skip_reason = (
                "This file contains upstream exclusion metadata, not active filter rules."
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

    # include 可能引入清单之外的来源，需一并纳入审计。
    for source_url, (source, text) in cache.items():
        if source_url not in state.summaries:
            state.summaries[source_url] = SourceSummary(
                url=source.url,
                kind=source.kind,
                status="included",
                input_lines=len(text.splitlines()),
            )

    # 排除规则只应用于 AdGuard 配置明确关联的来源。

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

        # include 片段也按自身格式分类，并执行同样的逐条目标兼容性检查。
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
        # 已知不兼容规则逐条记录并排除；未知转换错误仍由严格模式阻止发布。

        target_exclusion_reason = (
            detect_nonportable_native_rule(line, target, source_url=source.url)
            if source.kind in {"adblock", "dns", "cname"} and line and not is_comment_or_header(line)
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
            translated, category = compile_line(source.kind, line, target=target)
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
        "target": f"AdGuard network filter syntax ({target})",
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
            "Native AdGuard-compatible network-filter rules are preserved as Adblock-compatible syntax; "
            "hosts entries become exact-host HTTP(S) URL regex rules; domains-only entries use "
            "domain-and-subdomain scope unless explicitly configured as domains-exact; "
            "Native network-filter syntax from DNS/CNAME sources is retained where compatible; non-native DNS entries are converted only when safe, DNS-only modifiers are excluded individually, and copied CNAME patterns do not implement DNS CNAME-chain inspection. "
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

    # Generate test-only addresses dynamically; do not embed concrete dotted IPv4 literals.
    test_ipv4 = ".".join(str(octet) for octet in range(1, 5))
    test_ipv4_regex = re.escape(test_ipv4)
    test_ipv4_leading_zero = ".".join(f"{octet:03d}" for octet in range(1, 5))
    invalid_test_ipv4 = ".".join([str(255 + 1), *(str(octet) for octet in range(1, 4))])
    zero_ipv4 = ".".join(str(0) for _ in range(4))
    ip_host_rule = f"||{test_ipv4}^"

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

    scoped_excluded_source = Source("https://example.invalid/excluded-source.txt", "adblock")
    scoped_unrelated_source = Source("https://example.invalid/unrelated-source.txt", "adblock")
    scoped_metadata_source = Source("https://example.invalid/exclusions.txt", "exclusions")
    scoped_rule = "||excluded.example^"
    scoped_fetched = [
        (scoped_metadata_source, scoped_rule + "\n"),
        (scoped_excluded_source, scoped_rule + "\n"),
        (scoped_unrelated_source, scoped_rule + "\n"),
    ]

    def deterministic_exclusion_loader(_fetched):
        return (
            {scoped_excluded_source.url: parse_hostlist_exclusion_patterns(scoped_rule + "\n")},
            {"https://example.invalid/exclusions.txt": 1},
            "https://example.invalid/configuration.json",
        )

    scoped_state, _, _ = compile_sources_with_metadata(
        scoped_fetched,
        "adguard-windows",
        metadata_loader=deterministic_exclusion_loader,
        require_metadata=True,
    )
    check("source exclusions are applied only to their associated source",
          (
              scoped_state.summaries[scoped_excluded_source.url].excluded_by_metadata,
              scoped_state.summaries[scoped_unrelated_source.url].emitted_rules,
              scoped_rule in scoped_state.records,
          ),
          (1, 1, True))

    try:
        compile_sources_with_metadata(
            [],
            "adguard-windows",
            metadata_loader=lambda _fetched: ({}, {}, None),
            require_metadata=True,
        )
    except CompilationError:
        tests.append(("missing required exclusion metadata source fails closed", True, True))
    else:
        raise AssertionError("required exclusion metadata must not be bypassed")
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
    check("AdGuard Chromium MV3 is not a uBlock legacy environment",
          evaluate_filter_condition("!env_legacy", target_condition_flags("chromium-mv3")), True)
    check("Safari does not inherit the Chromium stylesheet capability",
          evaluate_filter_condition("cap_user_stylesheet", target_condition_flags("safari")), False)
    check("default compiler target is AdGuard for Windows", DEFAULT_TARGET, "adguard-windows")
    windows_flags = target_condition_flags("adguard-windows")
    check("Windows target selects Windows-specific rules",
          evaluate_filter_condition("adguard && adguard_app_windows && !adguard_ext_chromium_mv3", windows_flags), True)
    check("Windows target enables HTML filtering capability",
          evaluate_filter_condition("cap_html_filtering", windows_flags), True)
    check("Windows target enables IP-address filtering capability",
          evaluate_filter_condition("cap_ipaddress", windows_flags), True)
    check("Windows target does not inherit Chromium extension conditions",
          evaluate_filter_condition("adguard_ext_chromium_mv3 || env_chromium || env_mv3", windows_flags), False)
    windows_source = Source("https://example.com/windows-filter.txt", "adblock")
    windows_text = "!#if adguard_app_windows\n||windows-only.example^\n!#else\n||other-platform.example^\n!#endif\n"
    windows_lines = expand_filter_preprocessor(
        windows_source,
        windows_text,
        "adguard-windows",
        {windows_source.url: (windows_source, windows_text)},
    )
    check("Windows preprocessor selects Windows-specific rules",
          [line.text.strip() for line in windows_lines], ["||windows-only.example^"])
    check("AdGuard CNAME include from an official filter source is allowlisted",
          allow_preprocessor_include(
              "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
              "https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt",
          ), True)
    check("disguised CNAME ad-domain lists keep ordinary browser-filter semantics",
          classify_source("https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt"),
          "adblock")
    include_parent_url = (
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/"
        "master/BaseFilter/sections/adservers.txt"
    )
    include_fragment_url = "https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt"
    include_parent = Source(include_parent_url, "adblock")
    include_fragment = Source(include_fragment_url, classify_source(include_fragment_url))
    include_text = f"!#include {include_fragment_url}\n"
    include_cache = {
        include_parent_url: (include_parent, include_text),
        include_fragment_url: (include_fragment, "||tracker.example^\n"),
    }
    expanded_include = expand_filter_preprocessor(
        include_parent, include_text, "chromium-mv3", include_cache
    )
    check("official disguised CNAME rules stay in browser filtering after include expansion",
          [(line.source.kind, line.text.strip()) for line in expanded_include],
          [("adblock", "||tracker.example^")])
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
    unknown_cname_include = "https://adguardteam.github.io/cname-trackers/data/unknown/example.txt"
    try:
        classify_source(unknown_cname_include)
    except CompilationError:
        tests.append(("unknown official CNAME source format fails closed", True, True))
    else:
        raise AssertionError("unknown CNAME source format must not default to Adblock syntax")
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
    check("CNAME tracker list is classified by its source semantics",
          classify_source("https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt"),
          "cname")
    check("CNAME host rules are parsed rather than blindly passed through",
          compile_line("cname", "||tracker.Example.com^")[0],
          ["||tracker.example.com^"])
    check("DNS hostname rules normalize without changing subtree scope",
          compile_line("dns", "||Ads.Example.com^")[0],
          ["||ads.example.com^"])
    check("DNS match-case modifier preserves source host casing",
          compile_line("dns", "||Ads.Example.com^$match-case")[0],
          ["||Ads.Example.com^$match-case"])
    check("DNS match-case exact-host rule preserves source host casing",
          compile_line("dns", "Ads.Example.com$match-case")[0],
          [exact_hostname_regex_rule("Ads.Example.com", match_case=True) + "$match-case"])
    check("DNS plain host entries are converted to exact-host URL rules",
          compile_line("dns", "tracker.example.com")[0],
          [exact_hostname_regex_rule("tracker.example.com")])

    dns_source = Source("https://example.invalid/dns-list.txt", "dns")
    dns_state = compile_fetched_sources(
        [(dns_source, "||ads.example^\n||types.example^$dnstype=A\n")],
        "chromium-mv3",
    )
    check("native DNS-source rule is retained in the network filter",
          "||ads.example^" in dns_state.records, True)
    check("DNS-only modifier is excluded individually",
          len(dns_state.target_exclusions), 1)
    check("DNS source is not skipped wholesale",
          dns_state.summaries[dns_source.url].status, "ok")
    check("unsupported syntax was not silently discarded",
          len(dns_state.issues), 0)

    native_source = Source("https://example.invalid/native-rules.txt", "adblock")
    native_state = compile_fetched_sources(
        [(native_source, f"{ip_host_rule}$network\nexample.com##.ad:remove-class(foo)\n")],
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
    check("CNAME source is not skipped wholesale",
          "||tracker.example.com^" in cname_state.records, True)
    check("CNAME source syntax does not cause conversion errors",
          len(cname_state.issues), 0)

    mixed_sources = [
        (Source("https://example.invalid/hosts.txt", "hosts"), f"{zero_ipv4} Ads.Example.com\n"),
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
    check("localhost host entry is not emitted as an ad block", compile_line("hosts", f"{zero_ipv4} localhost")[0], [])
    check("mixed hosts mapping skips localhost but retains the block alias",
          compile_line("hosts", f"{zero_ipv4} localhost ads.example.com")[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("host record preserves exact-host scope", compile_line("hosts", f"{zero_ipv4} Ads.Example.com")[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("domain-only preserves subtree scope", compile_line("domains", "Ads.Example.com")[0],
          ["||ads.example.com^"])
    check("DNS subtree rule canonicalizes case without changing subtree scope",
          compile_line("dns", "||Ads.Example.com^")[0],
          ["||ads.example.com^"])
    check("DNS wildcard rule keeps wildcard scope while canonicalizing case",
          compile_line("dns", "||MobileAnalytics.*.AmazonAWS.com^")[0],
          ["||mobileanalytics.*.amazonaws.com^"])
    check("DNS exception retains exception and subtree semantics",
          compile_line("dns", "@@||Ads.Example.com^")[0],
          ["@@||ads.example.com^"])
    check("DNS wildcard exact-host exception is converted to URL authority scope",
          compile_line("dns", "@@||cdn.us*.exponea.com^|")[0],
          [r"@@/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?cdn\.us[A-Za-z0-9._-]*\.exponea\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("unanchored separator and wildcard filters remain unchanged",
          compile_line("dns", "-adx-*.rayjump.com^")[0],
          ["-adx-*.rayjump.com^"])
    check("DNS leading-dot mask without caret is converted safely",
          compile_line("dns", ".3.n.2.1.l50.js")[0],
          ["||*.3.n.2.1.l50.js^"])
    check("DNS inline comment is ignored", compile_line("dns", "example.com # source note")[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("Adblock-compatible DNS exception end-anchor rule is preserved verbatim",
          compile_line("dns", "@@||example.com^|")[0],
          ["@@||example.com^|"])
    check("DNS partial domain anchor keeps prefix semantics", compile_line("dns", "||advertising.civitai.")[0],
          ["||advertising.civitai."])
    check("DNS leading-dot rule blocks subdomains but not root domain",
          compile_line("dns", ".example.com^")[0],
          ["||*.example.com^"])
    check("DNS wildcard TLD is not a literal hostname label",
          compile_line("dns", "||example.TLD^")[0],
          ["||example.*^"])
    check("DNS scheme-prefix syntax keeps prefix scope",
          compile_line("dns", "://example.")[0],
          ["||example.*^"])
    check("DNS root TLD syntax maps to the TLD subtree",
          compile_line("dns", "||com^")[0],
          ["||*.com^"])
    check("anchored DNS hostname regex compiles to URL authority regex",
          compile_line("dns", "/^(?:\\w+\\.)*minepi\\.com$/")[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?(?:(?:\w+\.)*minepi\.com)(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("anchored DNS hostname regex is scoped to URL authority",
          compile_line("dns", f"/^{test_ipv4_regex}$")[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?" + test_ipv4_regex + r"(?::[0-9]+)?(?:[\/?#]|$)/"])

    url_scoped_test_regex = r"/(https?:\/\/)" + test_ipv4_regex + r".{100,}/"
    check("URL-scoped regex remains a URL-scoped regex", compile_line("dns", url_scoped_test_regex)[0],
          [url_scoped_test_regex])
    unanchored_dns_regex = "/" + test_ipv4_regex + "/"
    check("unanchored DNS regex is scoped to hostname characters",
          compile_line("dns", unanchored_dns_regex)[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?[A-Za-z0-9._-]*" + test_ipv4_regex + r"[A-Za-z0-9._-]*(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("hash character inside native URL regex is preserved",
          compile_line("dns", r"/https?:\/\/example\.com\/path#frag/")[0],
          [r"/https?:\/\/example\.com\/path#frag/"])
    check("DNS hostname regex with nested groups stays inside URL authority",
          compile_line("dns", r"/^(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$/")[0],
          [r"/^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]+@)?(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
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
        compile_line("hosts", f"{test_ipv4} ads.example.com")
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
    check("uBO scriptlet rules are not assumed portable to AdGuard",
          detect_nonportable_native_rule(
              "example.com##+js(no-such-scriptlet)",
              "adguard-windows",
              source_url="https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
          ) is not None, True)
    check("AdGuard-documented matches-attr syntax is not rejected",
          detect_nonportable_native_rule(
              'example.com#?#div:matches-attr(class="ad")',
              "adguard-windows",
              source_url="https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
          ), None)
    check("native IPv4 host rules are preserved", compile_line("adblock", ip_host_rule)[0],
          [ip_host_rule])
    check("bare IPv4 text preserves URL-substring semantics",
          compile_line("adblock", test_ipv4)[0],
          [test_ipv4])
    check("bare IPv4 exception preserves URL-substring scope",
          compile_line("adblock", f"@@{test_ipv4}")[0],
          [f"@@{test_ipv4}"])
    check("bare IPv4 modifier remains attached without changing scope",
          compile_line("adblock", f"{test_ipv4}$important")[0],
          [f"{test_ipv4}$important"])
    check("leading-zero IPv4-looking pattern preserves source spelling",
          compile_line("adblock", test_ipv4_leading_zero)[0],
          [test_ipv4_leading_zero])
    multi_zero_octets = tuple(range(4, 8))
    multi_zero_ipv4 = ".".join(
        f"{octet:03d}" if index == 0 else str(octet)
        for index, octet in enumerate(multi_zero_octets)
    )
    check("multiple leading zeroes remain part of the URL pattern",
          compile_line("adblock", multi_zero_ipv4)[0],
          [multi_zero_ipv4])
    check("invalid dotted-quad-shaped text remains a URL pattern",
          compile_line("adblock", invalid_test_ipv4)[0],
          [invalid_test_ipv4])
    try:
        compile_line("adblock", f"{ip_host_rule}$network")
    except CompilationError:
        tests.append(("network modifier rejected for browser target", True, True))
    else:
        raise AssertionError("the app-only $network modifier must not be published to a browser filter")
    check("network-filter syntax for an IP host rule is passed through verbatim",
          compile_line("dns", ip_host_rule)[0],
          [ip_host_rule])
    try:
        compile_line("dns", test_ipv4)
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
    check("Lite manifest URLs are unique", len({source.url for source in configured_sources}), len(urls))
    check("Lite manifest source families are explicitly classified",
          sorted({source.kind for source in configured_sources}),
          ["adblock", "cname", "dns", "exclusions"])
    print(f"Passed {len(tests)} semantic regression checks.")

def main() -> int:
    parser = argparse.ArgumentParser(description="Compile upstream blocklists into an AdGuard network filter for the selected target, with explicit semantic-loss reporting.")
    parser.add_argument("--target", choices=sorted(TARGET_PROFILES), default=DEFAULT_TARGET, help=f"AdGuard target profile (default: {DEFAULT_TARGET})")
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

    # 固定处理顺序，避免下载完成顺序影响输出。
    fetched.sort(key=lambda item: sources.index(item[0]))

    # Apply source-specific upstream exclusions. If required metadata fails,
    # only build a diagnostic report; never publish without those semantics.
    metadata_failures: list[dict[str, str]] = []
    try:
        state, metadata_pattern_counts, metadata_config_url = compile_sources_with_metadata(
            fetched,
            args.target,
            require_metadata=any(source.kind == "exclusions" for source in sources),
        )
    except Exception as error:
        message = f"{type(error).__name__}: {error}"
        metadata_failure = {
            "url": ADGUARD_SDNS_CONFIGURATION_URL,
            "format": "source-metadata",
            "error": message,
        }
        metadata_failures.append(metadata_failure)
        source_failures.append(metadata_failure)
        print(f"[METADATA FAILED] required source-exclusion metadata: {message}", file=sys.stderr)
        # Diagnostic compilation only; the fatal gate below prevents publishing.
        state = compile_fetched_sources(fetched, args.target)
        metadata_pattern_counts = {}
        metadata_config_url = ADGUARD_SDNS_CONFIGURATION_URL
    state.issues.sort(key=lambda issue: (str(issue["source"]), int(issue.get("line") or 0)))
    report = build_report(state, source_failures=source_failures, output_path=args.output, target=args.target)
    report_path = Path(args.report)
    output_path = Path(args.output)

    # 严格编译失败时仍保留审计报告。
    atomic_write_text(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    if metadata_failures:
        print(
            "ABORTED: required source-exclusion metadata is unavailable. "
            f"Existing output was not changed. Review {report_path}.",
            file=sys.stderr,
        )
        return 2

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

    tz_utc8 = dt.timezone(dt.timedelta(hours=8))
    timestamp = dt.datetime.now(tz_utc8).strftime("%Y-%m-%d %H:%M:%S")
    num_rules = len(rules)
    header = f"""! Title: Adblock-Rule-Collection-Lite
! Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
! Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
! LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
! LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
! Generated: {timestamp} (UTC+8)
! Total rules: {num_rules}
"""
    document = header.rstrip("\n") + "\n\n" + "\n".join(rules) + "\n"
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
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_259_Dandelion_Sprout's_Anti-Malware_List/filter.txt"
]

if __name__ == "__main__":
    raise SystemExit(main())
