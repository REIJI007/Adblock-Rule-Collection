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

OUTPUT_DEFAULT = "ADBLOCK_RULE_COLLECTION.txt"
REPORT_DEFAULT = "ADBLOCK_RULE_COLLECTION.semantic-report.json"
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
    (re.compile(r":matches-path\s*\(", re.IGNORECASE),
     "uBlock procedural operator :matches-path() has no verified AdGuard equivalent"),
    (re.compile(r":remove-(?:attr|class)\s*\(", re.IGNORECASE),
     "the current AdGuard filter compiler does not support :remove-attr()/:remove-class()"),
    (re.compile(r":(?:others|watch-attr)\s*\(", re.IGNORECASE),
     "uBlock procedural operator is documented as unsupported by AdGuard"),
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
    badfilter_directives_consumed: int = 0
    badfilter_rules_disabled: int = 0
    unmatched_badfilter_directives: int = 0

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

def exact_hostname_regex_rule(hostname: str, *, exception: bool = False) -> str:
    """生成仅匹配指定 HTTP(S)/WebSocket 主机名的 AdGuard 正则规则，不扩展到子域。"""
    domain = canonical_host_or_ipv4(hostname)
    if not domain:
        raise CompilationError(f"invalid exact hostname: {hostname!r}")
    escaped = re.escape(domain)
    # 同时覆盖 HTTP(S) 与 WebSocket，并保留 URL authority 与端口边界。
    body = (
        r"^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?"
        + escaped
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + body + "/"

def normalize_native_domain_rule(line: str) -> str:
    """只规范化明确的主机锚定规则；绝不重写未锚定 URL 子串规则。"""
    match = re.fullmatch(
        r"(?P<exception>@@)?(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^(?P<tail>\$.*)?",
        line,
    )
    if not match:
        return line

    # Do not normalize IP literals either: their URL/host parsing semantics can vary
    # across engines, and normalizing dotted quads is not a proven semantics-preserving rewrite.
    hostname = canonical_hostname(match.group("host"), allow_single_label=False)
    if not hostname:
        return line

    return (
        (match.group("exception") or "")
        + match.group("anchor")
        + hostname
        + "^"
        + (match.group("tail") or "")
    )

def detect_nonportable_native_rule(line: str, target: str = "generic") -> str | None:
    if DNS_ONLY_MODIFIER_RE.search(line):
        return "DNS-only modifier cannot be represented safely in an AdGuard network filter"
    if target != "adguard-windows" and NETWORK_ONLY_MODIFIER_RE.search(line):
        return "AdGuard application-only $network modifier is not supported by this target"

    # These are cosmetic/Extended CSS operators. Search only after a cosmetic
    # delimiter to avoid rejecting a URL or regex that merely contains the text.
    cosmetic_markers = [
        (line.find(marker), marker)
        for marker in VALID_HASH_RULE_PREFIXES
        if line.find(marker) >= 0
    ]
    if cosmetic_markers:
        marker_pos, marker = min(cosmetic_markers, key=lambda item: item[0])
        selector = line[marker_pos + len(marker):]
        for pattern, explanation in NON_PORTABLE_NATIVE_PATTERNS:
            if pattern.search(selector):
                return explanation
    return None

def normalize_compatible_cosmetic_rule(line: str, target: str) -> str:
    """Translate one known equivalent uBO pseudo-class name to AdGuard syntax."""
    if target not in TARGET_PROFILES:
        return line
    markers = [
        (line.find(marker), marker)
        for marker in VALID_HASH_RULE_PREFIXES
        if line.find(marker) >= 0
    ]
    if not markers:
        return line
    pos, marker = min(markers, key=lambda item: item[0])
    selector_start = pos + len(marker)
    selector = line[selector_start:]
    # uBO :matches-prop and AdGuard :matches-property share property-chain semantics.
    # Preserve the argument byte-for-byte to avoid changing its regular expressions.
    selector = re.sub(r":matches-prop(?=\s*\()", ":matches-property", selector, flags=re.IGNORECASE)
    return line[:selector_start] + selector

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
    """把可证明安全的 DNS hostname regex 约束到 URL authority 的主机名部分。"""
    if not regex_body:
        return None

    anchored_start = regex_body.startswith("^")
    anchored_end = regex_body.endswith("$")
    start = 1 if anchored_start else 0
    end = len(regex_body) - (1 if anchored_end else 0)
    inner = regex_body[start:end]
    if not inner or "/" in inner:
        return None
    if any(token in inner for token in ("(?=", "(?!", "(?<=", "(?<!", "(?P", "\\k<")):
        return None
    if re.search(r"\(\?(?!:)", inner):
        return None

    # 非捕获分组是允许的；其余字符集必须位于保守的 hostname-regex 子集内。
    check_inner = inner.replace("(?:", "")
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ".,_*+?()|\\[]{}^-"
    )
    if any(char not in allowed for char in check_inner):
        return None
    try:
        re.compile(inner)
    except re.error:
        return None

    # 裸点号改写为 hostname 字符类，避免 .* 越过 hostname 边界匹配路径/查询。
    # 否定字符类、URL 分隔符和无法证明安全的转义一律拒绝转换。
    safe: list[str] = []
    escaped = False
    in_class = False
    class_first = False
    for char in inner:
        if escaped:
            if char in {"w", "d"}:
                safe.append("\\" + char)
            elif char in r".*+?()[]{}|\^-":
                safe.append("\\" + char)
            else:
                return None
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_class:
            if class_first and char == "^":
                return None
            if char in "/:?#@" or char.isspace():
                return None
            safe.append(char)
            if char == "]":
                in_class = False
            class_first = False
            continue
        if char == "[":
            in_class = True
            class_first = True
            safe.append(char)
        elif char == ".":
            safe.append(r"[A-Za-z0-9._-]")
        elif char in "^$":
            # 只有最外层首尾锚点才能安全映射到 hostname 边界。
            return None
        else:
            safe.append(char)

    if escaped or in_class:
        return None

    host_char = r"[A-Za-z0-9._-]"
    host_prefix = "" if anchored_start else host_char + "*"
    host_suffix = "" if anchored_end else host_char + "*"
    url_pattern = (
        r"^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?"
        + host_prefix
        + "(?:"
        + "".join(safe)
        + ")"
        + host_suffix
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + url_pattern + "/"

def compile_dns_hostname_mask_rule(pattern: str, *, exception: bool = False) -> str:
    """把 DNS hostname mask 编译为限定在 URL hostname 上的规则。"""
    source = pattern
    subdomain_anchor = source.startswith("||")
    start_anchor = False
    if subdomain_anchor:
        source = source[2:]
    elif source.startswith("|"):
        start_anchor = True
        source = source[1:]

    end_anchor = False
    if source.endswith("|"):
        end_anchor = True
        source = source[:-1]
    if source.endswith("^"):
        end_anchor = True
        source = source[:-1]

    # This adapter handles hostname masks only, never URL/path patterns.
    if not source or "^" in source or "|" in source:
        raise CompilationError(f"unsupported DNS hostname mask: {pattern}")
    if not re.fullmatch(r"[A-Za-z0-9*._-]+", source):
        raise CompilationError(f"unsupported DNS hostname mask: {pattern}")

    source = source.lower()
    host_pattern = "".join(
        r"[A-Za-z0-9._-]*" if char == "*" else re.escape(char)
        for char in source
    )
    if subdomain_anchor:
        # DNS || anchors on a domain boundary and includes subdomains.
        host_prefix = r"(?:[A-Za-z0-9_-]+\.)*"
    elif start_anchor:
        host_prefix = ""
    else:
        # Unanchored DNS masks may occur anywhere in the queried hostname.
        host_prefix = r"[A-Za-z0-9._-]*"

    host_suffix = "" if end_anchor else r"[A-Za-z0-9._-]*"
    url_pattern = (
        r"^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?"
        + host_prefix
        + "(?:"
        + host_pattern
        + ")"
        + host_suffix
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + url_pattern + "/"

def compile_dns_rule(line: str) -> str:
    """只转换能明确证明浏览器匹配语义的 DNS 规则。"""
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("@@"):
        raise CompilationError("misplaced DNS exception marker")

    # 先识别正则的结束位置，再解析 `$` 修饰符，避免混淆正则锚点。

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

        # 已包含 HTTP(S) 作用域的正则保持原样，不再按主机名正则改写。

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
                    "DNS hostname regex cannot be represented safely as a URL regex"
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

    # DNS hostname wildcard/anchor semantics differ from URL-pattern semantics.
    # Convert DNS host masks that could otherwise match URL paths or query strings.
    if "/" not in pattern and (
        "*" in pattern
        or pattern.endswith("|")
        or (pattern.startswith("|") and not pattern.startswith("||"))
        or (
            pattern.endswith("^")
            and not pattern.startswith(".")
            and not (pattern.startswith("||") and "*" not in pattern)
        )
    ):
        translated = compile_dns_hostname_mask_rule(pattern, exception=exception)
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # 纯域名列表中的裸域名只匹配该主机，不应扩展到子域。

    if (
        not pattern.startswith(("||", "|", "."))
        and not any(ch in pattern for ch in "*^/")
    ):
        try:
            ipaddress.ip_address(pattern)
        except ValueError:
            pass
        else:
            raise CompilationError(
                "bare IP in AdGuard DNS syntax matches CNAME targets resolving to that IP; "
                "an AdGuard network filter cannot preserve DNS-resolution semantics"
            )
        hostname = canonical_hostname(pattern, allow_single_label=False)
        if hostname:
            translated = exact_hostname_regex_rule(hostname, exception=exception)
            return translated + ("$" + ",".join(modifiers) if modifiers else "")
        raise CompilationError(f"unsupported DNS domain or address rule: {pattern}")

    # 主机名结束锚点与整个 URL 的结束锚点含义不同。
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

    # `.example.com` 只匹配子域，不匹配根域。

    leading_dot = re.fullmatch(r"\.([A-Za-z0-9.-]+)\^?", pattern)
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

    # 保留主机前缀规则的原有语义，包括末标签前缀匹配。

    if re.fullmatch(r"\|\|[A-Za-z0-9*.-]+", pattern):
        translated = ("@@" if exception else "") + pattern.lower()
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # 单竖线加 `^` 表示精确主机锚点，不能改成 URL 起始锚点。

    exact_match = re.fullmatch(r"\|([^|^*/$]+)\^", pattern)
    if exact_match:
        hostname = canonical_host_or_ipv4(
            exact_match.group(1), allow_single_label=False
        )
        if not hostname:
            raise CompilationError(f"invalid exact DNS hostname: {pattern}")
        translated = exact_hostname_regex_rule(hostname, exception=exception)
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # 处理标准子域规则和简单主机名通配规则。
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
                # 对严格 IDNA 校验不接受的上游标签，保留原样且不扩大匹配范围。

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
    line: str, *, source_kind: str | None = None
) -> bool:
    """识别原生网络规则；DNS hostname masks 不可直接按 URL pattern 语义透传。"""
    candidate = line.strip()
    if not candidate:
        return False

    regex_candidate = candidate[2:] if candidate.startswith("@@") else candidate
    if regex_candidate.startswith("/"):
        closing = find_regex_rule_end(regex_candidate)
        if closing is None:
            return False
        regex_body = regex_candidate[1:closing]
        explicit_url_scope = re.search(
            r"(?:https?|wss?)\s*:", regex_body, re.IGNORECASE
        ) is not None
        if source_kind == "dns":
            # DNS regex defaults to hostname matching; only explicit URL regexes pass through.
            return explicit_url_scope
        return True

    if source_kind == "dns":
        no_exception = candidate[2:] if candidate.startswith("@@") else candidate
        dns_pattern = no_exception.split("$", 1)[0]
        plausible_hostname_mask = re.fullmatch(r"[A-Za-z0-9*._|^\-]+", dns_pattern) is not None
        if plausible_hostname_mask and "/" not in dns_pattern and "://" not in dns_pattern:
            simple_subtree = re.fullmatch(r"\|\|[A-Za-z0-9.-]+\^", dns_pattern) is not None
            if (
                (dns_pattern.startswith("|") and not dns_pattern.startswith("||"))
                or dns_pattern.endswith("|")
                or "*" in dns_pattern
                or ("^" in dns_pattern and not simple_subtree)
            ):
                return False

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
        normalized = normalize_native_domain_rule(line)
        normalized = normalize_compatible_cosmetic_rule(normalized, target)
        return [normalized], "native"

    if kind == "hosts":
        return compile_hosts_line(line)

    if kind == "domains":
        return [compile_domain_line(line)], "domains"

    if kind == "domains-exact":
        return [compile_domain_exact_line(line)], "domains-exact"

    if kind == "cname":
        raise CompilationError(
            "DNS CNAME-aware source semantics cannot be represented by a flat network-filter rule; "
            "skip this source for network-filter targets rather than publish a semantically weaker rule"
        )

    if kind == "exclusions":
        raise CompilationError(
            "this is an exclusion selector file, not an active filter list; it must be "
            "applied to its designated source group rather than emitted as rules"
        )

    if kind == "dns":
        # 必须先按来源语法判断；不能先用 URL 规则的字符形态决定直接透传。
        if looks_like_native_network_filter_rule(line, source_kind=kind):
            reason = detect_nonportable_native_rule(line, target)
            if reason:
                raise CompilationError(reason)
            return [line], "native-dns"

        # 行内注释从空白 + '#' 开始；保留正则/URL 中作为内容的 '#'.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line:
            return [], "comment"

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
    root_source_url: str | None = None

def parse_badfilter_rule(line: str) -> tuple[tuple[str, tuple[str, ...]], bool] | None:
    """Return a normalized rule key and whether the line is a $badfilter directive."""
    candidate = line.strip()
    if not candidate or is_comment_or_header(candidate):
        return None
    # Cosmetic rules have their own rule semantics; do not parse them as URL filters.
    if any(marker in candidate for marker in VALID_HASH_RULE_PREFIXES):
        return None

    exception = ""
    body = candidate
    if body.startswith("@@"):
        exception = "@@"
        body = body[2:]

    if body.startswith("/"):
        closing = find_regex_rule_end(body)
        if closing is None:
            return None
        pattern = body[:closing + 1]
        tail = body[closing + 1:]
        if tail and not tail.startswith("$"):
            return None
        modifier_text = tail[1:] if tail else ""
    else:
        escaped = False
        modifier_pos: int | None = None
        for index, char in enumerate(body):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == "$":
                modifier_pos = index
                break
        if modifier_pos is None:
            pattern = body
            modifier_text = ""
        else:
            pattern = body[:modifier_pos]
            modifier_text = body[modifier_pos + 1:]

    if not pattern:
        return None
    try:
        modifiers = split_modifiers(modifier_text) if modifier_text else []
    except CompilationError:
        return None

    badfilter_tokens = [
        token for token in modifiers
        if token.partition("=")[0].strip().lower() == "badfilter"
    ]
    if any("=" in token for token in badfilter_tokens):
        return None

    normalized_modifiers: list[str] = []
    for token in modifiers:
        if token.strip().lower() == "badfilter":
            continue
        key, separator, value = token.partition("=")
        normalized_modifiers.append(
            key.strip().lower() + ("=" + value.strip() if separator else "")
        )
    return (exception + pattern, tuple(sorted(normalized_modifiers))), bool(badfilter_tokens)

def apply_source_scoped_badfilters(
    expanded_lines: list[ExpandedLine],
    state: CompileState,
) -> list[ExpandedLine]:
    """Apply $badfilter only within one logical upstream filter, including its includes."""
    candidates: list[tuple[ExpandedLine, tuple[str, tuple[str, tuple[str, ...]]] | None, str]] = []
    badfilter_keys: set[tuple[str, tuple[str, tuple[str, ...]]]] = set()
    base_keys: set[tuple[str, tuple[str, tuple[str, ...]]]] = set()
    directives: list[tuple[str, tuple[str, tuple[str, ...]]]] = []

    for entry in expanded_lines:
        if entry.source.kind not in {"adblock", "dns"}:
            candidates.append((entry, None, "keep"))
            continue
        line = entry.text.strip()
        parsed = parse_badfilter_rule(line)
        if parsed is None:
            if re.search(r"(?:\$|,)badfilter(?:=|,|$)", line, re.IGNORECASE) and not any(
                marker in line for marker in VALID_HASH_RULE_PREFIXES
            ):
                add_issue(
                    state,
                    state.summaries[entry.source.url],
                    entry.line_number,
                    line,
                    "unable to parse $badfilter directive safely",
                )
                candidates.append((entry, None, "drop"))
            else:
                candidates.append((entry, None, "keep"))
            continue

        rule_key, is_badfilter = parsed
        scope = entry.root_source_url or entry.source.url
        scoped_key = (scope, rule_key)
        if is_badfilter:
            badfilter_keys.add(scoped_key)
            directives.append(scoped_key)
            state.badfilter_directives_consumed += 1
            candidates.append((entry, scoped_key, "directive"))
        else:
            base_keys.add(scoped_key)
            candidates.append((entry, scoped_key, "base"))

    result: list[ExpandedLine] = []
    for entry, scoped_key, role in candidates:
        if role in {"drop", "directive"}:
            continue
        if role == "base" and scoped_key in badfilter_keys:
            state.badfilter_rules_disabled += 1
            continue
        result.append(entry)

    state.unmatched_badfilter_directives += sum(
        1 for scoped_key in directives if scoped_key not in base_keys
    )
    return result

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
    root_source_url: str | None = None,
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
                    root_source_url or source.url,
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
            output.append(ExpandedLine(source, line_number, raw_line, root_source_url or source.url))

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

        if source.kind == "cname":
            summary.status = "skipped-target-mismatch"
            summary.target_skip_reason = (
                "DNS CNAME-chain semantics require a DNS-aware engine; this output is a flat network filter."
            )
            summary.input_lines_skipped_by_target = summary.input_lines
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

    # Resolve $badfilter before global deduplication, scoped to each root upstream filter.
    expanded_lines = apply_source_scoped_badfilters(expanded_lines, state)

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
        if source.kind == "cname":
            summary.status = "skipped-target-mismatch"
            summary.target_skip_reason = (
                "DNS CNAME-chain semantics require a DNS-aware engine; this output is a flat network filter."
            )
            summary.input_lines_skipped_by_target += 1
            continue

        if not is_comment_or_header(line):
            matched_exclusions = source_exclusions.get(source.url, [])
            if any(pattern.matches(raw_rule) for pattern in matched_exclusions):
                summary.excluded_by_metadata += 1
                continue
        # 已知不兼容规则逐条记录并排除；未知转换错误仍由严格模式阻止发布。

        target_exclusion_reason = (
            detect_nonportable_native_rule(line, target)
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
        "target_sources_skipped": [
            {
                "url": summary.url,
                "format": summary.kind,
                "reason": summary.target_skip_reason,
                "input_lines_skipped": summary.input_lines_skipped_by_target,
            }
            for summary in state.summaries.values()
            if summary.status == "skipped-target-mismatch"
        ],
        "input_lines_skipped_by_target": sum(
            summary.input_lines_skipped_by_target
            for summary in state.summaries.values()
        ),
        "badfilter_directives_consumed": state.badfilter_directives_consumed,
        "badfilter_rules_disabled_within_source": state.badfilter_rules_disabled,
        "unmatched_badfilter_directives": state.unmatched_badfilter_directives,
        "target_excluded_rule_count": len(state.target_exclusions),
        "target_exclusions": state.target_exclusions,
        "unsupported_count": len(state.issues),
        "unsupported_rules": state.issues,
        "semantic_guarantee": (
            "Native AdGuard-compatible network-filter rules are preserved as Adblock-compatible syntax; "
            "hosts and domains-only entries become exact-host HTTP(S) URL regex rules; "
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
    try:
        compile_line("cname", "||tracker.Example.com^")
    except CompilationError:
        tests.append(("CNAME-aware source cannot be silently treated as a network-filter rule", True, True))
    else:
        raise AssertionError("CNAME-aware sources must not be silently published as ordinary URL rules")

    check("DNS network-filter syntax is preserved verbatim",
          compile_line("dns", "||Ads.Example.com^")[0],
          ["||Ads.Example.com^"])
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
    check("CNAME-aware source is omitted from non-DNS network-filter output",
          len(cname_state.records), 0)
    check("CNAME-aware source is marked as a target mismatch",
          cname_state.summaries[cname_source.url].status, "skipped-target-mismatch")
    check("CNAME source lines are explicitly counted as target-skipped",
          cname_state.summaries[cname_source.url].input_lines_skipped_by_target, 1)
    check("CNAME source omission is not misreported as a translation success",
          len(cname_state.issues), 0)


    badfilter_source_a = Source("https://example.invalid/list-a.txt", "adblock")
    badfilter_source_b = Source("https://example.invalid/list-b.txt", "adblock")
    badfilter_fragment = Source("https://example.invalid/list-a-fragment.txt", "adblock")
    badfilter_lines = [
        ExpandedLine(badfilter_source_a, 1, "||shared.example^", badfilter_source_a.url),
        ExpandedLine(badfilter_fragment, 1, "||included.example^", badfilter_source_a.url),
        ExpandedLine(badfilter_source_a, 2, "||shared.example^$badfilter", badfilter_source_a.url),
        ExpandedLine(badfilter_source_a, 3, "||included.example^$badfilter", badfilter_source_a.url),
        ExpandedLine(badfilter_source_b, 1, "||shared.example^", badfilter_source_b.url),
        ExpandedLine(badfilter_source_a, 4, "||ordered.example^$script,third-party", badfilter_source_a.url),
        ExpandedLine(badfilter_source_a, 5, "||ordered.example^$third-party,script,badfilter", badfilter_source_a.url),
    ]
    badfilter_state = CompileState()
    badfilter_remaining = apply_source_scoped_badfilters(badfilter_lines, badfilter_state)
    check("badfilter removes only matching rules from its own upstream list",
          [(item.root_source_url, item.text.strip()) for item in badfilter_remaining],
          [(badfilter_source_b.url, "||shared.example^")])
    check("badfilter scope includes fragments of the same root filter",
          badfilter_state.badfilter_rules_disabled, 3)
    check("badfilter directives are consumed rather than emitted as active rules",
          badfilter_state.badfilter_directives_consumed, 3)

    partial_badfilter_lines = [
        ExpandedLine(badfilter_source_a, 1, "||partial.example^$domain=site-a.example", badfilter_source_a.url),
        ExpandedLine(badfilter_source_a, 2, "||partial.example^$badfilter", badfilter_source_a.url),
    ]
    partial_badfilter_state = CompileState()
    partial_remaining = apply_source_scoped_badfilters(partial_badfilter_lines, partial_badfilter_state)
    check("badfilter does not cancel a rule with a different modifier",
          [item.text.strip() for item in partial_remaining],
          ["||partial.example^$domain=site-a.example"])
    check("unmatched badfilter directives are visible in the report",
          partial_badfilter_state.unmatched_badfilter_directives, 1)

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
          [r"/^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("host record preserves exact-host scope", compile_line("hosts", f"{zero_ipv4} Ads.Example.com")[0],
          [r"/^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    websocket_host_rule = exact_hostname_regex_rule("ads.example.com")
    check("exact-host conversion preserves WebSocket scope",
          re.search(websocket_host_rule[1:-1], "wss://ads.example.com/socket") is not None,
          True)
    check("domain-only preserves subtree scope", compile_line("domains", "Ads.Example.com")[0],
          ["||ads.example.com^"])
    check("DNS subtree rule is preserved verbatim", compile_line("dns", "||Ads.Example.com^")[0],
          ["||Ads.Example.com^"])
    dns_wildcard = compile_line("dns", "||MobileAnalytics.*.AmazonAWS.com^")[0][0]
    check("DNS wildcard rule is scoped to URL hostname",
          dns_wildcard.startswith(r"/^(?:https?|wss?):\/\/"),
          True)
    check("DNS wildcard matches a matching hostname",
          re.search(dns_wildcard[1:-1], "https://MobileAnalytics.us-east.AmazonAWS.com/pixel", re.IGNORECASE) is not None,
          True)
    check("DNS wildcard cannot match only because URL path contains mask",
          re.search(dns_wildcard[1:-1], "https://safe.example/path/MobileAnalytics.us-east.AmazonAWS.com") is None,
          True)
    check("DNS exception is preserved verbatim", compile_line("dns", "@@||Ads.Example.com^")[0],
          ["@@||Ads.Example.com^"])
    dns_single_pipe_exception = compile_line("dns", "@@|cdn.taboola.com^|")[0][0]
    check("DNS single-pipe exception becomes a scoped URL regex",
          dns_single_pipe_exception.startswith(r"@@/^(?:https?|wss?):\/\/"),
          True)
    check("DNS single-pipe exception matches the exact hostname",
          re.search(dns_single_pipe_exception[3:-1], "https://cdn.taboola.com/pixel") is not None,
          True)
    check("DNS single-pipe exception does not match a subdomain",
          re.search(dns_single_pipe_exception[3:-1], "https://sub.cdn.taboola.com/pixel") is None,
          True)
    check("DNS single-pipe exception cannot match hostname text in path",
          re.search(dns_single_pipe_exception[3:-1], "https://safe.example/path/cdn.taboola.com") is None,
          True)
    dns_wildcard_exception = compile_line("dns", "@@||cdn.us*.exponea.com^|")[0][0]
    check("DNS wildcard end-anchor exception is converted to a URL-host regex",
          dns_wildcard_exception.startswith(r"@@/^(?:https?|wss?):\/\/"),
          True)
    check("DNS wildcard end-anchor exception matches the host",
          re.search(dns_wildcard_exception[3:-1], "https://cdn.us-east.exponea.com/pixel") is not None,
          True)
    check("DNS wildcard end-anchor exception excludes longer suffix hosts",
          re.search(dns_wildcard_exception[3:-1], "https://cdn.us-east.exponea.com.evil/pixel") is None,
          True)
    check("DNS wildcard end-anchor exception cannot match through URL path",
          re.search(dns_wildcard_exception[3:-1], "https://safe.example/path/cdn.us-east.exponea.com") is None,
          True)
    unanchored_mask = compile_line("dns", "-adx-*.rayjump.com^")[0][0]
    check("unanchored DNS wildcard is scoped to hostname",
          unanchored_mask.startswith(r"/^(?:https?|wss?):\/\/"),
          True)
    check("unanchored DNS wildcard matches host substring",
          re.search(unanchored_mask[1:-1], "https://tracker-adx-123.rayjump.com/pixel") is not None,
          True)
    check("unanchored DNS wildcard cannot match URL path only",
          re.search(unanchored_mask[1:-1], "https://safe.example/path/-adx-123.rayjump.com") is None,
          True)
    check("DNS leading-dot mask without caret is converted safely",
          compile_line("dns", ".3.n.2.1.l50.js")[0],
          ["||*.3.n.2.1.l50.js^"])
    check("DNS inline comment is ignored", compile_line("dns", "example.com # source note")[0],
          [r"/^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    dns_end_anchor_exception = compile_line("dns", "@@||example.com^|")[0][0]
    check("DNS hostname end-anchor exception is translated to URL authority scope",
          dns_end_anchor_exception.startswith(r"@@/^(?:https?|wss?):\/\/"),
          True)
    check("DNS end-anchor exception matches subdomain hostnames",
          re.search(dns_end_anchor_exception[3:-1], "https://sub.example.com/pixel") is not None,
          True)
    check("DNS end-anchor exception rejects longer suffix hostnames",
          re.search(dns_end_anchor_exception[3:-1], "https://example.com.evil/pixel") is None,
          True)
    check("DNS end-anchor exception cannot match hostname text in a URL path",
          re.search(dns_end_anchor_exception[3:-1], "https://safe.example/path/example.com") is None,
          True)
    check("DNS partial domain anchor keeps prefix semantics", compile_line("dns", "||advertising.civitai.")[0],
          ["||advertising.civitai."])
    unanchored_caret = compile_line("dns", "track.example.com^")[0][0]
    check("unanchored DNS caret pattern is scoped to the hostname",
          unanchored_caret.startswith(r"/^(?:https?|wss?):\/\/"),
          True)
    check("unanchored DNS caret pattern cannot match URL paths only",
          re.search(unanchored_caret[1:-1], "https://safe.example/path/track.example.com") is None,
          True)
    check("uBO property matcher is translated to AdGuard's equivalent syntax",
          compile_line("adblock", "example.com##div:matches-prop(foo.bar=1)")[0],
          ["example.com##div:matches-property(foo.bar=1)"])
    check("DNS leading-dot rule preserves subdomain-only scope",
          compile_line("dns", ".example.com^")[0],
          ["||*.example.com^"])
    check("anchored DNS hostname regex compiles to URL authority regex",
          compile_line("dns", "/^(?:\\w+\\.)*minepi\\.com$/")[0],
          [r"/^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?(?:(?:\w+\.)*minepi\.com)(?::[0-9]+)?(?:[\/?#]|$)/"])
    try:
        compile_line("dns", f"/^{test_ipv4_regex}:/")
    except CompilationError:
        tests.append(("DNS regex that is not a hostname regex is rejected", True, True))
    else:
        raise AssertionError("a DNS hostname regex must not be reinterpreted as an arbitrary URL regex")

    url_scoped_test_regex = r"/(https?:\/\/)" + test_ipv4_regex + r".{100,}/"
    check("URL-scoped regex remains a URL-scoped regex", compile_line("dns", url_scoped_test_regex)[0],
          [url_scoped_test_regex])
    unanchored_dns_regex = "/" + test_ipv4_regex + "/"
    unanchored_dns_compiled = compile_line("dns", unanchored_dns_regex)[0][0]
    check("unanchored DNS regex is scoped to URL hostname",
          unanchored_dns_compiled.startswith(r"/^(?:https?|wss?):\/\/"),
          True)
    check("unanchored DNS regex cannot match only because the URL path contains the pattern",
          re.search(unanchored_dns_compiled[1:-1], "https://safe.example/path/" + test_ipv4 + "/pixel") is None,
          True)
    check("unanchored DNS regex still matches a hostname containing the pattern",
          re.search(unanchored_dns_compiled[1:-1], "https://" + test_ipv4 + ".example/pixel") is not None,
          True)
    try:
        compile_line("dns", r"/^foo[^a]+$/")
    except CompilationError:
        tests.append(("DNS regex with a negated character class is rejected rather than widened to URL scope", True, True))
    else:
        raise AssertionError("unsafe DNS hostname regex must fail closed")
    check("hash character inside native URL regex is preserved",
          compile_line("dns", r"/https?:\/\/example\.com\/path#frag/")[0],
          [r"/https?:\/\/example\.com\/path#frag/"])
    check("DNS hostname regex with nested groups is URL-scoped",
          compile_line("dns", r"/^(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$/")[0],
          [r"/^(?:https?|wss?):\/\/(?:[^\/?#@]+@)?(?:(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com)(?::[0-9]+)?(?:[\/?#]|$)/"])
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
    for unsupported_selector in (
        "example.com##.ad:watch-attr(data-id)",
        "example.com##:others()",
        "example.com##.ad:remove-attr(onclick)",
    ):
        try:
            compile_line("adblock", unsupported_selector, target="adguard-windows")
        except CompilationError:
            tests.append((f"unsupported target selector is rejected: {unsupported_selector}", True, True))
        else:
            raise AssertionError(f"unsupported selector must not be published: {unsupported_selector}")
    check("AdGuard accepts uBO-compatible +js syntax", compile_line("adblock", "example.com##+js(no-such-scriptlet)")[0],
          ["example.com##+js(no-such-scriptlet)"])
    check("native IPv4 host rules are preserved", compile_line("adblock", ip_host_rule)[0],
          [ip_host_rule])
    check("bare IPv4 filter remains a URL-substring rule",
          compile_line("adblock", test_ipv4)[0],
          [test_ipv4])
    check("bare IPv4 exception keeps URL-substring semantics",
          compile_line("adblock", f"@@{test_ipv4}")[0],
          [f"@@{test_ipv4}"])
    check("bare IPv4 modifier does not introduce a host anchor",
          compile_line("adblock", f"{test_ipv4}$important")[0],
          [f"{test_ipv4}$important"])
    check("leading-zero IPv4-like pattern is not normalized",
          compile_line("adblock", test_ipv4_leading_zero)[0],
          [test_ipv4_leading_zero])
    check("invalid dotted-quad text remains a valid substring pattern",
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
    check("manifest covers the required input and metadata families",
          sorted({source.kind for source in configured_sources}),
          ["adblock", "cname", "dns", "exclusions", "hosts"])
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
    header = f"""! Title: Adblock-Rule-Collection
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
