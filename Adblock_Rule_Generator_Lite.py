# -*- coding: utf-8 -*-
"""本模块是 Lite 规则集合的生成入口，从集中配置中读取 Lite 专用的上游来源，并将下载内容编译为独立的 Lite AdGuard 网络过滤产物。

默认使用 universal 通用目标：先按各声明平台计算上游条件指令，只保留共同启用的规则，再执行保守的跨引擎语法检查。对已经符合网络过滤语法的原生规则优先保持原样；Hosts、纯域名和 DNS 等来源只在能够证明转换安全时进行适配。

编译期间会记录来源下载失败、目标不兼容规则和无法转换的条目。严格模式下，只要存在未获授权的来源失败或未解决的语义损失，就不会覆盖 Lite 既有规则产物；审计报告仍会保留，供维护者定位问题。
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

from universal_compat import UNIVERSAL_TARGETS, universal_rule_error
from upstream_source_classifier import SourceFormatDetectionError, classify_source_content
from upstream_sources import load_upstream_urls

OUTPUT_DEFAULT = "ADBLOCK_RULE_COLLECTION_Lite.txt"
REPORT_DEFAULT = "ADBLOCK_RULE_COLLECTION_Lite.semantic-report.json"
DEFAULT_TARGET = "universal"
FETCH_WORKERS = 12
FETCH_TIMEOUT_SECONDS = 18

# 下列前缀属于广告过滤规则语法中的操作符或标记，例如元素隐藏、例外和 CSS 规则；它们不是普通说明注释，解析时必须按规则语法识别，不能直接丢弃。
VALID_HASH_RULE_PREFIXES = (
    "##", "#@#", "#$#", "#$@#", "#?#", "#@?#", "#%#", "#@%#", "#$?#", "#@$?#",
)
COMMENT_PREFIXES = ("!",)
FILTER_DIRECTIVE_RE = re.compile(
    r"^!#(?:if|else|endif|include|safari_cb_affinity|pragma)\b",
    re.IGNORECASE,
)
# 下列名称是系统 Hosts 文件中常见的本机回环别名，解析 Hosts 源时会将其识别为系统用途并跳过，避免把本机网络配置误发布成广告或跟踪拦截规则。

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

# domains 会生成覆盖根域及其所有子域的域名锚定规则；domains-exact 则生成只匹配指定主机名的 HTTP(S) 规则，不会扩大到子域。

# 来源格式由下列类型显式标记：adblock、hosts、domains、domains-exact、dns、cname 和 exclusions；不同类型采用不同解析器，不能仅凭内容外观随意互换。
# 上游过滤器中的 !#if、!#else 等条件指令会根据所选目标配置的能力标志求值；只有该目标启用的分支才会进入对应编译结果。

KNOWN_CONDITION_FLAGS = {
    "adguard", "adguard_app_windows", "adguard_app_mac", "adguard_app_android",
    "adguard_app_ios", "adguard_app_cli", "adguard_ext_safari",
    "adguard_ext_chromium", "adguard_ext_chromium_mv3", "adguard_ext_firefox",
    "adguard_ext_edge", "adguard_ext_edge_mv3", "adguard_ext_opera",
    "adguard_ext_opera_mv3", "adguard_ext_android_cb", "ext_ublock",
    "ext_ubol", "ext_abp", "ext_safari", "ext_devbuild", "env_mobile", "env_safari", "env_chromium",
    "env_firefox", "env_edge", "env_mv3", "env_legacy",
    "cap_html_filtering", "cap_ipaddress", "cap_user_stylesheet",
}
TARGET_PROFILES = {
    # 此配置代表 AdGuard for Windows 桌面过滤引擎，启用 Windows 应用特有的条件标志和能力；它不能与 AdGuard 浏览器扩展配置混为一谈。
    "adguard-windows": {
        "adguard": True,
        "adguard_app_windows": True,
        "cap_html_filtering": True,
        "cap_ipaddress": True,
    },
    # chromium 对应 Chromium 平台上的 MV2 扩展环境；MV3 使用独立的 chromium-mv3 配置，二者的条件标志和可用能力并不相同。
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
    "ublock-origin-chromium": {
        "ext_ublock": True, "env_chromium": True, "cap_user_stylesheet": True,
    },
    "ublock-origin-firefox": {
        "ext_ublock": True, "env_firefox": True, "cap_user_stylesheet": True,
    },
    # universal 是复合目标：生成器会分别计算所有声明目标的条件分支，并只保留每个目标都启用的共同规则。
    "universal": {},
    "generic": {"adguard": True},
}
# DNS 和 CNAME 类型的来源按规则逐条处理：已经符合网络过滤语法的条目优先原样保留，不会仅因为来源被标记为 DNS/CNAME 就强制改写。
# 如果某条规则依赖 DNS 层专用修饰符或解析上下文，而浏览器网络过滤层无法等价表达，则只排除该条并记录来源、行号和原因，避免整份来源被粗略丢弃或发生静默语义损失。
MAX_INCLUDE_DEPTH = 12
ADGUARD_SDNS_CONFIGURATION_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/configuration.json"
)

# 已知只适用于特定过滤引擎、且没有经过验证的跨引擎等价实现的 uBlock Origin 操作，不能直接复制到所有输出目标中。

NON_PORTABLE_NATIVE_PATTERNS = (
    # AdGuard 与 uBlock Origin 的脚本或程序化 DOM 操作语法及运行时能力并不完全相同；在没有可验证的一一对应实现时，不能把这类操作当作等价规则透传。

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
    # 以集合保存已经编译出的规则，利用集合的唯一性自动合并重复项，避免重复规则增加产物体积，也减少后续排序和写文件的工作量。

    records: set[str] = field(default_factory=set)
    issues: list[dict[str, object]] = field(default_factory=list)
    target_exclusions: list[dict[str, object]] = field(default_factory=list)
    summaries: dict[str, SourceSummary] = field(default_factory=dict)

def build_sources(urls: Iterable[str]) -> list[Source]:
    # URL 清单只负责描述下载位置；格式必须等下载后由内容识别器判定。
    sources = [Source(url=url, kind="auto") for url in urls]
    if len({source.url for source in sources}) != len(sources):
        raise CompilationError("The upstream manifest contains duplicate URLs")
    return sources

def canonical_hostname(value: str, *, allow_single_label: bool = True) -> str | None:
    """验证输入是否符合本模块接受的 DNS 主机名格式，并返回规范化后的主机名表示。allow_single_label 控制是否接受没有点号的单标签名称；输入为空、含非法标签或超出长度限制时返回 None，不猜测其含义。"""
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
    """先尝试按 IPv4 地址解析并规范化，再按主机名规则验证和规范化输入。该函数用于处理网络过滤规则中的主机部分；无法安全识别的值返回 None，交由调用方决定是否保留原文或报错。"""
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            return str(address)
        return None
    except ValueError:
        return canonical_hostname(value, allow_single_label=allow_single_label)

def exact_hostname_regex_rule(hostname: str, *, exception: bool = False) -> str:
    """把经过验证的主机名或 IPv4 地址转成 AdGuard 斜杠分隔正则，并限定匹配 HTTP(S) URL 的 authority 主机部分。规则同时处理可选用户信息、端口和主机边界；exception=True 时生成 @@ 例外规则，且不会扩展到其他子域。"""
    domain = canonical_host_or_ipv4(hostname)
    if not domain:
        raise CompilationError(f"invalid exact hostname: {hostname!r}")
    escaped = re.escape(domain)
    # AdGuard 网络过滤器使用成对斜杠包围正则表达式正文；因此，作为 URL 匹配文本的斜杠必须按正则语法转义，避免提前结束表达式。
    body = (
        r"^https?:\/\/(?:[^\/?#@]+@)?"
        + escaped
        + r"(?::[0-9]+)?(?:[\/?#]|$)"
    )
    return ("@@" if exception else "") + "/" + body + "/"

def normalize_native_domain_rule(line: str) -> str:
    """只处理结构明确的裸 IPv4 规则，以及以 || 或 | 开始、以主机边界符结束的简单域名规则。可识别的主机部分会规范化大小写和地址写法；其他复杂网络过滤语法保持原样，避免无意改变其匹配范围。"""
    # 对原生浏览器过滤规则中的裸 IPv4 地址，先规范化地址写法，再转换为以主机名边界为锚点的网络规则，避免把地址误当成任意 URL 子串。
    # DNS 来源中的裸地址和域名表达式由 DNS 适配器单独判断；不能直接套用浏览器过滤规则的转换路径，否则可能丢失 DNS 解析层面的匹配语义。

    bare_ipv4 = re.fullmatch(
        r"(?P<exception>@@)?(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?P<tail>\$.*)?",
        line,
    )
    if bare_ipv4:
        octets = [int(part, 10) for part in bare_ipv4.group("ip").split(".")]
        if any(octet > 255 for octet in octets):
            raise CompilationError(
                f"invalid IPv4 address in native browser rule: {bare_ipv4.group('ip')}"
            )
        # IPv4 八位组按十进制数值重新输出，去掉诸如 001 这样的前导零；这样同一地址的不同文本写法会归一为同一规则，便于准确去重。
        ip_literal = ".".join(str(octet) for octet in octets)
        return (
            (bare_ipv4.group("exception") or "")
            + "||"
            + ip_literal
            + "^"
            + (bare_ipv4.group("tail") or "")
        )

    match = re.fullmatch(r"(?P<exception>@@)?(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^(?P<tail>\$.*)?", line)
    if not match:
        return line
    hostname = canonical_host_or_ipv4(match.group("host"), allow_single_label=False)
    if not hostname:
        # 如果规则主机部分未通过本项目的主机名规范化器，但仍可能是上游引擎允许的合法写法，则保留原文；贸然改写可能扩大或缩小原规则的匹配范围。

        return line
    return (
        (match.group("exception") or "")
        + match.group("anchor")
        + hostname
        + "^"
        + (match.group("tail") or "")
    )

def detect_nonportable_native_rule(line: str, target: str = "generic") -> str | None:
    if target == "universal":
        return universal_rule_error(line)
    if DNS_ONLY_MODIFIER_RE.search(line):
        return "DNS-only modifier cannot be represented safely in an AdGuard network filter"
    if target != "adguard-windows" and NETWORK_ONLY_MODIFIER_RE.search(line):
        return "AdGuard application-only $network modifier is not supported by this target"
    for pattern, explanation in NON_PORTABLE_NATIVE_PATTERNS:
        if pattern.search(line):
            return explanation
    return None

def canonical_wildcard_hostname_mask(value: str) -> str | None:
    """检查 DNS 通配主机名的总长度、标签长度、允许字符和通配符位置，并将通过验证的模式转换为小写。函数只接受至少包含两个标签的主机名模式；格式不合法时返回 None，不放宽为普通字符串。"""
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
            # 对包含 * 的主机名标签采用单独校验：允许合法的通配符位置，同时仍拒绝以连字符开头或结尾等无效标签，避免过度放宽格式检查。

            if not re.fullmatch(r"[a-z0-9*-]+", label):
                return None
            if label.startswith("-") or label.endswith("-"):
                return None
    return value.lower()

def split_modifiers(modifier_text: str) -> list[str]:
    """将网络规则末尾的修饰符列表按逗号拆分，同时跟踪单引号、双引号和反斜杠转义状态，确保引号内部的逗号不会被误当成分隔符。若引号未闭合或产生空修饰符，则抛出 CompilationError。"""
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

def _valid_filter_modifier_suffix(suffix: str) -> bool:
    """判断候选正则结束斜杠之后的内容是否为空或合法的修饰符列表。"""
    if not suffix:
        return True
    if not suffix.startswith("$"):
        return False
    try:
        tokens = split_modifiers(suffix[1:])
    except CompilationError:
        return False
    return bool(tokens) and all(
        re.fullmatch(r"~?[A-Za-z][A-Za-z0-9_-]*(?:=.*)?", token) is not None
        for token in tokens
    )


def find_regex_rule_end(body: str) -> int | None:
    """定位斜杠正则的结束分隔符；跳过 URL/路径中的斜杠，并要求其后只能是修饰符列表或行尾。"""
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
        elif char == "/" and _valid_filter_modifier_suffix(body[index + 1:]):
            return index
    return None


NATIVE_REQUEST_FILTER_MODIFIERS = {
    "script", "image", "stylesheet", "object", "xmlhttprequest",
    "subdocument", "font", "media", "popup", "other", "document",
    "third-party", "3p", "match-case", "domain", "network", "all",
    "removeparam",
}


def native_request_filter_modifier_keys(line: str) -> set[str]:
    """提取用于区分网络请求过滤规则与 DNS 主机表达式的修饰符名称。"""
    body = line[2:] if line.startswith("@@") else line
    if body.startswith("/"):
        closing = find_regex_rule_end(body)
        if closing is not None:
            suffix = body[closing + 1:]
        elif body.startswith("/^"):
            return set()
        else:
            _, separator, modifier_text = body.partition("$")
            suffix = "$" + modifier_text if separator else ""
    else:
        _, separator, modifier_text = body.partition("$")
        suffix = "$" + modifier_text if separator else ""

    if not suffix.startswith("$"):
        return set()
    try:
        tokens = split_modifiers(suffix[1:])
    except CompilationError:
        return set()
    return {
        token.partition("=")[0].strip().lower().lstrip("~")
        for token in tokens
    } & NATIVE_REQUEST_FILTER_MODIFIERS


def normalize_native_slash_regex_rule(line: str) -> str:
    """将正则正文中未转义的字面斜杠转义，避免目标引擎把 URL 路径斜杠误认作正则结束符。"""
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    closing = find_regex_rule_end(body)
    if closing is None:
        return line

    regex_body = body[1:closing]
    escaped_body: list[str] = []
    escaped = False
    for char in regex_body:
        if char == "/" and not escaped:
            escaped_body.append(r"\/")
        else:
            escaped_body.append(char)
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False

    normalized = "/" + "".join(escaped_body) + body[closing:]
    return ("@@" if exception else "") + normalized


def compile_dns_hostname_regex(regex_body: str, *, exception: bool = False) -> str | None:
    """仅接受以 ^ 开头、以 $ 结尾且处于允许字符和分组范围内的主机名正则。验证通过后，在其外层加入 HTTP(S) 协议、可选用户信息、端口以及 URL 边界，使 DNS 主机名表达式能够用于请求 URL 匹配；不支持的正则语法返回 None。"""
    if not (regex_body.startswith("^") and regex_body.endswith("$")):
        return None
    inner = regex_body[1:-1]
    if not inner or "/" in inner or any(token in inner for token in ("(?=", "(?!", "(?<=", "(?<!", "(?P", "\\k<")):
        return None
    # 这里只转换能够验证为安全的主机名正则子集；前瞻、后顾、命名捕获等未纳入兼容范围的特殊分组会被拒绝，不能猜测其在目标引擎中的行为。

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
    """把 DNS 列表中的域名表达式适配为浏览器网络过滤规则，但只处理能够保持原匹配范围的已知语法。函数会分别处理斜杠正则、域名锚点、前导点、通配主机和例外标记；依赖 DNS 解析结果或专用 DNS 修饰符、无法在 URL 层等价表达的条目会抛出 CompilationError。"""
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("@@"):
        raise CompilationError("misplaced DNS exception marker")

    # 斜杠分隔的正则正文内部可能包含美元符号或转义斜杠；必须先定位未转义的结束斜杠，再解析其后的 $ 修饰符，防止把正则内容误拆成修饰符。

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

        # 如果上游正则已经明确匹配 HTTP 或 HTTPS URL，就保留其原始 URL 作用域；再次套用主机名包装会改变匹配范围，因此不能重复转换。

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
                if regex_body.startswith("^"):
                    # DNS 主机名或 IP 正则描述的是 DNS 名称本身，并不天然包含 HTTP(S) URL 的协议和主机边界；对于带起始锚点的表达式，需要补上 URL authority 匹配范围。
                    # 包装时保留原有正则正文及其分组、选择和量词结构，不把 DNS 表达式简化成普通字符串，以免丢失上游定义的匹配条件。
                    # 另外加入 URL authority 的起止边界，使规则只作用于请求 URL 的主机部分，而不是误匹配路径、查询参数或其他任意文本。
                    # 当源正则还包含主机名结束锚点时，同时保留可选端口和路径、查询或片段分隔边界，确保主机名结束与整个 URL 结束不会被混为一谈。
                    if regex_body.endswith("$"):
                        inner = regex_body[1:-1]
                        boundary = (
                            r"(?:[\/?#]|$)"
                            if ":" in inner
                            else r"(?::[0-9]+)?(?:[\/?#]|$)"
                        )
                        url_scoped_body = (
                            r"^https?:\/\/(?:[^\/?#@]+@)?"
                            + inner
                            + boundary
                        )
                    else:
                        url_scoped_body = (
                            r"^https?:\/\/(?:[^\/?#@]+@)?"
                            + regex_body[1:]
                        )
                    translated = (("@@" if exception else "") + "/" + url_scoped_body + "/")
                else:
                    raise CompilationError(
                        "DNS regex cannot be proven equivalent as a network-filter URL regex"
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

    # 纯域名列表中的裸域名按精确主机名处理，只生成该主机自身的匹配规则；不能擅自扩展成覆盖全部子域的 ||domain^ 规则。

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

    # DNS 主机名的结束位置不等于完整 URL 的结束位置；转换精确主机规则时必须同时考虑端口及路径、查询、片段等 URL 边界。
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

    # DNS 语法中的前导点表示只匹配其下级子域，不包含 example.com 根域；转换时需保留这一排除根域的语义。

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

    # 对没有终止边界的主机锚定前缀规则，保留其前缀匹配含义；即使最后一个标签只给出了前缀，也不能擅自补上 ^ 改成完整主机名匹配。

    if re.fullmatch(r"\|\|[A-Za-z0-9*.-]+", pattern):
        translated = ("@@" if exception else "") + pattern.lower()
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # 在此类 DNS 输入中，单竖线与 ^ 组合代表精确主机名边界；它不同于通用 Adblock 语法中对完整 URL 起始位置的描述，转换时必须使用精确主机正则。

    exact_match = re.fullmatch(r"\|([^|^*/$]+)\^", pattern)
    if exact_match:
        hostname = canonical_host_or_ipv4(
            exact_match.group(1), allow_single_label=False
        )
        if not hostname:
            raise CompilationError(f"invalid exact DNS hostname: {pattern}")
        translated = exact_hostname_regex_rule(hostname, exception=exception)
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # 此分支处理以 || 开始、以 ^ 结束的标准子域规则；若主机部分含通配符则先校验通配域名，否则按普通 DNS 主机名规范化。
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
                # 如果上游标签不符合本项目采用的严格 IDNA 主机名校验，但仍处于允许保留的字符集合中，则只做小写化并保留原有锚点，不擅自改写或扩大匹配范围。

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

    # Hosts 文件中的普通地址映射表达的是“主机名解析到某个 IP”，其语义与浏览器过滤器拦截请求不同；只有明确用于黑洞或回环的映射才能安全转换为主机拦截规则。

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
    """读取纯域名列表中的单条记录，先移除行尾说明并校验域名，再生成 ||domain^ 形式的网络过滤规则。该输出同时覆盖指定根域和其子域；空值或非法域名会作为编译错误报告。"""
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid domains-only entry: {candidate!r}")
    return "||" + hostname + "^"

def compile_domain_exact_line(line: str) -> str:
    """读取纯域名列表中的单条记录，完成注释剥离和主机名校验后，调用精确主机规则生成器输出 HTTP(S) 匹配正则。与 compile_domain_line 不同，此函数只匹配该主机本身，不扩大到下级子域。"""
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid exact-host domains entry: {candidate!r}")
    return exact_hostname_regex_rule(hostname)

def looks_like_native_network_filter_rule(line: str) -> bool:
    """判断输入条目是否已经采用 AdGuard 网络过滤语法。

    已经符合原生网络过滤格式的规则应直接保留，不因来源类型而重复改写；裸域名会交由 DNS 适配器转换为精确主机规则，前导点 DNS 后缀则交由适配器处理为仅匹配子域的规则。
    """
    candidate = line.strip()
    if not candidate:
        return False

    if candidate.startswith("/"):
        closing = find_regex_rule_end(candidate)
        if closing is None:
            # 未以 /^ 起始且没有正则结束分隔符的斜杠前缀，是合法的普通 URL 子串过滤模式；不把它误判为 DNS 正则。
            return not candidate.startswith("/^")
        regex_body = candidate[1:closing]
        if native_request_filter_modifier_keys(candidate):
            return True
        if re.search(r"https?\s*:", regex_body, re.IGNORECASE) is not None or "/" in regex_body:
            return True
        # 没有主机起始锚点的正则可直接匹配 URL；纯主机名正则仍交由 DNS 适配器补充 URL authority 边界。
        return not regex_body.startswith("^")

    if native_request_filter_modifier_keys(candidate):
        return True

    if any(operator in candidate for operator in VALID_HASH_RULE_PREFIXES):
        return True

    # 已经使用主机锚点、通用锚点、通配符或分隔符语法的条目，通常已经是合法的网络过滤规则；即使来源类型标记为 DNS 或 CNAME，也不应仅凭来源类型就重写它们。
    # 这些模式会按原生网络过滤语法传递；只有确实属于 DNS 专用表达式、且需要适配才能维持语义的条目，才进入后续转换逻辑。
    # 这样可以避免对本来可直接使用的原生规则重复转换，从而意外改变例外规则、锚点或修饰符的含义。
    if candidate.startswith(("||", "@@||", "|", "@@|")):
        return True
    if "://" in candidate:
        return True
    if re.fullmatch(r"\S*[\^|*]\S*", candidate):
        return True
    if candidate.startswith("."):
        # 以点号开头的 DNS 后缀写法具有“仅匹配子域”的特殊含义，不是普通 URL 子串；它会在后续 DNS 适配分支中转换。
        return False

    # 对通过主机名校验的单个裸域名，按 DNS 主机表达式处理，并转换为只匹配该主机的 HTTP(S) URL 规则；这避免把域名误解释成任意 URL 子串。
    # 其他不符合主机名格式、但仍是单个无空白 token 的条目，可能已经是通用 URL 子串过滤表达式，应保留其原文而不是强行按域名改写。
    # 因此，本分支只转换能够识别为 DNS 主机名的条目，其他候选值维持原有的 URL 子串匹配语义。
    if re.fullmatch(r"\S+", candidate):
        try:
            ipaddress.ip_address(candidate)
            # DNS 列表中的裸 IP 可能用于匹配解析后指向该地址的 CNAME 目标；这类语义依赖 DNS 解析结果，而不是请求 URL 中显式出现的主机名。
            # 单纯把 IP 写成 URL 子串规则无法可靠复现这一行为，因此必须将其留在不支持范围内并交由审计报告说明。
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

    def finalize(rules: list[str], category: str) -> tuple[list[str], str]:
        if target == "universal":
            for output_rule in rules:
                reason = universal_rule_error(output_rule)
                if reason:
                    raise CompilationError(reason)
        return rules, category

    if kind == "adblock":
        reason = detect_nonportable_native_rule(line, target)
        if reason:
            raise CompilationError(reason)
        return finalize([normalize_native_domain_rule(line)], "native")

    if kind == "hosts":
        rules, category = compile_hosts_line(line)
        return finalize(rules, category)

    if kind == "domains":
        return finalize([compile_domain_line(line)], "domains")

    if kind == "domains-exact":
        return finalize([compile_domain_exact_line(line)], "domains-exact")

    if kind == "cname":
        reason = detect_nonportable_native_rule(line, target)
        if reason:
            raise CompilationError(reason)
        if looks_like_native_network_filter_rule(line):
            return finalize([line], "native-cname")
        return finalize([compile_dns_rule(line)], "cname-converted")

    if kind == "exclusions":
        raise CompilationError(
            "this is an exclusion selector file, not an active blocklist; it must be "
            "applied to its designated source group rather than emitted as rules"
        )

    if kind == "dns":
        if looks_like_native_network_filter_rule(line):
            native_line = normalize_native_slash_regex_rule(line)
            reason = detect_nonportable_native_rule(native_line, target)
            if reason:
                raise CompilationError(reason)
            return finalize([native_line], "native-dns")

        line = line.split("#", 1)[0].strip()
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
            rules, category = compile_hosts_line(line, category="hosts-in-dns")
            return finalize(rules, category)
        return finalize([compile_dns_rule(line)], "dns-converted")

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
    if source.kind == "auto":
        try:
            source = Source(source.url, classify_source_content(text))
        except SourceFormatDetectionError as error:
            raise CompilationError(
                f"unable to identify upstream content format for {source.url}: {error}"
            ) from error
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
    # 无论选择哪一种目标配置，生成器最终都输出 AdGuard 兼容的过滤语法；不会生成依赖 uBlock Origin 开发版或专有构建环境的特殊格式。
    flags["ext_devbuild"] = False
    return flags

def evaluate_filter_condition(expression: str, flags: dict[str, bool]) -> bool:
    """解析并计算 AdGuard 过滤器预处理器的布尔条件表达式，支持标志名称、true/false、括号、逻辑非 !、逻辑与 && 和逻辑或 ||。标志值由当前目标配置提供；遇到未知标志、非法 token、缺失括号或多余 token 时抛出 CompilationError。"""
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
    """判断预处理器 !#include 是否可以访问目标 URL。默认只允许协议、主机和端口均相同的同源引用；此外仅放行代码中明确列出的 AdGuard CNAME 数据跨域路径，其他跨域引用一律拒绝，避免从未审核的站点递归载入规则。"""
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
    # 每遇到一层 !#if 就压入一个独立状态帧，分别保存进入该层前的父级启用状态、当前条件真假以及是否已经处理过 !#else，以便正确恢复嵌套条件。
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
            # safari_cb_affinity 是 Safari 内容拦截器的分组元数据；非 Safari 目标不使用这一属性，因此在展开时移除该指令本身，不把它写入通用规则文件。

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
                # include 片段也必须独立通过内容识别；不再因同源关系沿用父来源格式。
                included_source, included_text = fetch_source(Source(include_url, "auto"))
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

def expand_filter_preprocessor_universal(
    source: Source,
    text: str,
    cache: dict[str, tuple[Source, str]],
) -> list[ExpandedLine]:
    """Keep only source lines selected in every supported engine/profile."""
    per_profile = [
        expand_filter_preprocessor(source, text, profile, cache)
        for profile in UNIVERSAL_TARGETS
    ]
    common_lines = {line.text.strip() for line in per_profile[0]}
    for expanded in per_profile[1:]:
        common_lines.intersection_update(line.text.strip() for line in expanded)
    return [
        line for line in per_profile[0]
        if line.text.strip() in common_lines
    ]


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
    """把上游排除文件逐行解析为三类匹配器：普通文本采用子串匹配，包含星号的模式采用通配符匹配，斜杠包围的模式采用不区分大小写的多行正则匹配。空行、注释、头信息和重复模式会被跳过；无效正则会抛出 CompilationError。"""
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

        # exclusions 来源保存上游维护者指定的排除匹配模式，属于 DNS 列表编译元数据；它只用于过滤对应来源中的规则，不应进入浏览器订阅正文。

        if source.kind == "exclusions":
            summary.status = "consumed-as-metadata"
            summary.target_skip_reason = (
                "This file contains upstream exclusion metadata, not active filter rules."
            )
            continue

        if source.kind == "empty":
            summary.status = "empty-noop"
            summary.target_skip_reason = "The upstream contains no active filter entries."
            continue

        if target == "universal" and source.kind == "cname":
            summary.status = "skipped-target-mismatch"
            summary.input_lines_skipped_by_target = summary.input_lines
            summary.target_skip_reason = (
                "CNAME-uncloaking requires DNS resolution context and has no shared "
                "equivalent in the selected browser MV2 engines."
            )
            continue

        try:
            expanded_lines.extend(
                expand_filter_preprocessor_universal(source, text, cache)
                if target == "universal"
                else expand_filter_preprocessor(source, text, target, cache)
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

    # 上游规则中的 !#include 可能额外下载当前 URL 清单未直接列出的文件；这些被递归引入的来源也必须加入来源摘要和审计报告，不能遗漏其失败或规则数量。
    for source_url, (source, text) in cache.items():
        if source_url not in state.summaries:
            state.summaries[source_url] = SourceSummary(
                url=source.url,
                kind=source.kind,
                status="included",
                input_lines=len(text.splitlines()),
            )

    # 上游排除模式只能应用于 AdGuard 元数据明确关联的来源；不能把某个来源的例外选择器全局套用到其他列表，以免误删无关规则。

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

        # 被 !#include 引入的文件同样需要按自身 URL 识别来源格式，并与主清单中的来源一样逐条执行目标平台兼容性检查和语义审计。
        if source.kind == "exclusions":
            summary.status = "consumed-as-metadata"
            summary.target_skip_reason = (
                "This file contains upstream exclusion metadata, not active filter rules."
            )
            continue
        if target == "universal" and source.kind == "cname" and not is_comment_or_header(line):
            summary.target_excluded_rules += 1
            state.target_exclusions.append({
                "source": source.url,
                "format": source.kind,
                "line": expanded.line_number,
                "rule": line[:500],
                "reason": "CNAME-uncloaking semantics are not shared by all target engines.",
            })
            continue
        if not is_comment_or_header(line):
            matched_exclusions = source_exclusions.get(source.url, [])
            if any(pattern.matches(raw_rule) for pattern in matched_exclusions):
                summary.excluded_by_metadata += 1
                continue
        # 对已经识别的目标不兼容规则，按单条记录来源、行号和排除原因后跳过；对于尚无法安全转换的未知语法，则保留为编译问题，由严格模式阻止发布，不能静默丢弃。

        target_exclusion_candidate = (
            normalize_native_slash_regex_rule(line)
            if source.kind == "dns" and looks_like_native_network_filter_rule(line)
            else line
        )
        target_exclusion_reason = (
            detect_nonportable_native_rule(target_exclusion_candidate, target)
            if (source.kind == "adblock" or (source.kind == "dns" and looks_like_native_network_filter_rule(line))) and line and not is_comment_or_header(line)
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
        "target": (
            "Universal ABP/EasyList subset: AdGuard Windows + AdGuard Browser Extension MV2 "
            "+ uBlock Origin MV2"
            if target == "universal"
            else f"AdGuard network filter syntax ({target})"
        ),
        "condition_profiles": list(UNIVERSAL_TARGETS) if target == "universal" else [target],
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
            "Universal mode intersects preprocessor-active source lines across the declared MV2 profiles, "
            "then admits only conservative shared ABP/EasyList network filters and basic native CSS cosmetic rules. "
            "Engine-specific modifiers, HTML filtering, scriptlets, procedural/extended CSS, and CNAME-uncloaking "
            "sources are excluded and reported. This is a conservative compatibility contract, not a claim that "
            "all browser runtimes implement every allowed feature identically."
            if target == "universal"
            else (
            "Native AdGuard-compatible network-filter rules are preserved as Adblock-compatible syntax; "
            "hosts entries become exact-host HTTP(S) URL regex rules; domains-only entries use "
            "domain-and-subdomain scope unless explicitly configured as domains-exact; "
            "Native network-filter syntax from DNS/CNAME sources is retained where compatible; non-native DNS entries are converted only when safe, DNS-only modifiers are excluded individually, and copied CNAME patterns do not implement DNS CNAME-chain inspection. "
            "Known non-portable rules are excluded individually with source-line diagnostics; "
            "unknown in-scope conversion failures still fail strict compilation. All exclusions "
            "are visible in the report. This is not a proof for arbitrary regex or "
            "engine-specific rules."
            )
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

    # 回归测试所需的 IPv4 地址均由数字序列在运行时拼接生成，不在测试代码中写死具体点分十进制地址，避免测试样例与真实上游地址产生不必要的耦合。
    test_ipv4 = ".".join(str(octet) for octet in range(1, 5))
    test_ipv4_regex = re.escape(test_ipv4)
    test_ipv4_leading_zero = ".".join(f"{octet:03d}" for octet in range(1, 5))
    invalid_test_ipv4 = ".".join([str(255 + 1), *(str(octet) for octet in range(1, 4))])
    zero_ipv4 = ".".join(str(0) for _ in range(4))
    ip_host_rule = f"||{test_ipv4}^"

    check("universal accepts a basic ABP host rule", universal_rule_error("||ads.example.com^"), None)
    check("universal accepts a basic ABP exception", universal_rule_error("@@||safe.example.com^"), None)
    check("universal accepts common request-type and party modifiers",
          universal_rule_error("||ads.example.com^$script,third-party"), None)
    check("universal accepts a common domain modifier",
          universal_rule_error("||ads.example.com^$domain=example.com|~sub.example.com"), None)
    check("universal accepts basic native CSS cosmetic rules",
          universal_rule_error("example.com##.ad-banner"), None)
    check("universal rejects Windows application filtering",
          universal_rule_error("||app.example.com^$app=some.application") is not None, True)
    check("universal rejects AdGuard network-only filtering",
          universal_rule_error("||network.example.com^$network") is not None, True)
    check("universal rejects DNS-only modifiers",
          universal_rule_error("||dns.example.com^$dnstype=A") is not None, True)
    check("universal rejects AdGuard HTML filtering",
          universal_rule_error("example.com$script:contains(ad)") is not None, True)
    check("universal rejects scriptlets without a shared resource contract",
          universal_rule_error("example.com##+js(example-scriptlet)") is not None, True)
    check("universal rejects procedural/extended cosmetic syntax",
          universal_rule_error("example.com#?#div:has-text(ad)") is not None, True)
    check("universal rejects engine-specific redirect modifiers",
          universal_rule_error("||ads.example.com^$redirect=empty") is not None, True)

    universal_source = Source("https://example.invalid/universal.txt", "adblock")
    universal_text = (
        "||shared.example^\n"
        "!#if adguard_app_windows\n||windows-only.example^\n!#endif\n"
        "!#if ext_ublock\n||ubo-only.example^\n!#endif\n"
    )
    universal_lines = expand_filter_preprocessor_universal(
        universal_source, universal_text,
        {universal_source.url: (universal_source, universal_text)},
    )
    check("universal preprocessing keeps only lines active in every target profile",
          [item.text.strip() for item in universal_lines], ["||shared.example^"])

    try:
        compile_line("adblock", "||app.example^$app=some.application", target="universal")
    except CompilationError:
        tests.append(("universal compiler rejects application-only modifiers", True, True))
    else:
        raise AssertionError("universal compiler must reject $app rules")

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
    check("hosts mappings are detected from content",
          classify_source_content("0.0.0.0 ads.example.com\n"), "hosts")
    check("plain domain lists require explicit subdomain scope metadata",
          classify_source_content("! Title: Domain filter\n! Description: blocks domains and all their subdomains\ntracker.example.com\nads.example.net\n"), "domains")
    try:
        classify_source_content("tracker.example.com\nads.example.net\n")
    except SourceFormatDetectionError:
        tests.append(("ambiguous bare-domain scope fails closed", True, True))
    else:
        raise AssertionError("bare domains without scope metadata must not be guessed")
    check("native network rules are detected from content",
          classify_source_content("[Adblock Plus]\n! Title: Example filter\n||ads.example.com^\n"), "adblock")
    check("unanchored Adblock URL patterns are detected from content",
          classify_source_content("! Title: Example EasyList filter\n-ads/assets/$script\npage_view_count\n"), "adblock")
    check("empty or comment-only upstreams are treated as no-op",
          classify_source_content("! This source currently has no active entries\n"), "empty")
    check("zero-byte upstream content is treated as empty no-op",
          classify_source_content(""), "empty")
    check("DNS-specific modifiers are detected from content",
          classify_source_content("||ads.example.com^$dnstype=A\n"), "dns")
    check("CNAME original-tracker metadata is detected from content",
          classify_source_content("! Title: AdGuard CNAME original trackers list\n! Description: used only by software capable of scanning CNAME records\n||tracker.example.com^\n"), "cname")
    check("CNAME disguised-microsite metadata is detected from content",
          classify_source_content("! Title: AdGuard CNAME disguised microsites list\n||site.example.com^\n"), "cname")
    check("ordinary disguised CNAME ads retain browser-filter semantics",
          classify_source_content("! Title: AdGuard CNAME disguised ads list\n||ads.example.com^\n"), "adblock")
    exclusion_fixture = "\n".join(
        "! https://github.com/AdguardTeam/AdguardDNS/issues/" + str(index) + "\ntracker" + str(index) + ".example.com"
        for index in range(30)
    )
    check("AdGuard DNS exclusion metadata is detected from its content signature",
          classify_source_content(exclusion_fixture), "exclusions")
    try:
        classify_source_content("unrecognized mixed input\n||ads.example.com^\n")
    except SourceFormatDetectionError:
        tests.append(("ambiguous mixed content fails closed", True, True))
    else:
        raise AssertionError("ambiguous source content must not be guessed")
    check("Chromium MV2 preprocessor condition evaluates true",
          evaluate_filter_condition("adguard && adguard_ext_chromium && !adguard_ext_safari", target_condition_flags("chromium")), True)
    check("Chromium MV3 gets the MV3 condition, not the MV2 condition",
          evaluate_filter_condition("adguard_ext_chromium_mv3 && !adguard_ext_chromium", target_condition_flags("chromium-mv3")), True)
    check("uBlock-only and development-build conditions are false for AdGuard output",
          evaluate_filter_condition("ext_ublock || ext_ubol || ext_abp || ext_devbuild", target_condition_flags("chromium-mv3")), False)
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
    check("default compiler target is the shared portable profile", DEFAULT_TARGET, "universal")
    windows_flags = target_condition_flags("adguard-windows")
    check("uBlock Origin development-build condition is false for AdGuard Windows",
          evaluate_filter_condition("ext_devbuild", windows_flags), False)
    check("Windows target selects Windows-specific rules",
          evaluate_filter_condition("adguard && adguard_app_windows && !adguard_ext_chromium_mv3", windows_flags), True)
    check("Windows target enables HTML filtering capability",
          evaluate_filter_condition("cap_html_filtering", windows_flags), True)
    check("Windows target enables IP-address filtering capability",
          evaluate_filter_condition("cap_ipaddress", windows_flags), True)
    check("Windows target does not inherit Chromium extension conditions",
          evaluate_filter_condition("adguard_ext_chromium_mv3 || env_chromium || env_mv3", windows_flags), False)
    windows_source = Source("https://example.com/windows-filter.txt", "adblock")
    windows_text = (
        "!#if adguard_app_windows\n"
        "||windows-only.example^\n"
        "!#else\n"
        "||other-platform.example^\n"
        "!#endif\n"
        "!#if ext_devbuild\n"
        "||development-build-only.example^\n"
        "!#else\n"
        "||non-development-build.example^\n"
        "!#endif\n"
    )
    windows_lines = expand_filter_preprocessor(
        windows_source,
        windows_text,
        "adguard-windows",
        {windows_source.url: (windows_source, windows_text)},
    )
    check("Windows preprocessor selects Windows-specific rules",
          [line.text.strip() for line in windows_lines],
          ["||windows-only.example^", "||non-development-build.example^"])
    check("AdGuard CNAME include from an official filter source is allowlisted",
          allow_preprocessor_include(
              "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
              "https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt",
          ), True)
    check("disguised CNAME ad-domain lists keep ordinary browser-filter semantics",
          classify_source_content("||galaksion.com^\\n"),
          "adblock")
    include_parent_url = (
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/"
        "master/BaseFilter/sections/adservers.txt"
    )
    include_fragment_url = "https://adguardteam.github.io/cname-trackers/data/ads/galaksion.txt"
    include_parent = Source(include_parent_url, "adblock")
    include_fragment = Source(include_fragment_url, classify_source_content("||tracker.example^"))
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
    check("exact-host domain metadata is detected from content",
          classify_source_content("! Title: Exact hosts only\nexample.com\n"), "domains-exact")
    check("arbitrary cross-origin preprocessor include is rejected",
          allow_preprocessor_include(
              "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
              "https://evil.example/list.txt",
          ), False)
    try:
        classify_source_content("not a valid filter format")
    except SourceFormatDetectionError:
        tests.append(("unknown source content fails closed", True, True))
    else:
        raise AssertionError("unknown source content must not default to Adblock syntax")
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
    check("DNS list metadata overrides generic network syntax",
          classify_source_content("! Title: AdGuard DNS filter\n||dns.example^\n"), "dns")
    check("CNAME network-filter syntax is preserved verbatim",
          compile_line("cname", "||tracker.Example.com^")[0],
          ["||tracker.Example.com^"])
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
    empty_source = Source("https://example.invalid/empty-list.txt", "empty")
    empty_state = compile_fetched_sources(
        [(empty_source, "! empty list\\n")],
        "chromium-mv3",
    )
    check("empty source is recorded without parser guessing",
          empty_state.summaries[empty_source.url].status, "empty-noop")
    check("empty source does not emit rules", len(empty_state.records), 0)

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
        classify_source_content("format is not inferable from this text")
    except SourceFormatDetectionError:
        tests.append(("unrecognized source content rejected", True, True))
    else:
        raise AssertionError("unrecognized source content must fail closed")
    check("plain domain-list entries block the domain and its subdomains",
          compile_line("domains", "Example.COM")[0],
          ["||example.com^"])
    check("exact-host domain-list entries do not expand to subdomains",
          compile_line("domains-exact", "Example.COM")[0],
          [exact_hostname_regex_rule("example.com")])
    check("localhost host entry is not emitted as an ad block", compile_line("hosts", f"{zero_ipv4} localhost")[0], [])
    check("mixed hosts mapping skips localhost but retains the block alias",
          compile_line("hosts", f"{zero_ipv4} localhost ads.example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("host record preserves exact-host scope", compile_line("hosts", f"{zero_ipv4} Ads.Example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("domain-only preserves subtree scope", compile_line("domains", "Ads.Example.com")[0],
          ["||ads.example.com^"])
    check("DNS subtree rule is preserved verbatim", compile_line("dns", "||Ads.Example.com^")[0],
          ["||Ads.Example.com^"])
    check("DNS wildcard rule is preserved verbatim", compile_line("dns", "||MobileAnalytics.*.AmazonAWS.com^")[0],
          ["||MobileAnalytics.*.AmazonAWS.com^"])
    check("DNS exception is preserved verbatim", compile_line("dns", "@@||Ads.Example.com^")[0],
          ["@@||Ads.Example.com^"])
    check("DNS wildcard exact-host exception uses existing filter syntax",
          compile_line("dns", "@@||cdn.us*.exponea.com^|")[0],
          ["@@||cdn.us*.exponea.com^|"])
    check("unanchored separator and wildcard filters remain unchanged",
          compile_line("dns", "-adx-*.rayjump.com^")[0],
          ["-adx-*.rayjump.com^"])
    check("DNS leading-dot mask without caret is converted safely",
          compile_line("dns", ".3.n.2.1.l50.js")[0],
          ["||*.3.n.2.1.l50.js^"])
    check("DNS inline comment is ignored", compile_line("dns", "example.com # source note")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("Adblock-compatible DNS exception end-anchor rule is preserved verbatim",
          compile_line("dns", "@@||example.com^|")[0],
          ["@@||example.com^|"])
    check("DNS partial domain anchor keeps prefix semantics", compile_line("dns", "||advertising.civitai.")[0],
          ["||advertising.civitai."])
    check("DNS leading-dot rule is preserved when already valid network syntax",
          compile_line("dns", ".example.com^")[0],
          [".example.com^"])
    check("anchored DNS hostname regex compiles to URL authority regex",
          compile_line("dns", "/^(?:\\w+\\.)*minepi\\.com$/")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?(?:(?:\w+\.)*minepi\.com)(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("DNS IPv4 address regex is URL-scoped",
          compile_line("dns", f"/^{test_ipv4_regex}:/")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?" + test_ipv4_regex + r":/"])

    raw_path_dns_regex = r"/^.*\.(live|buzz)/.*&[a-z]{1,3}=[a-zA-Z0-9%]{250,}\$/$document"
    portable_path_dns_regex = r"/^.*\.(live|buzz)\/.*&[a-z]{1,3}=[a-zA-Z0-9%]{250,}\$/$document"
    check("DNS-source URL regex escapes literal path slashes without changing its match",
          compile_line("dns", raw_path_dns_regex, target="universal")[0],
          [portable_path_dns_regex])
    check("slash-prefixed ABP substring rule is not mistaken for an unclosed DNS regex",
          compile_line("dns", "/btn_share_fb.", target="universal")[0],
          ["/btn_share_fb."])
    check("DNS-source common request modifier is preserved as native filtering syntax",
          compile_line("dns", ".microsoft.com.chrome.$document", target="universal")[0],
          [".microsoft.com.chrome.$document"])
    check("DNS-source slash-prefixed request rule with document modifier is preserved",
          compile_line("dns", "/scan-update-and-protect-your-browser.html$document", target="universal")[0],
          ["/scan-update-and-protect-your-browser.html$document"])

    universal_dns_source = Source("https://example.invalid/universal-dns-rules.txt", "dns")
    universal_dns_state = compile_fetched_sources(
        [(universal_dns_source,
          ".avito.www.booking.$all\n"
          r"/^142\.91\.159\.[12]?\d?\d$/$network" + "\n"
          ".microsoft.com.chrome.$document\n"
          + raw_path_dns_regex + "\n")],
        "universal",
    )
    check("DNS-source rules with nonportable $all and $network are excluded by target policy",
          len(universal_dns_state.target_exclusions), 2)
    check("DNS-source rules rejected by target policy are not parser errors",
          len(universal_dns_state.issues), 0)
    check("DNS-source rule with shared $document semantics remains published",
          ".microsoft.com.chrome.$document" in universal_dns_state.records, True)
    check("URL-path regex survives the full universal source compilation pipeline",
          portable_path_dns_regex in universal_dns_state.records, True)

    url_scoped_test_regex = r"/(https?:\/\/)" + test_ipv4_regex + r".{100,}/"
    check("URL-scoped regex remains a URL-scoped regex", compile_line("dns", url_scoped_test_regex)[0],
          [url_scoped_test_regex])
    unanchored_dns_regex = "/" + test_ipv4_regex + "/"
    check("unanchored DNS regex already valid for URL matching is preserved",
          compile_line("dns", unanchored_dns_regex)[0],
          [unanchored_dns_regex])
    check("hash character inside native URL regex is preserved",
          compile_line("dns", r"/https?:\/\/example\.com\/path#frag/")[0],
          [r"/https?:\/\/example\.com\/path#frag/"])
    check("DNS hostname regex with nested groups is URL-scoped",
          compile_line("dns", r"/^(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com$/")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?(mon|tue|wed|thu|fri|sat|sun)\d{1,2}\.\w{2}\d{1,6}\w{4}\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
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
    check("AdGuard accepts uBO-compatible +js syntax", compile_line("adblock", "example.com##+js(no-such-scriptlet)")[0],
          ["example.com##+js(no-such-scriptlet)"])
    check("native IPv4 host rules are preserved", compile_line("adblock", ip_host_rule)[0],
          [ip_host_rule])
    check("bare IPv4 browser rule is normalized to a host-anchored rule",
          compile_line("adblock", test_ipv4)[0],
          [ip_host_rule])
    check("bare IPv4 browser exception is normalized and remains an exception",
          compile_line("adblock", f"@@{test_ipv4}")[0],
          [f"@@{ip_host_rule}"])
    check("bare IPv4 host normalization preserves important modifier",
          compile_line("adblock", f"{test_ipv4}$important")[0],
          [f"{ip_host_rule}$important"])
    check("leading-zero IPv4 octets normalize to canonical decimal form",
          compile_line("adblock", test_ipv4_leading_zero)[0],
          [ip_host_rule])
    multi_zero_octets = tuple(range(4, 8))
    multi_zero_ipv4 = ".".join(
        f"{octet:03d}" if index == 0 else str(octet)
        for index, octet in enumerate(multi_zero_octets)
    )
    multi_zero_expected = "||" + ".".join(str(octet) for octet in multi_zero_octets) + "^"
    check("multiple leading zeroes in an IPv4 octet normalize to canonical decimal form",
          compile_line("adblock", multi_zero_ipv4)[0],
          [multi_zero_expected])
    try:
        compile_line("adblock", invalid_test_ipv4)
    except CompilationError:
        tests.append(("invalid dotted-quad IP is rejected", True, True))
    else:
        raise AssertionError("invalid IPv4 literals must not be published as raw rules")
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
    check("Lite manifest URLs are unique", len({source.url for source in configured_sources}), len(urls))
    check("all Lite manifest sources remain pending content detection",
          [source.kind for source in configured_sources],
          ["auto"] * len(urls))
    print(f"Passed {len(tests)} semantic regression checks.")

def main() -> int:
    parser = argparse.ArgumentParser(description="Compile upstream blocklists into an AdGuard network filter for the selected target, with explicit semantic-loss reporting.")
    parser.add_argument("--target", choices=sorted(TARGET_PROFILES), default=DEFAULT_TARGET, help=f"Target profile (default: {DEFAULT_TARGET}; universal = shared AdGuard/uBO MV2 subset)")
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
                label = "SOURCE FORMAT FAILED" if "unable to identify upstream content format" in message else "FETCH FAILED"
                print(f"[{label}] {source.kind}: {source.url}: {message}", file=sys.stderr)

    # 下载任务虽然并发执行，但完成先后受网络延迟影响；这里重新按配置清单中的原始顺序排列来源，确保后续统计和生成过程不受并发时序干扰。
    source_order = {source.url: index for index, source in enumerate(sources)}
    fetched.sort(key=lambda item: source_order[item[0].url])

    # 在正式编译前，先按上游元数据中明确关联的来源应用排除模式；如果存在必需的排除元数据，就必须确保该元数据成功读取。
    # 必需元数据加载失败时，只能执行诊断性编译并生成报告，不能在缺少上游排除语义的情况下发布可能包含错误规则的产物。
    metadata_failures: list[dict[str, str]] = []
    try:
        state, metadata_pattern_counts, metadata_config_url = compile_sources_with_metadata(
            fetched,
            args.target,
            require_metadata=any(source.kind == "exclusions" for source, _ in fetched),
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
        # 此处的回退编译仅用于收集可诊断的信息；下方的致命错误检查仍会中止发布，因此不会用缺少必需元数据的结果覆盖现有产物。
        state = compile_fetched_sources(fetched, args.target)
        metadata_pattern_counts = {}
        metadata_config_url = ADGUARD_SDNS_CONFIGURATION_URL
    state.issues.sort(key=lambda issue: (str(issue["source"]), int(issue.get("line") or 0)))
    report = build_report(state, source_failures=source_failures, output_path=args.output, target=args.target)
    report_path = Path(args.report)
    output_path = Path(args.output)

    # 即使严格编译因来源下载失败、语义转换问题或必需元数据缺失而终止，也先原子写入审计报告，保留失败来源、排除项和错误行供维护者排查。
    atomic_write_text(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    if metadata_failures:
        print(
            "ABORTED: required source-exclusion metadata is unavailable. "
            f"Existing output was not changed. Review {report_path}.",
            file=sys.stderr,
        )
        return 2

    format_detection_failures = [
        failure for failure in source_failures
        if "unable to identify upstream content format" in failure["error"]
    ]
    if format_detection_failures:
        print(
            f"ABORTED: {len(format_detection_failures)} source(s) have unknown or ambiguous formats. "
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

urls = load_upstream_urls("lite")

if __name__ == "__main__":
    raise SystemExit(main())
