# -*- coding: utf-8 -*-
"""基于下载内容识别上游过滤源格式，不使用 URL、文件名或人工映射。"""

from __future__ import annotations

import ipaddress
import re


SUPPORTED_SOURCE_KINDS = {
    "adblock",
    "hosts",
    "domains",
    "domains-exact",
    "dns",
    "cname",
    "exclusions",
    "empty",
}


class SourceFormatDetectionError(ValueError):
    """内容不足以唯一确定来源格式或语义时抛出。"""


_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", re.IGNORECASE)
_DNS_MODIFIER_RE = re.compile(
    r"\$(?:client|dnstype|dnsrewrite|ctag)(?:=|,|$)", re.IGNORECASE
)
_NATIVE_RULE_MARKERS = (
    "||",
    "@@",
    "##",
    "#@#",
    "#$#",
    "#$@#",
    "#?#",
    "#@?#",
    "#%#",
    "#@%#",
    "$",
)


def _is_hostname(value: str, *, allow_single_label: bool = False) -> bool:
    value = value.rstrip(".")
    if not value or len(value) > 253 or "/" in value or "\\" in value:
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = value.split(".")
    if not allow_single_label and len(labels) < 2:
        return False
    return all(
        len(label) <= 63 and _HOST_LABEL_RE.fullmatch(label) is not None
        for label in labels
    )


def _is_hosts_mapping(line: str) -> bool:
    fields = line.split("#", 1)[0].split()
    if len(fields) < 2:
        return False
    try:
        ipaddress.ip_address(fields[0])
    except ValueError:
        return False
    return all(_is_hostname(host, allow_single_label=True) for host in fields[1:])


def _looks_like_native_rule(line: str) -> bool:
    """判断单行是否符合 ABP/EasyList 网络或元素过滤规则的基本词法形态。

    ABP 的网络过滤 pattern 可以是任意无空白 URL 子串，不要求必须以 || 开头；
    因此 -ads、.ashx?adid=、://tracker.example/、page_view_count 等均是合法
    pattern。带空白的行只有在包含已知 cosmetic/extended-CSS 操作符时才接受。
    """
    if not line or line != line.strip():
        return False
    if line.startswith(("||", "@@||", "|", "@@|", "*", "/")):
        return True
    if any(marker in line for marker in _NATIVE_RULE_MARKERS[2:]):
        return True
    if re.search(r"\S+#(?:@)?\$?#", line) is not None:
        return True
    if "://" in line:
        return True
    if re.fullmatch(r"\S+", line):
        return True
    return False


def classify_source_content(content: str) -> str:
    """仅依据完整文本中的语法与自描述元数据识别来源类型。

    对存在多种合理解释的内容直接失败，不使用 URL 路径、域名、扩展名或
    来源清单中的位置推断语义。
    """
    if not isinstance(content, str):
        raise SourceFormatDetectionError("upstream content must be text")
    if not content.strip():
        # A genuinely empty feed has no active entries and needs no parser.
        # The compiler records it as empty-noop; non-empty unknown content still fails closed.
        return "empty"

    lines = content.lstrip("\ufeff").splitlines()
    title = ""
    description = ""
    comments: list[str] = []
    active: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(
            r"\[(?:Adblock Plus|AdGuard)(?:\s+\d+(?:\.\d+)*)?\]",
            line,
            re.IGNORECASE,
        ):
            comments.append(line)
            continue
        if line.startswith("!"):
            comments.append(line)
            metadata = re.match(r"!\s*(title|description)\s*:\s*(.*)", line, re.IGNORECASE)
            if metadata:
                key, value = metadata.group(1).lower(), metadata.group(2).strip()
                if key == "title":
                    title = value
                else:
                    description = value
            continue
        if line.startswith("#") and not line.startswith(("#@", "##", "#$", "#?")):
            continue
        active.append(line)

    if not active:
        # 空清单没有待解析的规则，因此无需猜测格式；编译器会把它作为 no-op 记录，不输出任何规则。
        return "empty"

    metadata_text = f"{title} {description}".lower()

    # AdGuard DNS exclusions 是关联来源的元数据选择器，不是普通拦截清单。
    # 该文件的自有内容特征是大量指向旧 AdGuardDNS issue tracker 的注释。
    legacy_dns_issue_refs = sum(
        1
        for line in comments
        if re.search(
            r"github\.com/AdguardTeam/AdguardDNS/issues/\d+",
            line,
            re.IGNORECASE,
        )
    )
    if legacy_dns_issue_refs >= 30:
        return "exclusions"

    # 原始 CNAME tracker 与 disguised microsites 需要 DNS/CNAME 感知处理。
    # 普通 disguised ads 列表虽含 CNAME 描述，但其内容是常规网络过滤规则。
    if (
        "cname" in metadata_text
        and (
            "original tracker" in metadata_text
            or "original trackers" in metadata_text
            or "microsite" in metadata_text
        )
    ):
        return "cname"

    if re.search(
        r"\b(?:dns\s+(?:filter|blocklist|rules?)|(?:filter|blocklist)\s+for\s+dns)\b",
        metadata_text,
    ):
        return "dns"

    dns_specific_entries = [line for line in active if _DNS_MODIFIER_RE.search(line)]
    if dns_specific_entries:
        return "dns"

    hosts_entries = [line for line in active if _is_hosts_mapping(line)]
    if hosts_entries:
        if len(hosts_entries) != len(active):
            samples = [line for line in active if not _is_hosts_mapping(line)][:3]
            raise SourceFormatDetectionError(
                "mixed hosts mappings and other rule syntax; refusing to choose a parser "
                f"(non-host samples: {samples!r})"
            )
        return "hosts"

    if all(_is_hostname(line) for line in active):
        if re.search(r"\bexact[- ]host(?:s)?\b|\bexact domains? only\b", metadata_text):
            return "domains-exact"
        if re.search(
            r"\b(?:all|including|with|and)\s+(?:its\s+|their\s+)?subdomains?\b"
            r"|\bdomains?\s+and\s+subdomains?\b",
            metadata_text,
        ):
            return "domains"
        raise SourceFormatDetectionError(
            "plain domain entries do not declare exact-host versus domain-and-subdomain scope"
        )

    native_entries = [line for line in active if _looks_like_native_rule(line)]
    if native_entries:
        if len(native_entries) != len(active):
            samples = [line for line in active if not _looks_like_native_rule(line)][:3]
            raise SourceFormatDetectionError(
                "mixed native filter rules and unrecognized entries; refusing to guess "
                f"(unrecognized samples: {samples!r})"
            )
        return "adblock"

    samples = active[:3]
    raise SourceFormatDetectionError(
        "content does not match a uniquely supported format "
        f"(active-entry samples: {samples!r})"
    )
