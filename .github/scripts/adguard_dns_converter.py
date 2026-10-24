import datetime
import ipaddress
import os
import re
from collections import Counter
from pathlib import Path
from zoneinfo import ZoneInfo


# 单个域名标签：字母数字开头结尾，中间可含连字符，总长不超过 63
DOMAIN_LABEL_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)

# 列表头部元数据，如 [Adblock Plus 2.0]、[AdGuard 1.0]，不属于过滤规则
ADBLOCK_HEADER_RE = re.compile(
    r"^\[(?:Adblock Plus|AdGuard)\s+\d+(?:\.\d+)*\]$",
    re.IGNORECASE,
)

# $dnstype 修饰符允许出现的 DNS 记录类型白名单
DNS_TYPES = set("""
    A AAAA A6 AFSDB AMTRELAY ANY APL ATMA AVC AXFR
    CAA CDNSKEY CDS CERT CNAME CSYNC DHCID DLV DNAME
    DNSKEY DOA DS EID EUI48 EUI64 GID GPOS HINFO HIP
    HTTPS IPSECKEY ISDN IXFR KEY KX L32 L64 LOC MAILA
    MAILB MB MD MF MG MINFO MR MX NAPTR NID NIMLOC NS
    NSAP NSAP-PTR NSEC NSEC3 NSEC3PARAM NULL NXT
    OPENPGPKEY OPT PTR PX RKEY RP RRSIG RT SIG SMIMEA
    SOA SPF SRV SSHFP SVCB TA TALINK TKEY TLSA TSIG TXT
    UINFO UID UNSPEC URI WKS ZONEMD
""".split())

# 本转换器仅接受的修饰符子集（其余依赖运行环境或存在兼容性问题，一律拒绝）
# AdGuard DNS-native modifiers. Browser-context modifiers are rejected,
# never stripped, because removing them can widen a rule's meaning.
ALLOWED_MODIFIERS = {
    "client",
    "denyallow",
    "dnstype",
    "dnsrewrite",
    "important",
    "respgeo",
}

class FatalConversionError(RuntimeError):
    # 致命错误：继续发布会导致规则语义不安全，必须中止整个流程
    pass

def canonical_domain(value: str, allow_underscore: bool = False):
    # Normalize a DNS name without changing its matching scope.
    # Underscore labels are accepted only where DNS owner names require them,
    # e.g. _sip._tcp.example.org in SRV-related rules.
    if not value or value != value.strip():
        return None

    if value.endswith(".."):
        return None

    if value.endswith("."):
        value = value[:-1]

    if not value or len(value) > 253 or "*" in value:
        return None

    try:
        labels = value.split(".")
        if any(not label for label in labels):
            return None

        ascii_labels = []
        for label in labels:
            if allow_underscore and "_" in label:
                ascii_label = label.lower()
                if not re.fullmatch(
                    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?",
                    ascii_label,
                ):
                    return None
            else:
                ascii_label = label.encode("idna").decode("ascii").lower()
                if len(ascii_label) > 63:
                    return None
                if not DOMAIN_LABEL_RE.fullmatch(ascii_label):
                    return None

            if len(ascii_label) > 63:
                return None
            ascii_labels.append(ascii_label)

        result = ".".join(ascii_labels)
        if len(result) > 253:
            return None

        try:
            ipaddress.ip_address(result)
            return None
        except ValueError:
            pass

        return result
    except (UnicodeError, ValueError):
        return None

def parse_dns_type_value(value: str):
    # Normalize DNS RR types. Per AdGuard DNS syntax, positive entries
    # dominate mixed positive/negative lists (e.g. ~A|AAAA == AAAA).
    if not value or value != value.strip():
        return None, "invalid dnstype value"

    components = value.split("|")
    if any(not item for item in components):
        return None, "empty dnstype entry"

    parsed = []
    for item in components:
        negated = item.startswith("~")
        type_name = item[1:] if negated else item
        if not type_name or not re.fullmatch(r"[A-Za-z0-9]+", type_name):
            return None, f"invalid dnstype name: {type_name}"
        type_name = type_name.upper()
        if type_name not in DNS_TYPES:
            return None, f"unsupported dnstype: {type_name}"
        parsed.append((negated, type_name))

    positives = sorted({name for negated, name in parsed if not negated})
    if positives:
        return "|".join(positives), None

    negatives = sorted({name for _, name in parsed})
    return "|".join("~" + name for name in negatives), None


def split_outside_quotes(value: str, separator: str):
    # Split outside quoted strings; preserve escapes so client names retain their meaning.
    parts = []
    current = []
    quote = None
    escaped = False

    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue

        if quote is not None and char == "\\":
            current.append(char)
            escaped = True
            continue

        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue

        if char in ("'", '"'):
            quote = char
            current.append(char)
        elif char == separator:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if quote is not None or escaped:
        return None, "unterminated quoted or escaped value"

    parts.append("".join(current).strip())
    return parts, None


def parse_denyallow_value(value: str):
    # denyallow's domain order does not affect semantics; normalize and sort it.
    if not value or value != value.strip():
        return None, "invalid denyallow value"

    raw_domains = value.split("|")
    if any(not item or item != item.strip() for item in raw_domains):
        return None, "empty or whitespace-padded denyallow domain"

    domains = []
    for raw_domain in raw_domains:
        domain = canonical_domain(raw_domain)
        if not domain:
            return None, f"invalid denyallow domain: {raw_domain}"
        domains.append(domain)

    if len(set(domains)) != len(domains):
        return None, "duplicate denyallow domain"

    return "|".join(sorted(domains)), None


def validate_client_value(value: str):
    # AdGuard DNS client entries may be IP/CIDR or client names; ~ excludes an entry.
    # Preserve the original value: client identifiers may be case-sensitive.
    if not value or value != value.strip():
        return None, "invalid client value"

    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None, "control character in client value"

    entries, error = split_outside_quotes(value, "|")
    if error:
        return None, error
    if any(not entry for entry in entries):
        return None, "empty client entry"

    for entry in entries:
        if entry.startswith("~"):
            item = entry[1:]
            if not item or item != item.strip():
                return None, "invalid whitespace or empty negated client entry"
        else:
            item = entry
        if not item:
            return None, "empty client entry"

        if item.startswith(("'", '"')):
            quote = item[0]
            if len(item) < 2 or item[-1] != quote:
                return None, "malformed quoted client name"
        elif any(char in item for char in ("'", '"', "\\")):
            return None, "quotes and escapes in client names must be quoted"
        elif any(char.isspace() for char in item):
            return None, "client names containing whitespace must be quoted"

    return value, None


def split_rule_pattern_modifiers(candidate: str):
    # A '$' inside an AdGuard DNS regex is regex syntax, not a modifier
    # delimiter. Find the closing slash before splitting modifiers.
    offset = 2 if candidate.startswith("@@") else 0
    body = candidate[offset:]

    if body.startswith("/"):
        escaped = False
        closing = None
        for index in range(1, len(body)):
            char = body[index]
            if char == "\\" and not escaped:
                escaped = True
                continue
            if char == "/" and not escaped and (
                index == len(body) - 1 or body[index + 1] == "$"
            ):
                closing = index
                break
            escaped = False

        if closing is not None:
            pattern = candidate[:offset + closing + 1]
            if closing == len(body) - 1:
                return pattern, None, None
            modifier_text = body[closing + 2:]
            parts, error = split_outside_quotes(modifier_text, "$")
            if error:
                return None, None, error
            if len(parts) != 1:
                return None, None, "multiple modifier delimiters"
            return pattern, parts[0], None

    parts, error = split_outside_quotes(candidate, "$")
    if error:
        return None, None, error
    if len(parts) > 2:
        return None, None, "multiple modifier delimiters"
    return parts[0], parts[1] if len(parts) == 2 else None, None


def normalize_dns_pattern(pattern: str):
    # Preserve AdGuard DNS hostname masks and regex rules. This deliberately
    # rejects browser URL/resource syntax rather than broadening its meaning.
    if not pattern or pattern != pattern.strip():
        return None, "empty or whitespace-padded hostname pattern"
    if any(ord(char) < 32 or ord(char) == 127 for char in pattern):
        return None, "control character in hostname pattern"

    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        expression = pattern[1:-1]
        # AdGuard DNS uses RE2-like regex semantics; reject Python-only
        # lookarounds/backreferences instead of silently changing meaning.
        if re.search(r"\(\?(?:[=!]|<[=!]|P=|\()|\\[1-9]|\\k<", expression):
            return None, "regex construct is not portable to AdGuard DNS"
        try:
            re.compile(expression)
        except re.error as error:
            return None, f"invalid regex pattern: {error}"
        return pattern, None

    if "/" in pattern or "\\" in pattern or "?" in pattern or "#" in pattern:
        return None, "unsupported hostname pattern character"

    prefix = ""
    body = pattern
    if body.startswith("||"):
        prefix, body = "||", body[2:]
    elif body.startswith("|"):
        prefix, body = "|", body[1:]

    suffix = ""
    if body.endswith("^"):
        suffix, body = "^", body[:-1]
    elif body.endswith("|"):
        suffix, body = "|", body[:-1]

    if not body:
        return None, "empty hostname mask"
    if "^" in body or "|" in body:
        return None, "separator or anchor is only supported at pattern boundaries"
    if len(body) > 253 or ".." in body:
        return None, "invalid hostname mask length or empty label"

    # A bare IP has a defined AdGuard DNS meaning (match domains resolving
    # to that IP). Anchoring it as a hostname mask is not equivalent.
    try:
        ip_literal = ipaddress.ip_address(body)
    except ValueError:
        ip_literal = None
    if ip_literal is not None:
        if prefix or suffix:
            return None, "IP literals cannot be used as anchored hostname masks"
        return str(ip_literal), None

    if "*" not in body and not body.startswith("."):
        normalized_domain = canonical_domain(body, allow_underscore=True)
        if normalized_domain:
            return prefix + normalized_domain + suffix, None

    # Wildcard and subdomain-only patterns must be ASCII to avoid ambiguous
    # IDNA normalization around wildcard labels.
    if not body.isascii():
        return None, "non-ASCII characters in wildcard hostname mask"

    labels = body.split(".")
    if body.startswith("."):
        labels = body[1:].split(".")
    if not labels or any(not label for label in labels):
        return None, "empty hostname-mask label"

    for label in labels:
        if not re.fullmatch(r"[A-Za-z0-9_*_-]+", label):
            return None, f"invalid hostname-mask label: {label}"

    return prefix + body.lower() + suffix, None


def validate_dnsrewrite_value(value: str):
    # Validate the AdGuard DNS $dnsrewrite forms documented by AdGuard:
    # RCODE keywords, IP/CNAME shorthand, and supported explicit RR records.
    if not value or value != value.strip():
        return None, "invalid dnsrewrite value"
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None, "control character in dnsrewrite value"

    rcodes = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP",
        "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH",
        "NOTZONE", "BADVERS", "BADKEY", "BADTIME", "BADMODE",
        "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE",
    }
    if value in rcodes:
        return value, None

    try:
        return str(ipaddress.ip_address(value)), None
    except ValueError:
        pass

    # Shorthand domain values are CNAME rewrites.
    if ";" not in value:
        domain = canonical_domain(value, allow_underscore=True)
        if domain:
            return domain, None
        return None, "unsupported dnsrewrite shorthand"

    parts = value.split(";", 2)
    if len(parts) != 3:
        return None, "dnsrewrite must use RCODE;RRTYPE;VALUE"
    rcode, rrtype, record_value = parts
    if rcode not in rcodes:
        return None, "unsupported or non-canonical dnsrewrite response code"

    if not rrtype:
        if not record_value:
            return f"{rcode};;", None
        return None, "dnsrewrite value without an RR type"

    rrtype = rrtype.upper()
    supported_types = {"A", "AAAA", "CNAME", "PTR", "MX", "TXT", "SRV", "HTTPS", "SVCB"}
    if rrtype not in supported_types:
        return None, f"unsupported dnsrewrite RR type: {rrtype}"
    if not record_value or record_value != record_value.strip():
        return None, "empty or whitespace-padded dnsrewrite record value"

    def record_name(name: str):
        if name == ".":
            return "."
        return canonical_domain(name, allow_underscore=True)

    if rrtype == "A":
        try:
            normalized_value = str(ipaddress.IPv4Address(record_value))
        except ValueError:
            return None, "dnsrewrite A record requires an IPv4 address"
    elif rrtype == "AAAA":
        try:
            normalized_value = str(ipaddress.IPv6Address(record_value))
        except ValueError:
            return None, "dnsrewrite AAAA record requires an IPv6 address"
    elif rrtype in {"CNAME", "PTR"}:
        normalized_value = record_name(record_value)
        if not normalized_value:
            return None, f"dnsrewrite {rrtype} record requires a valid domain"
    elif rrtype == "MX":
        fields = record_value.split()
        if len(fields) != 2 or not fields[0].isdigit():
            return None, "dnsrewrite MX record must be '<preference> <exchange>'"
        preference = int(fields[0])
        exchange = record_name(fields[1])
        if preference > 65535 or not exchange:
            return None, "invalid dnsrewrite MX preference or exchange"
        normalized_value = f"{preference} {exchange}"
    elif rrtype == "SRV":
        fields = record_value.split()
        if len(fields) != 4 or not all(field.isdigit() for field in fields[:3]):
            return None, "dnsrewrite SRV record must contain three integers and a target"
        numbers = [int(field) for field in fields[:3]]
        target = record_name(fields[3])
        if any(number > 65535 for number in numbers) or not target:
            return None, "invalid dnsrewrite SRV fields"
        normalized_value = " ".join(str(number) for number in numbers) + " " + target
    elif rrtype in {"HTTPS", "SVCB"}:
        fields = record_value.split()
        if len(fields) < 2 or not fields[0].isdigit():
            return None, f"dnsrewrite {rrtype} record must contain priority and target"
        priority = int(fields[0])
        target = record_name(fields[1])
        if priority > 65535 or not target:
            return None, f"invalid dnsrewrite {rrtype} priority or target"
        params = fields[2:]
        for param in params:
            if param == "no-default-alpn":
                continue
            if not re.fullmatch(r"[A-Za-z0-9-]+=[A-Za-z0-9:./_-]+", param):
                return None, f"unsupported dnsrewrite {rrtype} parameter: {param}"
        normalized_value = " ".join([str(priority), target] + params)
    else:  # TXT
        normalized_value = record_value

    return f"{rcode};{rrtype};{normalized_value}", None


def parse_respgeo_value(value: str):
    # respgeo values are either ISO-style country codes or ASNs, not a mix.
    if not value or value != value.strip():
        return None, "invalid respgeo value"
    entries = value.split("|")
    if any(not entry for entry in entries):
        return None, "empty respgeo entry"

    parsed = []
    categories = set()
    negations = set()
    for entry in entries:
        negated = entry.startswith("~")
        token = entry[1:] if negated else entry
        token = token.upper()
        if token in {"--", "AS--"}:
            category = "country" if token == "--" else "asn"
        elif re.fullmatch(r"AS[0-9]+", token):
            category = "asn"
        elif re.fullmatch(r"[A-Z]{2}", token):
            category = "country"
        else:
            return None, f"invalid respgeo entry: {entry}"
        categories.add(category)
        negations.add(negated)
        parsed.append(("~" if negated else "") + token)

    if len(categories) != 1:
        return None, "respgeo cannot mix country codes and ASNs"
    if len(negations) != 1:
        return None, "mixed positive and negative respgeo entries"
    return "|".join(sorted(set(parsed))), None


def parse_modifiers(modifier_text: str, allow_dnsrewrite_exception: bool = False):
    # Keep only modifiers documented by AdGuard DNS. Browser-only and
    # AdGuard Home-only modifiers are skipped rather than stripped.
    if not modifier_text:
        return None, "empty modifier list"

    raw_modifiers, split_error = split_outside_quotes(modifier_text, ",")
    if split_error:
        return None, split_error
    if any(not item for item in raw_modifiers):
        return None, "malformed modifier list"

    normalized = []
    seen = set()

    for token in raw_modifiers:
        key, separator, value = token.partition("=")
        key = key.strip().lower()
        value = value.strip()

        if not key:
            return None, "empty modifier name"
        if key == "badfilter":
            return None, "badfilter is not allowed in output rules"
        if key not in ALLOWED_MODIFIERS:
            return None, f"unsupported or non-portable modifier: {key}"
        if key in seen:
            return None, f"duplicate modifier: {key}"
        seen.add(key)

        if key == "important":
            if separator:
                return None, "important must not have a value"
            normalized.append(("important", None))
            continue

        if key == "dnsrewrite" and not separator:
            if allow_dnsrewrite_exception:
                normalized.append(("dnsrewrite", None))
                continue
            return None, "dnsrewrite requires a value except in exception rules"

        if not separator:
            return None, f"{key} requires a value"

        if key == "dnstype":
            parsed_value, error = parse_dns_type_value(value)
        elif key == "denyallow":
            parsed_value, error = parse_denyallow_value(value)
        elif key == "client":
            parsed_value, error = validate_client_value(value)
        elif key == "dnsrewrite":
            parsed_value, error = validate_dnsrewrite_value(value)
        elif key == "respgeo":
            parsed_value, error = parse_respgeo_value(value)
        else:
            return None, f"unsupported modifier: {key}"

        if error:
            return None, error
        normalized.append((key, parsed_value))

    normalized.sort(key=lambda item: item[0])
    result = []
    for key, value in normalized:
        result.append(key if value is None else f"{key}={value}")
    return ",".join(result), None


def parse_adguard_dns_rule(candidate: str, allow_exact_anchor=True):
    # Parse rules expressible in AdGuard DNS: hostname masks, regexes,
    # domain-only rules and documented DNS modifiers. Unsupported browser
    # syntax is rejected instead of being widened or silently rewritten.
    if not candidate:
        return None, "empty rule"
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return None, "control character in rule"

    allow_prefix = "@@" if candidate.startswith("@@") else ""
    if allow_prefix and candidate.startswith("@@@"):
        return None, "misplaced exception marker"

    pattern, modifier_text, split_error = split_rule_pattern_modifiers(candidate)
    if split_error:
        return None, split_error
    if allow_prefix:
        if not pattern.startswith("@@"):
            return None, "malformed exception rule"
        pattern = pattern[2:]
    elif pattern.startswith("@@"):
        return None, "misplaced exception marker"

    normalized_pattern, error = normalize_dns_pattern(pattern)
    if error:
        return None, error

    normalized = allow_prefix + normalized_pattern
    if modifier_text is not None:
        normalized_modifiers, error = parse_modifiers(
            modifier_text,
            allow_dnsrewrite_exception=bool(allow_prefix),
        )
        if error:
            return None, error
        normalized += "$" + normalized_modifiers

    return normalized, None


def parse_hosts_as_adguard(line: str):
    # 识别 Hosts 格式行，返回 (是否为Hosts行, 规则列表, 错误信息)
    # 仅将未指定地址（0.0.0.0 等）或环回地址视为屏蔽映射；
    # 其他 IP 映射无法等价表示为屏蔽规则，予以拒绝
    # Hosts 条目只作用于所列主机名本身，不含子域名，
    # 因此输出为 |domain^ 而非 ||domain^
    body = line.split("#", 1)[0].strip()

    if not body:
        return False, None, None

    parts = body.split()

    # 首段不是 IP 则不是 Hosts 行
    try:
        address = ipaddress.ip_address(parts[0])
    except (ValueError, IndexError):
        return False, None, None

    # A lone IP is valid AdGuard DNS domains-only syntax (it matches
    # domains resolving to that address), not an incomplete Hosts mapping.
    if len(parts) == 1:
        return False, None, None

    if len(parts) < 2:
        return True, None, "Hosts mapping has no hostname"

    if not (address.is_unspecified or address.is_loopback):
        return (
            True,
            None,
            "non-blocking Hosts IP mapping cannot be represented "
            "as an equivalent Adblock-style block rule",
        )

    domains = []

    for raw_domain in parts[1:]:
        domain = canonical_domain(raw_domain)

        if not domain:
            return (
                True,
                None,
                f"invalid hostname in Hosts mapping: {raw_domain}",
            )

        domains.append(domain)

    if not domains:
        return True, None, "Hosts mapping contains no valid hostname"

    return True, [f"|{domain}^" for domain in domains], None

def extract_badfilter(candidate: str):
    # Match badfilter to the exact normalized target rule, preserving @@ and
    # every other modifier. Regex end anchors remain part of the regex pattern.
    pattern, modifier_text, split_error = split_rule_pattern_modifiers(candidate)
    if split_error or modifier_text is None:
        return False, candidate

    tokens, split_error = split_outside_quotes(modifier_text, ",")
    if split_error:
        return False, candidate

    if not any(token.strip().lower() == "badfilter" for token in tokens):
        return False, candidate

    remaining = [
        token.strip() for token in tokens
        if token.strip().lower() != "badfilter"
    ]
    if remaining:
        return True, pattern + "$" + ",".join(remaining)
    return True, pattern


def classify_and_convert(line: str):
    # 对单行分类并转换，返回 (规则列表, 类型, 拒绝原因)
    # 类型为 "badfilter" 时，返回的规则是"被禁用的目标规则"，而不是要输出的规则
    candidate = line.strip()

    if not candidate:
        return [], "empty", None

    if candidate.startswith(("!", "#")):
        return [], "comment", None

    # 列表头部属于元数据，不是过滤规则
    if ADBLOCK_HEADER_RE.fullmatch(candidate):
        return [], "comment", None

    # 先尝试按 Hosts 格式解析
    recognized, hosts_rules, hosts_error = parse_hosts_as_adguard(
        candidate
    )

    if recognized:
        if hosts_error:
            return [], "rejected", hosts_error

        return hosts_rules, "hosts", None

    # 先剥离 badfilter，再按 AdGuard 规则解析（得到规范化的目标规则）
    is_badfilter, stripped = extract_badfilter(candidate)
    converted, error = parse_adguard_dns_rule(stripped)

    if error:
        return [], "rejected", error

    if is_badfilter:
        return [converted], "badfilter", None

    return [converted], "adblock-style", None

def compile_file(input_path: str, output_path: str, title: str):
    # 读取源文件、逐行转换并去重，返回生成结果（尚未写盘）
    source_path = Path(input_path)

    if not source_path.is_file():
        raise RuntimeError(f"required input file does not exist: {input_path}")

    # 严格 UTF-8 解码：源文件损坏时直接报错，不静默替换
    with source_path.open("r", encoding="utf-8-sig", newline=None) as source:
        input_lines = source.readlines()

    if not input_lines:
        raise RuntimeError(f"input file is empty: {input_path}")

    stats = Counter()
    # 收集所有 badfilter 指向的目标规则，待全部解析完后统一移除
    badfilter_targets = set()
    rejected_samples = []
    rules = []
    seen = set()

    for line_number, original_line in enumerate(input_lines, 1):
        line = original_line.rstrip("\r\n")

        try:
            converted, kind, reason = classify_and_convert(line)
        except FatalConversionError as error:
            # 补充文件名与行号后继续向上抛出
            raise FatalConversionError(
                f"{input_path}:{line_number}: {error}"
            ) from error

        # 记录被拒绝的行，并保留最多 25 条样例用于排查
        if reason:
            stats["rejected"] += 1
            stats[f"reason: {reason}"] += 1
            # Track rejected exceptions separately: they are potential allowlist
            # semantic gaps, not ordinary unsupported blocking rules.
            if line.strip().startswith("@@"):
                stats["rejected: exception rule"] += 1

            if len(rejected_samples) < 25:
                rejected_samples.append(
                    f"{input_path}:{line_number}: "
                    f"{reason}: {line.strip()[:240]}"
                )

            continue

        if not converted:
            if kind not in ("empty", "comment"):
                stats[f"skipped: {kind}"] += 1
            continue

        # badfilter 规则本身不输出，只记录其目标
        if kind == "badfilter":
            stats["converted: badfilter"] += 1
            badfilter_targets.update(converted)
            continue

        stats[f"converted: {kind}"] += len(converted)

        # 保持原有顺序去重
        for rule in converted:
            if rule in seen:
                stats["duplicates"] += 1
                continue

            seen.add(rule)
            rules.append(rule)

    # 应用 badfilter：全局移除与目标规则完全相同的规则（与出现顺序无关）
    # 注意：合并源已无上游边界，因此对所有上游来源一视同仁地生效
    if badfilter_targets:
        removed_targets = {
            rule for rule in rules if rule in badfilter_targets
        }
        rules = [
            rule for rule in rules if rule not in badfilter_targets
        ]
        stats["badfilter: removed"] = len(removed_targets)
        # 未匹配到任何规则的 badfilter（目标不存在或本就不被支持）
        stats["badfilter: unmatched"] = len(
            badfilter_targets - removed_targets
        )

    # 转换结果为空时拒绝覆盖现有输出，防止发布空列表
    if not rules:
        raise RuntimeError(
            f"{input_path}: conversion produced zero rules. "
            "Refusing to replace the existing output with an "
            "empty or effectively unusable list."
        )

    timestamp = datetime.datetime.now(
        ZoneInfo("Asia/Singapore")
    ).strftime("%Y-%m-%d %H:%M:%S %Z")

    header = (
        f"!Title: {title}\n"
        "!Description: 一个汇总了多个DNS过滤器规则的DNS过滤器，每20分钟更新一次，确保即时同步上游减少误杀\n"
        "!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection\n"
        "!LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL%203.0\n"
        "!LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA%204.0\n"
        f"!Generated: {timestamp}\n"
        f"!RuleCount: {len(rules)}\n"
    )

    document = header + "\n" + "\n".join(rules) + "\n"

    return {
        "input_path": input_path,
        "output_path": output_path,
        "title": title,
        "document": document,
        "rules": rules,
        "stats": stats,
        "input_lines": len(input_lines),
        "rejected_samples": rejected_samples,
    }

def validate_generated_document(result):
    # 在写入文件前逐条校验输出规则（忽略注释与元数据）
    # 要求：语法合法、已是规范形式、无重复、数量与生成结果一致
    output_path = result["output_path"]
    validated = 0
    seen = set()

    for line_number, line in enumerate(
        result["document"].splitlines(), 1
    ):
        candidate = line.strip()

        if not candidate or candidate.startswith(("!", "#")):
            continue

        normalized, error = parse_adguard_dns_rule(
            candidate,
            allow_exact_anchor=True,
        )

        if error:
            raise RuntimeError(
                f"{output_path}:{line_number}: output validation "
                f"failed: {error}: {candidate}"
            )

        # 重新规范化后必须与原文一致
        if normalized != candidate:
            raise RuntimeError(
                f"{output_path}:{line_number}: output is not in "
                f"canonical form: {candidate}"
            )

        if candidate in seen:
            raise RuntimeError(
                f"{output_path}:{line_number}: duplicate output rule: "
                f"{candidate}"
            )

        seen.add(candidate)
        validated += 1

    if validated == 0:
        raise RuntimeError(
            f"{output_path}: output validation found zero rules"
        )

    if validated != len(result["rules"]):
        raise RuntimeError(
            f"{output_path}: validated rule count does not match "
            "the generated rule count"
        )

def write_step_summary(results):
    # 将转换统计与拒绝报告写入 GitHub Actions 的步骤摘要
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    if not summary_path:
        return

    lines = [
        "## AdGuard DNS rule conversion",
        "",
        "| Input | Output | Input lines | Output rules | Rejected | Rejected exceptions | Duplicates | Badfilter removed | Badfilter unmatched |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for result in results:
        stats = result["stats"]
        lines.append(
            f"| `{result['input_path']}` "
            f"| `{result['output_path']}` "
            f"| {result['input_lines']} "
            f"| {len(result['rules'])} "
            f"| {stats['rejected']} "
            f"| {stats['rejected: exception rule']} "
            f"| {stats['duplicates']} "
            f"| {stats['badfilter: removed']} "
            f"| {stats['badfilter: unmatched']} |"
        )

    for result in results:
        stats = result["stats"]

        lines.extend([
            "",
            f"### Rejection report: `{result['input_path']}`",
            "",
        ])

        # 按出现次数降序、原因字典序排列
        reasons = sorted(
            (
                (key.removeprefix("reason: "), value)
                for key, value in stats.items()
                if key.startswith("reason: ")
            ),
            key=lambda item: (-item[1], item[0]),
        )

        if reasons:
            for reason, count in reasons:
                lines.append(f"- {count} × {reason}")
        else:
            lines.append("- No rejected rules.")

        if result["rejected_samples"]:
            lines.extend([
                "",
                "Representative rejected lines:",
                "",
            ])
            for sample in result["rejected_samples"]:
                # 替换反引号，避免破坏 Markdown 行内代码
                safe_sample = sample.replace("`", "'")
                lines.append(f"- `{safe_sample}`")

    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")

def run_semantic_self_tests():
    # Guard the most important semantic boundaries against future regressions.
    cases = [
        ("||Example.COM^", "||example.com^"),
        ("@@||Example.COM^", "@@||example.com^"),
        ("|Example.COM^", "|example.com^"),
        ("@@|Example.COM^", "@@|example.com^"),
        (
            "||example.org^$denyallow=Sub.example.org|safe.org",
            "||example.org^$denyallow=safe.org|sub.example.org",
        ),
        (
            "||example.org^$dnstype=AAAA|A",
            "||example.org^$dnstype=A|AAAA",
        ),
        (
            "||example.org^$important,dnstype=AAAA|A",
            "||example.org^$dnstype=A|AAAA,important",
        ),
        (
            "||example.org^$client='Home, $ TV'",
            "||example.org^$client='Home, $ TV'",
        ),
        (
            "@@||example.org^$important",
            "@@||example.org^$important",
        ),
        (
            "||EXAMPLE.org^$dnsrewrite=NOERROR;A;1.2.3.4",
            "||example.org^$dnsrewrite=NOERROR;A;1.2.3.4",
        ),
        (
            "||example.org^$dnsrewrite=example.net",
            "||example.org^$dnsrewrite=example.net",
        ),
        (
            "||_sip._tcp.example.org^$dnsrewrite=NOERROR;SRV;10 60 8080 example.org",
            "||_sip._tcp.example.org^$dnsrewrite=NOERROR;SRV;10 60 8080 example.org",
        ),
        (
            "||*.example.org^$respgeo=US|FR",
            "||*.example.org^$respgeo=FR|US",
        ),
        (
            "||example.org^$dnstype=~A|AAAA",
            "||example.org^$dnstype=AAAA",
        ),
        (
            "/example$/",
            "/example$/",
        ),
        (
            "example.org",
            "example.org",
        ),
        (
            "@@||example.org^$dnsrewrite",
            "@@||example.org^$dnsrewrite",
        ),
    ]

    for source_rule, expected in cases:
        actual, error = parse_adguard_dns_rule(source_rule)
        if error or actual != expected:
            raise RuntimeError(
                "Semantic self-test failed for "
                f"{source_rule!r}: got {actual!r}, error={error!r}"
            )

    # Browser-context restrictions must not be stripped into broader DNS rules.
    for unsupported_rule in (
        "||example.org^$script",
        "||example.org^$ctag=device_pc",
        "||example.org^$dnsrewrite=NOERROR;CAA;0 issue \"ca.example\"",
        r"/example(?=\.org)/",
    ):
        _, error = parse_adguard_dns_rule(unsupported_rule)
        if not error:
            raise RuntimeError(
                "Semantic self-test failed: unsupported or non-portable "
                f"rule must be rejected: {unsupported_rule!r}"
            )

    has_badfilter, target = extract_badfilter(
        "||example.org^$denyallow=sub.example.org,badfilter"
    )
    if not has_badfilter or target != "||example.org^$denyallow=sub.example.org":
        raise RuntimeError("Semantic self-test failed: badfilter target extraction")

    has_badfilter, target = extract_badfilter("@@||example.org^$badfilter")
    if not has_badfilter or target != "@@||example.org^":
        raise RuntimeError("Semantic self-test failed: exception badfilter target extraction")

    print("Semantic self-tests passed.")


def main():
    run_semantic_self_tests()

    # 待处理的 输入文件 -> 输出文件 映射（完整版与精简版）
    configurations = [
        {
            "input": "ADBLOCK_RULE_COLLECTION.txt",
            "output": "ADBLOCK_RULE_COLLECTION_DNS.txt",
            "title": "Adblock-Rule-Collection-DNS",
        },
        {
            "input": "ADBLOCK_RULE_COLLECTION_Lite.txt",
            "output": "ADBLOCK_RULE_COLLECTION_DNS_Lite.txt",
            "title": "Adblock-Rule-Collection-DNS-Lite",
        },
    ]

    results = [
        compile_file(
            config["input"],
            config["output"],
            config["title"],
        )
        for config in configurations
    ]

    # 全部转换并校验通过后才开始写盘，保证两个输出要么都更新、要么都不更新
    for result in results:
        validate_generated_document(result)

    # 先写入临时文件
    staged_files = []

    for result in results:
        output_path = Path(result["output_path"])
        temporary_path = output_path.with_name(
            output_path.name + ".tmp"
        )

        with temporary_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output:
            output.write(result["document"])

        staged_files.append((temporary_path, output_path))

    # 再以原子操作替换正式输出文件
    for temporary_path, output_path in staged_files:
        os.replace(temporary_path, output_path)

    write_step_summary(results)

if __name__ == "__main__":
    main()
