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
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z", re.IGNORECASE)
HOSTS_LINE_RE = re.compile(r"^\s*(\S+)\s+(.+?)\s*$")

# These are known non-portable uBlock Origin operators, not ordinary ABP rules.
# Do not silently publish them as if AdGuard had identical behavior.
NON_PORTABLE_NATIVE_PATTERNS = (
    # AdGuard has its own scriptlet syntax (#%#//scriptlet(...)); uBO's +js()
    # must not be passed through as though the two syntaxes were interchangeable.
    (re.compile(r"\+js\s*\(", re.IGNORECASE), "uBlock scriptlet syntax (+js) needs an explicit AdGuard scriptlet mapping"),
    # These procedural operators are not part of AdGuard's documented Extended CSS.
    (re.compile(r":matches-path\s*\(", re.IGNORECASE), "uBlock procedural operator :matches-path() has no verified AdGuard equivalent"),
    (re.compile(r":remove-(?:attr|class)\s*\(", re.IGNORECASE), "uBlock procedural DOM-removal operator has no verified AdGuard equivalent"),
)
DNS_ONLY_MODIFIER_RE = re.compile(r"(?:\$|,)(?:client|dnstype|dnsrewrite|ctag)(?:=|,|$)", re.IGNORECASE)

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
    error: str | None = None

@dataclass
class RuleRecord:
    text: str
    source_urls: set[str] = field(default_factory=set)
    source_lines: list[dict[str, object]] = field(default_factory=list)

@dataclass
class CompileState:
    records: dict[str, RuleRecord] = field(default_factory=dict)
    issues: list[dict[str, object]] = field(default_factory=list)
    summaries: dict[str, SourceSummary] = field(default_factory=dict)

def classify_source(url: str) -> str:
    """Explicit source-family adapter for the configured upstream manifest.

    New upstreams should be classified here before being added. The default is
    native Adblock syntax because the remaining URLs in the curated manifest are
    browser filter lists; it is not a content-sniffing fallback.
    """
    lowered = url.lower()
    if "adaway.org/hosts.txt" in lowered or (
        "hosts" in urllib.parse.urlparse(lowered).path.rsplit("/", 1)[-1]
        and "filter" not in urllib.parse.urlparse(lowered).path.rsplit("/", 1)[-1]
    ):
        return "hosts"
    if (
        "adguardteam/adguardsdnsfilter/" in lowered
        or "filter_15_dnsfilter/" in lowered
        or lowered.endswith("-agh.txt")
    ):
        return "dns"
    if "adguardteam/cname-trackers/" in lowered:
        return "domains"
    return "adblock"

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

def exact_hostname_regex_rule(hostname: str, *, exception: bool = False) -> str:
    """Compile an exact host block into an AdGuard URL-regex rule.

    This intentionally does not use ||host^, because that rule includes all
    subdomains. Scope is browser HTTP(S) URLs with this exact authority host.
    """
    domain = canonical_hostname(hostname)
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
    hostname = canonical_hostname(match.group("host"), allow_single_label=False)
    if not hostname:
        # It looks like a simple domain rule, so publishing it unchanged would
        # hide a parsing failure. Leave unsupported validation to strict audit.
        raise CompilationError(f"invalid domain in anchored rule: {line}")
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

def compile_dns_rule(line: str) -> str:
    """Translate only DNS rule forms whose browser-filter meaning is provable."""
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("@@"):
        raise CompilationError("misplaced DNS exception marker")

    # Regex filters operate on hostnames in DNS mode, but on full URLs in browser
    # mode; transforming arbitrary host regexes safely requires a real regex AST.
    if body.startswith("/") and body.endswith("/") and len(body) > 2:
        raise CompilationError("DNS hostname regex cannot be proven equivalent as a browser URL regex")

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
                normalized_entries = [canonical_hostname(entry, allow_single_label=False) for entry in entries]
                if any(entry is None for entry in normalized_entries):
                    raise CompilationError("invalid domain in denyallow modifier")
                normalized_modifiers.append("denyallow=" + "|".join(entry for entry in normalized_entries if entry))
            else:
                raise CompilationError(
                    f"DNS-only or unverified modifier cannot be represented safely in a browser filter: {token}"
                )
        modifiers = normalized_modifiers

    # Bare domains in DNS lists block exactly that hostname, not the subtree.
    if not pattern.startswith(("||", "|")) and not any(ch in pattern for ch in "*^/"):
        hostname = canonical_hostname(pattern, allow_single_label=False)
        if hostname:
            translated = exact_hostname_regex_rule(hostname, exception=exception)
            return translated + ("$" + ",".join(modifiers) if modifiers else "")
        raise CompilationError(f"unsupported DNS domain or address rule: {pattern}")

    # A single leading pipe has exact-host semantics in DNS filters; convert it
    # into an exact-host URL regex instead of changing it to a subtree rule.
    exact_match = re.fullmatch(r"\|([^|^*/$]+)\^", pattern)
    if exact_match:
        hostname = canonical_hostname(exact_match.group(1), allow_single_label=False)
        if not hostname:
            raise CompilationError(f"invalid exact DNS hostname: {pattern}")
        translated = exact_hostname_regex_rule(hostname, exception=exception)
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    # A standard domain-subtree rule has the same core meaning in browser rules.
    subtree_match = re.fullmatch(r"\|\|([^|^*/$]+)\^", pattern)
    if subtree_match:
        hostname = canonical_hostname(subtree_match.group(1), allow_single_label=False)
        if not hostname:
            raise CompilationError(f"invalid DNS hostname: {pattern}")
        translated = (("@@" if exception else "") + "||" + hostname + "^")
        return translated + ("$" + ",".join(modifiers) if modifiers else "")

    raise CompilationError(f"DNS rule pattern cannot be translated losslessly: {pattern}")

def compile_hosts_line(line: str) -> list[str]:
    body = line.split("#", 1)[0].strip()
    if not body:
        return []
    parts = body.split()
    try:
        address = ipaddress.ip_address(parts[0])
    except (ValueError, IndexError):
        raise CompilationError("not a valid hosts mapping")
    if len(parts) < 2:
        raise CompilationError("hosts mapping has no hostname")
    if not (address.is_unspecified or address.is_loopback):
        raise CompilationError(
            f"hosts address {address} is a name-to-IP mapping, not a block; "
            "it cannot be represented by a browser blocking rule"
        )
    output: list[str] = []
    for original_host in parts[1:]:
        hostname = canonical_hostname(original_host)
        if not hostname:
            raise CompilationError(f"invalid hosts alias: {original_host}")
        output.append(exact_hostname_regex_rule(hostname))
    return output

def compile_domain_line(line: str) -> str:
    # Domain-only files may contain inline comments after whitespace.
    candidate = line.split("#", 1)[0].strip()
    hostname = canonical_hostname(candidate, allow_single_label=False)
    if not hostname:
        raise CompilationError(f"not a valid domains-only entry: {candidate!r}")
    return exact_hostname_regex_rule(hostname)

def compile_line(kind: str, raw_line: str) -> tuple[list[str], str]:
    line = raw_line.strip()
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
        return compile_hosts_line(line), "hosts"

    if kind == "domains":
        return [compile_domain_line(line)], "domains"

    if kind == "dns":
        # DNS lists can contain either Adblock-style host rules or hosts entries.
        first = line.split(None, 1)[0] if line else ""
        try:
            ipaddress.ip_address(first)
            looks_like_hosts = True
        except ValueError:
            looks_like_hosts = False
        if looks_like_hosts:
            return compile_hosts_line(line), "hosts-in-dns"
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

def compile_fetched_sources(fetched: list[tuple[Source, str]]) -> CompileState:
    state = CompileState()
    for source, text in fetched:
        summary = SourceSummary(url=source.url, kind=source.kind, status="ok")
        state.summaries[source.url] = summary
        lines = text.splitlines()
        summary.input_lines = len(lines)
        for line_number, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            try:
                translated, category = compile_line(source.kind, line)
            except CompilationError as error:
                add_issue(state, summary, line_number, line, str(error))
                continue
            if category == "comment":
                summary.ignored_comments += 1
            for output_rule in translated:
                if output_rule in state.records:
                    state.records[output_rule].source_urls.add(source.url)
                    state.records[output_rule].source_lines.append({
                        "source": source.url,
                        "line": line_number,
                        "original": line[:300],
                    })
                    summary.duplicate_rules += 1
                else:
                    state.records[output_rule] = RuleRecord(
                        text=output_rule,
                        source_urls={source.url},
                        source_lines=[{
                            "source": source.url,
                            "line": line_number,
                            "original": line[:300],
                        }],
                    )
                    summary.emitted_rules += 1
    return state

def build_report(state: CompileState, *, source_failures: list[dict[str, str]], output_path: str) -> dict[str, object]:
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
            "unsupported_lines": summary.unsupported_lines,
            "error": summary.error,
        })
    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": "AdGuard browser filter syntax",
        "output": output_path,
        "unique_rule_count": len(state.records),
        "source_count": len(source_summaries) + len(source_failures),
        "source_summaries": source_summaries,
        "source_failures": source_failures,
        "unsupported_count": len(state.issues),
        "unsupported_rules": state.issues,
        "semantic_guarantee": (
            "Rules classified as native are preserved as Adblock-compatible syntax; "
            "hosts and domains-only entries become exact-host HTTP(S) URL regex rules; "
            "DNS rules are converted only for supported patterns/modifiers. "
            "This is not a proof for arbitrary regex or engine-specific rules."
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
    check("host record preserves exact-host scope", compile_line("hosts", "0.0.0.0 Ads.Example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("domain-only preserves exact-host scope", compile_line("domains", "Ads.Example.com")[0],
          [r"/^https?:\/\/(?:[^\/?#@]+@)?ads\.example\.com(?::[0-9]+)?(?:[\/?#]|$)/"])
    check("DNS subtree rule preserves subtree", compile_line("dns", "||Ads.Example.com^")[0],
          ["||ads.example.com^"])
    check("DNS exception preserves exception", compile_line("dns", "@@||Ads.Example.com^")[0],
          ["@@||ads.example.com^"])
    check("Adblock badfilter remains explicit", compile_line("adblock", "||Ads.Example.com^$badfilter")[0],
          ["||ads.example.com^$badfilter"])
    check("cosmetic rules are retained", compile_line("adblock", "example.com##.ad")[0],
          ["example.com##.ad"])
    check("comments are not emitted", compile_line("adblock", "! comment")[0], [])
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
    try:
        compile_line("adblock", "example.com##+js(no-such-scriptlet)")
    except CompilationError:
        tests.append(("uBlock-only scriptlet rejected", True, True))
    else:
        raise AssertionError("uBlock-specific scriptlet must not be silently published")
    try:
        compile_line("adblock", "||example.com^$dnstype=A")
    except CompilationError:
        tests.append(("DNS-only modifier rejected in native list", True, True))
    else:
        raise AssertionError("DNS-only modifiers must not be silently published as browser rules")
    print(f"Passed {len(tests)} semantic regression checks.")

def main() -> int:
    parser = argparse.ArgumentParser(description="Compile upstream blocklists into an AdGuard browser filter with explicit semantic-loss reporting.")
    parser.add_argument("--output", default=OUTPUT_DEFAULT, help=f"compiled filter path (default: {OUTPUT_DEFAULT})")
    parser.add_argument("--report", default=REPORT_DEFAULT, help=f"JSON compilation report (default: {REPORT_DEFAULT})")
    parser.add_argument("--allow-lossy", action="store_true", help="explicitly publish only translatable rules; report all omitted rules")
    parser.add_argument("--allow-source-failures", action="store_true", help="explicitly allow publishing without sources that failed to download")
    parser.add_argument("--self-test", action="store_true", help="run built-in regression tests without downloading upstreams")
    args = parser.parse_args()

    if args.self_test:
        run_regression_tests()
        return 0

    sources = build_sources(urls)
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
    state = compile_fetched_sources(fetched)
    state.issues.sort(key=lambda issue: (str(issue["source"]), int(issue["line"])))
    report = build_report(state, source_failures=source_failures, output_path=args.output)
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
        "! Homepage: https://github.com/REIJI007/Adblock-Rule-Collection",
        "! Generated: " + timestamp,
        "! RuleCount: " + str(len(rules)),
        "! CompileReport: " + report_path.name,
    ]
    if source_failures or state.issues:
        header.append("! WARNING: This is an explicitly requested partial/lossy compilation; see the JSON report.")
    document = "\n".join(header) + "\n\n" + "\n".join(rules) + "\n"
    atomic_write_text(output_path, document)

    print(f"Published {len(rules)} unique rules to {output_path}")
    print(f"Sources: {len(fetched)}/{len(sources)}; unsupported lines: {len(state.issues)}; source failures: {len(source_failures)}")
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


