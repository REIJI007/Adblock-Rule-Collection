#!/usr/bin/env python3
"""Independently merge upstream rule text, run the repository compilers, and compare A vs B."""
from __future__ import annotations

import collections
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

ROOT = Path.cwd()
OUT = ROOT / "semantic-diff-output"
OUT.mkdir(exist_ok=True)
TARGET = "chromium-mv3"
SCOPE_KINDS = {"adblock", "hosts", "domains", "domains-exact"}
SYSTEM_HOST_ALIASES = {
    "localhost", "localhost.localdomain", "localhost4", "localhost6",
    "ip6-localhost", "ip6-loopback",
}
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z", re.I)
IPV4_RULE = re.compile(r"(?P<exception>@@)?(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?P<tail>\$.*)?")
ANCHOR_RULE = re.compile(r"(?P<exception>@@)?(?P<anchor>\|\||\|)(?P<host>[^|^*/$]+)\^(?P<tail>\$.*)?")
IF_RE = re.compile(r"!#if\s+(.+)")
ELSE_RE = re.compile(r"!#else")
ENDIF_RE = re.compile(r"!#endif")
INCLUDE_RE = re.compile(r"!#include\s+(.+)")
SAFARI_AFFINITY_RE = re.compile(r"!#safari_cb_affinity(?:\([^)]*\))?")
DIRECTIVE_PREFIXES = ("!#if", "!#else", "!#endif", "!#include", "!#pragma", "!#safari_cb_affinity")
HASH_RULE_PREFIXES = ("##", "#@#", "#$#", "#?#", "#%#", "#@$#", "#@?#", "#@%#")

def load_module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load compiler: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

def run_compiler(tag: str, path: str):
    mod = load_module(path, f"audit_compiler_{tag}")
    captured: dict[str, tuple[str, str]] = {}
    original_fetch = mod.fetch_source

    def wrapped_fetch(source):
        fetched_source, text = original_fetch(source)
        captured[fetched_source.url] = (fetched_source.kind, text)
        return fetched_source, text

    mod.fetch_source = wrapped_fetch
    out_path = OUT / f"B_{tag}.txt"
    report_path = OUT / f"compiler_report_{tag}.json"
    old_argv = sys.argv[:]
    sys.argv = [
        path, "--target", TARGET, "--output", str(out_path),
        "--report", str(report_path),
    ]
    start = dt.datetime.now(dt.timezone.utc)
    try:
        rc = mod.main()
        error = None
    except BaseException as exc:
        rc = 99
        error = f"{type(exc).__name__}: {exc}"
    finally:
        sys.argv = old_argv
        mod.fetch_source = original_fetch
    report = {}
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            error = f"Unable to read compiler report: {exc}"
    roots = list(getattr(mod, "urls", []))
    return {
        "tag": tag, "module": mod, "captured": captured, "root_urls": roots,
        "output_path": out_path, "report_path": report_path, "report": report,
        "return_code": rc, "error": error, "started_at": start.isoformat(),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

def target_flags(mod) -> dict[str, bool]:
    flags = {name: False for name in mod.KNOWN_CONDITION_FLAGS}
    flags.update(mod.TARGET_PROFILES[TARGET])
    return flags

def eval_condition(expression: str, flags: dict[str, bool]) -> bool:
    """Independent boolean parser for the upstream !#if syntax."""
    tokens = []
    cursor = 0
    while cursor < len(expression):
        if expression[cursor].isspace():
            cursor += 1
            continue
        m = re.match(r"&&|\|\||[!()]|[A-Za-z_][A-Za-z0-9_]*", expression[cursor:])
        if not m:
            raise ValueError(f"unsupported condition token near {expression[cursor:]!r}")
        tokens.append(m.group(0))
        cursor += len(m.group(0))
    if not tokens:
        raise ValueError("empty conditional expression")
    pos = 0
    def primary():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end of condition")
        tok = tokens[pos]
        if tok == "!":
            pos += 1
            return not primary()
        if tok == "(":
            pos += 1
            value = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("missing ) in condition")
            pos += 1
            return value
        if tok in {"&&", "||", ")"}:
            raise ValueError(f"unexpected condition operator {tok}")
        pos += 1
        if tok.lower() == "true":
            return True
        if tok.lower() == "false":
            return False
        if tok not in flags:
            raise ValueError(f"unknown condition flag {tok}")
        return flags[tok]
    def parse_and():
        nonlocal pos
        value = primary()
        while pos < len(tokens) and tokens[pos] == "&&":
            pos += 1
            rhs = primary()
            value = value and rhs
        return value
    def parse_or():
        nonlocal pos
        value = parse_and()
        while pos < len(tokens) and tokens[pos] == "||":
            pos += 1
            rhs = parse_and()
            value = value or rhs
        return value
    result = parse_or()
    if pos != len(tokens):
        raise ValueError(f"unexpected condition token {tokens[pos]}")
    return result

def independent_expand(mod, captured, url, kind, stack=()):
    """Expand includes/conditions from captured bytes without using compiler expansion code."""
    if len(stack) >= 12:
        raise ValueError("include depth exceeds 12")
    if url in stack:
        raise ValueError("recursive include: " + " -> ".join((*stack, url)))
    if url not in captured:
        return [], [{"url": url, "error": "source was not captured by the compiler fetch"}]
    _, text = captured[url]
    flags = target_flags(mod)
    frames = []
    active = True
    rows, problems = [], []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().lstrip("\ufeff")
        m = IF_RE.fullmatch(line)
        if m:
            try:
                condition = eval_condition(m.group(1), flags)
            except Exception as exc:
                problems.append({"url": url, "line": line_no, "error": str(exc)})
                condition = False
            frames.append({"parent": active, "condition": condition, "else": False})
            active = active and condition
            continue
        if ELSE_RE.fullmatch(line):
            if not frames or frames[-1]["else"]:
                problems.append({"url": url, "line": line_no, "error": "!#else without a unique open !#if"})
                active = False
                continue
            frame = frames[-1]
            frame["else"] = True
            active = frame["parent"] and not frame["condition"]
            continue
        if ENDIF_RE.fullmatch(line):
            if not frames:
                problems.append({"url": url, "line": line_no, "error": "!#endif without !#if"})
                active = False
                continue
            frame = frames.pop()
            active = frame["parent"]
            continue
        if SAFARI_AFFINITY_RE.fullmatch(line):
            continue
        m = INCLUDE_RE.fullmatch(line)
        if m:
            if not active:
                continue
            include_path = m.group(1).strip()
            if len(include_path) >= 2 and include_path[0] == include_path[-1] and include_path[0] in {"'", '"'}:
                include_path = include_path[1:-1]
            include_url = urljoin(url, include_path)
            parsed = urlparse(include_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                problems.append({"url": url, "line": line_no, "error": f"invalid include URL: {include_url}"})
                continue
            if include_url not in captured:
                problems.append({"url": url, "line": line_no, "error": f"include not captured: {include_url}"})
                continue
            child_kind = captured[include_url][0]
            child_rows, child_problems = independent_expand(mod, captured, include_url, child_kind, (*stack, url))
            rows.extend(child_rows)
            problems.extend(child_problems)
            continue
        if any(line.startswith(p) for p in DIRECTIVE_PREFIXES):
            if active and line.startswith("!#pragma"):
                continue
            if active:
                problems.append({"url": url, "line": line_no, "error": f"unprocessed directive: {line[:120]}"})
            continue
        if active:
            rows.append({"source": url, "line": line_no, "kind": kind, "raw": line})
    if frames:
        problems.append({"url": url, "error": f"{len(frames)} unterminated conditional block(s)"})
    return rows, problems

def is_comment_or_header(line: str) -> bool:
    if not line or line.startswith("!") or line.startswith("["):
        return True
    if line.startswith("#") and not line.startswith(HASH_RULE_PREFIXES):
        return True
    return False

def canonical_hostname(value: str, allow_single_label=False):
    value = value.strip()
    if not value or value.endswith(".."):
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
    normalized = []
    try:
        for label in labels:
            ascii_label = label.encode("idna").decode("ascii").lower()
            if len(ascii_label) > 63 or not DOMAIN_LABEL.fullmatch(ascii_label):
                return None
            normalized.append(ascii_label)
    except UnicodeError:
        return None
    result = ".".join(normalized)
    return result if len(result) <= 253 else None

def canonical_host_or_ipv4(value: str, allow_single_label=False):
    try:
        ip = ipaddress.ip_address(value)
        return str(ip) if ip.version == 4 else None
    except ValueError:
        return canonical_hostname(value, allow_single_label=allow_single_label)

def exact_hostname_regex(hostname: str, exception=False):
    host = canonical_host_or_ipv4(hostname)
    if not host:
        return None
    body = r"^https?:\/\/(?:[^\/?#@]+@)?" + re.escape(host) + r"(?::[0-9]+)?(?:[\/?#]|$)"
    return ("@@" if exception else "") + "/" + body + "/"

def normalize_native(line: str):
    m = IPV4_RULE.fullmatch(line)
    if m:
        parts = [int(part, 10) for part in m.group("ip").split(".")]
        if any(part > 255 for part in parts):
            return line, None
        ip = ".".join(str(part) for part in parts)
        out = (m.group("exception") or "") + "||" + ip + "^" + (m.group("tail") or "")
        if out != line:
            # The source pattern was a substring-style bare-IP token; host anchoring narrows its scope.
            return out, "bare_ipv4_anchor_change"
        return out, None
    m = ANCHOR_RULE.fullmatch(line)
    if not m:
        return line, None
    host = canonical_host_or_ipv4(m.group("host"), allow_single_label=False)
    if not host:
        return line, None
    out = (m.group("exception") or "") + m.group("anchor") + host + "^" + (m.group("tail") or "")
    return out, "native_hostname_canonicalization" if out != line else None

def reference_outputs(kind: str, line: str):
    """Independent, deliberately limited reference mapping for known source formats."""
    line = line.strip()
    if is_comment_or_header(line):
        return [], None
    if kind == "adblock":
        out, category = normalize_native(line)
        return [out], category
    if kind == "hosts":
        body = line.split("#", 1)[0].strip()
        if not body:
            return [], None
        fields = body.split()
        if len(fields) < 2:
            return [], None
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            return [], None
        if not (address.is_unspecified or address.is_loopback):
            return [], None
        output = []
        for host in fields[1:]:
            domain = canonical_hostname(host)
            if not domain or domain in SYSTEM_HOST_ALIASES:
                continue
            transformed = exact_hostname_regex(domain)
            if transformed:
                output.append(transformed)
        return output, "hosts_to_exact_hostname_regex"
    if kind in {"domains", "domains-exact"}:
        candidate = line.split("#", 1)[0].strip()
        domain = canonical_hostname(candidate)
        if not domain:
            return [], None
        if kind == "domains":
            return ["||" + domain + "^"], "domains_to_subdomain_anchor"
        transformed = exact_hostname_regex(domain)
        return ([transformed] if transformed else []), "domains_exact_to_exact_hostname_regex"
    return [], None

def load_rules(path: Path):
    if not path.exists():
        return set()
    result = set()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip().lstrip("\ufeff")
            if not line or line.startswith("!"):
                continue
            if line.startswith("["):
                continue
            result.add(line)
    return result

def write_lines(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in sorted(rows):
            f.write(line + "\n")

def summarize_one(run):
    tag, mod, captured = run["tag"], run["module"], run["captured"]
    report = run["report"]
    target_excluded = report.get("target_exclusions", [])
    unsupported = report.get("unsupported_rules", [])
    excluded_locations = set()
    for item in target_excluded + unsupported:
        if item.get("source") and item.get("line") is not None:
            try:
                excluded_locations.add((item["source"], int(item["line"])))
            except (TypeError, ValueError):
                pass

    rows, expansion_problems = [], []
    for url in dict.fromkeys(run["root_urls"]):
        try:
            kind = mod.classify_source(url)
        except Exception as exc:
            expansion_problems.append({"url": url, "error": f"root classification failed: {exc}"})
            continue
        one, problems = independent_expand(mod, captured, url, kind)
        rows.extend(one)
        expansion_problems.extend(problems)

    raw_all, raw_scope = set(), set()
    scope_raw_by_kind = collections.defaultdict(set)
    source_counts = collections.Counter()
    expected = set()
    transform_outputs = collections.defaultdict(set)
    transform_examples = collections.defaultdict(list)
    skipped_due_compiler_issue = 0

    for row in rows:
        kind, line = row["kind"], row["raw"]
        if is_comment_or_header(line):
            continue
        if any(line.startswith(p) for p in DIRECTIVE_PREFIXES):
            continue
        raw_all.add(line)
        source_counts[kind] += 1
        if kind not in SCOPE_KINDS:
            continue
        raw_scope.add(line)
        scope_raw_by_kind[kind].add(line)
        if (row["source"], row["line"]) in excluded_locations:
            skipped_due_compiler_issue += 1
            continue
        outputs, category = reference_outputs(kind, line)
        for out in outputs:
            expected.add(out)
            if category and out != line:
                transform_outputs[category].add(out)
                if len(transform_examples[category]) < 12:
                    transform_examples[category].append({
                        "source": row["source"], "line": row["line"],
                        "input": line, "output": out,
                    })

    write_lines(OUT / f"A_all_raw_merged_{tag}.txt", raw_all)
    write_lines(OUT / f"A_browser_scope_raw_{tag}.txt", raw_scope)
    b_rules = load_rules(run["output_path"])
    exact = b_rules & raw_scope
    risk = (transform_outputs["bare_ipv4_anchor_change"] & b_rules) - exact
    safe_categories = [
        "hosts_to_exact_hostname_regex",
        "domains_to_subdomain_anchor",
        "domains_exact_to_exact_hostname_regex",
        "native_hostname_canonicalization",
    ]
    safe_union = set().union(*(transform_outputs[c] for c in safe_categories)) if safe_categories else set()
    safe_transformed = (safe_union & b_rules) - exact - risk
    modeled = exact | safe_transformed | risk
    unclassified = b_rules - modeled
    expected_missing = expected - b_rules

    def sample(values, n=25):
        return sorted(values)[:n]

    compiler_status = "success" if run["return_code"] == 0 and run["output_path"].exists() else "failed_or_partial"
    source_manifest = []
    for url, (kind, text) in sorted(captured.items()):
        source_manifest.append({
            "url": url, "kind": kind, "sha256_utf8": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "utf8_bytes": len(text.encode("utf-8")),
        })
    (OUT / f"source_manifest_{tag}.json").write_text(
        json.dumps({
            "tag": tag, "target": TARGET, "started_at_utc": run["started_at"],
            "finished_at_utc": run["finished_at"], "root_source_count": len(set(run["root_urls"])),
            "captured_source_count": len(captured), "sources": source_manifest,
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    safe_counts = {category: len(values & b_rules) for category, values in transform_outputs.items()}
    report_out = {
        "tag": tag,
        "target": TARGET,
        "compiler_status": compiler_status,
        "compiler_return_code": run["return_code"],
        "compiler_error": run["error"],
        "started_at_utc": run["started_at"],
        "finished_at_utc": run["finished_at"],
        "root_source_count": len(set(run["root_urls"])),
        "captured_source_count_including_includes": len(captured),
        "source_fetch_failures_reported_by_compiler": len(report.get("source_failures", [])),
        "sources_skipped_by_target_reported_by_compiler": report.get("sources_skipped_by_target"),
        "input_lines_skipped_by_target_reported_by_compiler": report.get("input_lines_skipped_by_target"),
        "known_target_excluded_rules_reported_by_compiler": len(target_excluded),
        "unsupported_rules_reported_by_compiler": len(unsupported),
        "compiler_output_unique_rules": report.get("unique_rule_count"),
        "A_all_raw_merged_unique_lines": len(raw_all),
        "A_browser_scope_raw_unique_lines": len(raw_scope),
        "A_browser_scope_unique_raw_lines_by_kind": {k: len(v) for k, v in sorted(scope_raw_by_kind.items())},
        "A_browser_scope_occurrences_by_kind": dict(sorted(source_counts.items())),
        "B_unique_rules_read_from_compiler_output": len(b_rules),
        "B_exact_raw_rule_matches": len(exact),
        "B_transformed_but_reference_equivalent": len(safe_transformed),
        "B_transformed_with_known_semantic_scope_change": len(risk),
        "B_unclassified_no_reference_mapping": len(unclassified),
        "B_conservative_semantics_supported_exact_plus_safe_conversion": len(exact) + len(safe_transformed),
        "B_conservative_semantics_supported_percent": round(100 * (len(exact) + len(safe_transformed)) / len(b_rules), 6) if b_rules else None,
        "B_known_semantic_scope_change_examples_count": len(risk),
        "reference_expected_unique_output_rules_before_dedup": len(expected),
        "reference_expected_output_rules_missing_from_B": len(expected_missing),
        "raw_scope_entries_skipped_at_known_compiler_issue_locations": skipped_due_compiler_issue,
        "independent_expansion_problems": expansion_problems[:100],
        "source_failures": report.get("source_failures", []),
        "target_exclusion_reason_counts": dict(collections.Counter(x.get("reason", "") for x in target_excluded)),
        "unsupported_reason_counts": dict(collections.Counter(x.get("reason", "") for x in unsupported)),
        "transformation_matches_in_B_by_category": safe_counts,
        "examples": {
            "exact_raw_matches": sample(exact, 20),
            "safe_transformed_matches": {
                category: sample(values & b_rules, 15)
                for category, values in transform_outputs.items()
            },
            "known_scope_change_matches": sample(risk, 20),
            "unclassified_B_rules": sample(unclassified, 50),
            "expected_output_rules_missing_from_B": sample(expected_missing, 50),
            "transformation_input_output_examples": dict(transform_examples),
        },
        "methodology": {
            "A_all_raw_merged": "Deduplicated active non-comment lines from the compiler's upstream manifest plus active recursive !#include sources, preserving their source syntax and excluding headers/comments/directives. This A intentionally mixes formats such as Adblock, hosts and domain lists.",
            "A_browser_scope_raw": "Subset of A from adblock, hosts, domains and domains-exact source families; DNS, CNAME and exclusion sources are outside the browser-filter target.",
            "B": "Fresh output generated by the repository's own script against the captured live sources; source content is SHA-256 recorded in source_manifest.",
            "exact": "Unique B rules that are byte-for-byte present as raw active rules in the in-scope A corpus.",
            "safe_converted": "Unique B rules generated by a separate reference mapping for host mappings, domain-only entries, exact-domain entries, and simple hostname canonicalization. These transformations preserve the intended HTTP(S) host scope under the documented source format.",
            "scope_changed": "Bare IPv4 token normalized to ||IPv4^; this can narrow an unanchored substring match to a host-anchored match, so it is not counted as semantics-preserving.",
            "unclassified": "B rules that neither directly match an in-scope raw source line nor match one of the independently modeled conversions. This is unknown, not automatically a semantic error.",
            "limitation": "This is a conservative source-to-output equivalence audit, not a full execution of the AdGuard runtime on every possible URL. Exact matches are text-identical; converted matches are only counted when covered by the explicitly modeled mapping."
        },
    }
    (OUT / f"differential_report_{tag}.json").write_text(
        json.dumps(report_out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"[{tag}] status={compiler_status}; A-all={len(raw_all):,}; "
        f"A-browser={len(raw_scope):,}; B={len(b_rules):,}; "
        f"exact={len(exact):,}; safe-converted={len(safe_transformed):,}; "
        f"scope-change={len(risk):,}; unclassified={len(unclassified):,}; "
        f"supported={report_out['B_conservative_semantics_supported_percent']}%"
    )
    return report_out

def main():
    combined = {
        "audit_generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": TARGET,
        "repository": "REIJI007/Adblock-Rule-Collection",
        "results": {},
        "notes": [
            "Do not interpret unclassified rules as semantic mismatches without follow-up.",
            "This audit deliberately does not use the compiler's rule-conversion function to build A.",
            "Known bare-IPv4 anchoring changes are reported separately and excluded from the conservative semantics-preserved count.",
        ],
    }
    failures = []
    for tag, path in [
        ("main", "Adblock_Rule_Generator.py"),
        ("lite", "Adblock_Rule_Generator_Lite.py"),
    ]:
        print(f"Running project compiler and capturing live inputs for {tag}...")
        run = run_compiler(tag, path)
        if run["error"]:
            failures.append({"tag": tag, "error": run["error"]})
        combined["results"][tag] = summarize_one(run)
    combined["execution_errors"] = failures
    (OUT / "differential_summary.json").write_text(
        json.dumps(combined, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (OUT / "differential_summary.md").open("w", encoding="utf-8") as f:
        f.write("# 上游原始合并产物 A vs 项目脚本产物 B\n\n")
        f.write(f"- 审计时间（UTC）：{combined['audit_generated_at_utc']}\n")
        f.write(f"- 目标：{TARGET}\n\n")
        f.write("| 版本 | A 原始去重行数（全部来源） | A 浏览器范围行数 | B 唯一规则 | 原样一致 | 安全转换一致 | 范围变化转换 | 未建立对应 | 保守一致率 |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for tag, r in combined["results"].items():
            f.write(
                f"| {tag} | {r['A_all_raw_merged_unique_lines']:,} | {r['A_browser_scope_raw_unique_lines']:,} | "
                f"{r['B_unique_rules_read_from_compiler_output']:,} | {r['B_exact_raw_rule_matches']:,} | "
                f"{r['B_transformed_but_reference_equivalent']:,} | {r['B_transformed_with_known_semantic_scope_change']:,} | "
                f"{r['B_unclassified_no_reference_mapping']:,} | {r['B_conservative_semantics_supported_percent']}% |\n"
            )
        f.write("\n## 口径\n\n")
        f.write("“保守一致率”只包含原样一致与独立参考映射确认的安全转换。已知可能改变匹配范围的裸 IPv4 转换单独列出；未建立对应的规则标为未知，不能直接认定为错误。该审计是来源规则到输出规则的保守差分，不是对所有 URL 执行完整 AdGuard 引擎的形式化证明。\n")
    print("Audit files written to", OUT)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
