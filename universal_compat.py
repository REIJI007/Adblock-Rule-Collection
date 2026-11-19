# -*- coding: utf-8 -*-
"""Conservative syntax contract for the shared Main/Lite subscriptions.

This module deliberately accepts a portable ABP/EasyList subset rather than
trying to emulate every engine-specific extension. It is a publish-time safety
gate, not a complete implementation of any browser's filter parser.
"""
from __future__ import annotations

import re

# Concrete environments whose conditionally-selected rules must all intersect.
UNIVERSAL_TARGETS = (
    "adguard-windows",
    "chromium",              # AdGuard Browser Extension, MV2
    "firefox",               # AdGuard Browser Extension, MV2
    "ublock-origin-chromium",# uBlock Origin, MV2
    "ublock-origin-firefox", # uBlock Origin, MV2
)

# Network request types and modifiers with a conservative common interpretation.
_RESOURCE_TYPES = {
    "script", "image", "stylesheet", "object", "xmlhttprequest",
    "subdocument", "font", "media", "popup", "other", "document",
}
_COMMON_FLAGS = {
    "third-party", "3p", "match-case", "important", "badfilter",
}
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", re.I)

# These operators are engine extensions or require a runtime not shared by all
# three products. Keep the check explicit so new upstream syntax fails closed.
_COSMETIC_MARKERS_UNSUPPORTED = (
    "#@$?#", "#$?#", "#@?#", "#?#", "#$#", "#%#", "#@%#",
)
_COSMETIC_MARKERS_SUPPORTED = ("#@#", "##")

def _valid_domain_modifier(value: str) -> bool:
    if not value:
        return False
    for item in value.split("|"):
        item = item.strip()
        if not item:
            return False
        if item.startswith("~"):
            item = item[1:]
        if item == "*":
            continue
        if item.startswith("*."):
            item = item[2:]
        if not item or len(item) > 253 or item.startswith(".") or item.endswith("."):
            return False
        labels = item.split(".")
        if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
            return False
    return True

def _basic_css_selector(selector: str) -> bool:
    """Accept ordinary CSS selectors; reject scriptlets and procedural syntax."""
    selector = selector.strip()
    if not selector or any(ch in selector for ch in "{};\\n\\r"):
        return False
    lowered = selector.lower()
    forbidden = (
        "+js(", ":has-text(", ":contains(", ":matches-", ":matches(",
        ":xpath(", ":upward(", ":watch-attr(", ":remove(",
        ":remove-attr(", ":remove-class(", ":style(",
    )
    if any(token in lowered for token in forbidden):
        return False

    # Only a small, browser-native pseudo-class set is admitted. In particular,
    # no engine-specific procedural pseudo-classes or extended CSS operators.
    pseudo_pattern = re.compile(
        r":(?:not\\([^()]*\\)|nth-child\\([^()]*\\)|nth-of-type\\([^()]*\\)|"
        r"first-child|last-child|only-child|empty|root|checked|disabled|enabled|"
        r"focus|hover|active|visited|link|target|required|optional|valid|invalid|"
        r"read-only|read-write)(?![a-z0-9_-])",
        re.I,
    )
    without_pseudos = pseudo_pattern.sub("", selector)
    if ":" in without_pseudos:
        return False

    # CSS selectors used in filter lists must not contain executable content.
    return re.fullmatch(r"[A-Za-z0-9_.*#\\[\\]\\(\\)=~|^$'\"\\s>,+\\-]+", selector) is not None

def _cosmetic_rule_error(line: str) -> str | None:
    for marker in _COSMETIC_MARKERS_UNSUPPORTED:
        if marker in line:
            return f"cosmetic operator {marker!r} is outside the shared native-CSS subset"
    marker = next((m for m in _COSMETIC_MARKERS_SUPPORTED if m in line), None)
    if marker is None:
        return None

    domain_scope, selector_text = line.split(marker, 1)
    if "$$" in line:
        return "AdGuard HTML filtering is not part of the shared browser-filter syntax"
    if not selector_text.strip():
        return "empty cosmetic selector"
    if "+js(" in selector_text.lower():
        return "scriptlet injection is excluded because resource availability differs by engine"

    if domain_scope.strip():
        for domain in domain_scope.split(","):
            domain = domain.strip()
            if domain.startswith("~"):
                domain = domain[1:]
            if domain in {"", "*"}:
                continue
            # Cosmetic domain scopes are hostnames, not URLs or regexes.
            if not _valid_domain_modifier(domain):
                return f"unsupported cosmetic domain scope: {domain!r}"

    selectors = selector_text.split(",")
    if any(not _basic_css_selector(item) for item in selectors):
        return "selector is not in the conservative shared native-CSS subset"
    return None

def _split_network_pattern(line: str) -> tuple[str, list[str]] | None:
    body = line[2:] if line.startswith("@@") else line
    if not body:
        return None

    # Regex filters use slash delimiters. A dollar sign inside the regex body
    # must not be mistaken for the modifier separator.
    if body.startswith("/"):
        escaped = False
        end = None
        for index in range(1, len(body)):
            char = body[index]
            if escaped:
                escaped = False
            elif char == "\\\\":
                escaped = True
            elif char == "/":
                end = index
                break
        if end is None:
            return None
        pattern = body[: end + 1]
        tail = body[end + 1 :]
        if not tail:
            return pattern, []
        if not tail.startswith("$"):
            return None
        return pattern, [part.strip() for part in tail[1:].split(",")]

    pattern, separator, tail = body.partition("$")
    modifiers = [part.strip() for part in tail.split(",")] if separator else []
    return pattern, modifiers

def _portable_regex(pattern: str) -> bool:
    if len(pattern) < 2 or not pattern.startswith("/") or not pattern.endswith("/"):
        return False
    body = pattern[1:-1]
    unsupported = (
        "(?=", "(?!", "(?<=", "(?<!", "(?P", "(?>", "\\\\k<",
        "\\\\g<", "\\\\1", "\\\\2", "\\\\3", "\\\\A", "\\\\Z",
    )
    if any(token in body for token in unsupported):
        return False
    if re.search(r"(?:\\*|\\+|\\?|\\{\\d+(?:,\\d*)?\\})[+?]", body):
        return False
    try:
        re.compile(body)
    except re.error:
        return False
    return True

def universal_rule_error(raw_rule: str) -> str | None:
    """Return why a rule is not safe for the shared AdGuard/ uBO MV2 target."""
    line = raw_rule.strip()
    if not line or line.startswith("!") or line.startswith("["):
        return None
    if line.startswith("!#"):
        return "unexpanded filter preprocessor directive"
    if "$$" in line:
        return "AdGuard HTML filtering is not shared by all target engines"

    cosmetic_error = _cosmetic_rule_error(line)
    if cosmetic_error is not None:
        return cosmetic_error

    parsed = _split_network_pattern(line)
    if parsed is None:
        return "malformed or unsupported network-filter pattern"
    pattern, modifiers = parsed
    if not pattern or any(ch.isspace() for ch in pattern):
        return "empty or whitespace-containing network-filter pattern"

    if pattern.startswith("/"):
        if not _portable_regex(pattern):
            return "regular expression uses syntax outside the conservative shared subset"
    else:
        # Reject control characters and constructs that cannot be safely
        # interpreted as an ordinary ABP/EasyList URL pattern.
        if any(ord(ch) < 32 for ch in pattern):
            return "control character in network-filter pattern"

    seen: set[str] = set()
    for token in modifiers:
        if not token:
            return "empty network-filter modifier"
        key, equals, value = token.partition("=")
        key = key.strip().lower()
        if key in seen:
            return f"duplicate modifier: {key}"
        seen.add(key)

        negated = key.startswith("~")
        normalized = key[1:] if negated else key
        if normalized in _RESOURCE_TYPES:
            if equals:
                return f"resource-type modifier must not have a value: {key}"
            continue
        if normalized in _COMMON_FLAGS:
            if equals:
                return f"flag modifier must not have a value: {key}"
            continue
        if normalized == "domain" and equals and not negated:
            if not _valid_domain_modifier(value):
                return f"invalid or unsupported domain modifier: {value!r}"
            continue

        # Deliberately excluded: $app, $network, DNS modifiers, redirect /
        # script resources, CSP, removeparam, generic* exceptions, and uBO-
        # specific options. Similar spelling does not prove equal semantics.
        return f"modifier {key!r} is not in the shared ABP/EasyList compatibility contract"

    return None
