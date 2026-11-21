# -*- coding: utf-8 -*-
"""Load and validate the shared upstream URL manifest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONFIG_PATH = Path(__file__).resolve().with_name("upstream_sources.json")
SUPPORTED_PROFILES = {"main", "lite"}


class UpstreamConfigError(ValueError):
    """Raised when the centralized upstream manifest is invalid."""


def load_upstream_urls(profile: str) -> list[str]:
    """Return the ordered URL list for a generator profile.

    All source URLs live in upstream_sources.json. The two generators select
    different named profiles while sharing the same manifest and validation.
    """
    if profile not in SUPPORTED_PROFILES:
        raise UpstreamConfigError(
            f"Unknown upstream profile {profile!r}; "
            f"expected one of {sorted(SUPPORTED_PROFILES)}"
        )

    try:
        payload: Any = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UpstreamConfigError(
            f"Unable to read upstream manifest {CONFIG_PATH}: {error}"
        ) from error

    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise UpstreamConfigError(
            "Invalid upstream manifest: expected a JSON object with schema_version=1"
        )

    profiles = payload.get("sources")
    if not isinstance(profiles, dict):
        raise UpstreamConfigError(
            "Invalid upstream manifest: 'sources' must be an object"
        )

    urls = profiles.get(profile)
    if not isinstance(urls, list) or not urls:
        raise UpstreamConfigError(
            f"Invalid upstream manifest: sources[{profile!r}] must be a non-empty array"
        )

    seen: set[str] = set()
    for index, url in enumerate(urls, start=1):
        if not isinstance(url, str) or not url or url != url.strip():
            raise UpstreamConfigError(
                f"Invalid URL at sources[{profile!r}][{index}]: expected a non-empty, trimmed string"
            )
        if not url.startswith("https://"):
            raise UpstreamConfigError(
                f"Invalid URL at sources[{profile!r}][{index}]: HTTPS is required"
            )
        if url in seen:
            raise UpstreamConfigError(
                f"Duplicate URL at sources[{profile!r}][{index}]: {url}"
            )
        seen.add(url)

    return list(urls)
