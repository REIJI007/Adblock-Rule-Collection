# -*- coding: utf-8 -*-
"""读取并校验 Main 与 Lite 共用的上游 URL 配置文件。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONFIG_PATH = Path(__file__).resolve().with_name("upstream_sources.json")
SUPPORTED_PROFILES = {"main", "lite"}


class UpstreamConfigError(ValueError):
    """当集中式上游配置无法读取、结构不符合要求，或指定来源组未通过数据校验时抛出此异常。该异常继承 ValueError，便于调用方将配置错误与普通下载或规则编译错误区分处理。"""


def load_upstream_urls(profile: str) -> list[str]:
    """根据生成器配置组名称，读取并返回对应的上游 URL 列表，数组原有顺序会完整保留。

    Main 和 Lite 的订阅地址统一保存在同目录的 upstream_sources.json 中；调用方分别传入 main 或 lite，便可取得各自独立的来源清单。返回前会检查配置版本、分组结构、列表非空、字符串首尾空白、HTTPS 前缀和组内重复 URL；此函数只验证配置格式，不会实际访问上游站点或判断订阅是否在线。
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
