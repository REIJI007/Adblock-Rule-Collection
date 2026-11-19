# <h1 align="center">Adblock Rule Collection</h1>

<p align="center">
  多源广告过滤规则集合，自动整合、去重与转换规则。
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/REIJI007/Adblock-Rule-Collection?style=flat-square" alt="Stars">
  <img src="https://img.shields.io/github/forks/REIJI007/Adblock-Rule-Collection?style=flat-square" alt="Forks">
  <img src="https://img.shields.io/github/issues/REIJI007/Adblock-Rule-Collection?style=flat-square" alt="Issues">
</p>

## 订阅地址

| 类型 | 完整版 | 精简版 |
|---|---|---|
| 广告过滤 | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION.txt) | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_Lite.txt) |
| DNS | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DNS.txt) | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DNS_Lite.txt) |
| Hosts | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST.txt) | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST_Lite.txt) |
| Hosts IPv6 | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST_IPV6.txt) | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST_IPV6_Lite.txt) |
| 拦截域名列表 | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DOMAIN.txt) | [订阅](https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DOMAIN_Lite.txt) |


## 通用规则兼容范围

主规则与精简版规则（`ADBLOCK_RULE_COLLECTION.txt` / `ADBLOCK_RULE_COLLECTION_Lite.txt`）使用同一套保守的 ABP/EasyList 兼容语法契约，目标是：

- AdGuard for Windows
- AdGuard Browser Extension（MV2 规则能力）
- uBlock Origin（MV2 规则能力）

构建时会分别展开 AdGuard Windows、AdGuard 浏览器扩展 Chromium/Firefox MV2、uBlock Origin Chromium/Firefox MV2 的上游条件分支，只保留各目标均选择的规则，再执行共享语法白名单校验。引擎专属修饰符、HTML Filtering、Scriptlet、过程式/扩展 CSS、DNS CNAME Uncloaking 等无法保证语义一致的能力不会进入这两个通用产物，并会记录在构建审计报告中。

这两个文件是**过滤规则订阅**，不是 MV2 扩展安装包。MV2 仅描述本项目对浏览器过滤引擎能力的兼容目标，不代表所有采用 MV2 的浏览器都仍允许运行扩展。

**重要：** 截至 2026 年 11 月，Chrome 已禁用 MV2 扩展，Chrome Web Store 也已移除剩余 MV2 扩展。Firefox 仍支持 MV2；其他 Chromium 浏览器的支持政策各不相同。请确认实际浏览器仍允许运行 MV2 扩展后再订阅。参见 [Chrome MV2 支持时间表](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline) 和 [AdGuard 关于 Chrome 移除 MV2 的说明](https://adguard.com/kb/adguard-browser-extension/solving-problems/mv2-removal-in-chrome/)。

DNS、Hosts、IPv6 Hosts 和纯域名列表是其他输出格式，不属于这两个通用浏览器规则产物。

## 规则来源

[AdAway](https://github.com/AdAway/AdAway) · [AdBlocker](https://adblockultimate.net/filters) · [AdGuard](https://github.com/AdguardTeam/AdGuardFilters) · [EasyList](https://github.com/easylist/easylist) · [uBlock Origin](https://github.com/uBlockOrigin/uAssets) · [malware-filter](https://gitlab.com/malware-filter)

## 注意事项

规则可能导致误拦截或网站功能异常。Main 尽量保留满足共同语法契约的规则；Lite 使用更精简的来源集合。两个产物都不包含需要单一引擎专有运行时的规则，因此功能覆盖会低于各产品原生专用过滤器。

## License

[GPL-3.0](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL%203.0) · [CC BY-NC-SA 4.0](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA%204.0)
