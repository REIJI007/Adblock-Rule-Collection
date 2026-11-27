# DNS 域名验证

本验证器**只在 Adblock 主版/精简版生成后运行一次**，位置为规则生成步骤之后、Git 提交之前。后续 DNS、Hosts、IPv6 Hosts、纯域名清单等产物均由清理后的 Adblock 规则生成，不再重复发起 DNS 查询。

## 使用的公共 DNS

验证器只使用以下五家**无过滤公共递归 DNS**。为了避免依赖 DNS 名称本身，文档及验证器配置均使用 **DoH 的 IP 地址形式**：

| 服务 | IPv4 DoH | IPv6 DoH | 过滤配置 |
|---|---|---|---|
| Google Public DNS | `https://8.8.8.8/dns-query`、`https://8.8.4.4/dns-query` | `https://[2001:4860:4860::8888]/dns-query`、`https://[2001:4860:4860::8844]/dns-query` | 标准公共解析器，不使用过滤变体 citeturn352213search2turn352213search9 |
| Cloudflare 1.1.1.1 | `https://1.1.1.1/dns-query`、`https://1.0.0.1/dns-query` | `https://[2606:4700:4700::1111]/dns-query`、`https://[2606:4700:4700::1001]/dns-query` | 标准 unfiltered resolver；不使用 Malware / Families 变体 citeturn352213search0turn352213search4 |
| Tencent Public DNS | `https://119.29.29.29/dns-query`、`https://1.12.12.12/dns-query` | `https://[2402:4e00::]/dns-query`、`https://[2402:4e00:1::]/dns-query` | Public DNS 免费版 |
| Alibaba Public DNS | `https://223.5.5.5/dns-query`、`https://223.6.6.6/dns-query` | `https://[2400:3200::1]/dns-query`、`https://[2400:3200:baba::1]/dns-query` | Public DNS |
| AdGuard DNS | `https://94.140.14.140/dns-query`、`https://94.140.14.141/dns-query` | `https://[2a10:50c0::1:ff]/dns-query`、`https://[2a10:50c0::2:ff]/dns-query` | **Non-filtering**；不使用 Default / Family Protection citeturn352213search1turn352213search6 |

> **注意：** IPv6 地址放入 URL 的 authority 部分时必须使用方括号，例如 `https://[2001:4860:4860::8888]/dns-query`，否则 URL 解析器无法正确区分 IPv6 地址中的冒号与端口分隔符。

AdGuard 的 Non-filtering 端点明确声明不会过滤 DNS 请求，其 IPv4 / IPv6 地址分别为 `94.140.14.140`、`94.140.14.141`、`2a10:50c0::1:ff`、`2a10:50c0::2:ff`。citeturn352213search1turn352213search6


## 查询与判定规则

每个待验证域名会向五家 DNS 分别发起两种查询：

- `A`：IPv4 地址记录。
- `AAAA`：IPv6 地址记录。

因此每个域名有 **5 × 2 = 10 个逻辑 DNS 查询**。为处理瞬时网络错误，单个 DoH 请求最多尝试两次，因此实际 HTTP 请求数可能高于 10。

判定采用 OR 逻辑：

```text
只要任意一家 DNS 的 A 或 AAAA 查询返回 NOERROR（RCODE=0）
    => 有效域名，保留
否则（十次查询全部非 NOERROR 或查询失败）
    => 无效域名，剔除
```

补充说明：

1. `NXDOMAIN` 表示 DNS 明确返回名称不存在。
2. 超时、连接错误、HTTP 错误、`SERVFAIL`、`REFUSED` 等查询失败或非成功 RCODE，按本项目当前策略计为未成功解析。
3. **`NOERROR/NODATA` 仍算成功响应并保留域名**。它表示解析器成功回答该记录类型，只是没有该类型的地址记录；仅凭 A/AAAA 无记录不能推出域名不存在。
4. 例如 Google 的 A 查询只要成功返回，其他九次查询即使 NXDOMAIN 或失败，也会保留该域名。
5. 这是按用户要求采用的严格规则：只有十次查询均未得到 NOERROR 才剔除。

**误删风险提示：** 查询失败也被定义为无效，因此若某个真实存在的域名恰好在五家解析器上均发生超时、限流或服务故障，它仍可能被剔除。`example.com` 探针只能防止五家解析器整体不可用时整批写入，不能完全排除单个域名的局部故障或多家解析器部分故障。此项风险来自“查询失败也算无效”的判定要求。

为避免整个网络或 DNS 服务同时不可用时清空订阅，批量处理前会查询 `example.com` 的 A/AAAA 作为连通性探针。如果五家解析器对探针全部无法返回 NOERROR，则本次流程直接失败，**不修改现有 Adblock 文件**。

## 规则处理范围

命令行只接受以下两个文件名：

- `ADBLOCK_RULE_COLLECTION.txt`
- `ADBLOCK_RULE_COLLECTION_Lite.txt`

识别可明确提取主机名的 ABP/Adblock 规则（例如 `||example.com^`、`|example.com^`）、显式 `$domain=` 作用域、带域名作用域的 cosmetic 规则，以及本仓库编译器为 Hosts/精确域名来源生成的固定 URL-authority 正则模板（仅当正则主体是单一字面主机名时）。

保留通配符主机名、URL/路径过滤器、通用正则表达式、注释、IP 字面量以及无法无歧义识别的规则。负向 `~domain` 作用域不作为待删除域名，也不会因其域名查询失败而被移除，避免意外扩大规则匹配范围。

## 运行方式

默认 dry-run：

```bash
python dns_domain_validator.py ADBLOCK_RULE_COLLECTION.txt --report dns-validation.json
```

生成阶段实际应用清理：

```bash
python dns_domain_validator.py ADBLOCK_RULE_COLLECTION.txt --write \
  --cache .cache/dns-validation-main.json \
  --report dns-validation-main.json
```

验证缓存默认 15 分钟，用于避免短时间内重复工作流造成重复查询；缓存只在主版或 Lite 各自的 Adblock 生成流程使用，不会在下游工作流再次执行验证。每家 DNS 的请求启动速率默认限制为 18 QPS（低于腾讯 Public DNS 免费版文档标注的 20 QPS/域名调用上限）。

## 官方端点资料

- Google Public DNS：<https://developers.google.com/speed/public-dns/docs/doh>
- Cloudflare 1.1.1.1：<https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/>
- Tencent Public DNS：<https://cloud.tencent.com/document/product/302/110786>
- Alibaba DNS DoH：<https://static-aliyun-doc.oss-cn-hangzhou.aliyuncs.com/download/pdf/171662/API_Reference_intl_en-US.pdf>
- AdGuard DNS：<https://adguard-dns.io/en/public-dns.html>
