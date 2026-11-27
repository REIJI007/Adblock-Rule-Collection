# DNS 域名验证

本验证器**只在 Adblock 主版/精简版生成后运行一次**，位置为规则生成步骤之后、Git 提交之前。后续 DNS、Hosts、IPv6 Hosts、纯域名清单等产物均由清理后的 Adblock 规则生成，不再重复发起 DNS 查询。

## 使用的公共 DNS

全部使用无广告/恶意域名过滤列表的递归解析端点：

| 服务 | DoH 地址 | 配置说明 |
|---|---|---|
| Google Public DNS | `https://dns.google/dns-query` | Google 公共 DNS |
| Cloudflare 1.1.1.1 | `https://cloudflare-dns.com/dns-query` | 标准无过滤解析器，不使用 Security / Family 变体 |
| Tencent Public DNS | `https://doh.pub/dns-query` | 腾讯公共 DNS 免费版 |
| Alibaba Public DNS | `https://dns.alidns.com/dns-query` | 阿里云公共 DNS |
| AdGuard DNS | `https://unfiltered.adguard-dns.com/dns-query` | AdGuard 官方明确标注的 Non-filtering endpoint |

不使用 Cloudflare Security/Family、AdGuard Default/Family、Quad9 Threat Blocking 或其他带过滤功能的解析端点。

## 查询与判定规则

每个待验证域名会向五家 DNS 分别发起两种查询：

- `A`：IPv4 地址记录。
- `AAAA`：IPv6 地址记录。

因此每个域名最多对应 **5 × 2 = 10 次 DNS 查询**。

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

为避免整个网络或 DNS 服务同时不可用时清空订阅，批量处理前会查询 `example.com` 的 A/AAAA 作为连通性探针。如果五家解析器对探针全部无法返回 NOERROR，则本次流程直接失败，**不修改现有 Adblock 文件**。

## 规则处理范围

命令行只接受以下两个文件名：

- `ADBLOCK_RULE_COLLECTION.txt`
- `ADBLOCK_RULE_COLLECTION_Lite.txt`

识别可明确提取主机名的 ABP/Adblock 规则（例如 `||example.com^`、`|example.com^`）、显式 `$domain=` 作用域和带域名作用域的 cosmetic 规则。

保留通配符主机名、URL/路径过滤器、正则表达式、注释、IP 字面量以及无法无歧义识别的规则。负向 `~domain` 作用域不作为待删除域名，也不会因其域名查询失败而被移除，避免意外扩大规则匹配范围。

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

验证缓存默认 15 分钟，用于避免同一轮工作流内重复查询；缓存只在主版或 Lite 各自的 Adblock 生成流程使用，不会在下游工作流再次执行验证。每家 DNS 的请求启动速率默认限制为 10 QPS。

## 官方端点资料

- Google Public DNS：<https://developers.google.com/speed/public-dns/docs/doh>
- Cloudflare 1.1.1.1：<https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/>
- Tencent Public DNS：<https://cloud.tencent.com/document/product/302/110786>
- Alibaba DNS DoH：<https://static-aliyun-doc.oss-cn-hangzhou.aliyuncs.com/download/pdf/171662/API_Reference_intl_en-US.pdf>
- AdGuard DNS：<https://adguard-dns.io/en/public-dns.html>
