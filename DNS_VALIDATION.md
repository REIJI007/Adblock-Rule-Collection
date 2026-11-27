# DNS 域名验证与生成流水线

## 设计目标

DNS 验证作为 Adblock 生成流水线中的统一质量门，而不是独立的定时清理任务：

1. 原有 Main / Lite 规则生成器按原参数分别生成规则；生成器源代码和规则编译逻辑不修改。
2. 统一验证器收集 Main 与 Lite 中真正的拦截目标主机，规范化并去重。
3. 每个唯一目标主机只验证一次，验证结果同时用于清理 Main 和 Lite。
4. 只有验证流水线成功发布后，DNS、IPv4 Hosts、IPv6 Hosts、DOMAIN 衍生任务才启动。
5. DNS 验证不在下游工作流重复运行。

自动主流程位于 \`.github/workflows/Generate and Validate Adblock Collections.yml\`。原 Main / Lite 独立工作流保留 \`workflow_dispatch\` 手动入口；原生成器脚本及参数不变。

## 三家公共 DNS 与 DoH 连接方式

所有候选域名查询均使用 RFC 8484 DNS-over-HTTPS（DoH），不使用 UDP/53、TCP/53 或 DoT。只使用以下三家公共递归 DNS，不使用内容过滤变体：

| 服务 | TLS SNI / HTTP Host | IPv4 DoH URL | IPv6 DoH URL | 说明 |
|---|---|---|---|---|
| Google Public DNS | `dns.google` | `https://8.8.8.8/dns-query`、`https://8.8.4.4/dns-query` | `https://[2001:4860:4860::8888]/dns-query`、`https://[2001:4860:4860::8844]/dns-query` | 标准公共解析服务 |
| Cloudflare 1.1.1.1 | `cloudflare-dns.com` | `https://1.1.1.1/dns-query`、`https://1.0.0.1/dns-query` | `https://[2606:4700:4700::1111]/dns-query`、`https://[2606:4700:4700::1001]/dns-query` | 使用 unfiltered 解析器 |
| AdGuard DNS | `unfiltered.adguard-dns.com` | `https://94.140.14.140/dns-query`、`https://94.140.14.141/dns-query` | `https://[2a10:50c0::1:ff]/dns-query`、`https://[2a10:50c0::2:ff]/dns-query` | **Non-filtering**，不使用 Default / Family Protection |

### IP 直连与 TLS 身份验证

表格中的 URL 使用数字 IP 作为 HTTPS 连接目标。程序不会先通过系统 DNS 解析 DoH 服务主机名，而是：

- TCP socket 直接连接已配置的 IPv4 / IPv6 Bootstrap IP。
- TLS SNI 使用表格中的服务主机名。
- HTTP \`Host\` 使用相同的服务主机名。
- 使用系统 CA 信任链进行证书校验，并校验服务主机名；不关闭 TLS 验证。
- IPv6 URL 中必须将地址放在方括号内。

因此，IP 负责确定网络连接目标，主机名负责 TLS 身份验证和 HTTP 虚拟主机路由。**不能为了 IP 直连而关闭证书验证，也不能把 IP 字符串作为证书主机名。**

### 服务端点与配额边界

- Google 的 RFC 8484 DoH 标准 URI 为 `/dns-query`，GET 请求使用 Base64URL 编码的 DNS Wire Format。Google 建议使用 `dns.google` 主机名；本项目通过 IP 连接并保留该主机名作为 SNI / Host。
- Cloudflare 标准 unfiltered 解析器为 `1.1.1.1` / `1.0.0.1`，不使用 Malware 或 Families 地址。
- AdGuard 必须使用 Non-filtering 服务，不使用广告、跟踪器或家庭保护过滤端点。

## 查询和有效性判定

每个唯一目标主机向三家解析器各发两种查询：

- \`A\`：查询 IPv4 地址记录。
- \`AAAA\`：查询 IPv6 地址记录。

总计 **3 × 2 = 6 个逻辑查询 / 域名**。单个解析器连接错误时可能轮换备用 IP 地址，因此实际 HTTPS 请求数可能高于 10。

### 有效条件

**只有 DNS Answer 中出现与查询类型匹配、属于目标主机或其 CNAME 链、且可用的 IP 地址时，才算有效。**

- A 响应必须包含合法的 IPv4 地址记录。
- AAAA 响应必须包含合法的 IPv6 地址记录。
- 任意一家解析器的 A 或 AAAA 返回至少一个可用地址，即保留域名。
- 不要求三家解析器返回相同 IP；CDN、Anycast 和地理调度可能返回不同的合法地址。
- 支持 Answer 区中的 CNAME 链；只有链上最终存在 A / AAAA 地址才有效。
- 不接受 Answer 中与当前查询主机及其 CNAME 链无关的地址记录。

### 不计为有效 IP 的响应

| 响应 | 处理 |
|---|---|
| \`NOERROR\`，Answer 为空（NODATA） | 无地址 |
| 只有 CNAME，没有最终 A / AAAA 地址 | 无地址 |
| Answer 中只有错误记录类型 | 无地址 |
| \`NXDOMAIN\` | 无地址 |
| \`0.0.0.0\`、\`::\` 等 unspecified | 不计地址 |
| loopback、multicast、link-local、reserved 地址 | 不计地址 |
| 私有单播地址 | 视为有效地址 |
| SERVFAIL、REFUSED、HTTP 错误、超时、连接失败、格式错误 | 暂时失败，不作为失效证据 |

## 状态机与删除门槛

验证结果分为四种状态：

| 状态 | 含义 | 本轮行为 |
|---|---|---|
| \`valid\` | 至少一个查询返回可用 IP | 保留规则并清除旧的负向确认记录 |
| \`no_address\` | 健康解析器（至少 2/3 家）的 A / AAAA 查询均完整结束，但没有可用 IP | 记录一次负向观测，等待下一轮确认 |
| \`pending_confirmation\` | 已有无地址观测，但尚未达到删除门槛 | 保留规则，等待复查 |
| \`temporary_failure\` | 网络、服务、限流、协议或解析器健康状态异常 | 保留规则；不将故障当作失效证据 |

删除必须同时满足：

1. \`example.com\` A / AAAA 健康探针至少有 **3 家解析器**返回可用 IP。
2. 目标域名在参与判定的健康解析器（至少 2/3 家）中，A / AAAA 查询均返回完整 DNS 结果（NXDOMAIN 或 NOERROR 无地址）。
3. 没有任何一家解析器返回有效 IP。
4. 在 24 小时观察窗口内，至少取得 **3 次独立的 no-address 观测**。
5. 观测之间至少间隔 15 分钟，第一次与第三次至少间隔 30 分钟。

如果解析器池少于 3 家健康服务，或候选域名查询中出现 SERVFAIL、REFUSED、超时、连接错误、格式错误等情况，则该轮为 \`temporary_failure\`，不得增加负向确认次数，也不得删除域名。

这与“有一个可用 IP 就立即保留”并不矛盾：**通过条件立即生效，删除条件需要多轮充分证据。**

## 规则语义范围

验证器只识别真正的拦截目标，不把网站上下文误当成拦截域名。

| 规则 | DNS 验证对象 |
|---|---|
| \`||ads.example.com^\` | \`ads.example.com\` |
| \`|ads.example.com^\` | \`ads.example.com\` |
| \`||tracker.example.net^$script,domain=site.example\` | 只验证 \`tracker.example.net\` |
| \`site.example##.ad\` | 不验证 cosmetic 网站作用域 |
| Hosts 行 | 验证行中的公开主机名 |
| 通配符、URL / 路径、通用正则 | 无法安全提取目标时保留，不猜测 |

\`$domain=\` 和 cosmetic 作用域代表规则适用的网站范围，不是被拦截请求的目标主机，因此不参与 DNS 验证，也不会被 DNS 验证器重写。无法无歧义解析的规则保持原样。

## 缓存策略

缓存按域名记录解析状态、每家解析器的 A / AAAA RCODE、地址、CNAME 链及 TTL：

- **正向结果**：缓存期限取 CNAME 链和地址记录中最短的正 TTL，并受工作流配置的 6 小时上限约束。
- **无地址 / 待确认**：15 分钟后重新查询，以便逐轮累计负向证据。
- **暂时失败**：不缓存为无效，尽快重新查询。
- **状态升级**：每次新的 no-address 观测才会更新负向确认状态；缓存命中不会重复累计确认次数。
- **版本隔离**：缓存 schema 版本变更后旧缓存会被丢弃，避免沿用旧判定策略。

## 工作流执行顺序

\`\`\`text
原 Main 生成器 ─┐
                ├─> 合并目标主机并去重 ─> 三家 DoH / A + AAAA
原 Lite 生成器 ─┘                           |
                                            v
                                  状态判定 / 负向确认
                                            |
                                            v
                             删除比例、规则数量质量门
                                            |
                                            v
                              一次提交 Main + Lite
                                            |
                 ┌──────────────────────────┼───────────────────────┐
                 v                          v                       v
             DNS 规则                  IPv4 / IPv6 Hosts         DOMAIN 清单
\`\`\`

自动生成工作流每 20 分钟运行一次。Main / Lite 先分别使用原有生成器生成，再由 \`--both-adblock\` 对两个列表的候选主机并集验证一次。下游工作流通过 \`workflow_run\` 等待上游成功完成后启动，不再各自使用独立的 20 分钟定时器。

Main / Lite 原始生成器脚本和命令行参数保持不变；独立手动工作流入口仍保留。手动分别运行 Main 或 Lite 时，仍沿用各自原有的单文件生成流程。

## 质量保护

- 默认 dry-run，不传 \`--write\` 不修改 Adblock 文件。
- 如果任一输出的拟删除活动行比例超过 20%，则质量门阻止所有 Adblock 文件写入。
- 如果某个输出将被删成空文件，也阻止写入。
- DNS 报告和验证缓存仍会写出，便于检查异常与继续负向确认。
- 报告包含目标主机数量、缓存命中数、健康解析器（至少 2/3 家）、各状态计数、每家解析器的 RCODE / 地址 / TTL、文件删除比例和质量门错误。
- 工作流上传兼容性审计和 DNS 报告作为 Artifact。

## 本地使用

对 Main 与 Lite 一次性执行 dry-run：

\`\`\`bash
python dns_domain_validator.py --both-adblock \
  --cache .cache/dns-validation-state.json \
  --report dns-validation-report.json
\`\`\`

应用清理：

\`\`\`bash
python dns_domain_validator.py --both-adblock --write \
  --cache .cache/dns-validation-state.json \
  --report dns-validation-report.json \
  --qps 15 --timeout 8 \
  --cache-ttl-hours 6 \
  --min-healthy-resolvers 2 \
  --max-removal-ratio 0.20
\`\`\`

## 官方资料

- Google Public DNS DoH：<https://developers.google.com/speed/public-dns/docs/doh>
- Google DoH IP / Bootstrap 迁移说明：<https://developers.google.com/speed/public-dns/docs/doh/migration>
- Cloudflare 1.1.1.1 解析器与端点：<https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/>
- AdGuard DNS Non-filtering：<https://adguard-dns.io/en/public-dns.html>
