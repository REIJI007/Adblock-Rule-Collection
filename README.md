[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL%203.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 100px; margin-bottom: 40px;">Adblock-Rule-Collection</h1>

<!-- 居中的副标题 -->
<h2 align="center" style="font-size: 30px; margin-bottom: 40px;">一个将众多广告过滤器条目转化、去重、合并汇总生成的广告拦截器和DNS过滤器，规则总数多达百万，包含URL过滤规则、资源过滤规则、域名过滤规则、CSS选择器过滤规则、脚本过滤规则、隐私保护规则、Cookie过滤规则、白名单例外规则、关键字过滤规则、webrtc拦截规则、正则表达式过滤规则、网络过滤规则、字体和样式过滤规则、重定向拦截规则、脚本注入规则、反指纹跟踪规则、欺诈过滤规则、恶意网站过滤规则、网络钓鱼过滤规则、滥用过滤规则、挖矿过滤规则、垃圾邮件过滤规则、僵尸网络屏蔽规则、地理位置追踪屏蔽规则、视音频广告过滤规则、社交媒体插件过滤规则、点击劫持保护规则、弹窗过滤规则、下载劫持保护规则等类型的条目</h2>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/REIJI007/Adblock-Rule-Collection" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/REIJI007/Adblock-Rule-Collection" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/REIJI007/Adblock-Rule-Collection" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/REIJI007/Adblock-Rule-Collection" alt="license" style="margin-right: 10px;">
</p>


## 一、关于Adblock-Rule-Collection，你可使用本仓库中的python脚本合并去重生成广告过滤规则列表，注意修改生成文件的保存路径与生成的文件名，可按需求添加不同的上游广告过滤规则列表（兼容adblock plus语法的过滤器列表均可）进行DIY定制，这个脚本也可以把host拦截规则和Dnsmasq拦截规则处理为adblock plus拦截规则，随着加入合并的广告过滤规则越来越多，生成文件体积也会越来越大，若你的广告过滤程序订阅失败则就下载规则文件充当本地用户过滤器。

<hr>

## 警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博网站，使用前请斟酌考虑，如有误杀请积极向上游issue反馈，本仓库仅提供去重、转化、合并功能。完整版会有很多误杀，建议使用精简版（只含adguard官方列表）。另外需要说明一点，本仓库仅收集```中英文广告拦截```相关、```网络安全```相关、```隐私保护```相关列表

<hr>
<br>

## 二、本仓库使用方式如下：

<hr> 
1、订阅地址

*广告过滤器*
<table border="1" style="border-collapse: collapse; width: 100%;">
  <tr>
    <th>版本</th>
    <th>链接</th>
  </tr>
  <tr>
    <td>完整版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td>精简版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_Lite.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-lite.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
</table>

<br>

*DNS过滤器*
<table border="1" style="border-collapse: collapse; width: 100%;">
  <tr>
    <th>版本</th>
    <th>链接</th>
  </tr>
  <tr>
    <td>完整版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DNS.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-dns.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td>精简版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DNS_Lite.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-dns-lite.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
</table>

<br>

*Host列表*
<table border="1" style="border-collapse: collapse; width: 100%;">
  <tr>
    <th>版本</th>
    <th>链接</th>
  </tr>
  <tr>
    <td>完整版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-host.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td>精简版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST_Lite.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-host-lite.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
</table>

<br>

*Host IPV6列表*
<table border="1" style="border-collapse: collapse; width: 100%;">
  <tr>
    <th>版本</th>
    <th>链接</th>
  </tr>
  <tr>
    <td>完整版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST_IPV6.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-host-ipv6.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td>精简版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_HOST_IPV6_Lite.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-host-ipv6-lite.reiji007.org/">Cloudflare加速链接</a></strong>
    </td>
  </tr>
</table>

<br>

*拦截域名列表*
<table border="1" style="border-collapse: collapse; width: 100%;">
  <tr>
    <th>版本</th>
    <th>链接</th>
  </tr>
  <tr>
    <td>完整版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DOMAIN.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-domain.reiji007.org">Cloudflare加速链接</a></strong>
    </td>
  </tr>
  <tr>
    <td>精简版</td>
    <td>
      <strong><a href="https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_DOMAIN_Lite.txt">Github原始链接</a></strong> | 
      <strong><a href="https://www.adblock-domain-lite.reiji007.org">Cloudflare加速链接</a></strong>
    </td>
  </tr>
</table>


2、从Release中下载过滤器文件进行本地导入过滤器，release每20分钟自动发布一次
<hr>


## 三、适用范围
适用于ADguard,Adblock Plus,uBlock Origin,Brave Browser等各类符合Adblock Plus 语法、uBlock Origin 语法、AdGuard 语法的浏览器插件或广告拦截程序以及DNS服务器
<br>


## 四、特别致谢

<details>
  <summary>致谢名单</summary>

1. [Adaway](https://github.com/AdAway/AdAway)
2. [Adblocker](https://adblockultimate.net/filters)
3. [Adguard](https://github.com/AdguardTeam/AdGuardFilters)
4. [easylist](https://github.com/easylist/easylist)
5. [uBlockOrigin](https://github.com/uBlockOrigin/uAssets)
6. [blocklist project](https://github.com/blocklistproject/Lists)
7. [malware-filter](https://gitlab.com/malware-filter)
8. [phishing army](https://www.phishing.army)
9. [WindowsSpyBlocker](https://github.com/crazy-max/WindowsSpyBlocker)

</details>


<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL%203.0)
