[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 50px; margin-bottom: 20px;">Adguard-Rule-Collection</h1>

<!-- 居中的副标题 -->
<h4 align="center" >一个将众多广告过滤器条目转化、去重、合并汇总生成的广告拦截器,规则总数多达百万，包含URL过滤规则、资源过滤规则、域名过滤规则、CSS选择器规则、脚本过滤规则、隐私保护规则、Cookie过滤规则、白名单例外规则、关键字过滤规则、webrtc拦截屏蔽规则、正则表达式过滤规则、网络过滤规则、字体和样式过滤规则、重定向规则、脚本注入规则、反指纹跟踪规则、欺诈过滤规则、恶意网站过滤规则、网络钓鱼过滤规则、滥用网站过滤规则、挖矿过滤规则、垃圾邮件过滤规则、僵尸网络屏蔽规则等类型的条目</h4>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/REIJI007/Adblock-Rule-Collection" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/REIJI007/Adblock-Rule-Collection" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/REIJI007/Adblock-Rule-Collection" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/REIJI007/Adblock-Rule-Collection" alt="license" style="margin-right: 10px;">
</p>


 一、关于Adblock-Rule-Collection，你可使用本仓库中的python脚本合并去重生成广告过滤规则列表，注意修改生成文件的保存路径与生成的文件名，可按需求添加不同的上游广告过滤规则列表（兼容adblock plus语法的锅炉其列表均可）进行DIY定制，这个脚本也可以把host拦截规则和Dnsmasq拦截规则处理为adblock plus拦截规则,随着加入合并的广告过滤规则越来越多，生成文件体积也会越来越大，若你的广告过滤程序订阅失败则就下载规则文件充当本地用户过滤器。

<hr>

 警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博网站，使用前请斟酌考虑，如有误杀请积极向上游issue反馈，本仓库仅提供去重、筛选、合并功能

<hr>
<br>

## 二、本仓库使用方式如下：

<hr> 
1、订阅地址: 

**完整版** <br>
**https://raw.githubusercontent.com/Shura23/Adguard-Rule-Collection/refs/heads/main/ADBLOCK_RULE_COLLECTION.txt** <br>

**精简版** <br>
**https://raw.githubusercontent.com/Shura23/Adguard-Rule-Collection/refs/heads/main/ADBLOCK_RULE_COLLECTION_Lite.txt** <br>

2、从Release中下载过滤器文件进行本地导入广告过滤器，release每20分钟自动发布一次
<hr>


## 三、适用范围
适用于ADguard,Adblock Plus,uBlock Origin,Brave Browser等各类符合Adblock Plus (ABP) 语法、uBlock Origin 语法、AdGuard 语法的浏览器插件或广告拦截程序
<br>




## 四、特别致谢


<details>
  <summary>致谢名单</summary>

1. [anti-AD](https://github.com/privacy-protection-tools/anti-AD)
2. [easylist](https://github.com/easylist/easylist)
3. [cjxlist](https://github.com/cjx82630/cjxlist)
4. [uniartisan](https://github.com/uniartisan/adblock_list)
5. [Cats-Team](https://github.com/Cats-Team/AdRules)
6. [217heidai](https://github.com/217heidai/adblockfilters)
7. [GOODBYEADS](https://github.com/8680/GOODBYEADS)
8. [AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
9. [uBlockOrigin](https://github.com/uBlockOrigin/uAssets)
10. [ADguardTeam](https://github.com/AdguardTeam/AdGuardFilters)
11. [HyperADRules](https://github.com/Lynricsy/HyperADRules)
12. [guandasheng](https://github.com/guandasheng/adguardhome)
13. [xinggsf](https://github.com/xinggsf/Adblock-Plus-Rule)
14. [hoshsadiq](https://github.com/hoshsadiq/adblock-nocoin-list)
15. [jerryn70](https://github.com/jerryn70/GoodbyeAds)
16. [malware-filter](https://gitlab.com/malware-filter)
17. [abp-filters](https://gitlab.com/eyeo/anti-cv/abp-filters-anti-cv)
18. [banbendalao](https://github.com/banbendalao/ADgk)
19. [yokoffing](https://github.com/yokoffing/filterlists)
20. [Spam404](https://github.com/Spam404/lists)
21. [brave](https://github.com/brave/adblock-lists)
22. [Peter Lowe](https://pgl.yoyo.org/adservers/)
23. [DandelionSprout](https://github.com/DandelionSprout/adfilt)
24. [blocklistproject](https://github.com/blocklistproject/Lists)
25. [reek](https://github.com/reek/anti-adblock-killer)
26. [durablenapkin](https://github.com/durablenapkin/scamblocklist)
27. [oisd](https://github.com/sjhgvr/oisd)
28. [Perflyst](https://github.com/Perflyst/PiHoleBlocklist)
29. [hagezi](https://github.com/hagezi/dns-blocklists)
30. [neodevpro](https://github.com/neodevpro/neodevhost)
31. [notracking](https://github.com/notracking/hosts-blocklists)
32. [damengzhu](https://github.com/damengzhu/banad)
33. [hectorm](https://github.com/hectorm/hblock)
34. [badmojr](https://github.com/badmojr/1Hosts)
35. [afwfv](https://github.com/afwfv/DD-AD)
36. [paulgb](https://github.com/paulgb/BarbBlock)

  </details>






<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
