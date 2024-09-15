[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 100px; margin-bottom: 40px;">Adblock-Rule-Collection</h1>

<!-- 居中的副标题 -->
<h2 align="center" style="font-size: 30px; margin-bottom: 40px;">一个将众多广告过滤器条目转化、去重、合并汇总生成的广告拦截器,规则总数多达百万，包含URL过滤规则、资源过滤规则、域名过滤规则、CSS选择器规则、脚本过滤规则、隐私保护规则、Cookie过滤规则、白名单例外规则、关键字过滤规则、webrtc拦截屏蔽规则、正则表达式过滤规则、网络过滤规则、字体和样式过滤规则、重定向规则、脚本注入规则、反指纹跟踪规则、欺诈过滤规则、恶意网站过滤规则、网络钓鱼过滤规则、滥用网站过滤规则、挖矿过滤规则、垃圾邮件过滤规则、僵尸网络屏蔽规则等类型的条目</h2>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/REIJI007/Adblock-Rule-Collection" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/REIJI007/Adblock-Rule-Collection" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/REIJI007/Adblock-Rule-Collection" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/REIJI007/Adblock-Rule-Collection" alt="license" style="margin-right: 10px;">
</p>


## 一、关于Adblock-Rule-Collection，你可使用本仓库中的Adblock_rule_generator.py脚本合并去重生成广告过滤规则列表，注意修改生成文件的保存路径与生成的文件名，可按需求添加不同的上游广告过滤规则列表（兼容adblock plus语法的锅炉其列表均可）进行DIY定制，这个脚本也可以把host规则和Dnsmasq规则处理为adblock plus规则,随着加入合并的广告过滤规则越来越多，生成文件体积也会越来越大，若你的广告过滤程序订阅失败则就下载规则文件充当本地用户过滤器。

<hr>

## 警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博网站，使用前请斟酌考虑，如有误杀请积极向上游issue反馈，本仓库仅提供去重、筛选、合并功能

<hr>
<br>

## 二、本仓库使用方式如下：
1、订阅地址: <br> *https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION.txt*<br>
<br>
2、从Release中下载ADBLOCK_RULE_COLLECTION.txt文件进行本地导入广告过滤器，release每20分钟自动发布一次
<br>

## 三、适用范围
适用于ADguard,Adblock Plus,uBlock Origin,Brave Browser等各类符合Adblock Plus (ABP) 语法、uBlock Origin 语法、AdGuard 语法的浏览器插件或广告拦截程序
<br>


## 四、汇总引用规则列表有如下
<details>
  <summary>查看规则列表</summary>

1. [Anti-ad for adguard](https://anti-ad.net/adguard.txt)  
2. [Anti-ad-Easylist](https://anti-ad.net/easylist.txt)  
3. [OISD Big List](https://big.oisd.nl)  
4. [EasyList](https://easylist.to/easylist/easylist.txt)  
5. [EasyList — first-party servers](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt)  
6. [EasyList — third-party servers](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt)  
7. [EasyList Privacy](https://easylist.to/easylist/easyprivacy.txt)  
8. [EasyList Privacy — trackingservers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt)  
9. [EasyPrivacy — third-party trackers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt)  
10. [EasyPrivacy — third-party international trackers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt)  
11. [Easylist Cookie List](https://secure.fanboy.co.nz/fanboy-cookiemonster.txt)  
12. [EasyList China](https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt)  
13. [Adblock Warning Removal List](https://easylist-downloads.adblockplus.org/antiadblockfilters.txt)  
14. [Fanboy's Annoyance List](https://secure.fanboy.co.nz/fanboy-annoyance.txt)  
15. [Fanboy's Social Blocking List](https://easylist.to/easylist/fanboy-social.txt)  
16. [Fanboy's Anti-thirdparty Fonts](https://www.fanboy.co.nz/fanboy-antifonts.txt)  
17. [Fanboy's Notifications Blocking List](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt)  
18. [CJX's Annoyance List](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)  
19. [CJX's EasyList Lite](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt)  
20. [CJX's uBlock list](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt)  
21. [uniartrisan's Adblock List Plus](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt)  
22. [uniartrisan's Privacy List](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt)  
23. [AdRules AdBlock List Plus](https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt)  
24. [AdRules DNS List](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt)  
25. [AdBlock DNS](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt)  
26. [AdBlock Filter](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt)  
27. [GOODBYEADS](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt)  
28. [GOODBYEADS-DNS](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt)  
29. [GOODBYEADS-allow](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt)  
30. [AWAvenue-Ads-Rule](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt)  
31. [Bibaiji's ad-rules](https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/ad-rules.txt)  
32. [uBlock filters](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt)  
33. [uBlock privacy filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt)  
34. [uBlock mobile filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt)  
35. [uBlock Badware risks filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt)  
36. [uBlock Annoyances-Cookies filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt)  
37. [uBlock Annoyances-others filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt)  
38. [uBlock Resource abuse filters](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt)  
39. [uBlock Unbreak filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt)  
40. [AdGuard Base filter cryptominers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt)  
41. [AdGuard Exclusion rules](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt)  
42. [AdGuard Exception rules](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt)  
43. [AdGuardSDNSFilter](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt)  
44. [AdGuard Base filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt)  
45. [AdGuard Base filter — first-party servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt)  
46. [AdGuard Base filter — foreign servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt)  
47. [AdGuard Mobile filter](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)  
48. [AdGuard Tracking Protection filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt)  
49. [AdGuard Tracking Protection filter — first-party trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt)  
50. [AdGuard Tracking Protection filter — third-party trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt)
51. [AdGuard Tracking Protection filter — mobile trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt)  
52. [AdGuard URL Tracking filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt)  
53. [AdGuard Social media filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt)  
54. [AdGuard Annoyances filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt)  
55. [AdGuard CNAME original trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt)  
56. [AdGuard CNAME disguised ads list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt)  
57. [AdGuard CNAME disguised clickthroughs list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt)  
58. [AdGuard CNAME disguised microsites list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt)  
59. [AdGuard CNAME disguised trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt)  
60. [AdGuard CNAME disguised mail_trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt)  
61. [AdGuard Chinese filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)  
62. [AdGuard DNS filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt)  
63. [AdGuard for Android](https://filters.adtidy.org/android/filters/11.txt)  
64. [AdGuard for iOS](https://filters.adtidy.org/ios/filters/11.txt)  
65. [HyperADRules](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt)  
66. [HyperADRules-DNS](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt)  
67. [HyperADRules-allow](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/allow.txt)  
68. [TheBestAdrules](https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt)  
69. [xinggsf's rules](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt)  
70. [xinggsf's mv rules](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt)  
71. [superbigsteam rules](https://raw.githubusercontent.com/superbigsteam/adguardhomeguiz/main/rule/all.txt)  
72. [adblock-nocoin-list](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt)  
73. [GoodbyeAds-AdBlock-Filter](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt)  
74. [GoodbyeAds-Ultra-AdBlock-Filter](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master)  
75. [Phishing URL Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt)  
76. [Phishing URL Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt)  
77. [Phishing URL Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt)  
78. [Malicious URL Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt)  
79. [Malicious URL Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt)  
80. [Malicious URL Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt)  
81. [Tracking JS Blocklist](https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt)  
82. [Botnet IP Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt)  
83. [Botnet IP Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt)  
84. [Botnet IP Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt)  
85. [ABP filters](https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt)  
86. [adgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)  
87. [yokoffing's Annoyance List](https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt)  
88. [yokoffing's Privacy Essentials](https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt)  
89. [Spam404's Adblock-list](https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt)  
90. [Brave-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt)  
91. [Brave-ios-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt)  
92. [Brave-Android-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt)  
93. [Brave-Firstparty filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt)  
94. [Brave-Firstparty-cname filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt)  
95. [Brave-Unbreak filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt)  
96. [Filter unblocking search ads and self-promotions](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt)  
97. [Peter Lowe’s Ad and Tracking Server List](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0)  
98. [Dandelion Sprout's Anti-Malware List (for AdGuard)](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt)  
99. [Dandelion Sprout's Anti-Malware List (for Adblock Plus and AdBlock)](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt)  
100. [The Block List Project - Smart TV List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/smart-tv-ags.txt)  
101. [The Block List Project - Ads List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt)  
102. [The Block List Project - Basic Starter List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt)  
103. [The Block List Project - Tracking List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt)  
104. [The Block List Project - Malware List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt)  
105. [The Block List Project - Scam List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt)  
106. [The Block List Project - Phishing List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt)  
107. [The Block List Project - Ransomware List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt)  
108. [The Block List Project - Fraud List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt)  
109. [The Block List Project - Abuse List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt)  
110. [The Block List Project - Redirect List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/redirect-ags.txt)  
111. [Anti-Adblock Killer](https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt)  
112. [Scam Blocklist (Adblock Plus)](https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt)  
113. [Smart-TV Blocklist for AdGuard Home](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt)
114. [HaGeZi's Pro DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt)
115. [HaGeZi's Fake DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt)
116. [HaGeZi's Light DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt)
117. [HaGeZi's DynDNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt)
118. [HaGeZi's Normal DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt)
119. [HaGeZi's Personal DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/personal.txt)
120. [HaGeZi's Pop-Up Ads DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt)
121. [HaGeZi's Ultimate DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt)
122. [HaGeZi's The World's Most Abused TLDs - Aggressive](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt)
123. [HaGeZi's The World's Most Abused TLDs](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt)
124. [HaGeZi's Threat Intelligence Feeds DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt)
125. [HaGeZi's Allowlist Referral](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt)
126. [HaGeZi's Allowlist URL Shortener](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt)
127. [neodevpro's adblock list](https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker)
128. [notracking's adblock List](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)
129. [damengzhu's adblock List](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt)
130. [damengzhu's DNS List](https://raw.githubusercontent.com/damengzhu/banad/main/dnslist.txt)
131. [hectorm's adblock List](https://hblock.molinero.dev/hosts_adblock.txt)
132. [1Hosts's adblock list](https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/adblock.txt)
  

  

  
</details>

## 五、特别致谢
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
9. [Bibaiji](https://github.com/Bibaiji/ad-rules/)
10. [uBlockOrigin](https://github.com/uBlockOrigin/uAssets)
11. [ADguardTeam](https://github.com/AdguardTeam/AdGuardFilters)
12. [HyperADRules](https://github.com/Lynricsy/HyperADRules)
13. [guandasheng](https://github.com/guandasheng/adguardhome)
14. [xinggsf](https://github.com/xinggsf/Adblock-Plus-Rule)
15. [superbigsteam](https://github.com/superbigsteam/adguardhomeguiz)
16. [hoshsadiq](https://github.com/hoshsadiq/adblock-nocoin-list)
17. [jerryn70](https://github.com/jerryn70/GoodbyeAds)
18. [malware-filter](https://gitlab.com/malware-filter)
19. [abp-filters](https://gitlab.com/eyeo/anti-cv/abp-filters-anti-cv)
20. [banbendalao](https://github.com/banbendalao/ADgk)
21. [yokoffing](https://github.com/yokoffing/filterlists)
22. [Spam404](https://github.com/Spam404/lists)
23. [brave](https://github.com/brave/adblock-lists)
24. [Peter Lowe](https://pgl.yoyo.org/adservers/)
25. [DandelionSprout](https://github.com/DandelionSprout/adfilt)
26. [blocklistproject](https://github.com/blocklistproject/Lists)
27. [reek](https://github.com/reek/anti-adblock-killer)
28. [durablenapkin](https://github.com/durablenapkin/scamblocklist)
29. [oisd](https://github.com/sjhgvr/oisd)
30. [Perflyst](https://github.com/Perflyst/PiHoleBlocklist)
31. [hagezi](https://github.com/hagezi/dns-blocklists)
32. [neodevpro](https://github.com/neodevpro/neodevhost)
33. [notracking](https://github.com/notracking/hosts-blocklists)
34. [damengzhu](https://github.com/damengzhu/banad)
35. [hectorm](https://github.com/hectorm/hblock)
36. [badmojr](https://github.com/badmojr/1Hosts)

  </details>





<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
