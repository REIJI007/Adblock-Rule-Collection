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
**https://raw.githubusercontent.com/xiulou23/Adguard-Rule-Collection/refs/heads/main/ADBLOCK_RULE_COLLECTION.txt** <br>

**精简版** <br>
**https://raw.githubusercontent.com/xiulou23/Adguard-Rule-Collection/refs/heads/main/ADBLOCK_RULE_COLLECTION_Lite.txt** <br>

2、从Release中下载过滤器文件进行本地导入广告过滤器，release每20分钟自动发布一次
<hr>


## 三、适用范围
适用于ADguard,Adblock Plus,uBlock Origin,Brave Browser等各类符合Adblock Plus (ABP) 语法、uBlock Origin 语法、AdGuard 语法的浏览器插件或广告拦截程序
<br>


## 四、汇总引用规则列表有如下
<details>
  <summary>查看规则列表</summary>

1. [Anti-ad for AdGuard](https://anti-ad.net/adguard.txt)  
2. [Anti-ad EasyList](https://anti-ad.net/easylist.txt)  
3. [OISD Big List](https://big.oisd.nl)  
4. [EasyList](https://easylist.to/easylist/easylist.txt)  
5. [EasyList AdServers](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt)  
6. [EasyList ThirdParty Servers](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt)  
7. [EasyList AdServers Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers_popup.txt)  
8. [EasyList ThirdParty Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty_popup.txt)  
9. [EasyList AllowList](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt)  
10. [EasyList AllowList Dimensions](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_dimensions.txt)  
11. [EasyList AllowList General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_general_hide.txt)  
12. [EasyList AllowList Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_popup.txt)  
13. [EasyList General Block](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt)  
14. [EasyList General Block Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_popup.txt)  
15. [EasyList General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt)  
16. [EasyPrivacy](https://easylist.to/easylist/easyprivacy.txt)  
17. [EasyPrivacy AllowList](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt)  
18. [EasyPrivacy AllowList International](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt)  
19. [EasyPrivacy General](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt)  
20. [EasyPrivacy General EmailTrackers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general_emailtrackers.txt)  
21. [EasyPrivacy Third-Party](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt)  
22. [EasyPrivacy Third-Party International](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt)  
23. [EasyPrivacy TrackingServers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt)  
24. [EasyPrivacy TrackingServers ThirdParty](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt)  
25. [EasyPrivacy TrackingServers Admiral](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt)  
26. [EasyPrivacy TrackingServers General](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt)  
27. [EasyPrivacy TrackingServers Mining](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_mining.txt)  
28. [EasyPrivacy TrackingServers Notifications](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_notifications.txt)  
29. [EasyList Cookie List](https://secure.fanboy.co.nz/fanboy-cookiemonster.txt)  
30. [EasyList Cookie AllowList](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt)  
31. [EasyList Cookie AllowList General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist_general_hide.txt)  
32. [EasyList Cookie General Block](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_block.txt)  
33. [EasyList Cookie General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_hide.txt)  
34. [EasyList Cookie ThirdParty](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_thirdparty.txt)  
35. [EasyList China](https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt)  
36. [Adblock Warning Removal List](https://easylist-downloads.adblockplus.org/antiadblockfilters.txt)  
37. [Fanboy's Annoyance List](https://secure.fanboy.co.nz/fanboy-annoyance.txt)  
38. [Fanboy's Social Blocking List](https://easylist.to/easylist/fanboy-social.txt)  
39. [Fanboy's Anti-thirdparty Fonts](https://www.fanboy.co.nz/fanboy-antifonts.txt)  
40. [Fanboy's Notifications Blocking List](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt)  
41. [CJX's Annoyance List](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)  
42. [CJX's EasyList Lite](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt)  
43. [CJX's uBlock List](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt)  
44. [Uniartrisan's Adblock List Plus](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt)  
45. [Uniartrisan's Privacy List](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt)  
46. [AdRules AdBlock List Plus](https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt)  
47. [AdRules DNS List](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt)  
48. [AdBlock DNS](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt)  
49. [AdBlock Filter](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt)  
50. [GOODBYEADS](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt)
51. [GOODBYEADS-DNS](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt)  
52. [GOODBYEADS-allow](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt)  
53. [AWAvenue-Ads-Rule](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt)  
54. [uBlock filters](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt)  
55. [uBlock privacy filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt)  
56. [uBlock mobile filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt)  
57. [uBlock Badware risks filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt)  
58. [uBlock Annoyances-Cookies filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt)  
59. [uBlock Annoyances-others filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt)  
60. [uBlock Resource abuse filters](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt)  
61. [uBlock Unbreak filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt)  
62. [ADguard Base filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_2_Base/filter.txt)  
63. [ADguard Spyware filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_3_Spyware/filter.txt)  
64. [ADguard Social filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_4_Social/filter.txt)  
65. [ADguard Mobile filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_11_Mobile/filter.txt)  
66. [ADguard Annoyances filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_14_Annoyances/filter.txt)  
67. [ADguard DnsFilter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_15_DnsFilter/filter.txt)  
68. [ADguard TrackParam filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_17_TrackParam/filter.txt)  
69. [ADguard Annoyances_Cookies filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_18_Annoyances_Cookies/filter.txt)  
70. [ADguard Annoyances_Popups filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_19_Annoyances_Popups/filter.txt)  
71. [ADguard Annoyances_MobileApp filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_20_Annoyances_MobileApp/filter.txt)  
72. [ADguard Annoyances_Other filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_21_Annoyances_Other/filter.txt)  
73. [ADguard Annoyances_Widgets filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_22_Annoyances_Widgets/filter.txt)  
74. [ADguard Chinese filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/filter_224_Chinese/filter.txt)  
75. [ADguard ThirdParty EasyList](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_101_EasyList/filter.txt)  
76. [ADguard ThirdParty EasyListChina](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt)  
77. [ADguard ThirdParty EasyPrivacy](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_118_EasyPrivacy/filter.txt)  
78. [ADguard ThirdParty Fanboy's Annoyance List](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_122_FanboysAnnoyances/filter.txt)  
79. [ADguard ThirdParty Fanboy's Social Blocking List](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_123_FanboysSocialBlockingList/filter.txt)  
80. [ADguard ThirdParty Web Annoyances Ultralist](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_201_WebAnnoyancesUltralist/filter.txt)  
81. [ADguard ThirdParty Peter Lowe's List](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_204_PeterLowesList/filter.txt)  
82. [ADguard ThirdParty Adblock Warning Removal List](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_207_AdblockWarningRemovalList/filter.txt)  
83. [ADguard ThirdParty Online Malicious URL Blocklist](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_208_Online_Malicious_URL_Blocklist/filter.txt)  
84. [ADguard ThirdParty ADgk Mobile China list](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_209_ADgkMobileChinalist/filter.txt)  
85. [ADguard ThirdParty Spam404](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_210_Spam404/filter.txt)  
86. [ADguard ThirdParty Anti-Adblock Killer](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_211_AntiAdblockKillerReek/filter.txt)  
87. [ADguard ThirdParty China List And EasyList](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_219_ChinaListAndEasyList/filter.tx)  
88. [ADguard ThirdParty CJX's Annoyance List](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_220_CJXsAnnoyanceList/filter.txt)  
89. [ADguard ThirdParty xinggsf](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_228_xinggsf/filter.txt)  
90. [ADguard ThirdParty I Don't Care About Cookies](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_229_IdontCareAboutCookies/filter.txt)  
91. [ADguard ThirdParty Fanboy Antifonts](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_239_FanboyAntifonts/filter.txt)  
92. [ADguard ThirdParty BarbBlock](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_240_BarbBlock/filter.txt)  
93. [ADguard ThirdParty Fanboy Cookiemonster](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_241_FanboyCookiemonster/filter.txt)  
94. [ADguard ThirdParty NoCoin](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_242_NoCoin/filter.txt)  
95. [ADguard ThirdParty Dandelion Sprout Annoyances](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt)  
96. [ADguard ThirdParty Legitimate URL Shortener](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt)  
97. [ADguard ThirdParty Phishing URL Blocklist](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_255_Phishing_URL_Blocklist/filter.txt)  
98. [ADguard ThirdParty Scam Blocklist](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_256_Scam_Blocklist/filter.txt)  
99. [ADguard ThirdParty uBlock Origin Badware risks](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/refs/heads/master/filters/ThirdParty/filter_257_uBlock_Origin_Badware_risks/filter.txt)  
100. [AdGuard Base filter?first-party servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt)
101. [AdGuard Base filter?foreign servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt)  
102. [AdGuard Base filter cryptominers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt)  
103. [AdGuard Base filter-adservers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt)  
104. [AdGuard Base filter-adservers_firstparty](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt)  
105. [AdGuard Base filter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt)  
106. [AdGuard Base filter-allowlist_stealth](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt)  
107. [AdGuard Base filter-antiadblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/antiadblock.txt)  
108. [AdGuard Base filter-replace](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/replace.txt)  
109. [AdGuard Base filter-content_blocker](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/content_blocker.txt)  
110. [AdGuard Exclusion rules](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt)  
111. [AdGuard Exception rules](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt)  
112. [AdGuardSDNSFilter](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt)  
113. [AdGuard Tracking Protection filter ? first-party trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt)  
114. [AdGuard Tracking Protection filter ? third-party trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt)  
115. [AdGuard Tracking Protection filter ? mobile trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt)  
116. [AdGuard Social filter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt)  
117. [AdGuard Social filter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_elemhide.txt)  
118. [AdGuard Social filter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_extensions.txt)  
119. [AdGuard Social filter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_url.txt)  
120. [AdGuard Social filter-popups](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/popups.txt)  
121. [AdGuard Social filter-social_trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/social_trackers.txt)  
122. [AdGuard Annoyances filter-cookies_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt)  
123. [AdGuard Annoyances filter-cookies_general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt)  
124. [AdGuard Annoyances filter-mobile-app_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt)  
125. [AdGuard Annoyances filter-mobile-app_general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt)  
126. [AdGuard Annoyances filter-popups-antiadblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt)  
127. [AdGuard Annoyances filter-popups-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt)  
128. [AdGuard Annoyances filter-popups-general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt)  
129. [AdGuard Annoyances filter-popups-push-notifications_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt)  
130. [AdGuard Annoyances filter-popups-push-notifications_general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt)  
131. [AdGuard Annoyances filter-popups-subscriptions_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt)  
132. [AdGuard Annoyances filter-popups-subscriptions_general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt)  
133. [AdGuard Annoyances filter-Widgets](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt)  
134. [AdGuard CNAME original trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt)  
135. [AdGuard CNAME disguised ads list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt)  
136. [AdGuard CNAME disguised clickthroughs list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt)  
137. [AdGuard CNAME disguised microsites list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt)  
138. [AdGuard CNAME disguised trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt)  
139. [AdGuard CNAME disguised mail_trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt)  
140. [AdGuard for Android](https://filters.adtidy.org/android/filters/11.txt)  
141. [AdGuard for iOS](https://filters.adtidy.org/ios/filters/11.txt)  
142. [AdGuard Chinese filter-adservers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt)  
143. [AdGuard Chinese filter-adservers_firstparty](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt)  
144. [AdGuard ChineseFilter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt)  
145. [AdGuard ChineseFilter-antiadblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/antiadblock.txt)  
146. [AdGuard ChineseFilter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_elemhide.txt)  
147. [AdGuard ChineseFilter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_extensions.txt)  
148. [AdGuard ChineseFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_url.txt)  
149. [AdGuard ChineseFilter-replace](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/replace.txt)  
150. [AdGuard Mobile filter-adservers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)
151. [AdGuard MobileFilter-allowlist_app](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt)
152. [AdGuard MobileFilter-allowlist_web](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt)
153. [AdGuard MobileFilter-antiadblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/antiadblock.txt)
154. [AdGuard MobileFilter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_elemhide.txt)
155. [AdGuard MobileFilter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_extensions.txt)
156. [AdGuard MobileFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_url.txt)
157. [AdGuard MobileFilter-replace](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/replace.txt)
158. [AdGuard SpywareFilter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt)
159. [AdGuard SpywareFilter-cookies_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt)
160. [AdGuard SpywareFilter-cookies_general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_general.txt)
161. [AdGuard SpywareFilter-cookies_specific](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_specific.txt)
162. [AdGuard SpywareFilter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_elemhide.txt)
163. [AdGuard SpywareFilter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt)
164. [AdGuard SpywareFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_url.txt)
165. [AdGuard SpywareFilter-mobile](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt)
166. [AdGuard SpywareFilter-mobile_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt)
167. [AdGuard SpywareFilter-tracking_servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt)
168. [AdGuard SpywareFilter-tracking_servers_firstparty](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt)
169. [AdGuard TrackParamFilter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt)
170. [AdGuard TrackParamFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/general_url.txt)
171. [HyperADRules](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt)
172. [HyperADRules-DNS](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt)
173. [HyperADRules-allow](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/allow.txt)
174. [TheBestAdrules](https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt)
175. [xinggsf's rules](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt)
176. [xinggsf's mv rules](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt)
177. [adblock-nocoin-list](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt)
178. [GoodbyeAds-AdBlock-Filter](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt)
179. [GoodbyeAds-Ultra-AdBlock-Filter](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-Ultra-AdBlock-Filter.txt)
180. [Phishing URL Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt)
181. [Phishing URL Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt)
182. [Phishing URL Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt)
183. [Malicious URL Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt)
184. [Malicious URL Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt)
185. [Malicious URL Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt)
186. [Tracking JS Blocklist](https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt)
187. [Botnet IP Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt)
188. [Botnet IP Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt)
189. [Botnet IP Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt)
190. [ABP filters](https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt)
191. [adgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)
192. [yokoffing's Annoyance List](https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt)
193. [yokoffing's Privacy Essentials](https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt)
194. [Spam404's Adblock-list](https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt)
195. [Brave-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt)
196. [Brave-ios-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt)
197. [Brave-Android-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt)
198. [Brave-Firstparty filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt)
199. [Brave-Firstparty-cname filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt)
200. [Brave-Unbreak filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt)
201. [Filter unblocking search ads and self-promotions](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt)
202. [Peter Lowe’s Ad and Tracking Server List](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0)
203. [Dandelion Sprout's Anti-Malware List (for AdGuard)](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt)
204. [Dandelion Sprout's Anti-Malware List (for Adblock Plus and AdBlock)](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt)
205. [Dandelion Sprout's Compilation List](https://raw.githubusercontent.com/DandelionSprout/adfilt/refs/heads/master/AdGuard%20Home%20Compilation%20List/AdGuardHomeCompilationList.txt)
206. [The Block List Project - Smart TV List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/smart-tv-ags.txt)
207. [The Block List Project - Ads List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt)
208. [The Block List Project - Basic Starter List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt)
209. [The Block List Project - Tracking List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt)
210. [The Block List Project - Malware List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt)
211. [The Block List Project - Scam List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt)
212. [The Block List Project - Phishing List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt)
213. [The Block List Project - Ransomware List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt)
214. [The Block List Project - Fraud List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt)
215. [The Block List Project - Abuse List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt)
216. [The Block List Project - Redirect List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/redirect-ags.txt)
217. [Anti-Adblock Killer](https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt)
218. [Scam Blocklist (Adblock Plus)](https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt)
219. [Smart-TV Blocklist for AdGuard Home](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt)
220. [HaGeZi's Pro DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt)
221. [HaGeZi's Fake DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt)
222. [HaGeZi's Light DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt)
223. [HaGeZi's DynDNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt)
224. [HaGeZi's Normal DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt)
225. [HaGeZi's Personal DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/personal.txt)
226. [HaGeZi's Pop-Up Ads DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt)
227. [HaGeZi's Ultimate DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt)
228. [HaGeZi's The World's Most Abused TLDs - Aggressive](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt)
229. [HaGeZi's The World's Most Abused TLDs - Allow](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt)
230. [HaGeZi's Threat Intelligence Feeds DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt)
231. [HaGeZi's Allowlist Referral](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt)
232. [HaGeZi's Allowlist URL Shortener](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt)
233. [neodevpro's adblock list](https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker)
234. [notracking's adblock List](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)
235. [damengzhu's adblock List](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt)
236. [damengzhu's DNS List](https://raw.githubusercontent.com/damengzhu/banad/main/dnslist.txt)
237. [hectorm's adblock List](https://hblock.molinero.dev/hosts_adblock.txt)
238. [1Hosts's adblock list](https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/adblock.txt)
239. [DD-AD](https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/all.txt)

  

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
