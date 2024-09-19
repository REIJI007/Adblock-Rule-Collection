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


## 一、关于Adblock-Rule-Collection，你可使用本仓库中的python脚本合并去重生成广告过滤规则列表，注意修改生成文件的保存路径与生成的文件名，可按需求添加不同的上游广告过滤规则列表（兼容adblock plus语法的锅炉其列表均可）进行DIY定制，这个脚本也可以把host拦截规则和Dnsmasq拦截规则处理为adblock plus拦截规则,随着加入合并的广告过滤规则越来越多，生成文件体积也会越来越大，若你的广告过滤程序订阅失败则就下载规则文件充当本地用户过滤器。

<hr>

## 警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博网站，使用前请斟酌考虑，如有误杀请积极向上游issue反馈，本仓库仅提供去重、筛选、合并功能

<hr>
<br>

## 二、本仓库使用方式如下：

<hr> 
1、订阅地址: 

**完整版** <br>
**https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION.txt** <br>

**精简版(只包含adguard列表)** <br>
**https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION_Lite.txt** <br>

2、从Release中下载过滤器文件进行本地导入广告过滤器，release每20分钟自动发布一次
<hr>


## 三、适用范围
适用于ADguard,Adblock Plus,uBlock Origin,Brave Browser等各类符合Adblock Plus (ABP) 语法、uBlock Origin 语法、AdGuard 语法的浏览器插件或广告拦截程序
<br>


## 四、汇总引用规则列表有如下
<details>
  <summary>查看规则列表</summary>

1. [Anti-ad for AdGuard](https://anti-ad.net/adguard.txt)
2. [Anti-ad-Easylist](https://anti-ad.net/easylist.txt)
3. [OISD Big List](https://big.oisd.nl)
4. [EasyList](https://easylist.to/easylist/easylist.txt)
5. [EasyList Adservers](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt)
6. [EasyList Third-Party Servers](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt)
7. [EasyList Adservers Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers_popup.txt)
8. [EasyList Third-Party Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty_popup.txt)
9. [EasyList Allowlist](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt)
10. [EasyList Allowlist Dimensions](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_dimensions.txt)
11. [EasyList General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_general_hide.txt)
12. [EasyList Popup Allowlist](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_popup.txt)
13. [EasyList General Block](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt)
14. [EasyList General Block Popup](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_popup.txt)
15. [EasyList General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt)
16. [EasyPrivacy](https://easylist.to/easylist/easyprivacy.txt)
17. [EasyPrivacy Allowlist](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt)
18. [EasyPrivacy International Allowlist](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt)
19. [EasyPrivacy General](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt)
20. [EasyPrivacy General Email Trackers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general_emailtrackers.txt)
21. [EasyPrivacy Third-Party](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt)
22. [EasyPrivacy International Third-Party](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt)
23. [EasyPrivacy Tracking Servers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt)
24. [EasyPrivacy Third-Party Tracking Servers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt)
25. [EasyPrivacy Admiral Tracking Servers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt)
26. [EasyPrivacy General Tracking Servers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt)
27. [EasyPrivacy Mining Tracking Servers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_mining.txt)
28. [EasyPrivacy Notification Tracking Servers](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_notifications.txt)
29. [Easylist Cookie List](https://secure.fanboy.co.nz/fanboy-cookiemonster.txt)
30. [Easylist Cookie Allowlist](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt)
31. [Easylist Cookie General Hide Allowlist](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist_general_hide.txt)
32. [Easylist Cookie General Block](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_block.txt)
33. [Easylist Cookie General Hide](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_hide.txt)
34. [Easylist Cookie Third-Party](https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_thirdparty.txt)
35. [EasyList China](https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt)
36. [Adblock Warning Removal List](https://easylist-downloads.adblockplus.org/antiadblockfilters.txt)
37. [Fanboy's Annoyance List](https://secure.fanboy.co.nz/fanboy-annoyance.txt)
38. [Fanboy's Social Blocking List](https://easylist.to/easylist/fanboy-social.txt)
39. [Fanboy's Anti-Thirdparty Fonts](https://www.fanboy.co.nz/fanboy-antifonts.txt)
40. [Fanboy's Notifications Blocking List](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt)
41. [CJX's Annoyance List](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)
42. [CJX's EasyList Lite](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt)
43. [CJX's uBlock List](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt)
44. [uniartrisan's Adblock List Plus](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt)
45. [uniartrisan's Privacy List](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt)
46. [AdRules AdBlock List Plus](https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt)
47. [AdRules DNS List](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt)
48. [AdBlock DNS](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt)
49. [AdBlock Filter](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt)
50. [GOODBYEADS](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt)
51. [GOODBYEADS DNS](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt)
52. [GOODBYEADS Allow](https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt)
53. [AWAvenue Ads Rule](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt)
54. [uBlock Filters](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt)
55. [uBlock Privacy Filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt)
56. [uBlock Mobile Filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt)
57. [uBlock Badware Risks Filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt)
58. [uBlock Annoyances Cookies Filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt)
59. [uBlock Annoyances Others Filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt)
60. [uBlock Resource Abuse Filters](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt)
61. [uBlock Unbreak Filter](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt)
62. [AdGuard Base Filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt)
63. [AdGuard Base Filter — First-Party Servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt)
64. [AdGuard Base Filter — Foreign Servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt)
65. [AdGuard Base Filter Cryptominers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt)
66. [AdGuard Base Filter Adservers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt)
67. [AdGuard Base Filter Adservers First-Party](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt)
68. [AdGuard Base Filter Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt)
69. [AdGuard Base Filter Stealth Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt)
70. [AdGuard Base Filter Anti-Adblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/antiadblock.txt)
71. [AdGuard Base Filter Replace](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/replace.txt)
72. [AdGuard Base Filter Content Blocker](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/content_blocker.txt)
73. [AdGuard Exclusion Rules](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt)
74. [AdGuard Exception Rules](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt)
75. [AdGuard SDNS Filter](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt)
76. [AdGuard Tracking Protection Filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt)
77. [AdGuard Tracking Protection Filter — First-Party Trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt)
78. [AdGuard Tracking Protection Filter — Third-Party Trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt)
79. [AdGuard Tracking Protection Filter — Mobile Trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt)
80. [AdGuard URL Tracking Filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt)
81. [AdGuard Social Media Filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt)
82. [AdGuard Social Filter Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt)
83. [AdGuard Social Filter General Element Hide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_elemhide.txt)
84. [AdGuard Social Filter General Extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_extensions.txt)
85. [AdGuard Social Filter General URL](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_url.txt)
86. [AdGuard Social Filter Popups](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/popups.txt)
87. [AdGuard Social Filter Social Trackers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/social_trackers.txt)
88. [AdGuard Annoyances Filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt)
89. [AdGuard Annoyances Filter Cookies Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt)
90. [AdGuard Annoyances Filter Cookies General](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt)
91. [AdGuard Annoyances Filter Mobile App Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt)
92. [AdGuard Annoyances Filter Mobile App General](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt)
93. [AdGuard Annoyances Filter Popups Anti-Adblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt)
94. [AdGuard Annoyances Filter Popups Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt)
95. [AdGuard Annoyances Filter Popups General](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt)
96. [AdGuard Annoyances Filter Push Notifications Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt)
97. [AdGuard Annoyances Filter Push Notifications General](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt)
98. [AdGuard Annoyances Filter Subscriptions Allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt)
99. [AdGuard Annoyances Filter Subscriptions General](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt)
100. [AdGuard Annoyances Filter Widgets](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt)
101. [AdGuard CNAME original trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt)  
102. [AdGuard CNAME disguised ads list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt)  
103. [AdGuard CNAME disguised clickthroughs list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt)  
104. [AdGuard CNAME disguised microsites list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt)  
105. [AdGuard CNAME disguised trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt)  
106. [AdGuard CNAME disguised mail_trackers list](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt)  
107. [AdGuard DNS filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt)  
108. [AdGuard for Android](https://filters.adtidy.org/android/filters/11.txt)  
109. [AdGuard for iOS](https://filters.adtidy.org/ios/filters/11.txt)  
110. [AdGuard Chinese filter](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)  
111. [AdGuard Chinese filter-adservers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt)  
112. [AdGuard Chinese filter-adservers_firstparty](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt)  
113. [AdGuard ChineseFilter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt)  
114. [AdGuard ChineseFilter-antiadblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/antiadblock.txt)  
115. [AdGuard ChineseFilter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_elemhide.txt)  
116. [AdGuard ChineseFilter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_extensions.txt)  
117. [AdGuard ChineseFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_url.txt)  
118. [AdGuard ChineseFilter-replace](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/replace.txt)  
119. [AdGuard Mobile filter](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)  
120. [AdGuard MobileFilter-adservers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)  
121. [AdGuard MobileFilter-allowlist_app](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt)  
122. [AdGuard MobileFilter-allowlist_web](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt)  
123. [AdGuard MobileFilter-antiadblock](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/antiadblock.txt)  
124. [AdGuard MobileFilter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_elemhide.txt)  
125. [AdGuard MobileFilter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_extensions.txt)  
126. [AdGuard MobileFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_url.txt)  
127. [AdGuard MobileFilter-replace](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/replace.txt)  
128. [AdGuard SpywareFilter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt)  
129. [AdGuard SpywareFilter-cookies_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt)  
130. [AdGuard SpywareFilter-cookies_general](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_general.txt)  
131. [AdGuard SpywareFilter-cookies_specific](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_specific.txt)  
132. [AdGuard SpywareFilter-general_elemhide](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_elemhide.txt)  
133. [AdGuard SpywareFilter-general_extensions](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt)  
134. [AdGuard SpywareFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_url.txt)  
135. [AdGuard SpywareFilter-mobile](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt)  
136. [AdGuard SpywareFilter-mobile_allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt)  
137. [AdGuard SpywareFilter-tracking_servers](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt)  
138. [AdGuard SpywareFilter-tracking_servers_firstparty](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt)  
139. [AdGuard TrackParamFilter-allowlist](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt)  
140. [AdGuard TrackParamFilter-general_url](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/general_url.txt)  
141. [HyperADRules](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt)  
142. [HyperADRules-DNS](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt)  
143. [HyperADRules-allow](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/allow.txt)  
144. [TheBestAdrules](https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt)  
145. [xinggsf's rules](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt)  
146. [xinggsf's mv rules](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt)  
147. [adblock-nocoin-list](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt)  
148. [GoodbyeAds-AdBlock-Filter](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt)  
149. [GoodbyeAds-Ultra-AdBlock-Filter](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-Ultra-AdBlock-Filter.txt)
150. [Phishing URL Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt)  
151. [Phishing URL Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt)  
152. [Phishing URL Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt)  
153. [Malicious URL Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt)  
154. [Malicious URL Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt)  
155. [Malicious URL Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt)  
156. [Tracking JS Blocklist](https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt)  
157. [Botnet IP Blocklist——AdGuard](https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt)  
158. [Botnet IP Blocklist——AdGuard Home](https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt)  
159. [Botnet IP Blocklist——uBlock Origin](https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt)  
160. [ABP filters](https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt)  
161. [adgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)  
162. [yokoffing's Annoyance List](https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt)  
163. [yokoffing's Privacy Essentials](https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt)  
164. [Spam404's Adblock-list](https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt)  
165. [Brave-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt)  
166. [Brave-ios-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt)  
167. [Brave-Android-specific filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt)  
168. [Brave-Firstparty filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt)  
169. [Brave-Firstparty-cname filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt)  
170. [Brave-Unbreak filter](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt)  
171. [Filter unblocking search ads and self-promotions](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt)  
172. [Peter Lowe’s Ad and Tracking Server List](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0)  
173. [Dandelion Sprout's Anti-Malware List (for AdGuard)](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt)  
174. [Dandelion Sprout's Anti-Malware List (for Adblock Plus and AdBlock)](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt)  
175. [The Block List Project - Smart TV List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/smart-tv-ags.txt)  
176. [The Block List Project - Ads List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt)  
177. [The Block List Project - Basic Starter List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt)  
178. [The Block List Project - Tracking List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt)  
179. [The Block List Project - Malware List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt)  
180. [The Block List Project - Scam List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt)  
181. [The Block List Project - Phishing List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt)  
182. [The Block List Project - Ransomware List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt)  
183. [The Block List Project - Fraud List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt)  
184. [The Block List Project - Abuse List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt)  
185. [The Block List Project - Redirect List](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/redirect-ags.txt)  
186. [Anti-Adblock Killer](https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt)  
187. [Scam Blocklist (Adblock Plus)](https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt)  
188. [Smart-TV Blocklist for AdGuard Home](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt)  
189. [HaGeZi's Pro DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt)  
190. [HaGeZi's Fake DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt)  
191. [HaGeZi's Light DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt)  
192. [HaGeZi's DynDNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt)  
193. [HaGeZi's Normal DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt)  
194. [HaGeZi's Personal DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/personal.txt)  
195. [HaGeZi's Pop-Up Ads DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt)  
196. [HaGeZi's Ultimate DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt)  
197. [HaGeZi's The World's Most Abused TLDs - Aggressive](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt)  
198. [HaGeZi's The World's Most Abused TLDs - Allow](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt)  
199. [HaGeZi's Threat Intelligence Feeds DNS Blocklist](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt)  
200. [HaGeZi's Allowlist Referral](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt)  
201. [HaGeZi's Allowlist URL Shortener](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt)  
202. [neodevpro's adblock list](https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker)  
203. [notracking's adblock List](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)  
204. [damengzhu's adblock List](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt)  
205. [damengzhu's DNS List](https://raw.githubusercontent.com/damengzhu/banad/main/dnslist.txt)  
206. [hectorm's adblock List](https://hblock.molinero.dev/hosts_adblock.txt)  
207. [1Hosts's adblock list](https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/adblock.txt)
208. [DD-AD](https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/all.txt)  
  



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

  </details>





<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
