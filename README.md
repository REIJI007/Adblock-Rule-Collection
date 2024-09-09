[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 100px; margin-bottom: 40px;">Adblock-Rule-Collection</h1>

<!-- 居中的副标题 -->
<h2 align="center" style="font-size: 30px; margin-bottom: 40px;">一个将众多广告过滤器条目去重、筛选、合并汇总合并生成的广告拦截器,规则总数多达百万，包含URL过滤规则、资源过滤规则、域名过滤规则、CSS选择器规则、脚本过滤规则、隐私保护规则、Cookie过滤规则、白名单例外规则、关键字过滤规则、webrtc拦截屏蔽规则、正则表达式过滤规则、网络过滤规则、字体和样式过滤规则、重定向规则、脚本注入规则、反指纹跟踪规则、欺诈过滤规则、恶意网站过滤规则、网络钓鱼过滤规则、滥用网站过滤规则、挖矿过滤规则、垃圾邮件过滤规则、僵尸网络屏蔽规则等类型的条目</h2>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/REIJI007/Adblock-Rule-Collection" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/REIJI007/Adblock-Rule-Collection" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/REIJI007/Adblock-Rule-Collection" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/REIJI007/Adblock-Rule-Collection" alt="license" style="margin-right: 10px;">
</p>


## 一、关于Adblock-Rule-Collection，你可使用本仓库中的Adblock_rule_generator.py脚本合并去重生成广告过滤规则列表，注意修改生成文件的保存路径与生成的文件名，可按需求添加不同的上游广告过滤规则列表进行DIY定制，但必须符合adblock plus语法或adguard语法才有效,随着加入合并的广告过滤规则越来越多，生成文件体积也会越来越大，若你的广告过滤程序订阅失败则就下载规则文件充当本地用户过滤器。
<hr>

##  警告:本过滤器订阅有可能破坏某些网站的功能，也有可能封禁某些色情、赌博、毒品网站，使用前请斟酌考虑，如有误杀请积极向上游issue反馈，本仓库仅提供去重、筛选、合并功能

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

1. [**Anti-ad for Adguard**](https://anti-ad.net/adguard.txt)
2. [**Anti-ad-Easylist**](https://anti-ad.net/easylist.txt)
3. [**OISD Big List**](https://big.oisd.nl)
4. [**EasyList**](https://easylist.to/easylist/easylist.txt)
5. [**EasyList — First-Party Servers**](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt)
6. [**EasyList — Third-Party Servers**](https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt)
7. [**EasyList Privacy**](https://easylist.to/easylist/easyprivacy.txt)
8. [**EasyList Privacy — Tracking Servers**](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt)
9. [**EasyPrivacy — Third-Party Trackers**](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt)
10. [**EasyPrivacy — Third-Party International Trackers**](https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt)
11. [**Easylist Cookie List**](https://secure.fanboy.co.nz/fanboy-cookiemonster.txt)
12. [**EasyList China**](https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt)
13. [**Adblock Warning Removal List**](https://easylist-downloads.adblockplus.org/antiadblockfilters.txt)
14. [**Fanboy's Annoyance List**](https://secure.fanboy.co.nz/fanboy-annoyance.txt)
15. [**Fanboy's Social Blocking List**](https://easylist.to/easylist/fanboy-social.txt)
16. [**Fanboy's Anti-Facebook List**](https://www.fanboy.co.nz/fanboy-antifacebook.txt)
17. [**Fanboy's Anti-Third-Party Fonts**](https://www.fanboy.co.nz/fanboy-antifonts.txt)
18. [**Fanboy's Notifications Blocking List**](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt)
19. [**CJX's Annoyance List**](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)
20. [**CJX's EasyList Lite**](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt)
21. [**CJX's uBlock List**](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt)
22. [**uniartrisan's Adblock List Plus**](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt)
23. [**uniartrisan's Privacy List**](https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt)
24. [**AdRules AdBlock List Plus**](https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt)
25. [**AdRules DNS List**](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt)
26. [**AdBlock DNS**](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt)
27. [**AdBlock Filter**](https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt)
28. [**GOODBYEADS**](https://raw.githubusercontent.com/8680/GOODBYEADS/master/rules.txt)
29. [**GOODBYEADS-DNS**](https://raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt)
30. [**GOODBYEADS-Allow**](https://raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt)
31. [**AWAvenue-Ads-Rule**](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt)
32. [**Bibaiji's Ad-Rules**](https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/ad-rules.txt)
33. [**uBlock Filters**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt)
34. [**uBlock Privacy Filter**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt)
35. [**uBlock Mobile Filter**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt)
36. [**uBlock Badware Risks Filter**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt)
37. [**uBlock Annoyances-Cookies Filter**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt)
38. [**uBlock Annoyances-Others Filter**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt)
39. [**uBlock Resource Abuse Filters**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt)
40. [**uBlock Unbreak Filter**](https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt)
41. [**AdGuard Base Filter Cryptominers**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt)
42. [**AdGuard Exclusion Rules**](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt)
43. [**AdGuard Exception Rules**](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt)
44. [**AdGuard SDNS Filter**](https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt)
45. [**AdGuard Base Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt)
46. [**AdGuard Base Filter — First-Party Servers**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt)
47. [**AdGuard Base Filter — Foreign Servers**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt)
48. [**AdGuard Mobile Filter**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)
49. [**AdGuard Tracking Protection Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt)
50. [**AdGuard Tracking Protection Filter — First-Party Trackers**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt)
51. [**AdGuard Tracking Protection filter — Third-Party Trackers**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt)
52. [**AdGuard Tracking Protection filter — Mobile Trackers**](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt)
53. [**AdGuard URL Tracking Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt)
54. [**AdGuard Social Media Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt)
55. [**AdGuard Annoyances Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt)
56. [**AdGuard CNAME Original Trackers List**](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt)
57. [**AdGuard CNAME Disguised Ads List**](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt)
58. [**AdGuard CNAME Disguised Clickthroughs List**](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt)
59. [**AdGuard CNAME Disguised Microsites List**](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt)
60. [**AdGuard CNAME Disguised Trackers List**](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt)
61. [**AdGuard CNAME Disguised Mail Trackers List**](https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt)
62. [**AdGuard Chinese Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)
63. [**AdGuard DNS Filter**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt)
64. [**AdGuard for Android**](https://filters.adtidy.org/android/filters/11.txt)
65. [**AdGuard for iOS**](https://filters.adtidy.org/ios/filters/11.txt)
66. [**HyperADRules**](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt)
67. [**HyperADRules-DNS**](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt)
68. [**HyperADRules-Allow**](https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/allow.txt)
69. [**TheBestAdRules**](https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt)
70. [**xinggsf's Rules**](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt)
71. [**xinggsf's MV Rules**](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt)
72. [**superbigsteam Rules**](https://raw.githubusercontent.com/superbigsteam/adguardhomeguiz/main/rule/all.txt)
73. [**Adblock NoCoin List**](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt)
74. [**GoodbyeAds-AdBlock-Filter**](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt)
75. [**GoodbyeAds-Ultra-AdBlock-Filter**](https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master)
76. [**Phishing URL Blocklist — AdGuard**](https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt)
77. [**Phishing URL Blocklist — AdGuard Home**](https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt)
78. [**Phishing URL Blocklist — uBlock Origin**](https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt)
79. [**Malicious URL Blocklist — AdGuard**](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt)
80. [**Malicious URL Blocklist — AdGuard Home**](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt)
81. [**Malicious URL Blocklist — uBlock Origin**](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt)
82. [**Tracking JS Blocklist**](https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt)
83. [**Botnet IP Blocklist — AdGuard**](https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt)
84. [**Botnet IP Blocklist — AdGuard Home**](https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt)
85. [**Botnet IP Blocklist — uBlock Origin**](https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt)
86. [**ABP Filters**](https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt)
87. [**ADgk**](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)
88. [**Yokoffing's Annoyance List**](https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt)
89. [**Yokoffing's Privacy Essentials**](https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt)
90. [**Spam404's Adblock List**](https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt)
91. [**Brave-Specific Filter**](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt)
92. [**Brave-iOS-Specific Filter**](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt)
93. [**Brave-Android-Specific Filter**](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt)
94. [**Brave-Firstparty Filter**](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt)
95. [**Brave-Firstparty-CNAME Filter**](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt)
96. [**Brave-Unbreak Filter**](https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt)
97. [**Filter Unblocking Search Ads and Self-Promotions**](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt)
98. [**Peter Lowe’s Ad and Tracking Server List**](https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0)
99. [**Dandelion Sprout's Anti-Malware List (AdGuard)**](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt)
100. [**Dandelion Sprout's Anti-Malware List (Adblock Plus and AdBlock)**](https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt)
101. [**The Block List Project - Ads List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt)
102. [**The Block List Project - Basic Starter List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt)
103. [**The Block List Project - Tracking List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt)
104. [**The Block List Project - Malware List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt)
105. [**The Block List Project - Scam List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt)
106. [**The Block List Project - Phishing List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt)
107. [**The Block List Project - Ransomware List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt)
108. [**The Block List Project - Fraud List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt)
109. [**The Block List Project - Abuse List**](https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt)
110. [**Anti-Adblock Killer**](https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt)
111. [**Scam Blocklist (Adblock Plus)**](https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt)
112. [**Smart-TV Blocklist for AdGuard Home**](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt)


</details>

## 五、特别致谢
<details>
  <summary>致谢名单</summary>

1、anti-AD
(https://github.com/privacy-protection-tools/anti-AD)<br>
2、easylist
(https://github.com/easylist/easylist)<br>
3、cjxlist
(https://github.com/cjx82630/cjxlist)<br>
4、uniartisan
(https://github.com/uniartisan/adblock_list)<br>
5、Cats-Team
(https://github.com/Cats-Team/AdRules)<br>
6、217heidai
(https://github.com/217heidai/adblockfilters)<br>
7、GOODBYEADS
(https://github.com/8680/GOODBYEADS)<br>
8、AWAvenue-Ads-Rule
(https://github.com/TG-Twilight/AWAvenue-Ads-Rule)<br>
9、Bibaiji
(https://github.com/Bibaiji/ad-rules/)<br>
10、uBlockOrigin
(https://github.com/uBlockOrigin/uAssets)<br>
11、ADguardTeam
(https://github.com/AdguardTeam/AdGuardFilters)<br>
12、HyperADRules
(https://github.com/Lynricsy/HyperADRules)<br>
13、guandasheng
(https://github.com/guandasheng/adguardhome)<br>
14、xinggsf
(https://github.com/xinggsf/Adblock-Plus-Rule)<br>
15、superbigsteam
(https://github.com/superbigsteam/adguardhomeguiz)<br>
16、hoshsadiq
(https://github.com/hoshsadiq/adblock-nocoin-list)<br>
17、jerryn70
(https://github.com/jerryn70/GoodbyeAds)<br>
18、malware-filter
(https://gitlab.com/malware-filter)<br>
19、abp-filters
(https://gitlab.com/eyeo/anti-cv/abp-filters-anti-cv)<br>
20、banbendalao
(https://github.com/banbendalao/ADgk)<br>
21、yokoffing
(https://github.com/yokoffing/filterlists)<br>
22、Spam404
(https://github.com/Spam404/lists)<br>
23、brave
(https://github.com/brave/adblock-lists)<br>
24、Peter Lowe
(https://pgl.yoyo.org/adservers/)<br>
25、DandelionSprout
(https://github.com/DandelionSprout/adfilt)<br>
26、blocklistproject
(https://github.com/blocklistproject/Lists)<br>
27、reek
(https://github.com/reek/anti-adblock-killer)<br>
28、durablenapkin
(https://github.com/durablenapkin/scamblocklist)<br>
29、oisd
(https://github.com/sjhgvr/oisd)<br>
30、Perflyst
(https://github.com/Perflyst/PiHoleBlocklist)<br>




  </details>





<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
