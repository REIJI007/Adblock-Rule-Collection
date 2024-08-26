[![GPL 3.0 license](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
[![CC BY-NC-SA 4.0 license](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
<!-- 居中的大标题 -->
<h1 align="center" style="font-size: 100px; margin-bottom: 40px;">Adblock-Rule-Collection</h1>

<!-- 居中的副标题 -->
<h2 align="center" style="font-size: 30px; margin-bottom: 40px;">一个将众多广告过滤器条目去重汇总合并生成的广告拦截器,规则总数多达百万，包含URL规则、资源过滤规则、域名过滤规则、区域选择器规则、脚本过滤规则、隐私规则、Cookie 过滤规则、例外规则、关键字过滤规则、webrtc拦截屏蔽规则、正则表达式过滤规则、网络过滤规则、字体和样式过滤规则、重定向规则、脚本注入规则、反指纹跟踪规则等类型的条目</h2>

<!-- 徽章（根据需要调整） -->
<p align="center" style="margin-bottom: 40px;">
    <img src="https://img.shields.io/badge/last%20commit-today-brightgreen" alt="last commit" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/forks/REIJI007/Adblock-Rule-Collection" alt="forks" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/stars/REIJI007/Adblock-Rule-Collection" alt="stars" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/issues/REIJI007/Adblock-Rule-Collection" alt="issues" style="margin-right: 10px;">
    <img src="https://img.shields.io/github/license/REIJI007/Adblock-Rule-Collection" alt="license" style="margin-right: 10px;">
</p>


## 一、关于Adblock-Rule-Collection，你可使用本仓库中的Adblock_rule_generator.py脚本合并去重生成广告过滤规则列表，注意修改生成文件的保存路径与生成的文件名，可按需求添加不同的上游广告过滤规则列表进行DIY定制，但必须符合adblock plus语法或adguard语法才有效,随着加入合并的广告过滤规则越来越多，生成文件体积也会越来越大，若你的广告过滤程序订阅失败则就下载规则文件充当本地用户过滤器

<br>

## 二、本仓库使用方式如下：
1、订阅地址: <br> *https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/ADBLOCK_RULE_COLLECTION.txt*<br>
<br>
2、从Release中下载ADBLOCK_RULE_COLLECTION.txt文件进行本地导入广告过滤器，release每20分钟自动发布一次
<br>

## 三、适用范围
适用于ADguard,Adblock Plus,uBlock Origin,Brave Browser等各类符合Adblock Plus (ABP) 语法、uBlock Origin 语法、AdGuard 语法的浏览器插件或广告拦截程序
<br>


## 四、汇总引用规则列表有如下，未来会加入更多
<details>
  <summary>点击展开查看汇总引用规则列表</summary>

**1. Anti-ad for adguard**  
*https://anti-ad.net/adguard.txt*<br>

**2. Anti-ad-Easylist**  
*https://anti-ad.net/easylist.txt*<br>

**3. EasyList**  
*https://easylist.to/easylist/easylist.txt*<br>

**4. EasyList — first-party servers**  
*https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt*<br>

**5. EasyList — third-party servers**  
*https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt*<br>

**6. EasyList Privacy**  
*https://easylist.to/easylist/easyprivacy.txt*<br>

**7. EasyList Privacy — trackingservers**  
*https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt*<br>

**8. EasyPrivacy — third-party trackers**  
*https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt*<br>

**9. EasyPrivacy — third-party international trackers**  
*https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt*<br>

**10. Easylist Cookie List**  
*https://secure.fanboy.co.nz/fanboy-cookiemonster.txt*<br>

**11. EasyList China**  
*https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt*<br>

**12. Fanboy's Annoyance List**  
*https://secure.fanboy.co.nz/fanboy-annoyance.txt*<br>

**13. Fanboy's Social Blocking List**  
*https://easylist.to/easylist/fanboy-social.txt*<br>

**14. CJX's Annoyance List**  
*https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt*<br>

**15. CJX's EasyList Lite**  
*https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt*<br>

**16. CJX's uBlock list**  
*https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt*<br>

**17. uniartrisan's Adblock List Plus**  
*https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt*<br>

**18. uniartrisan's Privacy List**  
*https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt*<br>

**19. AdRules AdBlock List Plus**  
*https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt*<br>

**20. AdRules DNS List**  
*https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt*<br>

**21. AdBlock DNS**  
*https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt*<br>

**22. AdBlock Filter**  
*https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt*<br>

**23. GOODBYEADS**  
*https://raw.githubusercontent.com/8680/GOODBYEADS/master/rules.txt*<br>

**24. GOODBYEADS-DNS**  
*https://raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt*<br>

**25. GOODBYEADS-allow**  
*https://raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt*<br>

**26. AWAvenue-Ads-Rule**  
*https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt*<br>

**27. Bibaiji's ad-rules**  
*https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/ad-rules.txt*<br>

**28. uBlock filters**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt*<br>

**29. uBlock privacy filter**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt*<br>

**30. uBlock mobile filter**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt*<br>

**31. uBlock Badware risks filter**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt*<br>

**32. uBlock Annoyances-Cookies filter**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt*<br>

**33. uBlock Annoyances-others filter**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt*<br>

**34. uBlock Unbreak filter**  
*https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt*<br>

**35. AdGuard Base filter cryptominers**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt*<br>

**36. AdGuard Exclusion rules**  
*https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt*<br>

**37. AdGuard Exception rules**  
*https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt*<br>

**38. AdGuardSDNSFilter**  
*https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt*<br>

**39. Adgurd Base filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt*<br>

**40. AdGuard Base filter — first-party servers**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt*<br>

**41. AdGuard Base filter — foreign servers**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt*<br>

**42. Adgurd Mobile filter**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt*<br>

**43. Adgurd Tracking Protection filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt*<br>

**44. AdGuard Tracking Protection filter — first-party trackers**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt*<br>

**45. AdGuard Tracking Protection filter — third-party trackers**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt*<br>

**46. AdGuard Tracking Protection filter — mobile trackers**  
*https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt*<br>

**47. Adgurd URL Tracking filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt*<br>

**48. Adgurd Social media filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt*<br>

**49. Adgurd Annoyances filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt*<br>

**50. AdGuard CNAME original trackers list**  
*https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt*<br>

**51. AdGuard CNAME disguised ads list**  
*https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt*<br>

**52. AdGuard CNAME disguised clickthroughs list**  
*https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt*<br>

**53. AdGuard CNAME disguised microsites list**  
*https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt*<br>

**54. AdGuard CNAME disguised trackers list**  
*https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt*<br>

**55. AdGuard CNAME disguised mail_trackers list**  
*https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt*<br>

**56. Adgurd Chinese filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt*<br>

**57. Adgurd DNS filter**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt*<br>

**58. AdGuard for Android**  
*https://filters.adtidy.org/android/filters/11.txt*<br>

**59. AdGuard for iOS**  
*https://filters.adtidy.org/ios/filters/11.txt*<br>

**60. HyperADRules**  
*https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt*<br>

**61. HyperADRules-DNS**  
*https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt*<br>

**62. TheBestAdrules**  
*https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt*<br>

**63. xinggsf's rules**  
*https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt*<br>

**64. xinggsf's mv rules**  
*https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt*<br>

**65. superbigsteam rules**  
*https://raw.githubusercontent.com/superbigsteam/adguardhomeguiz/main/rule/all.txt*<br>

**66. adblock-nocoin-list**  
*https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt*<br>

**67. GoodbyeAds-AdBlock-Filter**  
*https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt*<br>

**68. GoodbyeAds-Ultra-AdBlock-Filter**  
*https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-Ultra-AdBlock-Filter.txt*<br>

**69. Phishing URL Blocklist——AdGuard**  
*https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt*<br>

**70. Phishing URL Blocklist——AdGuard Home**  
*https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt*<br>

**71. Phishing URL Blocklist——uBlock Origin**  
*https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt*<br>

**72. Malicious URL Blocklist——AdGuard**  
*https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt*<br>

**73. Malicious URL Blocklist——AdGuard Home**  
*https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt*<br>

**74. Malicious URL Blocklist——uBlock Origin**  
*https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt*<br>

**75. Tracking JS Blocklist**  
*https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt*<br>

**76. Botnet IP Blocklist——AdGuard**  
*https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt*<br>

**77. Botnet IP Blocklist——AdGuard Home**  
*https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt*<br>

**78. Botnet IP Blocklist——uBlock Origin**  
*https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt*<br>

**79. ABP filters**  
*https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt*<br>

**80. adgk**  
*https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt*<br>

**81. yokoffing's Annoyance List**  
*https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt*<br>

**82. yokoffing's Privacy Essentials**  
*https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt*<br>

**83. Spam404's Adblock-list**  
*https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt*<br>

**84. Brave-specific filter**  
*https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt*<br>

**85. Brave-ios-specific filter**  
*https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt*<br>

**86. Brave-Android-specific filter**  
*https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt*<br>

**87. Brave-Firstparty filter**  
*https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt*<br>

**88. Brave-Firstparty-cname filter**  
*https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt*<br>

**89. Brave-Unbreak filter**  
*https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt*<br>

**90. Filter unblocking search ads and self-promotions**  
*https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt*<br>

**91. Peter Lowe’s Ad and Tracking Server List**  
*https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0*<br>

**92. Dandelion Sprout's Anti-Malware List (for AdGuard)**  
*https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt*<br>

**93. Dandelion Sprout's Anti-Malware List (for Adblock Plus and AdBlock)**  
*https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt*<br>

**94. Fanboy's Notifications Blocking List**  
*https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt*<br>

**95. The Block List Project - Ads List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt*<br>

**96. The Block List Project - Basic Starter List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt*<br>

**97. The Block List Project - Tracking List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt*<br>

**98. The Block List Project - Malware List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt*<br>

**99. The Block List Project - Scam List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt*<br>

**100. The Block List Project - Phishing List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt*<br>

**101. The Block List Project - Ransomware List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt*<br>

**102. The Block List Project - Fraud List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt*<br>

**103. The Block List Project - Abuse List**  
*https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt*<br>

</details>


<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
