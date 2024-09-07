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

1. Anti-ad for adguard<br>  
   https://anti-ad.net/adguard.txt<br>
   
3. Anti-ad-Easylist<br>  
   https://anti-ad.net/easylist.txt<br>

4. OISD Big List<br> 
   https://big.oisd.nl<br>

5. EasyList<br>  
   https://easylist.to/easylist/easylist.txt<br>

6. EasyList — first-party servers<br>  
   https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt<br>

7. EasyList — third-party servers<br>  
   https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt<br>

8. EasyList Privacy<br>  
   https://easylist.to/easylist/easyprivacy.txt<br>

9. EasyList Privacy — trackingservers<br>  
   https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt<br>

10. EasyPrivacy — third-party trackers<br>  
   https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt<br>

11. EasyPrivacy — third-party international trackers<br>  
   https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt<br>

12. Easylist Cookie List<br>  
    https://secure.fanboy.co.nz/fanboy-cookiemonster.txt<br>

13. EasyList China<br>  
    https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt<br>
    
13、Adblock Warning Removal List<br>
    https://easylist-downloads.adblockplus.org/antiadblockfilters.txt<br>

14. Fanboy's Annoyance List<br>  
    https://secure.fanboy.co.nz/fanboy-annoyance.txt<br>

15. Fanboy's Social Blocking List<br>  
    https://easylist.to/easylist/fanboy-social.txt<br>
    
16. Fanboy's Anti-Facebook List<br>
    https://www.fanboy.co.nz/fanboy-antifacebook.txt<br>

17. Fanboy's Anti-thirdparty Fonts<br>
    https://www.fanboy.co.nz/fanboy-antifonts.txt<br>
    
18. Fanboy's Notifications Blocking List<br>  
    https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt<br>
    
19. CJX's Annoyance List<br>  
    https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt<br>

20. CJX's EasyList Lite<br>  
    https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt<br>

21. CJX's uBlock list<br>  
    https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt<br>

22. uniartrisan's Adblock List Plus<br>  
    https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt<br>

23. uniartrisan's Privacy List<br>  
    https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt<br>

24. AdRules AdBlock List Plus<br>  
    https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt<br>

25. AdRules DNS List<br>  
    https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt<br>

26. AdBlock DNS<br>  
    https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt<br>

27. AdBlock Filter<br>  
    https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt<br>

28. GOODBYEADS<br>  
    https://raw.githubusercontent.com/8680/GOODBYEADS/master/rules.txt<br>

29. GOODBYEADS-DNS<br>  
    https://raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt<br>

30. GOODBYEADS-allow<br>  
    https://raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt<br>

31. AWAvenue-Ads-Rule<br>  
    https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt<br>

32. Bibaiji's ad-rules<br>  
    https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/ad-rules.txt<br>

33. uBlock filters<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt<br>

34. uBlock privacy filter<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt<br>

35. uBlock mobile filter<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt<br>

36. uBlock Badware risks filter<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt<br>

37. uBlock Annoyances-Cookies filter<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt<br>

38. uBlock Annoyances-others filter<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt<br>

39. uBlock Resource abuse filters<br>
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt<br>

40. uBlock Unbreak filter<br>  
    https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt<br>

41. AdGuard Base filter cryptominers<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt<br>

42. AdGuard Exclusion rules<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt<br>

43. AdGuard Exception rules<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt<br>

44. AdGuardSDNSFilter<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt<br>

45. AdGuard Base filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt<br>

46. AdGuard Base filter — first-party servers<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt<br>

47. AdGuard Base filter — foreign servers<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt<br>

48. AdGuard Mobile filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt<br>

49. AdGuard Tracking Protection filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt<br>

50. AdGuard Tracking Protection filter — first-party trackers<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt<br>

51. AdGuard Tracking Protection filter — third-party trackers<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt<br>

52. AdGuard Tracking Protection filter — mobile trackers<br>  
    https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt<br>

53. AdGuard URL Tracking filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt<br>

54. AdGuard Social media filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt<br>

55. AdGuard Annoyances filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt<br>

56. AdGuard CNAME original trackers list<br>  
    https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt<br>

57. AdGuard CNAME disguised ads list<br>  
    https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt<br>

58. AdGuard CNAME disguised clickthroughs list<br>  
    https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt<br>

59. AdGuard CNAME disguised microsites list<br>  
    https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt<br>

60. AdGuard CNAME disguised trackers list<br>  
    https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt<br>

61. AdGuard CNAME disguised mail_trackers list<br>  
    https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt<br>

62. AdGuard Chinese filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt<br>

63. AdGuard DNS filter<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt<br>

64. AdGuard for Android<br>  
    https://filters.adtidy.org/android/filters/11.txt<br>

65. AdGuard for iOS<br>  
    https://filters.adtidy.org/ios/filters/11.txt<br>

66. HyperADRules<br>  
    https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt<br>

67. HyperADRules-DNS<br>  
    https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt<br>

68. HyperADRules-allow<br>
    https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/allow.txt<br>

69. TheBestAdrules<br>  
    https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt<br>

70. xinggsf's rules<br>  
    https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt<br>

71. xinggsf's mv rules<br>  
    https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt<br>

72. superbigsteam rules<br>  
    https://raw.githubusercontent.com/superbigsteam/adguardhomeguiz/main/rule/all.txt<br>

73. adblock-nocoin-list<br>  
    https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt<br>

74. GoodbyeAds-AdBlock-Filter<br>  
    https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt<br>

75. GoodbyeAds-Ultra-AdBlock-Filter<br>  
    https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master<br>

76. Phishing URL Blocklist——AdGuard<br>  
    https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt<br>

77. Phishing URL Blocklist——AdGuard Home<br>  
    https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt<br>

78. Phishing URL Blocklist——uBlock Origin<br>  
    https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt<br>

79. Malicious URL Blocklist——AdGuard<br>  
    https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt<br>

80. Malicious URL Blocklist——AdGuard Home<br>  
    https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt<br>

81. Malicious URL Blocklist——uBlock Origin<br>  
    https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt<br>

82. Tracking JS Blocklist<br>  
    https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt<br>

83. Botnet IP Blocklist——AdGuard<br>  
    https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt<br>

84. Botnet IP Blocklist——AdGuard Home<br>  
    https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt<br>

85. Botnet IP Blocklist——uBlock Origin<br>  
    https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt<br>

86. ABP filters<br>  
    https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt<br>

87. adgk<br>  
    https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt<br>

88. yokoffing's Annoyance List<br>  
    https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt<br>

89. yokoffing's Privacy Essentials<br>  
    https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt<br>

90. Spam404's Adblock-list<br>  
    https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt<br>

91. Brave-specific filter<br>  
    https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt<br>

92. Brave-ios-specific filter<br>  
    https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt<br>

93. Brave-Android-specific filter<br>  
    https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt<br>

94. Brave-Firstparty filter<br>  
    https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt<br>

95. Brave-Firstparty-cname filter<br>  
    https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt<br>

96. Brave-Unbreak filter<br>  
    https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt<br>

97. Filter unblocking search ads and self-promotions<br>  
    https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt<br>

98. Peter Lowe’s Ad and Tracking Server List<br>  
    https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0<br>

99. Dandelion Sprout's Anti-Malware List (for AdGuard)<br>  
    https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt<br>

100. Dandelion Sprout's Anti-Malware List (for Adblock Plus and AdBlock)<br>  
    https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt<br>

101. The Block List Project - Ads List<br>  
    https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt<br>

102. The Block List Project - Basic Starter List<br>  
    https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt<br>

103. The Block List Project - Tracking List<br>  
    https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt<br>

104. The Block List Project - Malware List<br>  
     https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt<br>

105. The Block List Project - Scam List<br>  
     https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt<br>

106. The Block List Project - Phishing List<br>  
     https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt<br>

107. The Block List Project - Ransomware List<br>  
     https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt<br>

108. The Block List Project - Fraud List<br>  
     https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt<br>

109. The Block List Project - Abuse List<br>  
     https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt<br>
     
110. Anti-Adblock Killer<br>
     https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt<br>

111. Scam Blocklist (Adblock Plus)<br>
     https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt<br>
  
112. Smart-TV Blocklist for AdGuard Home<br>
     https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt<br>
     


</details>

## 五、特别致谢
<details>
  <summary>致谢名单</summary>

2、anti-AD
(https://github.com/privacy-protection-tools/anti-AD)<br>
3、easylist
(https://github.com/easylist/easylist)<br>
4、cjxlist
(https://github.com/cjx82630/cjxlist)<br>
5、uniartisan
(https://github.com/uniartisan/adblock_list)<br>
6、Cats-Team
(https://github.com/Cats-Team/AdRules)<br>
7、217heidai
(https://github.com/217heidai/adblockfilters)<br>
8、GOODBYEADS
(https://github.com/8680/GOODBYEADS)<br>
9、AWAvenue-Ads-Rule
(https://github.com/TG-Twilight/AWAvenue-Ads-Rule)<br>
10、Bibaiji
(https://github.com/Bibaiji/ad-rules/)<br>
11、uBlockOrigin
(https://github.com/uBlockOrigin/uAssets)<br>
12、ADguardTeam
(https://github.com/AdguardTeam/AdGuardFilters)<br>
13、HyperADRules
(https://github.com/Lynricsy/HyperADRules)<br>
14、guandasheng
(https://github.com/guandasheng/adguardhome)<br>
15、xinggsf
(https://github.com/xinggsf/Adblock-Plus-Rule)<br>
16、superbigsteam
(https://github.com/superbigsteam/adguardhomeguiz)<br>
17、hoshsadiq
(https://github.com/hoshsadiq/adblock-nocoin-list)<br>
18、jerryn70
(https://github.com/jerryn70/GoodbyeAds)<br>
19、malware-filter
(https://gitlab.com/malware-filter)<br>
20、abp-filters
(https://gitlab.com/eyeo/anti-cv/abp-filters-anti-cv)<br>
21、banbendalao
(https://github.com/banbendalao/ADgk)<br>
22、yokoffing
(https://github.com/yokoffing/filterlists)<br>
23、Spam404
(https://github.com/Spam404/lists)<br>
24、brave
(https://github.com/brave/adblock-lists)<br>
25、Peter Lowe
(https://pgl.yoyo.org/adservers/)<br>
26、DandelionSprout
(https://github.com/DandelionSprout/adfilt)<br>
27、blocklistproject
(https://github.com/blocklistproject/Lists)<br>
28、reek
(https://github.com/reek/anti-adblock-killer)<br>
29、durablenapkin
(https://github.com/durablenapkin/scamblocklist)<br>
30、oisd
(https://github.com/sjhgvr/oisd)<br>
31、Perflyst
(https://github.com/Perflyst/PiHoleBlocklist)<br>




  </details>





<br>
<br>


## LICENSE
- [CC-BY-NC-SA 4.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0)
- [GPL-3.0 License](https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0)
