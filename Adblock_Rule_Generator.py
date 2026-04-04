# -*- coding: utf-8 -*-
import subprocess
import sys
import re
import ipaddress
from datetime import datetime, timezone, timedelta

# ==================== 自动安装唯一依赖（requests） ====================
def install_package(package):
    """自动安装缺失的包"""
    print(f"正在安装依赖: {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", package])
        print(f"✅ {package} 安装完成")
    except subprocess.CalledProcessError:
        print(f"❌ 无法安装 {package}，请手动执行: pip install {package}")
        sys.exit(1)

try:
    import requests
except ImportError:
    install_package("requests")
    import requests

# ==================== 注释行判断函数 ====================
# AdBlock 规则中以 # 开头的合法规则前缀（元素隐藏/脚本/异常等语法）
_VALID_HASH_PREFIXES = ("##", "#@#", "#$#", "#$@#", "#?#", "#@?#", "#%#")

def is_comment_line(line: str) -> bool:
    """
    Determine whether a line is a comment or metadata rather than a valid rule.

    Skip conditions:
      1. Starts with '!'  -> AdGuard/ABP standard comment
      2. Starts with '['  -> Filter-list header declaration (e.g. [Adblock Plus 2.0])
      3. Starts with '#'  -> Hosts-style comment, UNLESS it matches a valid rule prefix:
                             ##  #@#  #$#  #$@#  #?#  #@?#  #%#
    """
    if line.startswith('!'):
        return True
    if line.startswith('['):
        return True
    if line.startswith('#') and not line.startswith(_VALID_HASH_PREFIXES):
        return True
    return False

def is_pure_domain_or_ip(text: str) -> bool:
    """
    判断是否为纯域名或纯 IP：
    - 纯 IP：IPv4 / IPv6
    - 纯域名：不含空格、通配符、路径、协议、规则语法等，仅为裸域名
    """
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass

    # 纯域名：允许子域名、连字符、IDNA punycode；不允许路径、协议、通配符、规则语法
    domain_pattern = re.compile(
        r'^(?=.{1,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}$'
    )
    return bool(domain_pattern.match(text))

# ==================== 第一步：定义所有上游URL ====================
urls = [
	"https://adaway.org/hosts.txt",
	"https://filters.adavoid.org/ultimate-ad-filter.txt",
	"https://filters.adavoid.org/ultimate-privacy-filter.txt",
	"https://filters.adavoid.org/ultimate-security-filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/annoyances.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/self-promo.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/tweaks.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/banner_sizes.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/content_blocker.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/specific_app.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/specific_web.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/popups.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/social_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/cryptominers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
	"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_101_EasyList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_118_EasyPrivacy/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_122_FanboysAnnoyances/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_123_FanboysSocialBlockingList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_201_WebAnnoyancesUltralist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_204_PeterLowesList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_207_AdblockWarningRemovalList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_208_Online_Malicious_URL_Blocklist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_209_ADgkMobileChinalist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_210_Spam404/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_211_AntiAdblockKillerReek/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_219_ChinaListAndEasyList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_220_CJXsAnnoyanceList/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_228_xinggsf/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_229_IdontCareAboutCookies/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_239_FanboyAntifonts/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_240_BarbBlock/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_241_FanboyCookiemonster/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_242_NoCoin/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_255_Phishing_URL_Blocklist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_256_Scam_Blocklist/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_257_uBlock_Origin_Badware_risks/filter.txt",
	"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_259_Dandelion_Sprout's_Anti-Malware_List/filter.txt",
	"https://easylist.to/easylist/easylist.txt",
	"https://easylist.to/easylist/easyprivacy.txt",
	"https://easylist.to/easylist/fanboy-social.txt",
	"https://secure.fanboy.co.nz/fanboy-annoyance.txt",
	"https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_dimensions.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_dimensions.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_block_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_specific_hide_abp.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty_popup.txt",
	"https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general_emailtrackers.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_abp.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_a8net.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_acton.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_ad-ebis.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_adobe.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_at-internet.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_branch.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_commanders-act.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_criteo.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_dataunlocker.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_eulerian.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_ingenious-technologies.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_keyade.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_lead-forensics.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_np6.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_oracle.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_otto.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_plausible.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_tracedock.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_webtrekk.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname_wizaly.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_perimeterx.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_mining.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_notifications.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_agegate_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_ai_suggestions.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_annoyance_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_antifonts.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_chatapps_third-party.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_international_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_international_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_shopping_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_newsletter_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_notifications_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_allowlist_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_general_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_general_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_international.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_ABP.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_block.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_hide.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_specific_uBO.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_social_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/easylist/master/fanboy-addon/fanboy_sounds_thirdparty.txt",
	"https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_chinese.txt",
	"https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_english.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-general.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy-removeparam.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/legacy.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/ubol-filters.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/ubo-link-shorteners.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easyprivacy.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-ai.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-annoyances.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-chat.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-cookies.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-newsletters.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-notifications.txt",
	"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist-social.txt",
	"https://urlhaus.abuse.ch/downloads/hostfile/",
	"https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
	"https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
	"https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt",
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
	"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
	"https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt",
	"https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt",
	"https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt",
	"https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt",
	"https://blocklistproject.github.io/Lists/adguard/abuse-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/ads-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/basic-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/crypto-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/fraud-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/malware-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/phishing-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/scam-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/redirect-ags.txt",
	"https://blocklistproject.github.io/Lists/adguard/tracking-ags.txt",
	"https://phishing.army/download/phishing_army_blocklist.txt",
	"https://phishing.army/download/phishing_army_blocklist_extended.txt"
]


# ==================== 第二步：收集并去重有效规则 ====================
rules = set()
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for line in response.text.splitlines():
            stripped = line.strip()
            # Skip empty lines and all comment/metadata lines; keep only real rules.
            if stripped and not is_comment_line(stripped):
                if is_pure_domain_or_ip(stripped):
                    stripped = f"||{stripped}^"
                rules.add(stripped)
    except Exception as e:
        print(f"Warning: failed to fetch {url} -> {e}", file=sys.stderr)
        continue

# ==================== 第三步：生成头部注释 + 统计信息 ====================
tz_utc8 = timezone(timedelta(hours=8))
timestamp = datetime.now(tz_utc8).strftime("%Y-%m-%d %H:%M:%S")

num_rules = len(rules)
header = f"""! Title: Adblock-Rule-Collection
! Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
! Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
! LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
! LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
! Generated: {timestamp} (UTC+8)
! Total rules: {num_rules}
"""

# ==================== 第四步：写入文件（按字母排序） ====================
with open("ADBLOCK_RULE_COLLECTION.txt", "w", encoding="utf-8") as f:
    f.write(header)
    for rule in sorted(rules):
        f.write(rule + "\n")

print(f"Done. Output: ADBLOCK_RULE_COLLECTION.txt")
print(f"Total rules: {num_rules}")
print(f"Generated: {timestamp} (UTC+8)")
