import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
import re
import time
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta

# 设置日志配置，日志文件名为'adblock_rule_downloader.log'，日志级别为INFO
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_packages(packages):
    # 检查并安装所需的Python包
    for package in packages:
        if importlib.util.find_spec(package) is None:
            logging.info(f"Package '{package}' is not installed. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
            logging.info(f"Package '{package}' installed successfully.")
        else:
            logging.info(f"Package '{package}' is already installed.")

# 确保安装的包列表
required_packages = ["aiohttp", "urllib3", "certifi"]

install_packages(required_packages)

warnings.simplefilter('ignore', InsecureRequestWarning)

# 判断是否为有效规则的行，去除注释和空白行
def is_valid_rule(line):
    line = line.strip()
    if not line or line.startswith(('!', '#', '[', ';', '//', '/*', '*/')):
        return False
    return True

# 判断是否为IPv4映射规则
def is_ip_domain_mapping(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+\S+', line) is not None

# 判断是否为纯IPv4地址
def is_ip_address(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line) is not None

# 判断是否为IPv6映射规则
def is_ipv6_domain_mapping(line):
    return re.match(r'^[\da-fA-F:]+\s+\S+', line) is not None

# 判断是否为纯IPv6地址
def is_ipv6_address(line):
    return re.match(r'^[\da-fA-F:]+$', line) is not None

# 判断是否为纯域名
def is_domain(line):
    # 检测是否是合法的域名
    domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, line) is not None

# 处理每一行规则，转换为统一格式
def process_line(line):
    line = line.strip()
    
    if not is_valid_rule(line):
        return None

    # 处理IPv4地址映射：0.0.0.0 和 127.0.0.1
    if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"
    
    # 处理IPv6地址映射：:: 和 ::1
    if line.startswith('::') or line.startswith('::1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"

    # 忽略其他IPv4和IPv6域名映射
    if is_ip_domain_mapping(line) or is_ipv6_domain_mapping(line):
        return None

    # 处理纯IPv4地址
    if is_ip_address(line):
        return f"||{line}^"
    
    # 处理纯IPv6地址
    if is_ipv6_address(line):
        return f"||{line}^"

    # 处理Dnsmasq规则，address= 和 server=，添加对 IPv4 和 IPv6 的处理
    if line.startswith('address='):
        parts = line.split('=')  
        if len(parts) == 3:
            domain = parts[1].strip()
            target_ip = parts[2].strip()
            if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                return f"||{domain}^"

    elif line.startswith('server='):
        parts = line.split('=', 1)
        if len(parts) == 2:
            server_info = parts[1].split('/')
            if len(server_info) == 3:
                domain = server_info[1].strip()
                target_ip = server_info[2].strip()
                if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                    return f"||{domain}^"
    
    # 处理纯域名
    if is_domain(line):
        return f"||{line}^"
    
    return line


# 异步下载过滤器规则
async def download_filter(session, url, retries=5):
    rules = set()
    attempt = 0
    while attempt < retries:
        try:
            async with session.get(url, ssl=False) as response:
                logging.info(f"Downloading from {url}, attempt {attempt + 1}")
                if response.status == 200:
                    logging.info(f"Successfully downloaded from {url}")
                    text = await response.text()
                    lines = text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if is_valid_rule(line):
                            processed_line = process_line(line)
                            if processed_line is not None:
                                rules.add(processed_line)
                    break
                else:
                    logging.error(f"Failed to download from {url} with status code {response.status}")
        except Exception as e:
            logging.error(f"Error downloading {url}: {e}")
        attempt += 1
        if attempt < retries:
            wait_time = 2 ** attempt
            logging.info(f"Retrying in {wait_time} seconds...")
            await asyncio.sleep(wait_time)
        else:
            logging.error(f"Max retries reached for {url}")
    return rules

# 异步下载多个过滤器规则
async def download_filters(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)
    return all_rules

# 验证规则的有效性
def validate_rules(rules):
    validated_rules = set()
    for rule in rules:
        if is_valid_rule(rule):
            validated_rules.add(rule)
    return validated_rules

# 将规则写入文件
def write_rules_to_file(rules, save_path):
    now = datetime.now(timezone(timedelta(hours=8)))
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')
    header = f"""
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
!LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
!生成时间: {timestamp}
!有效规则数目: {len(rules)}
"""
    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {len(rules)} rules to file {save_path}")
        f.write(header)
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules) if rule is not None)
    logging.info(f"Successfully wrote rules to {save_path}")
    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {len(rules)}")

# 主函数
def main():
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    filter_urls = [
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
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/foreign.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/cryptominers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/content_blocker.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/popups.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/social_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_app.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_web.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/general_url.txt",
"https://filters.adtidy.org/extension/ublock/filters/2.txt",
"https://filters.adtidy.org/extension/ublock/filters/3.txt",
"https://filters.adtidy.org/extension/ublock/filters/4.txt",
"https://filters.adtidy.org/extension/ublock/filters/11.txt",
"https://filters.adtidy.org/extension/ublock/filters/14.txt",
"https://filters.adtidy.org/extension/ublock/filters/15.txt",
"https://filters.adtidy.org/extension/ublock/filters/17.txt",
"https://filters.adtidy.org/extension/ublock/filters/18.txt",
"https://filters.adtidy.org/extension/ublock/filters/19.txt",
"https://filters.adtidy.org/extension/ublock/filters/20.txt",
"https://filters.adtidy.org/extension/ublock/filters/21.txt",
"https://filters.adtidy.org/extension/ublock/filters/22.txt",
"https://filters.adtidy.org/extension/ublock/filters/101.txt",
"https://filters.adtidy.org/extension/ublock/filters/104.txt",
"https://filters.adtidy.org/extension/ublock/filters/118.txt",
"https://filters.adtidy.org/extension/ublock/filters/122.txt",
"https://filters.adtidy.org/extension/ublock/filters/123.txt",
"https://filters.adtidy.org/extension/ublock/filters/201.txt",
"https://filters.adtidy.org/extension/ublock/filters/204.txt",
"https://filters.adtidy.org/extension/ublock/filters/207.txt",
"https://filters.adtidy.org/extension/ublock/filters/208.txt",
"https://filters.adtidy.org/extension/ublock/filters/209.txt",
"https://filters.adtidy.org/extension/ublock/filters/220.txt",
"https://filters.adtidy.org/extension/ublock/filters/224.txt",
"https://filters.adtidy.org/extension/ublock/filters/228.txt",
"https://filters.adtidy.org/extension/ublock/filters/239.txt",
"https://filters.adtidy.org/extension/ublock/filters/240.txt",
"https://filters.adtidy.org/extension/ublock/filters/241.txt",
"https://filters.adtidy.org/extension/ublock/filters/242.txt",
"https://filters.adtidy.org/extension/ublock/filters/250.txt",
"https://filters.adtidy.org/extension/ublock/filters/251.txt",
"https://filters.adtidy.org/extension/ublock/filters/255.txt",
"https://filters.adtidy.org/extension/ublock/filters/256.txt",
"https://filters.adtidy.org/extension/ublock/filters/257.txt",
"https://filters.adtidy.org/extension/chromium/filters/2.txt",
"https://filters.adtidy.org/extension/chromium/filters/3.txt",
"https://filters.adtidy.org/extension/chromium/filters/4.txt",
"https://filters.adtidy.org/extension/chromium/filters/11.txt",
"https://filters.adtidy.org/extension/chromium/filters/14.txt",
"https://filters.adtidy.org/extension/chromium/filters/15.txt",
"https://filters.adtidy.org/extension/chromium/filters/17.txt",
"https://filters.adtidy.org/extension/chromium/filters/18.txt",
"https://filters.adtidy.org/extension/chromium/filters/19.txt",
"https://filters.adtidy.org/extension/chromium/filters/20.txt",
"https://filters.adtidy.org/extension/chromium/filters/21.txt",
"https://filters.adtidy.org/extension/chromium/filters/22.txt",
"https://filters.adtidy.org/extension/chromium/filters/101.txt",
"https://filters.adtidy.org/extension/chromium/filters/104.txt",
"https://filters.adtidy.org/extension/chromium/filters/118.txt",
"https://filters.adtidy.org/extension/chromium/filters/122.txt",
"https://filters.adtidy.org/extension/chromium/filters/123.txt",
"https://filters.adtidy.org/extension/chromium/filters/201.txt",
"https://filters.adtidy.org/extension/chromium/filters/204.txt",
"https://filters.adtidy.org/extension/chromium/filters/207.txt",
"https://filters.adtidy.org/extension/chromium/filters/208.txt",
"https://filters.adtidy.org/extension/chromium/filters/209.txt",
"https://filters.adtidy.org/extension/chromium/filters/220.txt",
"https://filters.adtidy.org/extension/chromium/filters/224.txt",
"https://filters.adtidy.org/extension/chromium/filters/228.txt",
"https://filters.adtidy.org/extension/chromium/filters/239.txt",
"https://filters.adtidy.org/extension/chromium/filters/240.txt",
"https://filters.adtidy.org/extension/chromium/filters/241.txt",
"https://filters.adtidy.org/extension/chromium/filters/242.txt",
"https://filters.adtidy.org/extension/chromium/filters/250.txt",
"https://filters.adtidy.org/extension/chromium/filters/251.txt",
"https://filters.adtidy.org/extension/chromium/filters/255.txt",
"https://filters.adtidy.org/extension/chromium/filters/256.txt",
"https://filters.adtidy.org/extension/chromium/filters/257.txt",
"https://filters.adtidy.org/extension/firefox/filters/2.txt",
"https://filters.adtidy.org/extension/firefox/filters/3.txt",
"https://filters.adtidy.org/extension/firefox/filters/4.txt",
"https://filters.adtidy.org/extension/firefox/filters/11.txt",
"https://filters.adtidy.org/extension/firefox/filters/14.txt",
"https://filters.adtidy.org/extension/firefox/filters/15.txt",
"https://filters.adtidy.org/extension/firefox/filters/17.txt",
"https://filters.adtidy.org/extension/firefox/filters/18.txt",
"https://filters.adtidy.org/extension/firefox/filters/19.txt",
"https://filters.adtidy.org/extension/firefox/filters/20.txt",
"https://filters.adtidy.org/extension/firefox/filters/21.txt",
"https://filters.adtidy.org/extension/firefox/filters/22.txt",
"https://filters.adtidy.org/extension/firefox/filters/101.txt",
"https://filters.adtidy.org/extension/firefox/filters/104.txt",
"https://filters.adtidy.org/extension/firefox/filters/118.txt",
"https://filters.adtidy.org/extension/firefox/filters/122.txt",
"https://filters.adtidy.org/extension/firefox/filters/123.txt",
"https://filters.adtidy.org/extension/firefox/filters/201.txt",
"https://filters.adtidy.org/extension/firefox/filters/204.txt",
"https://filters.adtidy.org/extension/firefox/filters/207.txt",
"https://filters.adtidy.org/extension/firefox/filters/208.txt",
"https://filters.adtidy.org/extension/firefox/filters/209.txt",
"https://filters.adtidy.org/extension/firefox/filters/220.txt",
"https://filters.adtidy.org/extension/firefox/filters/224.txt",
"https://filters.adtidy.org/extension/firefox/filters/228.txt",
"https://filters.adtidy.org/extension/firefox/filters/239.txt",
"https://filters.adtidy.org/extension/firefox/filters/240.txt",
"https://filters.adtidy.org/extension/firefox/filters/241.txt",
"https://filters.adtidy.org/extension/firefox/filters/242.txt",
"https://filters.adtidy.org/extension/firefox/filters/250.txt",
"https://filters.adtidy.org/extension/firefox/filters/251.txt",
"https://filters.adtidy.org/extension/firefox/filters/255.txt",
"https://filters.adtidy.org/extension/firefox/filters/256.txt",
"https://filters.adtidy.org/extension/firefox/filters/257.txt",
"https://filters.adtidy.org/windows/filters/2.txt",
"https://filters.adtidy.org/windows/filters/3.txt",
"https://filters.adtidy.org/windows/filters/4.txt",
"https://filters.adtidy.org/windows/filters/11.txt",
"https://filters.adtidy.org/windows/filters/14.txt",
"https://filters.adtidy.org/windows/filters/15.txt",
"https://filters.adtidy.org/windows/filters/17.txt",
"https://filters.adtidy.org/windows/filters/18.txt",
"https://filters.adtidy.org/windows/filters/19.txt",
"https://filters.adtidy.org/windows/filters/20.txt",
"https://filters.adtidy.org/windows/filters/21.txt",
"https://filters.adtidy.org/windows/filters/22.txt",
"https://filters.adtidy.org/windows/filters/101.txt",
"https://filters.adtidy.org/windows/filters/104.txt",
"https://filters.adtidy.org/windows/filters/118.txt",
"https://filters.adtidy.org/windows/filters/122.txt",
"https://filters.adtidy.org/windows/filters/123.txt",
"https://filters.adtidy.org/windows/filters/201.txt",
"https://filters.adtidy.org/windows/filters/204.txt",
"https://filters.adtidy.org/windows/filters/207.txt",
"https://filters.adtidy.org/windows/filters/208.txt",
"https://filters.adtidy.org/windows/filters/209.txt",
"https://filters.adtidy.org/windows/filters/220.txt",
"https://filters.adtidy.org/windows/filters/224.txt",
"https://filters.adtidy.org/windows/filters/228.txt",
"https://filters.adtidy.org/windows/filters/239.txt",
"https://filters.adtidy.org/windows/filters/240.txt",
"https://filters.adtidy.org/windows/filters/241.txt",
"https://filters.adtidy.org/windows/filters/242.txt",
"https://filters.adtidy.org/windows/filters/250.txt",
"https://filters.adtidy.org/windows/filters/251.txt",
"https://filters.adtidy.org/windows/filters/255.txt",
"https://filters.adtidy.org/windows/filters/256.txt",
"https://filters.adtidy.org/windows/filters/257.txt",
"https://filters.adtidy.org/android/filters/2_optimized.txt",
"https://filters.adtidy.org/android/filters/3_optimized.txt",
"https://filters.adtidy.org/android/filters/4_optimized.txt",
"https://filters.adtidy.org/android/filters/11_optimized.txt",
"https://filters.adtidy.org/android/filters/14_optimized.txt",
"https://filters.adtidy.org/android/filters/15_optimized.txt",
"https://filters.adtidy.org/android/filters/17_optimized.txt",
"https://filters.adtidy.org/android/filters/18_optimized.txt",
"https://filters.adtidy.org/android/filters/19_optimized.txt",
"https://filters.adtidy.org/android/filters/20_optimized.txt",
"https://filters.adtidy.org/android/filters/21_optimized.txt",
"https://filters.adtidy.org/android/filters/22_optimized.txt",
"https://filters.adtidy.org/android/filters/101_optimized.txt",
"https://filters.adtidy.org/android/filters/104_optimized.txt",
"https://filters.adtidy.org/android/filters/118_optimized.txt",
"https://filters.adtidy.org/android/filters/122_optimized.txt",
"https://filters.adtidy.org/android/filters/123_optimized.txt",
"https://filters.adtidy.org/android/filters/201_optimized.txt",
"https://filters.adtidy.org/android/filters/204_optimized.txt",
"https://filters.adtidy.org/android/filters/207_optimized.txt",
"https://filters.adtidy.org/android/filters/208_optimized.txt",
"https://filters.adtidy.org/android/filters/209_optimized.txt",
"https://filters.adtidy.org/android/filters/220_optimized.txt",
"https://filters.adtidy.org/android/filters/224_optimized.txt",
"https://filters.adtidy.org/android/filters/228_optimized.txt",
"https://filters.adtidy.org/android/filters/239_optimized.txt",
"https://filters.adtidy.org/android/filters/240_optimized.txt",
"https://filters.adtidy.org/android/filters/241_optimized.txt",
"https://filters.adtidy.org/android/filters/242_optimized.txt",
"https://filters.adtidy.org/android/filters/250_optimized.txt",
"https://filters.adtidy.org/android/filters/251_optimized.txt",
"https://filters.adtidy.org/android/filters/255_optimized.txt",
"https://filters.adtidy.org/android/filters/256_optimized.txt",
"https://filters.adtidy.org/android/filters/257_optimized.txt",
"https://filters.adtidy.org/ios/filters/2_optimized.txt",
"https://filters.adtidy.org/ios/filters/3_optimized.txt",
"https://filters.adtidy.org/ios/filters/4_optimized.txt",
"https://filters.adtidy.org/ios/filters/11_optimized.txt",
"https://filters.adtidy.org/ios/filters/14_optimized.txt",
"https://filters.adtidy.org/ios/filters/15_optimized.txt",
"https://filters.adtidy.org/ios/filters/17_optimized.txt",
"https://filters.adtidy.org/ios/filters/18_optimized.txt",
"https://filters.adtidy.org/ios/filters/19_optimized.txt",
"https://filters.adtidy.org/ios/filters/20_optimized.txt",
"https://filters.adtidy.org/ios/filters/21_optimized.txt",
"https://filters.adtidy.org/ios/filters/22_optimized.txt",
"https://filters.adtidy.org/ios/filters/101_optimized.txt",
"https://filters.adtidy.org/ios/filters/104_optimized.txt",
"https://filters.adtidy.org/ios/filters/118_optimized.txt",
"https://filters.adtidy.org/ios/filters/122_optimized.txt",
"https://filters.adtidy.org/ios/filters/123_optimized.txt",
"https://filters.adtidy.org/ios/filters/201_optimized.txt",
"https://filters.adtidy.org/ios/filters/204_optimized.txt",
"https://filters.adtidy.org/ios/filters/207_optimized.txt",
"https://filters.adtidy.org/ios/filters/208_optimized.txt",
"https://filters.adtidy.org/ios/filters/209_optimized.txt",
"https://filters.adtidy.org/ios/filters/220_optimized.txt",
"https://filters.adtidy.org/ios/filters/224_optimized.txt",
"https://filters.adtidy.org/ios/filters/228_optimized.txt",
"https://filters.adtidy.org/ios/filters/239_optimized.txt",
"https://filters.adtidy.org/ios/filters/240_optimized.txt",
"https://filters.adtidy.org/ios/filters/241_optimized.txt",
"https://filters.adtidy.org/ios/filters/242_optimized.txt",
"https://filters.adtidy.org/ios/filters/250_optimized.txt",
"https://filters.adtidy.org/ios/filters/251_optimized.txt",
"https://filters.adtidy.org/ios/filters/255_optimized.txt",
"https://filters.adtidy.org/ios/filters/256_optimized.txt",
"https://filters.adtidy.org/ios/filters/257_optimized.txt",
"https://easylist.to/easylist/easylist.txt",
"https://easylist.to/easylist/easyprivacy.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers_popup.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty_popup.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_dimensions.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_general_hide.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_allowlist_popup.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_block_popup.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_general_hide.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_allowlist_international.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general_emailtrackers.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_mining.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_notifications.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_allowlist_general_hide.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_block.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_general_hide.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_thirdparty.txt",
"https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/lan-block.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/smart-tv-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ads-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/basic-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/tracking-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/malware-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/scam-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/phishing-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/ransomware-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/fraud-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/abuse-ags.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/adguard/redirect-ags.txt",
"https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
"https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
"https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
"https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt",
"https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt",
"https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt",
"https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt",
"https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt",
"https://phishing.army/download/phishing_army_blocklist.txt",
"https://phishing.army/download/phishing_army_blocklist_extended.txt",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy_v6.txt",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra_v6.txt",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/update.txt",
"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/update_v6.txt"
    ]

    save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')
    rules = asyncio.run(download_filters(filter_urls))
    validated_rules = validate_rules(rules)
    write_rules_to_file(validated_rules, save_path)

if __name__ == '__main__':
    main()
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    else:
        print("Non-interactive mode, exiting...")
