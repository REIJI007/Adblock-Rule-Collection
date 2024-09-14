import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
import re
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta

# 设置日志配置
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_packages(packages):
    """确保所需的 Python 包已安装。

    参数:
    packages (list): 包名列表，每个包名都是一个字符串。
    """
    for package in packages:
        if importlib.util.find_spec(package) is None:
            logging.info(f"Package '{package}' is not installed. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
            logging.info(f"Package '{package}' installed successfully.")
        else:
            logging.info(f"Package '{package}' is already installed.")

# 要确保安装的包列表
required_packages = ["aiohttp", "urllib3", "certifi"]

# 安装所需的包
install_packages(required_packages)

# 忽略不安全请求警告
warnings.simplefilter('ignore', InsecureRequestWarning)

# 过滤器 URL 列表
filter_urls = [
    "https://anti-ad.net/adguard.txt",
    "https://anti-ad.net/easylist.txt",
    "https://big.oisd.nl",
    "https://easylist.to/easylist/easylist.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    "https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://easylist.to/easylist/fanboy-social.txt",
    "https://www.fanboy.co.nz/fanboy-antifonts.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-ublock.txt",
    "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt",
    "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/rules.txt",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/ad-rules.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-others.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/rules.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    "https://filters.adtidy.org/android/filters/11.txt",
    "https://filters.adtidy.org/ios/filters/11.txt",
    "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt",
    "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt",
    "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/allow.txt",
    "https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/superbigsteam/adguardhomeguiz/main/rule/all.txt",
    "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-Ultra-AdBlock-Filter.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
    "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter.txt",
    "https://malware-filter.gitlab.io/malware-filter/tracking-filter.txt",
    "https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt",
    "https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt",
    "https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt",
    "https://easylist-msie.adblockplus.org/abp-filters-anti-cv.txt",
    "https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt",
    "https://raw.githubusercontent.com/yokoffing/filterlists/main/annoyance_list.txt",
    "https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt",
    "https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-ios-specific.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty-cname.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareABP.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Other%20domains%20versions/FanboyNotifications-LoadableInUBO.txt",
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
    "https://raw.githubusercontent.com/reek/anti-adblock-killer/master/anti-adblock-killer-filters.txt",
    "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/personal.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-aggressive.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock-allow.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
    "https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker",
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/dnslist.txt",
    "https://hblock.molinero.dev/hosts_adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/adblock.txt"
]

def convert_rule(rule):
    """将 host 规则和 IP 地址转换为 AdBlock 语法规则。
    
    参数:
    rule (str): 要转换的规则。
    
    返回:
    str: 转换后的规则。
    """
    # 检查是否为 host 规则（0.0.0.0 或 127.0.0.1 开头）
    host_pattern = r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)$'
    match_host = re.match(host_pattern, rule)
    if match_host:
        domain = match_host.group(2)
        return f"||{domain}^"
    
    # 检查是否为 IP 地址规则
    ip_pattern = r'^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$'
    match_ip = re.match(ip_pattern, rule)
    if match_ip:
        ip = match_ip.group(1)
        return f"||{ip}^"

    return rule

async def download_filter(session, url):
    """异步下载单个过滤器文件并提取所有非空、非注释行。

    参数:
    session (aiohttp.ClientSession): aiohttp 客户端会话对象。
    url (str): 要下载的过滤器 URL。

    返回:
    set: 一个包含所有非空、非注释行的集合。
    """
    rules = set()  # 使用集合来存储唯一的规则
    try:
        async with session.get(url, ssl=False) as response:
            logging.info(f"Downloading from {url}")
            if response.status == 200:
                logging.info(f"Successfully downloaded from {url}")
                text = await response.text()
                lines = text.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not is_comment(line):  # 确保行不为空且不是注释
                        converted_rule = convert_rule(line)
                        rules.add(converted_rule)
            else:
                logging.error(f"Failed to download from {url} with status code {response.status}")
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
    return rules

def is_comment(line):
    """检查给定的行是否为注释。

    参数:
    line (str): 要检查的行。

    返回:
    bool: 如果行是注释，则返回 True；否则返回 False。
    """
    return line.startswith('#') or line.startswith('!')

async def download_all_filters():
    """下载所有过滤器并合并规则。"""
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in filter_urls]
        results = await asyncio.gather(*tasks)
        all_rules = set()
        for result in results:
            all_rules.update(result)
        return all_rules

def save_rules(rules, filename):
    """将规则保存到文件。

    参数:
    rules (set): 要保存的规则集合。
    filename (str): 文件名。
    """
    with open(filename, 'w', encoding='utf-8') as file:
        for rule in sorted(rules):
            file.write(f"{rule}\n")
    logging.info(f"Rules saved to {filename}")

def main():
    """主函数。"""
    logging.info("Starting filter download...")
    try:
        rules = asyncio.run(download_all_filters())
        save_rules(rules, 'adblock_rules.txt')
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    logging.info("Filter download finished.")

if __name__ == "__main__":
    main()
