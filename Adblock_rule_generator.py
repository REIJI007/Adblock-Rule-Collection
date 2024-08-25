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

# 设置日志
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_packages(packages):
    """确保安装所需的包"""
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
"https://easylist.to/easylist/easylist.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_thirdparty.txt",
"https://easylist.to/easylist/easyprivacy.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
"https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
"https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
"https://raw.githubusercontent.com/easylist/easylistchina/master/easylistchina.txt",
"https://secure.fanboy.co.nz/fanboy-annoyance.txt",
"https://easylist.to/easylist/fanboy-social.txt",
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
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
"https://filters.adtidy.org/android/filters/11.txt",
"https://filters.adtidy.org/ios/filters/11.txt",
"https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt",
"https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt",
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
"https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt"
]

def is_valid_rule(line):
    """检查是否符合 Adblock、Adblock Plus、uBlock Origin 和 AdGuard 语法的有效规则"""
    line = line.strip()  # 去除首尾空白字符
    
    # 1. 排除空行和注释行
    if not line or line.startswith(('!', '#', '[', ';', '//')):
        return False

    # 2. 正则表达式规则（以 / 开头和结尾）
    if line.startswith('/') and line.endswith('/'):
        return is_valid_regex(line[1:-1])

    # 3. 含有 `$` 的规则（用于匹配特定行为的规则）
    if "$" in line:
        # 确保规则不是注释行
        if not line.startswith(('!', '#', '[', ';', '//')):
        return True

    # 4. 域名规则（以 ||、|、@@ 开头）
    if line.startswith(('||', '|', '@@')):
        return True

    # 5. CSS 选择器规则（以 ##、#@#、#?#、#@?# 开头，或者符合正则表达式）
    if line.startswith(('##', '#@#', '#?#', '#@?#')) or re.search(r'#\^?([^\s]+)$', line):
        return True

    return False

def is_valid_regex(pattern):
    """检查正则表达式是否有效"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

async def download_filter(url, session):
    """下载单个过滤器"""
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            content = await response.text()
            return content.splitlines()
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
        return []

async def filter_rules_from_content(content):
    """从内容中过滤有效的规则"""
    lines = content.splitlines()
    return [line for line in lines if is_valid_rule(line)]

async def download_and_filter(url, session):
    """下载过滤器并筛选规则"""
    content = await download_filter(url, session)
    return await filter_rules_from_content('\n'.join(content))

async def download_filters(urls):
    """异步下载所有过滤器"""
    async with aiohttp.ClientSession() as session:
        tasks = [download_and_filter(url, session) for url in urls]
        results = await asyncio.gather(*tasks)
        return [line for result in results for line in result]

def write_rules_to_file(rules, path):
    """将规则写入文件"""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            for rule in sorted(rules):
                f.write(f"{rule}\n")
    except Exception as e:
        logging.error(f"Error writing rules to file: {e}")

def main():
    """主函数，下载过滤器并生成文件。"""
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    # 异步下载并筛选所有过滤器
    rules = asyncio.run(download_filters(filter_urls))
    
    # 统计有效条目总数
    valid_rule_count = len(rules)
    logging.info(f"Total valid rules: {valid_rule_count}")
    print(f"Total valid rules: {valid_rule_count}")

    # 写入文件
    logging.info("Finished downloading filters. Writing rules to file...")
    print("Finished downloading filters. Writing rules to file...")

    save_path = 'filtered_rules.txt'
    write_rules_to_file(rules, save_path)

if __name__ == "__main__":
    main()
