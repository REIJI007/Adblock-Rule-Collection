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
        # 检查包是否已安装
        if importlib.util.find_spec(package) is None:
            logging.info(f"Package '{package}' is not installed. Installing...")
            # 安装包
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

# 保存路径设定为当前工作目录下，文件名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

def is_valid_rule(line):
    """排除有效规则格式。

    参数:
    line (str): 要检查的规则行。

    返回:
    bool: 如果该行符合有效规则格式，则返回 True，否则返回 False。
    """
    line = line.strip()  # 去除首尾的空白字符
    # 排除空行和注释行
    if not line or line.startswith(('!', '#', '[', ';', '//','/*','*/')):
        return False

    return True

def is_valid_host_rule(line):
    """验证 host 规则是否有效。

    参数:
    line (str): host 文件中的一行。

    返回:
    bool: 如果该行是有效的 host 规则，返回 True，否则返回 False。
    """
    line = line.strip()
    if not line or line.startswith(('#', '!', '[', ';')):
        return False
    parts = line.split()
    return len(parts) == 2 and all(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", part) for part in parts[:1])

def is_valid_dnsmasq_rule(line):
    """验证 Dnsmasq 规则是否有效。

    参数:
    line (str): Dnsmasq 规则中的一行。

    返回:
    bool: 如果该行是有效的 Dnsmasq 规则，返回 True，否则返回 False。
    """
    line = line.strip()
    return bool(re.match(r"^address=\/[a-zA-Z0-9-]+\.[a-zA-Z]+\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line))

def convert_host_to_adblock(line):
    """将 host 规则转换为 Adblock Plus 规则格式。

    参数:
    line (str): host 文件中的一行。

    返回:
    str: 对应的 Adblock Plus 规则。
    """
    parts = line.split()
    domain = parts[1]
    return f"||{domain}^"

def convert_dnsmasq_to_adblock(line):
    """将 Dnsmasq 规则转换为 Adblock Plus 规则格式。

    参数:
    line (str): Dnsmasq 规则中的一行。

    返回:
    str: 对应的 Adblock Plus 规则。
    """
    domain = line.split('/')[1]
    return f"||{domain}^"

def process_line(line):
    """根据不同的规则类型处理行并转换为 Adblock Plus 规则。

    参数:
    line (str): 要处理的规则行。

    返回:
    str: 转换后的 Adblock Plus 规则。
    """
    if is_valid_rule(line):
        return line
    elif is_valid_host_rule(line):
        return convert_host_to_adblock(line)
    elif is_valid_dnsmasq_rule(line):
        return convert_dnsmasq_to_adblock(line)
    return None

async def download_filter(session, url):
    """异步下载单个过滤器文件并提取有效的规则。

    参数:
    session (aiohttp.ClientSession): aiohttp 客户端会话对象。
    url (str): 要下载的过滤器 URL。

    返回:
    set: 一个包含所有有效规则的集合。
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
                    processed_rule = process_line(line)  # 使用新处理函数
                    if processed_rule:
                        rules.add(processed_rule)
            else:
                logging.error(f"Failed to download from {url} with status code {response.status}")
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
    return rules

async def download_filters(urls):
    """并行下载多个过滤器文件并返回所有过滤规则的集合。

    参数:
    urls (list): 过滤器 URL 列表。

    返回:
    set: 一个包含所有有效规则的集合。
    """
    async with aiohttp.ClientSession() as session:
        # 创建所有下载任务
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()  # 存储所有过滤规则的集合
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)  # 更新集合
    return all_rules

def validate_rules(rules):
    """对规则集合进行重新验证，确保每条规则都符合格式。

    参数:
    rules (set): 要验证的规则集合。

    返回:
    set: 一个包含所有有效规则的集合。
    """
    validated_rules = set()
    for rule in rules:
        if is_valid_rule(rule):
            validated_rules.add(rule)
    return validated_rules

def write_rules_to_file(rules, save_path):
    """将过滤规则写入指定的文件。

    参数:
    rules (set): 要写入的规则集合。
    save_path (str): 文件保存路径。
    """
    now = datetime.now(timezone(timedelta(hours=8)))  # 获取当前时间并设置为东八区时间
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')  # 格式化时间戳

    # 文件头部注释
    header = f"""
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0
!LICENSE2：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0
!生成时间: {timestamp}
!有效规则数目: {len(rules)}
"""

    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {len(rules)} rules to file {save_path}")
        f.write(header)  # 写入文件头
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules))  # 写入所有规则，每个规则占一行

    logging.info(f"Successfully wrote rules to {save_path}")
    logging.info(f"有效规则数目: {len(rules)}")

    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {len(rules)}")

def main():
    """主函数，执行过滤器下载和文件生成操作"""
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    # 更新为需要下载的过滤器 URL 列表
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

    # 异步下载所有过滤器并保存
    loop = asyncio.get_event_loop()
    rules = loop.run_until_complete(download_filters(filter_urls))

    # 验证规则
    validated_rules = validate_rules(rules)

    # 写入文件
    write_rules_to_file(validated_rules, save_path)

if __name__ == '__main__':
    main()
