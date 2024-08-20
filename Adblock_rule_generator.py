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
required_packages = ["aiohttp"]

# 安装所需的包
install_packages(required_packages)

# 忽略不安全请求警告
warnings.simplefilter('ignore', InsecureRequestWarning)

# 过滤器 URL 列表
filter_urls = [
    "https://anti-ad.net/adguard.txt",
    "https://anti-ad.net/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",
    "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt",
    "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_privacy.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/rules.txt",
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/dns.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/ad-rules.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_7_Japanese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt",
    "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt",
    "https://raw.githubusercontent.com/guandasheng/adguardhome/main/rule/all.txt"
]

# 保存路径设定为 M 盘根目录下，并命名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join('M:\\', 'ADBLOCK_RULE_COLLECTION.txt')

def is_valid_adblock_plus_ublock_origin_rule(line):
    """检查是否符合 Adblock Plus 和 uBlock Origin 语法"""
    if not line:
        return False

    # 检查 CSS 选择器规则，包括反规则选择器
    if line.startswith("##") or line.startswith("#@#"):
        return True

    # 例外规则
    if line.startswith("@@"):
        return True

    # URL 和域名规则
    if line.startswith("||") or line.startswith("|"):
        return not line.startswith("||#")  # 域名规则，排除带 # 的规则

    # 正则表达式规则
    if line.startswith("/") and line.endswith("/"):
        return is_valid_regex(line[1:-1])

    # 带条件的规则，包括资源类型和其他条件
    if "$" in line:
        valid_conditions = ["document", "script", "subdocument", "third-party", "image", "stylesheet", "font", "media", "xmlhttprequest", "csp", "popup", "domain"]
        parts = line.split("$")
        if len(parts) == 2 and any(cond in parts[1] for cond in valid_conditions):
            return True
        return False

    return False

def is_valid_adguard_rule(line):
    """检查是否符合 AdGuard 语法"""
    if not line:
        return False
    
    # 检查 CSS 选择器规则，包括反规则选择器
    if line.startswith("##") or line.startswith("#@#"):
        return True

    # 例外规则
    if line.startswith("@@"):
        return True

    # URL 和域名规则
    if line.startswith("||") or line.startswith("|"):
        return True

    # 正则表达式规则
    if line.startswith("/") and line.endswith("/"):
        return is_valid_regex(line[1:-1])

    # 带条件的规则，包括资源类型和其他条件
    if "$" in line:
        valid_conditions = ["document", "script", "subdocument", "third-party", "image", "stylesheet", "font", "media", "xmlhttprequest", "csp", "popup", "domain"]
        parts = line.split("$")
        if len(parts) == 2 and any(cond in parts[1] for cond in valid_conditions):
            return True
        return False

    # 排除规则
    if line.startswith("~"):
        return True

    return False

def is_valid_rule(line):
    """检查是否符合 Adblock Plus、uBlock Origin 和 AdGuard 语法"""
    return (
        is_valid_adblock_plus_ublock_origin_rule(line) or 
        is_valid_adguard_rule(line)
    ) and not (line.startswith('!') or line.startswith('#'))  # 排除注释行

def is_valid_regex(pattern):
    """检查正则表达式是否有效"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False

async def download_filter(session, url):
    """异步下载单个过滤器"""
    rules = set()  # 使用 set 来确保规则的唯一性
    try:
        async with session.get(url, ssl=False) as response:
            logging.info(f"Downloading from {url}")
            if response.status == 200:
                logging.info(f"Successfully downloaded from {url}")
                text = await response.text()
                lines = text.splitlines()
                for line in lines:
                    line = line.strip()
                    # 过滤掉注释行、空行以及不符合语法的行
                    if line and is_valid_rule(line):
                        rules.add(line)
            else:
                logging.error(f"Failed to download from {url} with status code {response.status}")
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
    return rules

async def download_filters(urls):
    """并行下载过滤器并返回所有过滤规则的集合"""
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()  # 所有规则的集合
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)  # 将每个任务下载的规则更新到全局集合中
    return all_rules

def write_rules_to_file(rules, save_path):
    """将规则写入文件"""
    # 获取东八区当前时间
    now = datetime.now(timezone(timedelta(hours=8)))
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')

    header = f"""
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅集合
!Last Modified: {timestamp}
!Expires: 1 day
!Licence: https://creativecommons.org/licenses/by/3.0/
!Github: https://github.com/your_github_username/your_repository_name
    """.strip()

    try:
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(header + '\n\n')
            for rule in sorted(rules):  # 排序后写入文件
                f.write(rule + '\n')
        logging.info(f"Rules successfully written to {save_path}")
    except Exception as e:
        logging.error(f"Failed to write rules to file: {e}")

def main():
    """主函数"""
    loop = asyncio.get_event_loop()
    rules = loop.run_until_complete(download_filters(filter_urls))
    write_rules_to_file(rules, save_path)
    logging.info("Adblock rule download and save completed.")

if __name__ == "__main__":
    main()
