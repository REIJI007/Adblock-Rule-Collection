import os
import sys
import subprocess
import logging
import warnings
import importlib.util
import asyncio
import aiohttp
import re
from datetime import datetime, timezone, timedelta
from urllib3.exceptions import InsecureRequestWarning

# 日志配置
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 安装所需的包
def install_packages(packages):
    for package in packages:
        if importlib.util.find_spec(package) is None:
            logging.info(f"Installing package: {package}")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)

install_packages(["aiohttp", "urllib3", "certifi"])
warnings.simplefilter('ignore', InsecureRequestWarning)

filter_urls = [
    "https://anti-ad.net/adguard.txt", "https://big.oisd.nl", # 等等...
]

# 处理规则行
def process_rule(line):
    line = line.strip()
    if not line or line.startswith(('!', '#', '[', ';', '//', '/*', '*/', '!--')):
        return None
    if line.startswith(('127.0.0.1', '0.0.0.0')):
        parts = line.split()
        if len(parts) == 2 and not is_ip_address(parts[1]):
            return f"||{parts[1]}^"
    if line.startswith('||') and '$all' in line and is_ip_address(line[2:].split('^')[0]):
        return f"{line.split('$')[0]}^"
    if is_ip_address(line):
        return f"||{line}^"
    return line

def is_ip_address(address):
    parts = address.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

# 去除重复规则
def remove_duplicate_ip_rules(rules):
    ip_rules, result = {}, []
    for rule in rules:
        processed_rule = process_rule(rule)
        if processed_rule:
            if processed_rule.startswith('||') and is_ip_address(processed_rule[2:].split('^')[0]):
                ip = processed_rule[2:].split('^')[0]
                if ip not in ip_rules or processed_rule == f"||{ip}^":
                    ip_rules[ip] = processed_rule
            else:
                result.append(processed_rule)
    result.extend(ip_rules.values())
    return result

# 写入文件
def write_rules_to_file(rules, save_path):
    now = datetime.now(timezone(timedelta(hours=8)))
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')
    # 文件头部注释
    header = f"""
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0
!LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0
!生成时间: {timestamp}
!有效规则数目: {len(rules)}
"""
    rules = list(set(rules))
    with open(save_path, 'w', encoding='utf-8') as f:
        f.write(header)
        f.writelines(f"{rule}\n" for rule in sorted(rules))
    logging.info(f"Rules saved to {save_path}, count: {len(rules)}")

async def download_filter(session, url):
    rules = set()
    try:
        async with session.get(url, ssl=False) as response:
            content = await response.text()
            for line in content.splitlines():
                processed_rule = process_rule(line)
                if processed_rule:
                    rules.add(processed_rule)
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
    return rules

# 下载并处理过滤规则
async def download_and_save_rules():
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in filter_urls]
        results = await asyncio.gather(*tasks)
        all_rules = set().union(*results)
        write_rules_to_file(all_rules, os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt'))

# 执行异步下载
asyncio.run(download_and_save_rules())
