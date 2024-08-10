import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
from collections import defaultdict
from urllib3.exceptions import InsecureRequestWarning

# 设置日志
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_packages(packages):
    """Ensure the required packages are installed."""
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
    # 列表省略, 保持不变
]

# 保存路径设定为当前工作目录的根目录下，并命名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

def is_valid_regex(pattern):
    """检查正则表达式是否有效"""
    try:
        import re
        re.compile(pattern)
        return True
    except re.error:
        return False

async def download_filter(session, url):
    """异步下载单个过滤器"""
    rules = defaultdict(set)
    try:
        async with session.get(url, ssl=False) as response:
            logging.info(f"Downloading from {url}")
            if response.status == 200:
                logging.info(f"Successfully downloaded from {url}")
                text = await response.text()
                lines = text.splitlines()
                for line in lines:
                    line = line.strip()
                    # 过滤掉注释行和空行
                    if line and not (line.startswith('!') or line.startswith('#')):
                        if line.startswith('/') and line.endswith('/') and is_valid_regex(line[1:-1]):
                            rules['正则表达式'].add(line)
                        elif line.startswith("||"):
                            rules['URL'].add(line)
                        elif line.startswith("##") or line.startswith("#@#"):
                            rules['CSS'].add(line)
                        elif "$script" in line:
                            rules['脚本过滤'].add(line)
                        elif "$iframe" in line:
                            rules['iframe过滤'].add(line)
                        elif "$third-party" in line:
                            rules['跟踪器过滤'].add(line)
                        elif "$document" in line:
                            rules['反广告拦截'].add(line)
                        else:
                            rules['其他规则'].add(line)
            else:
                logging.error(f"Failed to download from {url} with status code {response.status}")
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
    return rules

async def download_filters(urls):
    """并行下载过滤器并返回所有过滤规则的集合"""
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = defaultdict(set)
        for future in asyncio.as_completed(tasks):
            rules = await future
            for rule_type, rule_set in rules.items():
                all_rules[rule_type].update(rule_set)
    return all_rules

def merge_and_sort_rules(all_rules):
    """合并并排序所有规则"""
    sorted_rules = {k: sorted(v) for k, v in all_rules.items()}
    return sorted_rules

def write_rules_to_file(sorted_rules, save_path):
    """将规则写入文件"""
    # 文件头部注释信息
    header = """
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0
!LICENSE2：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0
!有效规则数目: {rule_count}
"""

    total_rules_count = sum(len(rules) for rules in sorted_rules.values())
    rule_type_counts = "\n".join([f"! {rule_type}: {len(rules)} 条规则" for rule_type, rules in sorted_rules.items()])

    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {total_rules_count} rules to file {save_path}")
        f.write(header.format(rule_count=total_rules_count))
        f.write('\n')
        f.write(f"! 规则分类统计:\n{rule_type_counts}\n\n")
        for rule_type, rules in sorted_rules.items():
            f.write(f"! {rule_type} ({len(rules)} 条规则)\n")
            f.writelines(f"{rule}\n" for rule in rules)
            f.write('\n')

    logging.info(f"Successfully wrote rules to {save_path}")
    logging.info(f"有效规则数目: {total_rules_count}")
    for rule_type, rules in sorted_rules.items():
        logging.info(f"{rule_type}: {len(rules)} 条规则")
        print(f"{rule_type}: {len(rules)} 条规则")

    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {total_rules_count}")

def main():
    """主函数，下载过滤器并生成合并后的文件"""
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    all_rules = asyncio.run(download_filters(filter_urls))

    logging.info("Finished downloading filters. Sorting rules...")
    print("Finished downloading filters. Sorting rules...")

    sorted_rules = merge_and_sort_rules(all_rules)

    write_rules_to_file(sorted_rules, save_path)

if __name__ == "__main__":
    main()
