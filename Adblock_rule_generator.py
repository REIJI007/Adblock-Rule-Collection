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
    # 此处填入你的过滤器 URL 列表
]

# 保存路径设定为当前工作目录的根目录下，并命名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

def is_valid_rule(line):
    """检查是否符合 Adblock Plus、uBlock Origin、AdGuard 等广告过滤器语法"""
    return (
        line.startswith("||") or               # 域名规则
        line.startswith("|") or                # URL 规则
        line.startswith("/") and line.endswith("/") and is_valid_regex(line[1:-1]) or  # 正则表达式规则
        line.startswith("##") or               # CSS 选择器规则
        line.startswith("#@#") or              # CSS 选择器例外规则
        line.startswith("@@") or               # 例外规则
        line.startswith("!#if") or             # 条件注释
        line.startswith("!#endif") or          # 条件注释结束
        line.startswith("!#include") or        # 引入规则
        line.startswith("!#endif") or          # 结束引入规则
        "$" in line                            # 资源类型、其他条件规则
    )

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
                    if line and not (line.startswith('!') or line.startswith('#')) and is_valid_rule(line):
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
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0
!LICENSE2：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0
!生成时间: {timestamp}
!有效规则数目: {len(rules)}
"""

    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {len(rules)} rules to file {save_path}")
        f.write(header)
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules))  # 将所有规则写入文件并排序

    logging.info(f"Successfully wrote rules to {save_path}")
    logging.info(f"有效规则数目: {len(rules)}")

    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {len(rules)}")

def main():
    """主函数，下载过滤器并生成合并后的文件"""
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    rules = asyncio.run(download_filters(filter_urls))  # 异步运行下载任务

    logging.info("Finished downloading filters. Writing rules to file...")
    print("Finished downloading filters. Writing rules to file...")

    write_rules_to_file(rules, save_path)  # 写入文件

if __name__ == "__main__":
    main()
