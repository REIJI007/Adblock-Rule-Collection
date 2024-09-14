import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
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
    # ... (保持原有的 URL 列表不变)
]

# 保存路径设定为当前工作目录下，文件名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

async def download_filter(session, url):
    """异步下载单个过滤器文件并提取所有非空行。

    参数:
    session (aiohttp.ClientSession): aiohttp 客户端会话对象。
    url (str): 要下载的过滤器 URL。

    返回:
    set: 一个包含所有非空行的集合。
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
                    if line:  # 只需确保行不为空
                        rules.add(line)
            else:
                logging.error(f"Failed to download from {url} with status code {response.status}")
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
    return rules

async def download_filters(urls):
    """并行下载多个过滤器文件并返回所有规则的集合。

    参数:
    urls (list): 过滤器 URL 列表。

    返回:
    set: 一个包含所有非空行的集合。
    """
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)
    return all_rules

def write_rules_to_file(rules, save_path):
    """将规则写入指定的文件。

    参数:
    rules (set): 要写入的规则集合。
    save_path (str): 文件保存路径。
    """
    now = datetime.now(timezone(timedelta(hours=8)))  # 获取当前时间并设置为东八区时间
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')  # 格式化时间戳

    # 文件头部注释
    header = f"""
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0
!LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0
!生成时间: {timestamp}
!规则数目: {len(rules)}
"""

    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {len(rules)} rules to file {save_path}")
        f.write(header)  # 写入文件头
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules))  # 写入所有规则，每个规则占一行

    logging.info(f"Successfully wrote rules to {save_path}")
    logging.info(f"规则数目: {len(rules)}")

    print(f"Successfully wrote rules to {save_path}")
    print(f"规则数目: {len(rules)}")

def main():
    """主函数，执行过滤器下载和文件生成操作"""
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    # 下载所有过滤器并收集规则
    rules = asyncio.run(download_filters(filter_urls))

    logging.info("Finished downloading filters. Writing rules to file...")
    print("Finished downloading filters. Writing rules to file...")

    # 将收集的规则写入文件
    write_rules_to_file(rules, save_path)

if __name__ == "__main__":
    main()
    
    # 检查是否在交互式环境中运行
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    else:
        print("Non-interactive mode, exiting...")
