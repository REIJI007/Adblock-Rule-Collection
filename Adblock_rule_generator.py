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
required_packages = ["aiohttp", "urllib3", "certifi"]

# 安装所需的包
install_packages(required_packages)

# 忽略不安全请求警告
warnings.simplefilter('ignore', InsecureRequestWarning)

# 过滤器 URL 列表
filter_urls = [
    # (保留URL列表不变)
]

# 保存路径设定为当前工作目录的根目录下，并命名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

def is_valid_rule(line):
    """检查是否符合 Adblock Plus、uBlock Origin 和 AdGuard 语法"""
    if not line or line.startswith(('!', '#', '[')):
        return False

    # 域名规则和基本URL规则
    if line.startswith(('||', '|', '@@')):
        return True

    # CSS 选择器规则，包括 AdGuard 的扩展选择器
    if line.startswith(('##', '#@#', '#?#', '#@?#')) or re.search(r'#\^?([^\s]+)$', line):
        return True

    # 正则表达式规则
    if line.startswith('/') and line.endswith('/'):
        return is_valid_regex(line[1:-1])

    # 特殊协议处理
    if re.match(r'^(https?|ftp|ws|wss|data|blob|about|chrome-extension|file|filesystem|moz-extension|mailto|tel|sms|magnet|telnet|ssh|steam|irc|itms|intent|spotify|geo|maps|gopher|telnet|vnc|webcal|javascript):', line):
        return True

    # AdGuard 特有的规则
    adguard_keywords = [
        'script:inject(', 'csp=', 'redirect=', 'removeparam=', 'cookie=',
        'header=', 'important', 'badfilter', 'empty', 'rewrite=', 'referrerpolicy=',
        'permissionspolicy=', 'webrtc', 'stealth', 'ping', 'media', 'replace',
        'stylesheet', 'mediaelement', 'urlblock', 'xhr', 'third-party', 'inline-script',
        'subdocument', 'image', 'popup', 'elemhide', 'jsinject', 'specifichide',
        'denyallow', 'path', 'document', 'font', 'stylesheet', 'all', 'min', 'max',
        'redirect-rule=', 'remove-class=', 'remove-style=', 'dnsrewrite=', 'dnsblock=',
        'dnsallow=', 'dnsmask=', 'network', 'css', 'important', 'important!', 'image',
        'media', 'object', 'third-party', 'ping', 'noscript', 'csp', 'block',
        'removeheader', 'addheader', 'modifyheader', 'setcookie', 'removeparam',
        'addparam', 'modifypattern', 'override', 'cookie', 'setcss', 'thirdparty',
        'firstparty', 'collapsing', 'collapse', 'subframe', 'frame', 'mainframe',
        'background', 'all', 'document', 'sitekey', 'method=', 'rewrite', 'xhr=',
        'popup=', 'popup=', 'removeparam=', 'cookie=', 'javascript=', 'referer=',
        'query=', 'network=', 'dns=', 'param=', 'regex=', 'requestmethod=', 'requesttype=',
        'useragent=', ':has(', ':contains(', ':matches-css(', ':matches-css-before(',
        ':matches-css-after(', '##+js(', '#%#//scriptlet', 'min-device-pixel-ratio=',
        'max-device-pixel-ratio=', 'media-type=', 'domain=', 'app=', 'match-case', 'popup',
        'important', 'collapse', 'third-party', 'first-party', 'domain=', 'xmlhttprequest',
        'websocket', 'websocket-connect', 'empty', 'ping', 'rewrite', 'redirect=',
        'redirect-rule=', 'removeheader=', 'addheader=', 'removeparam=', 'removeparam',
        'setcookie=', 'webrtc=', 'referrerpolicy=', 'permissionspolicy=', 'stealth=',
        'denyallow=', 'dnscname=', 'method=', 'dnsprefetch=', 'dnsblock=', 'dnsrewrite=',
        'dnsallow=', 'dnsmask=', 'noabp=1', 'noelemhide', 'sitekey=', 'dnstarget=',
        'dnscname=', 'dnsdoc=', 'dnsresolver=', 'dnsresolver-url=', 'dnsoverhttps=',
        'dnsoverhttps-target=', 'dnsoverhttps-resolver=', 'dnsoverhttps-target=',
        'dnsoverhttps-resolver=', 'max-age=', 'samesite=', 'secure', 'httponly', 'policy='
    ]
    
    for keyword in adguard_keywords:
        if keyword in line:
            return True

    # 检查资源类型和高级选项（`$` 表示规则后缀）
    if "$" in line:
        return True

    return False

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
        all_rules = set()
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)
    return all_rules

def write_rules_to_file(rules, save_path):
    """将规则写入文件"""
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
        f.writelines(f"{rule}\n" for rule in sorted(rules))

    logging.info(f"Successfully wrote rules to {save_path}")
    logging.info(f"有效规则数目: {len(rules)}")

    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {len(rules)}")

def main():
    """主函数，下载过滤器并生成合并后的文件"""
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    rules = asyncio.run(download_filters(filter_urls))

    logging.info("Finished downloading filters. Writing rules to file...")
    print("Finished downloading filters. Writing rules to file...")

    write_rules_to_file(rules, save_path)

if __name__ == "__main__":
    main()
    
    # 检查是否在交互式环境中运行
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    else:
        print("Non-interactive mode, exiting...")
