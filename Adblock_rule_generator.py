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

# 保存路径设定为当前工作目录的根目录下，并命名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

def is_valid_rule(line):
    """检查是否符合 Adblock Plus、uBlock Origin 和 AdGuard 语法"""
    if not line or line.startswith(('!', '#', '[')):
        return False

    # 域名规则和基本URL规则
    if line.startswith(('||', '|', '@@')):
        if line.endswith('^') or re.search(r'\$[a-zA-Z]+', line):
            return True

    # CSS 选择器规则，包括 AdGuard 的扩展选择器
    if line.startswith(('##', '#@#', '#?#', '#@?#')):
        if re.search(r'##\s*[\w\-\.\#\[\]\:\s]+', line):
            return True

    # 正则表达式规则
    if line.startswith('/') and line.endswith('/'):
        return is_valid_regex(line[1:-1])

    # 特殊协议处理
    if re.match(r'^(https?|ftp|ws|wss|data|blob|about|chrome-extension|file|filesystem|moz-extension|mailto|tel|sms|magnet|telnet|ssh|steam|irc|itms|intent|spotify|geo|maps|gopher|telnet|vnc|webcal|javascript):', line):
        if not re.search(r'\s', line):  # 必须是单行协议，无空格
            return True

    # 扩展的 AdGuard 规则
    adguard_keywords = [
        # 脚本注入与执行
        'script:inject(', 'jsinject', 'javascript=', 'inline-script', 'noscript', '##+js(', '#%#//scriptlet',
        '##script', '#script', 'script-src', 'unsafe-inline', 'unsafe-eval', 'defer', 'async', 'document.write',
        
        # CSS 和样式
        'csp=', 'stylesheet', 'mediaelement', ':matches-css(', ':matches-css-before(', ':matches-css-after(', 
        'css', 'setcss', 'style-src', 'font-src', 'remove-style=', 'addstyle=', 'display:none', 'visibility:hidden',
        'font-face', 'background-image', 'opacity', 'filter', 'transition', 'animation', 'background-color=',
        'border=', 'border-radius=', 'box-shadow=', 'color=', 'height=', 'width=', 'margin=', 'padding=',
        
        # 网络请求控制
        'redirect=', 'redirect-rule=', 'xhr', 'xmlhttprequest', 'websocket', 'websocket-connect', 'ping',
        'network', 'requestmethod=', 'requesttype=', 'connect-src', 'dns=', 'dnsrewrite=', 'dnsblock=',
        'dnsallow=', 'dnsmask=', 'dns-prefetch-control', 'x-dns-prefetch-control', 'dnsoverhttps=',
        'dnsoverhttps-target=', 'dnsoverhttps-resolver=', 'server=', 'server-version=', 'x-runtime=',
        'cache-control=', 'expires=', 'pragma=', 'etag=', 'vary=', 'age=', 'if-modified-since=',
        'if-none-match=', 'accept-encoding=', 'accept-language=', 'accept=', 'content-type=', 'range=',
        'if-range=', 'content-range=', 'authorization=', 'cookie=', 'set-cookie=', 'referer=', 'x-requested-with=',
        
        # Cookie 和 Header
        'cookie=', 'setcookie', 'addheader=', 'removeheader=', 'modifyheader=', 'header=', 'set-cookie',
        'cookie-samesite', 'samesite=', 'httponly', 'secure', 'policy=', 'referrerpolicy=', 'permissionspolicy=',
        'strict-transport-security', 'hsts=', 'x-content-type-options', 'x-xss-protection', 'x-frame-options',
        'x-permitted-cross-domain-policies', 'access-control-allow-origin', 'x-powered-by=', 'x-aspnet-version=',
        'x-robots-tag=', 'x-download-options=', 'x-content-security-policy', 'x-webkit-csp',
        
        # 广告与跟踪防护
        'block', 'important', 'badfilter', 'urlblock', 'third-party', 'thirdparty', 'first-party', 'popup=',
        'elemhide', 'specifichide', 'adblock', 'noabp=1', 'noelemhide', 'collapse', 'collapsing', 'background',
        'empty', 'image', 'media', 'object', 'frame', 'subframe', 'mainframe', 'redirect=', 'redirect-rule=',
        'requestheader=', 'responseheader=', 'url=', 'domain=', 'src=', 'cookie=', 'referer=', 'tracking=', 
        'filter=', 'filterset=', 'privacy=', 'ad=', 'block-ad=', 'block-tracker=', 'track=', 'trackers=',
        'adblockplus', 'uBlock', 'block-url=', 'block-domain=', 'block-source=', 'block-referrer=',
        
        # 安全与隐私
        'webrtc', 'stealth', 'denyallow', 'dnscname=', 'dnsprefetch=', 'dnsoverhttps=', 'referrer=', 
        'reflected-xss', 'x-content-security-policy', 'x-webkit-csp', 'x-content-options', 'frame-ancestors',
        'content-security-policy', 'report-uri=', 'report-to=', 'nel=', 'cross-origin-resource-policy',
        'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'clear-site-data', 'upgrade-insecure-requests=',
        'x-frame-options', 'x-permitted-cross-domain-policies', 'permissions-policy', 'feature-policy=',
        'strict-dynamic', 'no-store', 'no-cache', 'cache-control=', 'secure', 'samesite=', 'same-origin',
        
        # 请求与响应模式
        'method=', 'path=', 'regex=', 'param=', 'query=', 'useragent=', 'referer=', 'requesturl=', 
        'responsecode=', 'responseheader=', 'requestheader=', 'requestmethod=', 'requesttype=', 'content-type=',
        'response=', 'responsebody=', 'body=', 'headers=', 'cache=', 'session=', 'cookiepolicy=',
        
        # 特性与策略
        'sandbox=', 'base-uri=', 'content-type=', 'feature-policy', 'document-policy', 'sandbox=', 
        'upgrade-insecure-requests=', 'base-uri=', 'block-all-mixed-content=', 'secure-context', 
        'x-dns-prefetch-control=', 'x-download-options=', 'crossorigin', 'block-all-mixed-content',
        'x-content-type-options=', 'x-xss-protection=', 'expect-ct=', 'report-to=', 'expect-ct-report-uri=',
        'referrer-policy=', 'base-uri=', 'access-control-allow-headers=', 'cross-origin-embedder-policy=',
        'cross-origin-opener-policy=', 'cross-origin-resource-policy=', 'content-security-policy-report-only=',
        
        # 浏览器特定设置
        'chrome-extension=', 'firefox-extension=', 'safari-extension=', 'edge-extension=', 'browser-extension=',
        'extension=', 'plugin=', 'activex=', 'silverlight=', 'flash=', 'java=', 'object=', 'embed=', 
        'plugin-types=', 'object-type=', 'embed-type=', 'plugin=', 'flash=', 'silverlight=', 'java-applet=',
        
        # 其他
        'all', 'min', 'max', 'min-device-pixel-ratio=', 'max-device-pixel-ratio=', 'media-type=', 
        'app=', 'sitekey=', 'dnstarget=', 'dnsdoc=', 'dnsresolver=', 'dnsresolver-url=', 'dnsoverhttps=',
        'dnsoverhttps-target=', 'dnsoverhttps-resolver=', 'max-age=', 'samesite=', 'secure', 'httponly', 
        'policy=', 'location=', 'port=', 'range=', 'key=', 'value=', 'opt-in=', 'opt-out=', 'web-security=',
        'session-identifier=', 'unique-id=', 'click-tracking=', 'impression-tracking=', 'behavioral-tracking=',
        'contextual-tracking=', 'utm-source=', 'utm-medium=', 'utm-campaign=', 'utm-term=', 'utm-content=',
        'campaign=', 'source=', 'medium=', 'term=', 'content=', 'adgroup=', 'placement=', 'creative=', 
        'format=', 'device=', 'browser=', 'platform=', 'os=', 'locale=', 'region=', 'city=', 'country=',
    ]

    # 扩展的 uBlock Origin 规则
    ublock_keywords = [
        '$script', '$image', '$stylesheet', '$third-party', '$popup', '$object', '$xmlhttprequest', 
        '$subdocument', '$elemhide', '$webrtc', '$websocket', '$other', '$all', '$csp=', '$cookie=', 
        '$redirect=', '$document', '$important', '$media', '$generichide', '$inline-script', 
        '$inline-style', '$removeparam=', '$removeclass=', '$setclass=', '$setcookie=', '$denyallow=',
    ]

    # 扩展的 Adblock Plus 规则
    adblock_plus_keywords = [
        '$script', '$image', '$stylesheet', '$object', '$xmlhttprequest', '$subdocument', '$third-party',
        '$popup', '$csp=', '$cookie=', '$redirect=', '$document', '$important', '$media', '$webrtc', 
        '$genericblock', '$genericblock=', '$inline-script', '$inline-style', '$removeparam=',
        '$removeclass=', '$setclass=', '$setcookie=', '$denyallow=',
    ]

    def is_valid_adguard_rule(line):
        """检查是否符合 AdGuard 语法"""
        return any(keyword in line for keyword in adguard_keywords) and \
               re.search(r'\$[a-zA-Z]*', line) is not None

    def is_valid_ublock_rule(line):
        """检查是否符合 uBlock Origin 语法"""
        return any(keyword in line for keyword in ublock_keywords) and \
               re.search(r'\$[a-zA-Z]*', line) is not None

    def is_valid_adblock_plus_rule(line):
        """检查是否符合 Adblock Plus 语法"""
        return any(keyword in line for keyword in adblock_plus_keywords) and \
               re.search(r'\$[a-zA-Z]*', line) is not None

    def is_valid_regex(pattern):
        """验证正则表达式语法"""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    if any(keyword in line for keyword in adguard_keywords):
        return is_valid_adguard_rule(line)

    if any(keyword in line for keyword in ublock_keywords):
        return is_valid_ublock_rule(line)

    if any(keyword in line for keyword in adblock_plus_keywords):
        return is_valid_adblock_plus_rule(line)

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
