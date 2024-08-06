import subprocess
import sys
import warnings
import os

def install_packages(packages):
    """Ensure the required packages are installed."""
    for package in packages:
        try:
            # 尝试导入包，如果成功则说明已安装
            __import__(package)
            print(f"Package '{package}' is already installed.")
        except ImportError:
            # 如果导入失败则说明未安装，需要进行安装
            print(f"Package '{package}' is not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"Package '{package}' installed successfully.")

# 要确保安装的包列表
required_packages = ["requests"]

# 安装所需的包
install_packages(required_packages)

import requests

# 忽略不安全请求警告
from urllib3.exceptions import InsecureRequestWarning
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
    "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt"
]

# 保存路径设定为当前工作目录的根目录下，并命名为 'ADBLOCK_RULE_COLLECTION.txt'
save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')

def download_filters(urls):
    """下载过滤器并返回所有过滤规则的集合"""
    all_rules = set()  # 使用集合去重
    for url in urls:
        try:
            print(f"Downloading from {url}")
            response = requests.get(url, verify=False)  # 禁用 SSL 证书验证
            if response.status_code == 200:
                print(f"Successfully downloaded from {url}")
                lines = response.text.splitlines()
                for line in lines:
                    line = line.strip()
                    # 过滤掉注释行和空行
                    if line and not (line.startswith('!') or line.startswith('#')):
                        all_rules.add(line)
            else:
                print(f"Failed to download from {url} with status code {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {url}: {e}")
    return all_rules

def main():
    """主函数，下载过滤器并生成合并后的文件"""
    print("Starting to download filters...")
    all_rules = download_filters(filter_urls)
    print("Finished downloading filters. Sorting rules...")
    sorted_rules = sorted(all_rules)  # 对规则进行排序

    # 文件头部注释信息
    header = """# Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL3.0
!LICENSE2：https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC%20BY-NC-SA%204.0
!有效规则数目: {rule_count}
"""

    print(f"Writing {len(sorted_rules)} rules to file {save_path}")
    with open(save_path, 'w', encoding='utf-8') as f:
        # 写入文件头部信息并在之后间隔两行
        f.write(header.format(rule_count=len(sorted_rules)))
        f.write('\n\n')
        # 写入过滤规则
        for rule in sorted_rules:
            f.write(rule + '\n')

    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {len(sorted_rules)}")

if __name__ == "__main__":
    main()
