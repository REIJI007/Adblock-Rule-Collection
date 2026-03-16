# -*- coding: utf-8 -*-
import subprocess
import sys
from datetime import datetime, timezone, timedelta

# ==================== 自动安装唯一依赖（requests） ====================
def install_package(package):
    """自动安装缺失的包"""
    print(f"正在安装依赖: {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", package])
        print(f"✅ {package} 安装完成")
    except subprocess.CalledProcessError:
        print(f"❌ 无法安装 {package}，请手动执行: pip install {package}")
        sys.exit(1)

# 安装前置检查
try:
    import requests
except ImportError:
    install_package("requests")
    import requests  # 安装后立即导入

# ==================== 第一步：定义所有上游URL（用户精确提供） ====================
urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt"
]

# ==================== 第二步：收集并去重有效规则 ====================
rules = set()
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for line in response.text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('!'):
                rules.add(stripped)
    except Exception as e:
        print(f"⚠️ 拉取失败: {url} → {e}", file=sys.stderr)
        continue

# ==================== 第三步：生成头部注释 + 统计信息 ====================
tz_utc8 = timezone(timedelta(hours=8))
timestamp = datetime.now(tz_utc8).strftime("%Y-%m-%d %H:%M:%S")

num_rules = len(rules)
header = f"""! Title: Adblock-Rule-Collection-Lite
! Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
! Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
! LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
! LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
! 生成时间: {timestamp} （UTC+8）
! 有效规则数目: {num_rules}
"""

# ==================== 第四步：写入文件（按字母排序） ====================
with open("ADBLOCK_RULE_COLLECTION_Lite.txt", "w", encoding="utf-8") as f:
    f.write(header)
    for rule in sorted(rules):
        f.write(rule + "\n")

print(f"✅ 生成完成！文件：ADBLOCK_RULE_COLLECTION_Lite.txt")
print(f" 有效规则数目: {num_rules}")
print(f" 生成时间: {timestamp} （UTC+8）")
