# -*- coding: utf-8 -*-
"""
CloudFlare Scan

Original work  Copyright (c) 2026 xiaolin-007   (MIT License)
Modifications  Copyright (c) 2026 techiewmvp    (MIT License)

Permission notice: see the LICENSE file shipped with this program
(also viewable in the app via the "开源许可" link). The above copyright
notice and the permission notice must be kept in all copies or substantial
portions of the Software.
"""
import sys
import os
import re
import csv
import time
import ssl
import socket
import random
import asyncio
import platform
import ipaddress
from collections import deque
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse

import aiohttp

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QLineEdit, QProgressBar, QVBoxLayout, QHBoxLayout,
    QTextEdit, QFileDialog, QScrollArea, QFrame,
    QStackedWidget, QDialog, QDialogButtonBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSettings
from PySide6.QtGui import QFont, QIcon, QIntValidator


# ============================================================
# 应用信息（想改标题 / 版本 / 链接，只改这里）
# ============================================================
APP_NAME = "CloudFlare Scan"
APP_VERSION = "V5.1"
GITHUB_URL = "https://github.com/techiewmvp/CloudFlareScan"
WARNING_TEXT = "⚠ 请关闭代理后使用本程序"

LICENSE_TEXT = """MIT License

Copyright (c) 2026 xiaolin-007
Copyright (c) 2026 techiewmvp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


# ============================================================
# 字体 / 尺寸
# ============================================================
def get_system_font():
    system = platform.system()
    if system == "Windows":
        return "Microsoft YaHei"
    elif system == "Darwin":
        return "PingFang SC"
    return "DejaVu Sans"

SYSTEM_FONT = get_system_font()

FONT_TITLE = QFont(SYSTEM_FONT, 28)
FONT_TITLE.setBold(True)
FONT_BTN = QFont(SYSTEM_FONT, 11)
FONT_STATUS = QFont(SYSTEM_FONT, 10)

BTN_W = 120
BTN_H = 32
SPACING = 8


# ============================================================
# 主题
# ============================================================
THEMES = {
    "light": {
        "bg": "#F9FAFB", "text": "#111827", "sub": "#6B7280",
        "input_bg": "#FFFFFF", "input_border": "#D1D5DB",
        "panel": "#0B3C5D", "panel_text": "#ECF0F1", "panel_border": "#0F4C75",
        "sb_track": "#0F4C75", "sb_handle": "#1E90FF", "sb_hover": "#00BFFF",
        "progress_bg": "#E5E7EB",
        "tab_active": "#0B4F7A", "tab_off_bg": "#E5E7EB", "tab_off_fg": "#6B7280",
        "disabled_bg": "#E5E7EB", "disabled_fg": "#6B7280",
        "link": "#2563EB",
        "dialog_bg": "#FFFFFF", "dialog_border": "#D1D5DB",
        "warn_fg": "#DC2626", "warn_bg": "#FEE2E2",
        "theme_btn_bg": "#FFFFFF", "theme_btn_fg": "#111827",
    },
    "dark": {
        "bg": "#111827", "text": "#F3F4F6", "sub": "#9CA3AF",
        "input_bg": "#1F2937", "input_border": "#374151",
        "panel": "#0B1220", "panel_text": "#E5E7EB", "panel_border": "#1F2937",
        "sb_track": "#1F2937", "sb_handle": "#3B82F6", "sb_hover": "#60A5FA",
        "progress_bg": "#374151",
        "tab_active": "#2563EB", "tab_off_bg": "#1F2937", "tab_off_fg": "#9CA3AF",
        "disabled_bg": "#374151", "disabled_fg": "#6B7280",
        "link": "#60A5FA",
        "dialog_bg": "#1F2937", "dialog_border": "#374151",
        "warn_fg": "#FCA5A5", "warn_bg": "#7F1D1D",
        "theme_btn_bg": "#1F2937", "theme_btn_fg": "#F3F4F6",
    },
}
_current_theme = "light"

def set_theme(name: str):
    global _current_theme
    _current_theme = name if name in THEMES else "light"

def T() -> Dict[str, str]:
    return THEMES[_current_theme]

def line_edit_style() -> str:
    c = T()
    return f"""
        QLineEdit {{
            background: {c['input_bg']};
            border: 1px solid {c['input_border']};
            border-radius: 6px;
            padding: 0px 5px;
            font-family: "{SYSTEM_FONT}";
            color: {c['text']};
        }}
        QLineEdit:focus {{ border-color: #F97316; }}
        QLineEdit:disabled {{ color: {c['sub']}; }}
    """

def scrollbar_style() -> str:
    c = T()
    return f"""
        QScrollBar:vertical {{
            background: {c['sb_track']}; width: 8px; border-radius: 3px;
        }}
        QScrollBar::handle:vertical {{
            background: {c['sb_handle']}; min-height: 20px; border-radius: 3px;
        }}
        QScrollBar::handle:vertical:hover {{ background: {c['sb_hover']}; }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
    """


# ============================================================
# Cloudflare IP 段（内置）
# ============================================================
CF_IPV4_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/17", "172.64.128.0/18", "172.64.192.0/19", "172.64.224.0/22",
    "172.64.229.0/24", "172.64.230.0/23", "172.64.232.0/21", "172.64.240.0/21",
    "172.64.248.0/21", "172.65.0.0/16", "172.66.0.0/16", "172.67.0.0/16",
    "131.0.72.0/22"
]

CF_IPV6_CIDRS = [
    "2400:cb00:2049::/48", "2400:cb00:f00e::/48", "2606:4700::/32",
    "2606:4700:10::/48", "2606:4700:130::/48", "2606:4700:3000::/48",
    "2606:4700:3001::/48", "2606:4700:3002::/48", "2606:4700:3003::/48",
    "2606:4700:3004::/48", "2606:4700:3005::/48", "2606:4700:3006::/48",
    "2606:4700:3007::/48", "2606:4700:3008::/48", "2606:4700:3009::/48",
    "2606:4700:3010::/48", "2606:4700:3011::/48", "2606:4700:3012::/48",
    "2606:4700:3013::/48", "2606:4700:3014::/48", "2606:4700:3015::/48",
    "2606:4700:3016::/48", "2606:4700:3017::/48", "2606:4700:3018::/48",
    "2606:4700:3019::/48", "2606:4700:3020::/48", "2606:4700:3021::/48",
    "2606:4700:3022::/48", "2606:4700:3023::/48", "2606:4700:3024::/48",
    "2606:4700:3025::/48", "2606:4700:3026::/48", "2606:4700:3027::/48",
    "2606:4700:3028::/48", "2606:4700:3029::/48", "2606:4700:3030::/48",
    "2606:4700:3031::/48", "2606:4700:3032::/48", "2606:4700:3033::/48",
    "2606:4700:3034::/48", "2606:4700:3035::/48", "2606:4700:3036::/48",
    "2606:4700:5a::/48", "2606:4700:52::/48", "2606:4700:57::/48",
    "2606:4700:a0::/48", "2606:4700:a1::/48", "2606:4700:a8::/48",
    "2606:4700:a9::/48", "2606:4700:a::/48", "2606:4700:b::/48",
    "2606:4700:c::/48", "2606:4700:d0::/48", "2606:4700:d1::/48",
    "2606:4700:d::/48", "2606:4700:e0::/48", "2606:4700:e1::/48",
    "2606:4700:e2::/48", "2606:4700:e3::/48", "2606:4700:e4::/48",
    "2606:4700:e5::/48", "2606:4700:e6::/48", "2606:4700:e7::/48",
    "2606:4700:e::/48", "2606:4700:f1::/48", "2606:4700:f2::/48",
    "2606:4700:f3::/48", "2606:4700:f4::/48", "2606:4700:f5::/48",
    "2606:4700:f::/48", "2803:f800:50::/48", "2803:f800:51::/48",
    "2a06:98c1:3100::/48", "2a06:98c1:3101::/48", "2a06:98c1:3102::/48",
    "2a06:98c1:3103::/48", "2a06:98c1:3104::/48", "2a06:98c1:3105::/48",
    "2a06:98c1:3106::/48", "2a06:98c1:3107::/48", "2a06:98c1:3108::/48",
    "2a06:98c1:3109::/48", "2a06:98c1:310a::/48", "2a06:98c1:310b::/48",
    "2a06:98c1:310c::/48", "2a06:98c1:310d::/48", "2a06:98c1:310e::/48",
    "2a06:98c1:310f::/48", "2a06:98c1:3120::/48", "2a06:98c1:3121::/48",
    "2a06:98c1:3122::/48", "2a06:98c1:3123::/48", "2a06:98c1:3200::/48",
    "2a06:98c1:50::/48", "2a06:98c1:51::/48", "2a06:98c1:54::/48",
    "2a06:98c1:58::/48"
]

AIRPORT_CODES = {
    "HKG": "香港", "TPE": "台北", "KHH": "高雄", "MFM": "澳门",
    "NRT": "东京", "HND": "东京", "KIX": "大阪", "NGO": "名古屋",
    "FUK": "福冈", "CTS": "札幌", "OKA": "冲绳",
    "ICN": "首尔", "GMP": "首尔", "PUS": "釜山",
    "SIN": "新加坡", "BKK": "曼谷", "DMK": "曼谷",
    "KUL": "吉隆坡", "HKT": "普吉岛",
    "MNL": "马尼拉", "CEB": "宿务",
    "HAN": "河内", "SGN": "胡志明市",
    "JKT": "雅加达", "DPS": "巴厘岛",
    "DEL": "德里", "BOM": "孟买", "MAA": "金奈",
    "DXB": "迪拜", "AUH": "阿布扎比",
    "SJC": "圣何塞", "LAX": "洛杉矶", "SFO": "旧金山",
    "SEA": "西雅图", "PDX": "波特兰",
    "LAS": "拉斯维加斯", "PHX": "菲尼克斯",
    "DEN": "丹佛", "DFW": "达拉斯", "IAH": "休斯顿",
    "ORD": "芝加哥", "MSP": "明尼阿波利斯",
    "ATL": "亚特兰大", "MIA": "迈阿密", "MCO": "奥兰多",
    "JFK": "纽约", "EWR": "纽约", "LGA": "纽约",
    "BOS": "波士顿", "PHL": "费城", "IAD": "华盛顿",
    "YYZ": "多伦多", "YVR": "温哥华", "YUL": "蒙特利尔",
    "LHR": "伦敦", "LGW": "伦敦", "STN": "伦敦",
    "CDG": "巴黎", "ORY": "巴黎",
    "FRA": "法兰克福", "MUC": "慕尼黑", "TXL": "柏林",
    "AMS": "阿姆斯特丹", "EIN": "埃因霍温",
    "MAD": "马德里", "BCN": "巴塞罗那",
    "FCO": "罗马", "MXP": "米兰", "LIN": "米兰",
    "ZRH": "苏黎世", "GVA": "日内瓦",
    "VIE": "维也纳", "PRG": "布拉格",
    "WAW": "华沙", "KRK": "克拉科夫",
    "HEL": "赫尔辛基", "OSL": "奥斯陆", "ARN": "斯德哥尔摩",
    "CPH": "哥本哈根",
    "SYD": "悉尼", "MEL": "墨尔本", "BNE": "布里斯班",
    "PER": "珀斯", "ADL": "阿德莱德",
    "AKL": "奥克兰", "WLG": "惠灵顿",
    "GRU": "圣保罗", "GIG": "里约热内卢", "EZE": "布宜诺斯艾利斯",
    "SCL": "圣地亚哥", "LIM": "利马", "BOG": "波哥大",
    "JNB": "约翰内斯堡", "CPT": "开普敦", "CAI": "开罗",
}

# 固定扫描的全部端口（不再提供端口选择）
PORTS = [443, 2053, 2083, 2087, 2096, 8443]

# 内置测速地址
DEFAULT_TEST_HOST = "speed.cloudflare.com"
DEFAULT_TEST_PATH = "/__down?bytes=50000000"
# 用于获取 colo 地区码（/cdn-cgi/trace）的域名
TRACE_HOST = "speed.cloudflare.com"

# 单次扫描最多测试的 IP 数（防止自定义超大 CIDR 把内存/时间吃光）
MAX_SCAN_IPS = 50000


# ============================================================
# 通用工具函数
# ============================================================
def _make_insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

INSECURE_CTX = _make_insecure_ctx()


def get_iata_translation(iata_code: str) -> str:
    return AIRPORT_CODES.get(iata_code, iata_code if iata_code else "未知地区")


def parse_test_url(text: str) -> Tuple[str, str]:
    """把用户输入的测速地址拆成 (host, path)。留空 = 内置地址。
    支持 https://host/path?x=1 、host/path 、host 三种写法。
    端口由扫描端口决定，URL 里的端口会被忽略。"""
    text = (text or "").strip()
    if not text:
        return DEFAULT_TEST_HOST, DEFAULT_TEST_PATH
    if "://" not in text:
        text = "https://" + text
    u = urlparse(text)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("测速地址格式不正确")
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return u.hostname, path


def parse_cidr_text(text: str) -> Tuple[List[str], List[str], List[str]]:
    """解析 txt 内容，自动区分 IPv4 / IPv6。
    返回 (v4列表, v6列表, 无效条目)。
    支持：每行一个或逗号/空格/分号分隔；# 开头或行内 # 之后为注释；
    单个 IP（无掩码）按 /32 或 /128 处理。"""
    v4, v6, bad = [], [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for token in re.split(r"[,\s;]+", line):
            if not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                bad.append(token)
                continue
            (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6, bad


async def get_iata_code_async(session: aiohttp.ClientSession, ip: str, timeout: float = 3) -> Optional[str]:
    urls = (f"http://[{ip}]/cdn-cgi/trace", f"https://[{ip}]/cdn-cgi/trace") if ':' in ip \
        else (f"http://{ip}/cdn-cgi/trace", f"https://{ip}/cdn-cgi/trace")
    headers = {"User-Agent": "Mozilla/5.0", "Host": TRACE_HOST}
    for url in urls:
        try:
            async with session.get(url, headers=headers,
                                   ssl=INSECURE_CTX if url.startswith('https://') else None,
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.strip().split('\n'):
                        if line.startswith('colo='):
                            colo = line.split('=', 1)[1].strip()
                            if colo and colo.upper() != 'UNKNOWN':
                                return colo.upper()
                    if 'CF-RAY' in resp.headers:
                        cf_ray = resp.headers['CF-RAY']
                        if '-' in cf_ray:
                            for part in cf_ray.split('-')[-2:]:
                                if len(part) == 3 and part.isalpha():
                                    return part.upper()
        except Exception:
            continue
    return None


async def async_tcp_ping(ip: str, port: int, timeout: float = 1.0) -> Optional[float]:
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None
    latency = (time.monotonic() - start) * 1000
    # 连接已成功，关闭阶段的异常不应让这次测量作废
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return round(latency, 2)


async def measure_tcp_latency(ip: str, port: int, ping_times: int = 2, timeout: float = 1.0) -> Optional[float]:
    latencies = []
    for i in range(ping_times):
        lat = await async_tcp_ping(ip, port, timeout)
        if lat is not None:
            latencies.append(lat)
        if i < ping_times - 1:
            await asyncio.sleep(0.05)
    return min(latencies) if latencies else None


# ============================================================
# 扫描器：所有端口并发，总线程数 / 端口数 = 每端口线程数
# ============================================================
class CloudflareScanner:
    def __init__(self, cidrs: List[str], ip_version: int, ports: List[int],
                 log_callback=None, progress_callback=None,
                 max_workers=150, latency_threshold=220,
                 ipv4_sample_per_subnet=1, ipv6_sample_per_cidr=100):
        self.cidrs = cidrs
        self.ip_version = ip_version
        self.ports = ports
        self.max_workers = max_workers
        self.timeout = 1.0          # TCP 超时
        self.iata_timeout = 2.0     # 地区码查询超时
        self.ping_times = 2
        self.running = True
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.latency_threshold = latency_threshold
        self.ipv4_sample_per_subnet = ipv4_sample_per_subnet
        self.ipv6_sample_per_cidr = ipv6_sample_per_cidr
        self._iata_tasks: Dict[str, asyncio.Future] = {}

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def _sample_v4(self, network) -> List[str]:
        n = self.ipv4_sample_per_subnet
        subnets = [network] if network.prefixlen >= 24 else network.subnets(new_prefix=24)
        out = []
        for sub in subnets:
            hosts = list(sub.hosts()) or list(sub)
            out.extend(str(ip) for ip in random.sample(hosts, min(n, len(hosts))))
        return out

    def _sample_v6(self, network) -> List[str]:
        if network.num_addresses <= 2:
            return [str(network.network_address)]
        lo = int(network.network_address) + 1
        hi = int(network.broadcast_address) - 1
        k = min(self.ipv6_sample_per_cidr, network.num_addresses - 2)
        return [str(ipaddress.IPv6Address(random.randint(lo, hi))) for _ in range(k)]

    def generate_ips(self) -> List[str]:
        ips: List[str] = []
        for cidr in self.cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                self._log(f"处理CIDR {cidr} 时出错: {e}")
                continue
            ips.extend(self._sample_v4(network) if self.ip_version == 4 else self._sample_v6(network))
        ips = list(dict.fromkeys(ips))
        if len(ips) > MAX_SCAN_IPS:
            self._log(f"生成的IP过多({len(ips)})，已随机截取 {MAX_SCAN_IPS} 个")
            ips = random.sample(ips, MAX_SCAN_IPS)
        return ips

    async def _get_iata(self, session, ip: str) -> Optional[str]:
        """同一个 IP 在多个端口命中时，只查询一次地区码。"""
        task = self._iata_tasks.get(ip)
        if task is None:
            task = asyncio.ensure_future(get_iata_code_async(session, ip, self.iata_timeout))
            self._iata_tasks[ip] = task
        return await task

    async def test_single_ip(self, session, ip: str, port: int):
        if not self.running:
            return None
        latency = await measure_tcp_latency(ip, port, self.ping_times, self.timeout)
        if latency is None or latency >= self.latency_threshold:
            return None
        iata = None
        if self.running:
            try:
                iata = await self._get_iata(session, ip)
            except Exception as e:
                self._log(f"获取地区码失败 {ip}: {e}")
        return {
            'ip': ip, 'port': port, 'latency': latency, 'iata_code': iata,
            'chinese_name': get_iata_translation(iata) if iata else "未知地区",
            'success': True, 'ip_version': self.ip_version,
            'scan_time': datetime.now().strftime("%H:%M:%S"),
            'ping_times': self.ping_times
        }

    async def batch_test_ips(self, ip_list: List[str]):
        ports = self.ports
        per_port = max(1, self.max_workers // len(ports))
        queues = {p: deque(ip_list) for p in ports}
        total = len(ip_list) * len(ports)
        successful: List[dict] = []
        state = {'done': 0, 'last': 0.0}
        start_time = time.time()
        family = socket.AF_INET6 if self.ip_version == 6 else socket.AF_INET
        connector = aiohttp.TCPConnector(limit=self.max_workers, force_close=True,
                                         limit_per_host=0, family=family)

        def report(force=False):
            now = time.time()
            if force or now - state['last'] >= 0.5:
                elapsed = now - start_time
                speed = state['done'] / elapsed if elapsed > 0 else 0
                if self.progress_callback:
                    self.progress_callback(state['done'], total, len(successful), speed)
                state['last'] = now

        async def worker(port: int, session):
            q = queues[port]
            while self.running:
                try:
                    ip = q.popleft()
                except IndexError:
                    return
                try:
                    res = await self.test_single_ip(session, ip, port)
                except Exception:
                    res = None
                state['done'] += 1
                if res:
                    successful.append(res)
                report()

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [asyncio.create_task(worker(p, session)) for p in ports for _ in range(per_port)]
            await asyncio.gather(*tasks)
        report(force=True)
        order = {p: i for i, p in enumerate(ports)}
        successful.sort(key=lambda r: (order[r['port']], r['latency']))
        return successful

    async def run_scan_async(self):
        try:
            self._log(f"正在从 IPv{self.ip_version} 地址段生成随机IP...（共 {len(self.cidrs)} 个CIDR）")
            ip_list = self.generate_ips()
            if not ip_list:
                self._log(f"错误: 未能生成IPv{self.ip_version} IP列表")
                return None
            per_port = max(1, self.max_workers // len(self.ports))
            self._log(f"已生成 {len(ip_list)} 个随机IPv{self.ip_version} IP")
            self._log(f"开始延迟测试：{len(self.ports)} 个端口并发，每端口 {per_port} 线程")
            self._log("端口: " + " / ".join(str(p) for p in self.ports))
            results = await self.batch_test_ips(ip_list)
            if not self.running:
                self._log(f"IPv{self.ip_version}扫描被用户中止")
                return None
            return results
        except Exception as e:
            self._log(f"IPv{self.ip_version}扫描过程中出现错误: {e}")
            return None

    def stop(self):
        self.running = False


class ScanWorker(QThread):
    progress_update = Signal(int, int, int, float)
    status_message = Signal(str)
    scan_completed = Signal(list)

    def __init__(self, ip_version: int, cidrs: List[str], max_workers=150, latency_threshold=220,
                 ipv4_sample_per_subnet=1, ipv6_sample_per_cidr=100):
        super().__init__()
        self.ip_version = ip_version
        self.cidrs = cidrs
        self.max_workers = max_workers
        self.latency_threshold = latency_threshold
        self.ipv4_sample_per_subnet = ipv4_sample_per_subnet
        self.ipv6_sample_per_cidr = ipv6_sample_per_cidr
        self.scanner = None

    def run(self):
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        self.scanner = CloudflareScanner(
            cidrs=self.cidrs, ip_version=self.ip_version, ports=list(PORTS),
            log_callback=lambda msg: self.status_message.emit(msg),
            progress_callback=lambda c, t, s, sp: self.progress_update.emit(c, t, s, sp),
            max_workers=self.max_workers, latency_threshold=self.latency_threshold,
            ipv4_sample_per_subnet=self.ipv4_sample_per_subnet,
            ipv6_sample_per_cidr=self.ipv6_sample_per_cidr
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(self.scanner.run_scan_async())
            if results is not None:
                self.scan_completed.emit(results)
        finally:
            loop.close()

    def stop(self):
        if self.scanner:
            self.scanner.stop()


# ============================================================
# 测速：按端口依次测速，每个端口取 N 个 IP，按速度排序输出
# ============================================================
class SpeedTestWorker(QThread):
    progress_update = Signal(int, int, float)
    status_message = Signal(str)
    speed_test_completed = Signal(list)

    def __init__(self, results: List[Dict], region_code: str = None,
                 max_test_count=10, test_url: str = ""):
        super().__init__()
        self.results = results
        self.region_code = region_code.upper() if region_code else None
        self.max_test_count = max_test_count
        self.download_time_limit = 3
        self.test_host, self.test_path = parse_test_url(test_url)
        self.running = True

    def download_speed(self, ip: str, port: int) -> float:
        req = (f"GET {self.test_path} HTTP/1.1\r\nHost: {self.test_host}\r\n"
               f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
        conn = None
        try:
            conn = socket.create_connection((ip, port), timeout=3)
            conn = INSECURE_CTX.wrap_socket(conn, server_hostname=self.test_host)
            conn.sendall(req)
            start = time.time()
            data = b""
            header_done = False
            body = 0
            while time.time() - start < self.download_time_limit:
                buf = conn.recv(65536)
                if not buf:
                    break
                if not header_done:
                    data += buf
                    if b"\r\n\r\n" in data:
                        head, rest = data.split(b"\r\n\r\n", 1)
                        try:
                            status = int(head.split(b" ", 2)[1])
                        except (IndexError, ValueError):
                            raise RuntimeError("响应格式异常")
                        if status not in (200, 206):
                            raise RuntimeError(f"HTTP {status}")
                        header_done = True
                        body += len(rest)
                else:
                    body += len(buf)
            dur = time.time() - start
            return round((body / 1024 / 1024) / max(dur, 0.1), 2)
        except Exception as e:
            self.status_message.emit(f"  测速失败 {ip}:{port} - {e}")
            return 0.0
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def run(self):
        try:
            if not self.results:
                self.status_message.emit("错误：没有可用的IP进行测速")
                self.speed_test_completed.emit([])
                return
            test_type = '地区测速' if self.region_code else '完全测速'
            if self.region_code:
                filtered = [r for r in self.results
                            if r.get('iata_code') and r['iata_code'].upper() == self.region_code]
                self.status_message.emit(
                    f"开始地区测速：{self.region_code} ({AIRPORT_CODES.get(self.region_code, '未知地区')})")
            else:
                filtered = list(self.results)
                self.status_message.emit("开始完全测速")
            self.status_message.emit(f"测速地址: {self.test_host}{self.test_path[:40]}")
            if not filtered:
                self.status_message.emit("没有找到可用的IP进行测速")
                self.speed_test_completed.emit([])
                return

            by_port: Dict[int, List[dict]] = {}
            for r in filtered:
                by_port.setdefault(r['port'], []).append(r)

            plan = []
            for port in PORTS:
                items = sorted(by_port.get(port, []), key=lambda x: x.get('latency', float('inf')))
                if not items:
                    self.status_message.emit(f"端口 {port}: 没有可用IP，跳过")
                    continue
                if len(items) < self.max_test_count:
                    self.status_message.emit(
                        f"端口 {port}: 仅 {len(items)} 个可用IP（不足 {self.max_test_count}），按实际数量测速")
                plan.append((port, items[:self.max_test_count]))
            total = sum(len(t) for _, t in plan)
            if total == 0:
                self.status_message.emit("没有找到可用的IP进行测速")
                self.speed_test_completed.emit([])
                return

            done = 0
            final: List[dict] = []
            for port, targets in plan:
                if not self.running:
                    break
                self.status_message.emit(f"—— 端口 {port}：测速 {len(targets)} 个IP ——")
                port_results = []
                for info in targets:
                    if not self.running:
                        break
                    ip = info['ip']
                    self.status_message.emit(f"[{done + 1}/{total}] 正在测速 {ip}:{port}")
                    dl = self.download_speed(ip, port)
                    done += 1
                    self.progress_update.emit(done, total, 0)
                    if dl > 0:
                        port_results.append({
                            'ip': ip, 'port': port, 'latency': info.get('latency', 0),
                            'download_speed': dl,
                            'iata_code': info.get('iata_code') or 'UNKNOWN',
                            'chinese_name': info.get('chinese_name', '未知地区'),
                            'test_type': test_type
                        })
                        self.status_message.emit(f"  {dl} MB/s · {info.get('iata_code')} {info.get('chinese_name')}")
                    if self.running:
                        time.sleep(0.3)
                port_results.sort(key=lambda x: x['download_speed'], reverse=True)
                final.extend(port_results)
                self.status_message.emit(f"端口 {port} 完成：有效 {len(port_results)}/{len(targets)} 个")
            self.status_message.emit(f"测速完成！共 {len(final)} 条有效结果")
            self.speed_test_completed.emit(final)
        except Exception as e:
            self.status_message.emit(f"测速过程中出现错误: {e}")
            self.speed_test_completed.emit([])

    def stop(self):
        self.running = False


# ============================================================
# 对话框
# ============================================================
class CustomDialog(QDialog):
    def __init__(self, message: str, buttons=QDialogButtonBox.Ok, parent=None):
        super().__init__(parent)
        c = T()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setModal(True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setStyleSheet("CustomDialog{background:transparent;}")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(0)

        panel = QFrame()
        panel.setObjectName("dialogPanel")
        panel.setStyleSheet(f"""
            QFrame#dialogPanel {{
                background-color: {c['dialog_bg']};
                border: 1px solid {c['dialog_border']};
                border-radius: 12px;
            }}
            QLabel {{
                background: transparent; border: none;
                font-family: "{SYSTEM_FONT}"; font-size: 15px; color: {c['text']};
            }}
            QDialogButtonBox {{ background: transparent; border: none; }}
            QPushButton {{
                background: #F97316; color: white; border: none; border-radius: 6px;
                padding: 6px 18px; min-width: 62px; min-height: 20px;
                font-family: "{SYSTEM_FONT}"; font-size: 15px;
            }}
            QPushButton:hover {{ background: #EA580C; }}
            QPushButton:pressed {{ background: #C2410C; }}
        """)
        outer.addWidget(panel)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 24, 24, 20)
        layout.setSpacing(18)

        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        msg_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(msg_label)

        box = QDialogButtonBox(buttons)
        box.setCenterButtons(True)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        for std, text in ((QDialogButtonBox.Ok, "确定"), (QDialogButtonBox.Yes, "确定"),
                          (QDialogButtonBox.No, "取消")):
            b = box.button(std)
            if b:
                b.setText(text)
        layout.addWidget(box)
        self.setFixedSize(320, 160)

    @staticmethod
    def warning(parent, message):
        return CustomDialog(message, QDialogButtonBox.Ok, parent).exec()

    @staticmethod
    def question(parent, message):
        dlg = CustomDialog(message, QDialogButtonBox.Yes | QDialogButtonBox.No, parent)
        return dlg.exec() == QDialog.Accepted


class LicenseDialog(QDialog):
    """显示 MIT 许可全文（发布 exe 时需随附版权声明与许可声明）。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        c = T()
        self.setWindowTitle("开源许可")
        self.resize(470, 440)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setPlainText(LICENSE_TEXT)
        te.setStyleSheet(f"""
            QTextEdit {{
                background:{c['input_bg']}; color:{c['text']};
                border:1px solid {c['input_border']}; border-radius:6px; padding:8px;
                font-family: Consolas, 'Courier New', monospace; font-size:12px;
            }}
            {scrollbar_style()}
        """)
        lay.addWidget(te)
        btn = QPushButton("关闭")
        btn.setFixedSize(BTN_W, BTN_H)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet("QPushButton{background:#F97316;color:white;border-radius:6px;}"
                          "QPushButton:hover{background:#EA580C;}")
        btn.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(btn)
        row.addStretch()
        lay.addLayout(row)


# ============================================================
# 主窗口
# ============================================================
class CloudflareScanUI(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("CloudFlareScan", "CloudFlareScan")
        set_theme(str(self.settings.value("theme", "light")))

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(440, 830)
        self.setMinimumSize(430, 700)

        self.scan_worker = None
        self.speed_test_worker = None
        self.scanning = False
        self.speed_testing = False
        self.user_stopped = False
        self.scan_results: List[dict] = []
        self.speed_results: List[dict] = []
        self.custom_v4: List[str] = []
        self.custom_v6: List[str] = []
        self._btns = []      # (button, color)
        self._edits = []
        self._link_labels = []
        self.init_ui()
        self.apply_theme()

    # ---------- 控件工厂 ----------
    def style_btn(self, btn, color):
        c = T()
        btn.setStyleSheet(
            f"QPushButton{{background:{color};color:white;border-radius:6px;font-family:'{SYSTEM_FONT}';}}"
            f"QPushButton:disabled{{background:{c['disabled_bg']};color:{c['disabled_fg']};}}")

    def make_btn(self, text, color, enabled=True, size=(BTN_W, BTN_H)):
        btn = QPushButton(text)
        btn.setFixedSize(*size)
        btn.setFont(FONT_BTN)
        btn.setEnabled(enabled)
        btn.setCursor(Qt.PointingHandCursor)
        self._btns.append((btn, color))
        return btn

    def make_edit(self, text="", validator=None, placeholder=""):
        e = QLineEdit(text)
        e.setFixedHeight(BTN_H)
        e.setFont(FONT_BTN)
        if placeholder:
            e.setPlaceholderText(placeholder)
        if validator:
            e.setValidator(validator)
        self._edits.append(e)
        return e

    def make_field(self, label, edit, label_w=None, edit_w=None, spacing=3, box=None):
        w = QWidget()
        if box:
            w.setFixedSize(*box)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(spacing)
        lbl = QLabel(label)
        lbl.setFont(FONT_BTN)
        if label_w:
            lbl.setFixedWidth(label_w)
        lay.addWidget(lbl)
        if edit_w:
            edit.setFixedWidth(edit_w)
            lay.addWidget(edit)
        else:
            lay.addWidget(edit, 1)
        return w

    @staticmethod
    def centered_row(*widgets):
        row = QHBoxLayout()
        row.addStretch()
        for i, w in enumerate(widgets):
            if i:
                row.addSpacing(SPACING)
            row.addWidget(w)
        row.addStretch()
        return row

    # ---------- 界面搭建 ----------
    def init_ui(self):
        main = QVBoxLayout(self)
        main.setContentsMargins(14, 14, 14, 14)
        main.setSpacing(12)

        self.title_label = QLabel()
        self.title_label.setFont(FONT_TITLE)
        self.title_label.setAlignment(Qt.AlignCenter)
        main.addWidget(self.title_label)

        # 链接行：GitHub / 开源许可 / 主题切换
        link_layout = QHBoxLayout()
        link_layout.setAlignment(Qt.AlignCenter)
        link_layout.setSpacing(16)
        self.link_github = QLabel()
        self.link_github.setTextFormat(Qt.RichText)
        self.link_github.setOpenExternalLinks(True)
        self.link_github.setCursor(Qt.PointingHandCursor)
        link_layout.addWidget(self.link_github)
        self.link_license = QLabel()
        self.link_license.setTextFormat(Qt.RichText)
        self.link_license.setCursor(Qt.PointingHandCursor)
        self.link_license.linkActivated.connect(lambda _: LicenseDialog(self).exec())
        link_layout.addWidget(self.link_license)
        self.btn_theme = QPushButton()
        self.btn_theme.setFixedSize(84, 26)
        self.btn_theme.setCursor(Qt.PointingHandCursor)
        self.btn_theme.clicked.connect(self.toggle_theme)
        link_layout.addWidget(self.btn_theme)
        main.addLayout(link_layout)

        self.warn_label = QLabel(WARNING_TEXT)
        self.warn_label.setAlignment(Qt.AlignCenter)
        main.addWidget(self.warn_label, alignment=Qt.AlignCenter)

        # 行1：扫描
        self.btn_ipv4 = self.make_btn("IPv4 扫描", "#3B82F6")
        self.btn_ipv4.clicked.connect(lambda: self.start_scan(4))
        self.btn_ipv6 = self.make_btn("IPv6 扫描", "#22C55E")
        self.btn_ipv6.clicked.connect(lambda: self.start_scan(6))
        self.btn_stop = self.make_btn("停止任务", "#EF4444", enabled=False)
        self.btn_stop.clicked.connect(self.confirm_stop)
        main.addLayout(self.centered_row(self.btn_ipv4, self.btn_ipv6, self.btn_stop))

        # 行2：测速 / 导出
        self.btn_area = self.make_btn("地区测速", "#EC4899", enabled=False)
        self.btn_area.clicked.connect(self.start_region_speed)
        self.btn_full = self.make_btn("完全测速", "#F97316", enabled=False)
        self.btn_full.clicked.connect(self.start_full_speed)
        self.btn_export = self.make_btn("导出结果", "#8B5CF6", enabled=False)
        self.btn_export.clicked.connect(self.export_results)
        main.addLayout(self.centered_row(self.btn_area, self.btn_full, self.btn_export))

        # 行3：地区码 / 测速数量 / 导入CIDR
        self.input_region = self.make_edit(placeholder="输入地区码")
        self.input_region.setFixedWidth(BTN_W)
        self.input_region.textChanged.connect(self.auto_uppercase)
        self.input_speed_count = self.make_edit("10", QIntValidator(1, 99))
        cnt_widget = self.make_field("测速数量", self.input_speed_count, spacing=5, box=(BTN_W, BTN_H))
        self.btn_import = self.make_btn("导入CIDR", "#0EA5E9")
        self.btn_import.setToolTip("选择 txt 文件，自动识别 IPv4 / IPv6 段；导入后将替换对应版本的内置IP段")
        self.btn_import.clicked.connect(self.import_cidr_files)
        main.addLayout(self.centered_row(self.input_region, cnt_widget, self.btn_import))

        # 行4：线程 / 延迟 / 采样
        self.input_workers = self.make_edit("150", QIntValidator(1, 300))
        self.input_workers.setToolTip("总并发数，会平均分配给 6 个端口")
        self.input_latency = self.make_edit("220", QIntValidator(50, 999))
        self.input_v4_sample = self.make_edit("1", QIntValidator(1, 5))
        self.input_v6_sample = self.make_edit("100", QIntValidator(100, 300))
        row4 = QHBoxLayout()
        row4.addStretch()
        row4.addWidget(self.make_field("线程", self.input_workers, 30, 42))
        row4.addSpacing(5)
        row4.addWidget(self.make_field("延迟", self.input_latency, 30, 42))
        row4.addSpacing(5)
        row4.addWidget(self.make_field("V4采样", self.input_v4_sample, 50, 33))
        row4.addSpacing(5)
        row4.addWidget(self.make_field("V6采样", self.input_v6_sample, 50, 42))
        row4.addStretch()
        main.addLayout(row4)

        # 行5：自定义测速地址
        self.input_url = self.make_edit(placeholder="留空使用内置 speed.cloudflare.com")
        self.input_url.setToolTip("内置测速地址失效时填写，如 https://example.com/100mb.bin\n"
                                  "必须是托管在 Cloudflare 上的可下载文件；端口由扫描结果决定")
        main.addWidget(self.make_field("测速地址", self.input_url, spacing=6))

        # 行6：CIDR 来源状态 + 清除
        row6 = QHBoxLayout()
        self.cidr_label = QLabel()
        row6.addWidget(self.cidr_label, 1)
        self.btn_clear_cidr = self.make_btn("清除自定义", "#6B7280", size=(84, 24))
        self.btn_clear_cidr.clicked.connect(self.clear_custom_cidr)
        row6.addWidget(self.btn_clear_cidr)
        main.addLayout(row6)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setTextVisible(False)
        main.addWidget(self.progress_bar)

        status_frame = QHBoxLayout()
        self.status_label = QLabel("就绪")
        self.speed_label = QLabel("速度: 0 IP/秒")
        status_frame.addWidget(self.status_label)
        status_frame.addStretch()
        status_frame.addWidget(self.speed_label)
        main.addLayout(status_frame)

        tab_btn_layout = QHBoxLayout()
        tab_btn_layout.addStretch()
        self.tab_btn_log = QPushButton("扫描日志")
        self.tab_btn_speed = QPushButton("测速结果")
        for i, b in enumerate((self.tab_btn_log, self.tab_btn_speed)):
            b.setFixedSize(180, 32)
            b.setFont(FONT_BTN)
            b.setCheckable(True)
            b.clicked.connect(lambda _, idx=i: self.switch_tab(idx))
            tab_btn_layout.addWidget(b)
        tab_btn_layout.addStretch()
        main.addLayout(tab_btn_layout)

        self.stacked = QStackedWidget()
        self.log_tab = QWidget()
        log_layout = QVBoxLayout(self.log_tab)
        log_layout.setContentsMargins(0, 0, 0, 0)
        self.status_display = QTextEdit()
        self.status_display.setFont(FONT_STATUS)
        self.status_display.setReadOnly(True)
        log_layout.addWidget(self.status_display)
        self.stacked.addWidget(self.log_tab)

        self.speed_tab = QWidget()
        speed_tab_layout = QVBoxLayout(self.speed_tab)
        speed_tab_layout.setContentsMargins(0, 0, 0, 0)
        self.speed_scroll = QScrollArea()
        self.speed_scroll.setWidgetResizable(True)
        self.speed_container = QWidget()
        self.speed_container.setStyleSheet("background:transparent;")
        self.speed_layout = QVBoxLayout(self.speed_container)
        self.speed_layout.setContentsMargins(0, 0, 0, 0)
        self.speed_layout.setSpacing(2)
        self.speed_layout.addStretch()
        self.speed_scroll.setWidget(self.speed_container)
        speed_tab_layout.addWidget(self.speed_scroll)
        self.stacked.addWidget(self.speed_tab)
        main.addWidget(self.stacked, 1)

        self.update_cidr_label()

    # ---------- 主题 ----------
    def apply_theme(self):
        c = T()
        self.setStyleSheet(f"""
            QWidget {{ font-family: '{SYSTEM_FONT}'; background: {c['bg']}; }}
            QLabel {{ color: {c['text']}; }}
            QToolTip {{ color: {c['text']}; background: {c['input_bg']}; border: 1px solid {c['input_border']}; }}
        """)
        self.title_label.setText(
            f'<span style="color:#ff7a18;">CloudFlare</span> <span style="color:{c["text"]};">Scan</span>')
        self.link_github.setText(
            f'<a href="{GITHUB_URL}" style="color:{c["link"]};text-decoration:underline;font-size:15px;">GitHub ⭐</a>')
        self.link_license.setText(
            f'<a href="license" style="color:{c["link"]};text-decoration:underline;font-size:15px;">开源许可</a>')
        self.btn_theme.setText("深色模式" if _current_theme == "light" else "浅色模式")
        self.btn_theme.setStyleSheet(
            f"QPushButton{{background:{c['theme_btn_bg']};color:{c['theme_btn_fg']};"
            f"border:1px solid {c['input_border']};border-radius:13px;font-size:12px;}}")
        self.warn_label.setStyleSheet(
            f"color:{c['warn_fg']};background:{c['warn_bg']};font-size:14px;font-weight:bold;"
            f"padding:6px 14px;border-radius:6px;")
        for btn, color in self._btns:
            self.style_btn(btn, color)
        for e in self._edits:
            e.setStyleSheet(line_edit_style())
        small = f"color:{c['sub']};font-size:12px;padding:5px;font-family:'{SYSTEM_FONT}';"
        self.status_label.setStyleSheet(small)
        self.speed_label.setStyleSheet(small)
        self.cidr_label.setStyleSheet(f"color:{c['sub']};font-size:12px;padding:0px 5px;")
        self.progress_bar.setStyleSheet(
            f"QProgressBar{{background:{c['progress_bg']};border-radius:5px;}}"
            f"QProgressBar::chunk{{background:#22C55E;border-radius:5px;}}")
        self.status_display.setStyleSheet(f"""
            QTextEdit{{
                background:{c['panel']}; border:1px solid {c['panel_border']};
                border-radius:6px; padding:10px; color:{c['panel_text']};
                font-family:'{SYSTEM_FONT}';
            }}
            {scrollbar_style()}
        """)
        self.speed_scroll.setStyleSheet(f"""
            QScrollArea{{ background:{c['panel']}; border:none; border-radius:6px; }}
            {scrollbar_style()}
        """)
        self.switch_tab(self.stacked.currentIndex())
        if self.speed_results:
            self.render_speed_cards(self.speed_results)

    def toggle_theme(self):
        set_theme("dark" if _current_theme == "light" else "light")
        self.settings.setValue("theme", _current_theme)
        self.apply_theme()

    def switch_tab(self, idx):
        c = T()
        self.stacked.setCurrentIndex(idx)
        self.tab_btn_log.setChecked(idx == 0)
        self.tab_btn_speed.setChecked(idx == 1)
        active = f"background:{c['tab_active']};color:white;border:none;border-radius:15px;"
        inactive = f"background:{c['tab_off_bg']};color:{c['tab_off_fg']};border:none;border-radius:15px;"
        self.tab_btn_log.setStyleSheet(active if idx == 0 else inactive)
        self.tab_btn_speed.setStyleSheet(active if idx == 1 else inactive)

    # ---------- 自定义 CIDR ----------
    def update_cidr_label(self):
        v4 = f"自定义 {len(self.custom_v4)} 条" if self.custom_v4 else "内置"
        v6 = f"自定义 {len(self.custom_v6)} 条" if self.custom_v6 else "内置"
        self.cidr_label.setText(f"IP段来源 — IPv4: {v4} | IPv6: {v6}")

    @staticmethod
    def read_text_file(path: str) -> str:
        for enc in ("utf-8-sig", "gbk"):
            try:
                with open(path, "r", encoding=enc) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def import_cidr_files(self):
        if self.scanning or self.speed_testing:
            return
        files, _ = QFileDialog.getOpenFileNames(self, "选择包含CIDR的文本文件", "",
                                                "文本文件 (*.txt);;所有文件 (*)")
        if not files:
            return
        add4, add6, bad_all = [], [], []
        for path in files:
            try:
                v4, v6, bad = parse_cidr_text(self.read_text_file(path))
            except Exception as e:
                self.status_display.append(f"读取失败 {os.path.basename(path)}: {e}")
                continue
            add4 += v4
            add6 += v6
            bad_all += bad
            self.status_display.append(
                f"已读取 {os.path.basename(path)}：IPv4 {len(v4)} 条，IPv6 {len(v6)} 条，无效 {len(bad)} 条")
        if not add4 and not add6:
            CustomDialog.warning(self, "文件中没有识别到有效的 CIDR / IP 地址")
            return
        self.custom_v4 = list(dict.fromkeys(self.custom_v4 + add4))
        self.custom_v6 = list(dict.fromkeys(self.custom_v6 + add6))
        if bad_all:
            sample = ", ".join(bad_all[:5]) + (" ..." if len(bad_all) > 5 else "")
            self.status_display.append(f"已忽略无效条目 {len(bad_all)} 个: {sample}")
        self.status_display.append(
            f"自定义IP段合计：IPv4 {len(self.custom_v4)} 条，IPv6 {len(self.custom_v6)} 条"
            f"（对应版本扫描时将使用自定义段，未导入的版本仍用内置段）")
        self.update_cidr_label()

    def clear_custom_cidr(self):
        if self.scanning or self.speed_testing:
            return
        self.custom_v4, self.custom_v6 = [], []
        self.update_cidr_label()
        self.status_display.append("已清除自定义IP段，恢复使用内置IP段")

    # ---------- 事件 ----------
    def auto_uppercase(self, text):
        if text != text.upper():
            self.input_region.setText(text.upper())

    def confirm_stop(self):
        if not self.scanning and not self.speed_testing:
            return
        if CustomDialog.question(self, "确定要停止当前任务吗？"):
            self.stop_all()

    def start_scan(self, version):
        if self.scanning or self.speed_testing:
            return
        try:
            workers = int(self.input_workers.text().strip() or "150")
        except ValueError:
            workers = 150
        if workers < 1 or workers > 300:
            CustomDialog.warning(self, "并发线程数范围1-300")
            return

        v4_sample, v6_sample = 1, 100
        if version == 4:
            try:
                v4_sample = int(self.input_v4_sample.text().strip() or "1")
            except ValueError:
                v4_sample = 1
            if not 1 <= v4_sample <= 5:
                CustomDialog.warning(self, "IPv4 采样数范围 1 ~ 5 之间！")
                return
        else:
            try:
                v6_sample = int(self.input_v6_sample.text().strip() or "100")
            except ValueError:
                v6_sample = 100
            if not 100 <= v6_sample <= 300:
                CustomDialog.warning(self, "IPv6 采样数范围 100 ~ 300 之间！")
                return
        try:
            latency = max(50, int(self.input_latency.text() or "220"))
        except ValueError:
            latency = 220

        custom = self.custom_v4 if version == 4 else self.custom_v6
        builtin = CF_IPV4_CIDRS if version == 4 else CF_IPV6_CIDRS
        cidrs = list(custom) if custom else list(builtin)

        self.user_stopped = False
        self.scanning = True
        self.scan_results = []
        self.speed_results = []
        self.update_ui_state(True)
        self.clear_speed_cards()
        self.status_display.clear()
        self.status_display.append(f"正在开始IPv{version}扫描...")
        self.status_display.append(
            f"IP段来源: {'自定义 (%d 条)' % len(custom) if custom else '内置'}")
        self.status_display.append("=" * 25)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"IPv{version}扫描中...")
        self.speed_label.setText("速度: 0 IP/秒")

        worker = ScanWorker(version, cidrs, max_workers=workers, latency_threshold=latency,
                            ipv4_sample_per_subnet=v4_sample, ipv6_sample_per_cidr=v6_sample)
        worker.progress_update.connect(self.update_progress)
        worker.status_message.connect(self.update_status)
        worker.scan_completed.connect(self.scan_finished)
        worker.finished.connect(lambda: self.worker_finished("scan"))
        self.scan_worker = worker
        worker.start()

    def start_full_speed(self):
        self._start_speed(None)

    def start_region_speed(self):
        region = self.input_region.text().strip().upper()
        if not region:
            self.status_display.append("错误：请输入地区码（如SJC、SIN等）")
            return
        self._start_speed(region)

    def _start_speed(self, region: Optional[str]):
        if self.speed_testing or self.scanning:
            return
        if not self.scan_results:
            self.status_display.append("错误：请先运行扫描获取IP列表！")
            return
        try:
            cnt = int(self.input_speed_count.text().strip())
            if not 1 <= cnt <= 99:
                raise ValueError
        except ValueError:
            self.status_display.append("错误：测速数量必须在1-99之间！")
            return
        test_url = self.input_url.text().strip()
        try:
            parse_test_url(test_url)
        except ValueError:
            CustomDialog.warning(self, "测速地址格式不正确，请填写如 https://example.com/file.bin，或留空使用内置地址")
            return

        self.user_stopped = False
        self.speed_testing = True
        self.speed_results = []
        self.update_ui_state(True)
        self.clear_speed_cards()
        self.status_display.append("")
        self.progress_bar.setValue(0)
        self.status_label.setText(f"{region}地区测速中..." if region else "完全测速中...")
        self.speed_label.setText("测速进度: 准备中")
        w = SpeedTestWorker(self.scan_results, region_code=region, max_test_count=cnt, test_url=test_url)
        w.progress_update.connect(self.update_speed_progress)
        w.status_message.connect(self.update_status)
        w.speed_test_completed.connect(self.speed_test_finished)
        w.finished.connect(lambda: self.worker_finished("speed"))
        self.speed_test_worker = w
        w.start()

    def export_results(self):
        if not self.speed_results:
            self.status_display.append("错误：没有测速结果可以导出！")
            return
        fname, _ = QFileDialog.getSaveFileName(
            self, "保存测速结果", f"cfs_results_{datetime.now().strftime('%Y%m%d')}.csv", "CSV文件 (*.csv)")
        if not fname:
            return
        if not fname.endswith('.csv'):
            fname += '.csv'
        try:
            ranks: Dict[int, int] = {}
            with open(fname, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    '端口', '排名', 'IP地址', '地区码', '地区', '延迟(ms)', '下载速度(MB/s)', '测速类型'])
                writer.writeheader()
                for r in self.speed_results:
                    ranks[r['port']] = ranks.get(r['port'], 0) + 1
                    writer.writerow({
                        '端口': r['port'], '排名': ranks[r['port']], 'IP地址': r['ip'],
                        '地区码': r['iata_code'], '地区': r['chinese_name'],
                        '延迟(ms)': f"{r['latency']:.2f}", '下载速度(MB/s)': f"{r['download_speed']:.2f}",
                        '测速类型': r.get('test_type', '未知')
                    })
            self.status_display.append(f"测速结果已成功导出到: {fname}")
            self.status_label.setText(f"结果已导出到: {os.path.basename(fname)}")
            QTimer.singleShot(3000, lambda: self.status_label.setText("就绪"))
        except Exception as e:
            self.status_display.append(f"导出失败: {e}")

    def stop_all(self):
        self.user_stopped = True
        if self.scan_worker and self.scanning:
            self.scan_worker.stop()
        if self.speed_test_worker and self.speed_testing:
            self.speed_test_worker.stop()
        self.btn_stop.setEnabled(False)
        self.status_label.setText("正在停止...")

    def closeEvent(self, event):
        self.stop_all()
        for w in (self.scan_worker, self.speed_test_worker):
            if w and w.isRunning():
                w.wait(3000)
        event.accept()

    # ---------- 任务回调 ----------
    def scan_finished(self, results):
        known = [r for r in (results or []) if r.get('iata_code') and r.get('iata_code') != 'UNKNOWN']
        dropped = len(results or []) - len(known)
        self.scan_results = known
        if dropped:
            self.status_display.append(f"（{dropped} 条结果未获取到地区码，已排除）")
        self.show_scan_summary(known)

    def speed_test_finished(self, results):
        self.speed_results = results
        self.display_speed_results(results)

    def worker_finished(self, typ):
        if typ == "scan":
            self.scanning = False
        else:
            self.speed_testing = False
        if self.user_stopped:
            self.status_label.setText("已停止")
            self.status_display.append("\n任务已被用户停止")
        else:
            self.status_label.setText("扫描完成" if typ == "scan" else "测速完成")
        if not self.scanning and not self.speed_testing:
            self.update_ui_state(False)

    def update_ui_state(self, busy):
        self.btn_stop.setEnabled(busy)
        self.btn_ipv4.setEnabled(not busy)
        self.btn_ipv6.setEnabled(not busy)
        self.btn_full.setEnabled(not busy and bool(self.scan_results))
        self.btn_area.setEnabled(not busy and bool(self.scan_results))
        self.btn_export.setEnabled(not busy and bool(self.speed_results))
        self.btn_import.setEnabled(not busy)
        self.btn_clear_cidr.setEnabled(not busy)
        for e in self._edits:
            e.setEnabled(not busy)
        if not busy:
            self.progress_bar.setValue(0)

    def update_progress(self, cur, total, ok, speed):
        if total:
            self.progress_bar.setValue(int(cur / total * 100))
        self.status_label.setText(f"扫描中: {cur}/{total} ({ok}个可用)")
        self.speed_label.setText(f"速度: {speed:.1f} IP/秒")

    def update_speed_progress(self, cur, total, _):
        if total:
            self.progress_bar.setValue(int(cur / total * 100))
        self.status_label.setText(f"测速中: {cur}/{total}")
        self.speed_label.setText(f"测速进度: {cur}/{total}")

    def update_status(self, msg):
        self.status_display.append(msg)
        bar = self.status_display.verticalScrollBar()
        bar.setValue(bar.maximum())

    def show_scan_summary(self, results):
        if not results:
            self.status_display.append("\n扫描完成！未找到任何已知地区的可用IP地址。")
            return
        ip_region: Dict[str, str] = {}
        per_port = {p: 0 for p in PORTS}
        for r in results:
            ip_region[r['ip']] = f"{r['iata_code']} ({r['chinese_name']})"
            per_port[r['port']] = per_port.get(r['port'], 0) + 1
        v4 = sum(1 for ip in ip_region if ':' not in ip)
        v6 = len(ip_region) - v4
        stats: Dict[str, int] = {}
        for region in ip_region.values():
            stats[region] = stats.get(region, 0) + 1

        self.status_display.append("\n" + "=" * 25)
        self.status_display.append("扫描完成！统计信息：")
        if v4:
            self.status_display.append(f"可用IPv4地址: {v4} 个")
        if v6:
            self.status_display.append(f"可用IPv6地址: {v6} 个")
        self.status_display.append("各端口可用数量：")
        for p in PORTS:
            self.status_display.append(f"  端口 {p}: {per_port.get(p, 0)} 个")
        self.status_display.append(f"地区统计（共 {len(stats)} 个不同地区）：")
        for region, cnt in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            self.status_display.append(f"  {region}: {cnt}个IP")
        self.status_display.append("\n现在可以使用完全测速或地区测速功能。")

    # ---------- 测速结果展示 ----------
    def display_speed_results(self, results):
        if not results:
            self.status_display.append("测速完成：没有有效的测速结果（可检查网络/代理，或在“测速地址”填写自定义地址）")
            return
        self.switch_tab(1)
        self.render_speed_cards(results)
        ports = sorted({r['port'] for r in results}, key=PORTS.index)
        self.status_display.append(f"\n测速完成！共 {len(results)} 条结果，涉及端口: {', '.join(map(str, ports))}")

    def render_speed_cards(self, results):
        self.clear_speed_cards()
        current_port = None
        rank = 0
        for r in results:
            if r['port'] != current_port:
                current_port = r['port']
                rank = 0
                cnt = sum(1 for x in results if x['port'] == current_port)
                head = QLabel(f"端口 {current_port}  ·  共 {cnt} 个")
                head.setStyleSheet("color:#FBBF24;font-size:13px;font-weight:bold;"
                                   "background:transparent;padding:8px 12px 2px 12px;")
                self.speed_layout.insertWidget(self.speed_layout.count() - 1, head)
            rank += 1
            self.speed_layout.insertWidget(self.speed_layout.count() - 1, self.build_card(rank, r))

    def build_card(self, rank, r):
        card = QFrame()
        card.setStyleSheet("QFrame{background:transparent;border:none;margin:0;padding:0;}")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(10)

        num = QLabel(str(rank))
        num.setFixedWidth(20)
        num.setStyleSheet("color:white;font-size:13px;")
        layout.addWidget(num)

        info = QVBoxLayout()
        info.setSpacing(2)
        ip_label = QLabel(r['ip'])
        ip_label.setStyleSheet("color:white;font-size:13px;")
        ip_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tag_label = QLabel(f"{r['iata_code']} {r['chinese_name']}  |  端口 {r['port']}")
        tag_label.setStyleSheet("color:#7DD3FC;font-size:12px;")
        detail_label = QLabel(f"延迟: {r['latency']:.2f}ms  速度: {r['download_speed']:.2f} MB/s")
        detail_label.setStyleSheet("color:#D1D5DB;font-size:12px;")
        for w in (ip_label, tag_label, detail_label):
            info.addWidget(w)
        layout.addLayout(info, 1)

        btns = QVBoxLayout()
        btns.setSpacing(4)
        style = ("QPushButton{background:#8B5CF6;color:white;border-radius:4px;font-size:11px;}"
                 "QPushButton:hover{background:#7C3AED;}")
        b1 = QPushButton("复制IP")
        b2 = QPushButton("复制IP:端口")
        for b in (b1, b2):
            b.setFixedSize(84, 24)
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(style)
            btns.addWidget(b)
        hostport = f"[{r['ip']}]:{r['port']}" if ':' in r['ip'] else f"{r['ip']}:{r['port']}"
        b1.clicked.connect(lambda _, t=r['ip']: self.copy_text(t))
        b2.clicked.connect(lambda _, t=hostport: self.copy_text(t))
        layout.addLayout(btns)
        return card

    def clear_speed_cards(self):
        while self.speed_layout.count() > 0:
            item = self.speed_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.speed_layout.addStretch()

    def copy_text(self, text):
        QApplication.clipboard().setText(text)
        self.status_label.setText(f"已复制: {text[:27] + '...' if len(text) > 30 else text}")
        QTimer.singleShot(2000, lambda: self.status_label.setText("就绪"))


# ============================================================
# 入口
# ============================================================
def find_icon_file():
    candidates = [os.path.dirname(os.path.abspath(__file__))]
    if hasattr(sys, '_MEIPASS'):
        candidates.append(sys._MEIPASS)
    for base in candidates:
        for name in ("cfs.ico", "cfs.icns"):
            path = os.path.join(base, name)
            if os.path.exists(path):
                return path
    return None


if __name__ == "__main__":
    if platform.system() == "Darwin":
        os.environ['QT_MAC_WANTS_LAYER'] = '1'
    app = QApplication(sys.argv)
    icon = find_icon_file()
    if icon:
        app.setWindowIcon(QIcon(icon))
    win = CloudflareScanUI()
    if icon:
        win.setWindowIcon(QIcon(icon))
    win.show()
    sys.exit(app.exec())
