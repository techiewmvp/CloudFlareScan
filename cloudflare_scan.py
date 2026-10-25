# -*- coding: utf-8 -*-
"""
CloudFlare Scan

Original work  Copyright (c) 2026 xiaolin-007   (MIT License)
Modifications  Copyright (c) 2026 techiewmvp    (MIT License)

Permission notice: see the LICENSE file shipped with this program
(also viewable in the app via the "开源许可" link). The above copyright
notice and the permission notice must be kept in all copies or substantial
portions of the Software.

运行要求：Python 3.11+（使用 StreamWriter.start_tls），仅依赖 PySide6。
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
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit, QProgressBar,
    QVBoxLayout, QHBoxLayout, QTextEdit, QFileDialog, QScrollArea, QFrame,
    QStackedWidget, QDialog, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSettings
from PySide6.QtGui import QFont, QIcon, QIntValidator


# ============================================================
# 应用信息 / 可调参数
# ============================================================
APP_NAME = "CloudFlare Scan"
APP_VERSION = "V5.2"
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

PORTS = [443, 2053, 2083, 2087, 2096, 8443]       # 固定扫描的全部端口
DEFAULT_TEST_HOST = TRACE_HOST = "speed.cloudflare.com"
DEFAULT_TEST_PATH = "/__down?bytes=50000000"

# 优选（真连接延迟）
WORKERS_MIN, WORKERS_MAX, WORKERS_DEFAULT = 4, 32, 16   # 单端口线程数；总并发 = 该值 × 端口数
TCP_TIMEOUT, TLS_TIMEOUT, HTTP_TIMEOUT = 1.0, 2.0, 2.0  # 秒
PING_TIMES = 2          # 同一条 TLS 连接上的 HTTP 往返采样次数，取最小
DEAD_AFTER = 3          # 同一 IP 累计 N 个端口 TCP 层失败且无任何成功 → 判定不可达，跳过其余端口
MAX_SCAN_IPS = 50000    # 单次最多测试的 IP 数

# 测速
DOWNLOAD_SECONDS = 2    # 有效下载计时窗口（从收到首个正文数据开始计）
FIRST_BYTE_TIMEOUT = 3  # 发出请求后等待首个正文数据的最长时间
CANDIDATE_FACTOR = 3    # 候选数 = 测速数量 × 该倍数（按延迟从低到高取），最终按速度取前 N

SYSTEM_FONT = {"Windows": "Microsoft YaHei", "Darwin": "PingFang SC"}.get(platform.system(), "DejaVu Sans")
FONT_TITLE = QFont(SYSTEM_FONT, 28)
FONT_TITLE.setBold(True)
FONT_BTN = QFont(SYSTEM_FONT, 11)
FONT_STATUS = QFont(SYSTEM_FONT, 10)
BTN_W, BTN_H, SPACING = 120, 32, 8


# ============================================================
# 主题
# ============================================================
THEMES = {
    "light": dict(
        bg="#F9FAFB", text="#111827", sub="#6B7280", input_bg="#FFFFFF", input_border="#D1D5DB",
        panel="#0B3C5D", panel_text="#ECF0F1", panel_border="#0F4C75",
        sb_track="#0F4C75", sb_handle="#1E90FF", sb_hover="#00BFFF",
        track="#E5E7EB", tab_active="#0B4F7A", tab_off_bg="#E5E7EB", link="#2563EB",
        warn_fg="#DC2626", warn_bg="#FEE2E2"),
    "dark": dict(
        bg="#111827", text="#F3F4F6", sub="#9CA3AF", input_bg="#1F2937", input_border="#374151",
        panel="#0B1220", panel_text="#E5E7EB", panel_border="#1F2937",
        sb_track="#1F2937", sb_handle="#3B82F6", sb_hover="#60A5FA",
        track="#374151", tab_active="#2563EB", tab_off_bg="#1F2937", link="#60A5FA",
        warn_fg="#FCA5A5", warn_bg="#7F1D1D"),
}
_theme = "light"


def T() -> Dict[str, str]:
    return THEMES[_theme]


def line_edit_style() -> str:
    c = T()
    return (f"QLineEdit{{background:{c['input_bg']};border:1px solid {c['input_border']};border-radius:6px;"
            f"padding:0px 5px;font-family:'{SYSTEM_FONT}';color:{c['text']};}}"
            f"QLineEdit:focus{{border-color:#F97316;}}QLineEdit:disabled{{color:{c['sub']};}}")


def scrollbar_style() -> str:
    c = T()
    return (f"QScrollBar:vertical{{background:{c['sb_track']};width:8px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical{{background:{c['sb_handle']};min-height:20px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical:hover{{background:{c['sb_hover']};}}"
            f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0px;}}"
            f"QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{{background:none;}}")


# ============================================================
# 内置数据
# ============================================================
CF_IPV4_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/17", "172.64.128.0/18", "172.64.192.0/19", "172.64.224.0/22",
    "172.64.229.0/24", "172.64.230.0/23", "172.64.232.0/21", "172.64.240.0/21",
    "172.64.248.0/21", "172.65.0.0/16", "172.66.0.0/16", "172.67.0.0/16",
    "131.0.72.0/22",
]

# 与原列表完全等价，用规则生成以缩减体量
CF_IPV6_CIDRS = (
    ["2400:cb00:2049::/48", "2400:cb00:f00e::/48", "2606:4700::/32"]
    + [f"2606:4700:{h}::/48" for h in
       "10 130 5a 52 57 a0 a1 a8 a9 a b c d0 d1 d e0 e1 e2 e3 e4 e5 e6 e7 e f1 f2 f3 f4 f5 f".split()]
    + [f"2606:4700:30{i:02d}::/48" for i in range(37)]          # 3000 ~ 3036
    + ["2803:f800:50::/48", "2803:f800:51::/48"]
    + [f"2a06:98c1:31{i:02x}::/48" for i in range(16)]           # 3100 ~ 310f
    + [f"2a06:98c1:{h}::/48" for h in "3120 3121 3122 3123 3200 50 51 54 58".split()]
)

_CITIES = """
香港:HKG 台北:TPE 高雄:KHH 澳门:MFM 东京:NRT,HND 大阪:KIX 名古屋:NGO 福冈:FUK 札幌:CTS 冲绳:OKA
首尔:ICN,GMP 釜山:PUS 新加坡:SIN 曼谷:BKK,DMK 吉隆坡:KUL 普吉岛:HKT 马尼拉:MNL 宿务:CEB
河内:HAN 胡志明市:SGN 雅加达:JKT 巴厘岛:DPS 德里:DEL 孟买:BOM 金奈:MAA 迪拜:DXB 阿布扎比:AUH
圣何塞:SJC 洛杉矶:LAX 旧金山:SFO 西雅图:SEA 波特兰:PDX 拉斯维加斯:LAS 菲尼克斯:PHX 丹佛:DEN
达拉斯:DFW 休斯顿:IAH 芝加哥:ORD 明尼阿波利斯:MSP 亚特兰大:ATL 迈阿密:MIA 奥兰多:MCO
纽约:JFK,EWR,LGA 波士顿:BOS 费城:PHL 华盛顿:IAD 多伦多:YYZ 温哥华:YVR 蒙特利尔:YUL
伦敦:LHR,LGW,STN 巴黎:CDG,ORY 法兰克福:FRA 慕尼黑:MUC 柏林:TXL 阿姆斯特丹:AMS 埃因霍温:EIN
马德里:MAD 巴塞罗那:BCN 罗马:FCO 米兰:MXP,LIN 苏黎世:ZRH 日内瓦:GVA 维也纳:VIE 布拉格:PRG
华沙:WAW 克拉科夫:KRK 赫尔辛基:HEL 奥斯陆:OSL 斯德哥尔摩:ARN 哥本哈根:CPH
悉尼:SYD 墨尔本:MEL 布里斯班:BNE 珀斯:PER 阿德莱德:ADL 奥克兰:AKL 惠灵顿:WLG
圣保罗:GRU 里约热内卢:GIG 布宜诺斯艾利斯:EZE 圣地亚哥:SCL 利马:LIM 波哥大:BOG
约翰内斯堡:JNB 开普敦:CPT 开罗:CAI
"""
AIRPORT_CODES = {code: item.split(":")[0]
                 for item in _CITIES.split() for code in item.split(":")[1].split(",")}


# ============================================================
# 通用工具
# ============================================================
INSECURE_CTX = ssl.create_default_context()
INSECURE_CTX.check_hostname = False
INSECURE_CTX.verify_mode = ssl.CERT_NONE

TRACE_REQ = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\nUser-Agent: Mozilla/5.0\r\n"
             f"Accept: */*\r\nConnection: keep-alive\r\n\r\n").encode()


def parse_test_url(text: str) -> Tuple[str, str]:
    """测速地址 → (host, path)。留空 = 内置地址；URL 中的端口会被忽略（端口由扫描结果决定）。"""
    text = (text or "").strip()
    if not text:
        return DEFAULT_TEST_HOST, DEFAULT_TEST_PATH
    u = urlparse(text if "://" in text else "https://" + text)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("测速地址格式不正确")
    return u.hostname, (u.path or "/") + (f"?{u.query}" if u.query else "")


def parse_cidr_text(text: str) -> Tuple[List[str], List[str], List[str]]:
    """解析 txt，返回 (v4, v6, 无效条目)。支持换行/逗号/空格/分号分隔，# 为注释，单个 IP 视为 /32 或 /128。"""
    v4, v6, bad = [], [], []
    for raw in text.splitlines():
        for token in re.split(r"[,\s;]+", raw.split("#", 1)[0].strip()):
            if not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                bad.append(token)
                continue
            (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6, bad


async def read_http(reader: asyncio.StreamReader):
    """读取一个完整 HTTP/1.1 响应（支持 Content-Length / chunked），返回 (status, headers, body)。"""
    head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
    status = int(head[0].split()[1])
    hdr = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in head[1:] if ":" in l)}
    body = b""
    if "content-length" in hdr:
        body = await reader.readexactly(int(hdr["content-length"]))
    elif "chunked" in hdr.get("transfer-encoding", "").lower():
        while True:
            size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await reader.readline()
                break
            body += await reader.readexactly(size)
            await reader.readline()
    return status, hdr, body


def parse_colo(hdr: Dict[str, str], body: bytes) -> Optional[str]:
    m = re.search(rb"^colo=([A-Za-z]{3})\s*$", body, re.M)
    if m:
        return m.group(1).decode().upper()
    ray = hdr.get("cf-ray", "")
    return ray.rsplit("-", 1)[-1].upper() if re.fullmatch(r".+-[A-Za-z]{3}", ray) else None


# ============================================================
# 优选扫描：真连接延迟（TCP + TLS + HTTP 往返）+ 地区码一次拿到
# ============================================================
class ScanWorker(QThread):
    progress_update = Signal(int, int, int, float)
    status_message = Signal(str)
    scan_completed = Signal(list)

    def __init__(self, version: int, cidrs: List[str], per_port: int, latency: int, sample: int):
        super().__init__()
        self.version, self.cidrs, self.per_port = version, cidrs, per_port
        self.latency, self.sample = latency, sample
        self.running = True

    def stop(self):
        self.running = False

    # ---- IP 生成 ----
    def _sample_v4(self, net) -> List[str]:
        out = []
        for sub in ([net] if net.prefixlen >= 24 else net.subnets(new_prefix=24)):
            hosts = list(sub.hosts()) or list(sub)
            out += [str(ip) for ip in random.sample(hosts, min(self.sample, len(hosts)))]
        return out

    def _sample_v6(self, net) -> List[str]:
        if net.num_addresses <= 2:
            return [str(net.network_address)]
        lo, hi = int(net.network_address) + 1, int(net.broadcast_address) - 1
        k = min(self.sample, net.num_addresses - 2)
        return [str(ipaddress.IPv6Address(random.randint(lo, hi))) for _ in range(k)]

    def generate_ips(self) -> List[str]:
        ips: List[str] = []
        for cidr in self.cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            ips += self._sample_v4(net) if self.version == 4 else self._sample_v6(net)
        ips = list(dict.fromkeys(ips))
        if len(ips) > MAX_SCAN_IPS:
            self.status_message.emit(f"生成的IP过多({len(ips)})，已随机截取 {MAX_SCAN_IPS} 个")
            ips = random.sample(ips, MAX_SCAN_IPS)
        return ips

    # ---- 单个 (ip, port) 探测 ----
    async def probe(self, ip: str, port: int):
        """返回 (结果 dict 或 None, 是否 TCP 层失败)。
        真连接延迟 = TLS 握手完成后，在同一连接上发送 /cdn-cgi/trace 请求到收到完整响应的耗时，取 PING_TIMES 次最小值；
        同一次响应里直接解析 colo，不再单独查询地区码。"""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), TCP_TIMEOUT)
        except Exception:
            return None, True
        try:
            await asyncio.wait_for(writer.start_tls(INSECURE_CTX, server_hostname=TRACE_HOST), TLS_TIMEOUT)
            lats, colo = [], None
            for _ in range(PING_TIMES):
                t0 = time.perf_counter()
                writer.write(TRACE_REQ)
                status, hdr, body = await asyncio.wait_for(read_http(reader), HTTP_TIMEOUT)
                lats.append((time.perf_counter() - t0) * 1000)
                colo = colo or parse_colo(hdr, body)
                if status != 200 or not colo or lats[0] >= self.latency:
                    return None, False            # 首次已超阈值就不再浪费第二次往返
            return {"ip": ip, "port": port, "latency": round(min(lats), 2), "iata_code": colo,
                    "chinese_name": AIRPORT_CODES.get(colo, colo)}, False
        except Exception:
            return None, False
        finally:
            writer.transport.abort()              # RST 直接释放，避免在本地路由/NAT 表里堆积 TIME_WAIT

    # ---- 全端口共享任务队列 ----
    async def scan(self, ips: List[str]) -> List[dict]:
        """所有 (ip, port) 打乱后进入同一个队列，总并发 = 单端口线程数 × 端口数。
        线程不绑定端口：谁空闲谁取下一个任务，不会出现某端口先做完、其线程闲置的情况；
        打乱顺序还能把同一 IP / 同一端口的连接分散开，降低对路由与对端的瞬时压力。"""
        pairs = [(ip, p) for ip in ips for p in PORTS]
        random.shuffle(pairs)
        queue, total = deque(pairs), len(pairs)
        results: List[dict] = []
        alive, bad = set(), {}
        done, last, t0 = 0, 0.0, time.time()

        def report(force=False):
            nonlocal last
            now = time.time()
            if force or now - last >= 0.5:
                self.progress_update.emit(done, total, len(results), done / max(now - t0, 1e-6))
                last = now

        async def worker():
            nonlocal done
            while self.running and queue:
                ip, port = queue.popleft()
                if bad.get(ip, 0) >= DEAD_AFTER and ip not in alive:
                    done += 1                     # 该 IP 已判定不可达，跳过剩余端口
                    report()
                    continue
                res, tcp_fail = await self.probe(ip, port)
                if res:
                    results.append(res)
                    alive.add(ip)
                elif tcp_fail:
                    bad[ip] = bad.get(ip, 0) + 1
                done += 1
                report()

        await asyncio.gather(*(worker() for _ in range(self.per_port * len(PORTS))))
        report(True)
        return sorted(results, key=lambda r: r["latency"])

    def run(self):
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        try:
            self.status_message.emit(f"正在从 IPv{self.version} 地址段生成随机IP...（共 {len(self.cidrs)} 个CIDR）")
            ips = self.generate_ips()
            if not ips:
                self.status_message.emit(f"错误: 未能生成IPv{self.version} IP列表")
                return
            self.status_message.emit(
                f"已生成 {len(ips)} 个IP × {len(PORTS)} 个端口，共享任务队列，并发 {self.per_port * len(PORTS)}"
                f"（单端口 {self.per_port}）")
            self.status_message.emit("端口: " + " / ".join(map(str, PORTS)))
            results = asyncio.run(self.scan(ips))
            if self.running:
                self.scan_completed.emit(results)
        except Exception as e:
            self.status_message.emit(f"IPv{self.version}扫描过程中出现错误: {e}")


# ============================================================
# 测速：所有端口的优选结果合并成一个池，统一测速后取前 N
# ============================================================
class SpeedTestWorker(QThread):
    progress_update = Signal(int, int)
    status_message = Signal(str)
    speed_test_completed = Signal(list)

    def __init__(self, results: List[dict], region: Optional[str], top_n: int, test_url: str = ""):
        super().__init__()
        self.results, self.region, self.top_n = results, region, top_n
        self.host, self.path = parse_test_url(test_url)
        self.running = True

    def stop(self):
        self.running = False

    def download_speed(self, ip: str, port: int) -> float:
        req = (f"GET {self.path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: Mozilla/5.0\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=3)
            sock = INSECURE_CTX.wrap_socket(sock, server_hostname=self.host)
            sock.sendall(req)
            t_send, head, body, t0 = time.time(), b"", 0, None
            while True:
                now = time.time()
                if t0 is None and now - t_send > FIRST_BYTE_TIMEOUT:
                    break                                   # 迟迟没有正文数据
                if t0 is not None and now - t0 >= DOWNLOAD_SECONDS:
                    break                                   # 计时窗口结束
                try:
                    buf = sock.recv(65536)
                except socket.timeout:
                    break
                if not buf:
                    break
                if head is not None:                        # 仍在读响应头
                    head += buf
                    if b"\r\n\r\n" not in head:
                        continue
                    h, rest = head.split(b"\r\n\r\n", 1)
                    status = int(h.split(b" ", 2)[1])
                    if status not in (200, 206):
                        raise RuntimeError(f"HTTP {status}")
                    head = None
                    if not rest:
                        continue                            # 下一个数据块才是首个正文
                if t0 is None:
                    t0 = time.time()                        # 首个正文数据到达：开始计时，该块本身不计入字节数
                else:
                    body += len(buf)
            if t0 is None:
                raise RuntimeError("未收到正文数据")
            return round(body / 1048576 / max(time.time() - t0, 0.1), 2)
        except Exception as e:
            self.status_message.emit(f"  测速失败 {ip}:{port} - {e}")
            return 0.0
        finally:
            if sock:
                sock.close()

    def run(self):
        out: List[dict] = []
        try:
            kind = f"地区测速 {self.region}" if self.region else "完全测速"
            pool = [r for r in self.results if not self.region or r["iata_code"] == self.region]
            if self.region:
                self.status_message.emit(f"开始地区测速：{self.region} ({AIRPORT_CODES.get(self.region, '未知地区')})")
            if not pool:
                self.status_message.emit("没有找到可用的IP进行测速")
                return
            # 全端口合并：按真连接延迟取最低的 N×倍数 个候选，统一测速后按速度取前 N
            cands = sorted(pool, key=lambda r: r["latency"])[: self.top_n * CANDIDATE_FACTOR]
            self.status_message.emit(f"测速地址: {self.host}{self.path[:40]}")
            self.status_message.emit(f"全端口合并 {len(pool)} 个结果，取延迟最低的 {len(cands)} 个候选，最终保留速度前 {self.top_n}")
            for i, r in enumerate(cands, 1):
                if not self.running:
                    break
                self.status_message.emit(f"[{i}/{len(cands)}] 正在测速 {r['ip']}:{r['port']}")
                speed = self.download_speed(r["ip"], r["port"])
                self.progress_update.emit(i, len(cands))
                if speed > 0:
                    out.append({**r, "download_speed": speed, "test_type": kind})
                    self.status_message.emit(f"  {speed} MB/s · {r['iata_code']} {r['chinese_name']}")
            out = sorted(out, key=lambda r: r["download_speed"], reverse=True)[: self.top_n]
            self.status_message.emit(f"测速完成！有效 {len(out)} 条结果")
        except Exception as e:
            self.status_message.emit(f"测速过程中出现错误: {e}")
        finally:
            self.speed_test_completed.emit(out)


# ============================================================
# 对话框
# ============================================================
def show_msg(parent, text: str, confirm=False) -> bool:
    """提示框；confirm=True 时带“取消”按钮，返回是否点了“确定”。"""
    box = QMessageBox(QMessageBox.Question if confirm else QMessageBox.Warning,
                      APP_NAME, text, QMessageBox.NoButton, parent)
    ok = box.addButton("确定", QMessageBox.AcceptRole)
    if confirm:
        box.addButton("取消", QMessageBox.RejectRole)
    box.exec()
    return box.clickedButton() is ok


class LicenseDialog(QDialog):
    """显示 MIT 许可全文（发布 exe 时需随附版权声明与许可声明）。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        c = T()
        self.setWindowTitle("开源许可")
        self.resize(470, 440)
        lay = QVBoxLayout(self)
        te = QTextEdit()
        te.setReadOnly(True)
        te.setPlainText(LICENSE_TEXT)
        te.setStyleSheet(
            f"QTextEdit{{background:{c['input_bg']};color:{c['text']};border:1px solid {c['input_border']};"
            f"border-radius:6px;padding:8px;font-family:Consolas,'Courier New',monospace;font-size:12px;}}"
            + scrollbar_style())
        btn = QPushButton("关闭")
        btn.setFixedSize(BTN_W, BTN_H)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet("QPushButton{background:#F97316;color:white;border-radius:6px;}"
                          "QPushButton:hover{background:#EA580C;}")
        btn.clicked.connect(self.accept)
        lay.addWidget(te)
        lay.addWidget(btn, alignment=Qt.AlignCenter)


# ============================================================
# 主窗口
# ============================================================
class CloudflareScanUI(QWidget):
    def __init__(self):
        super().__init__()
        global _theme
        self.settings = QSettings("CloudFlareScan", "CloudFlareScan")
        saved = str(self.settings.value("theme", "light"))
        _theme = saved if saved in THEMES else "light"

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(440, 830)
        self.setMinimumSize(430, 700)

        self.scan_worker = self.speed_test_worker = None
        self.scanning = self.speed_testing = self.user_stopped = False
        self.scan_results: List[dict] = []
        self.speed_results: List[dict] = []
        self.custom_v4: List[str] = []
        self.custom_v6: List[str] = []
        self._btns, self._edits = [], []
        self.init_ui()
        self.apply_theme()

    # ---------- 控件工厂 ----------
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
        e.setPlaceholderText(placeholder)
        if validator:
            e.setValidator(validator)
        self._edits.append(e)
        return e

    @staticmethod
    def make_field(label, edit, label_w=None, edit_w=None, spacing=3, box=None):
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
        lay.addWidget(edit, 0 if edit_w else 1)
        return w

    @staticmethod
    def centered_row(*widgets, spacing=SPACING):
        row = QHBoxLayout()
        row.addStretch()
        for i, w in enumerate(widgets):
            if i:
                row.addSpacing(spacing)
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
        links = QHBoxLayout()
        links.setAlignment(Qt.AlignCenter)
        links.setSpacing(16)
        self.link_github, self.link_license = QLabel(), QLabel()
        for lbl in (self.link_github, self.link_license):
            lbl.setTextFormat(Qt.RichText)
            lbl.setCursor(Qt.PointingHandCursor)
            links.addWidget(lbl)
        self.link_github.setOpenExternalLinks(True)
        self.link_license.linkActivated.connect(lambda _: LicenseDialog(self).exec())
        self.btn_theme = QPushButton()
        self.btn_theme.setFixedSize(84, 26)
        self.btn_theme.setCursor(Qt.PointingHandCursor)
        self.btn_theme.clicked.connect(self.toggle_theme)
        links.addWidget(self.btn_theme)
        main.addLayout(links)

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
        self.btn_full.clicked.connect(lambda: self._start_speed(None))
        self.btn_export = self.make_btn("导出结果", "#8B5CF6", enabled=False)
        self.btn_export.clicked.connect(self.export_results)
        main.addLayout(self.centered_row(self.btn_area, self.btn_full, self.btn_export))

        # 行3：地区码 / 测速数量 / 导入CIDR
        self.input_region = self.make_edit(placeholder="输入地区码")
        self.input_region.setFixedWidth(BTN_W)
        self.input_region.textChanged.connect(
            lambda t: t != t.upper() and self.input_region.setText(t.upper()))
        self.input_speed_count = self.make_edit("10", QIntValidator(1, 99))
        self.input_speed_count.setToolTip(f"最终保留的IP数量；实际从全端口中延迟最低的 N×{CANDIDATE_FACTOR} 个候选里测速后取前 N")
        self.btn_import = self.make_btn("导入CIDR", "#0EA5E9")
        self.btn_import.setToolTip("选择 txt 文件，自动识别 IPv4 / IPv6 段；导入后将替换对应版本的内置IP段")
        self.btn_import.clicked.connect(self.import_cidr_files)
        main.addLayout(self.centered_row(
            self.input_region, self.make_field("测速数量", self.input_speed_count, spacing=5, box=(BTN_W, BTN_H)),
            self.btn_import))

        # 行4：线程 / 延迟 / 采样
        self.input_workers = self.make_edit(str(WORKERS_DEFAULT), QIntValidator(WORKERS_MIN, WORKERS_MAX))
        self.input_workers.setToolTip(f"每个端口的并发线程数（{WORKERS_MIN}-{WORKERS_MAX}），总并发 = 该值 × {len(PORTS)}")
        self.input_latency = self.make_edit("220", QIntValidator(50, 999))
        self.input_latency.setToolTip("真连接延迟阈值（ms）：TLS 握手后一次 HTTPS 请求往返")
        self.input_v4_sample = self.make_edit("1", QIntValidator(1, 5))
        self.input_v6_sample = self.make_edit("100", QIntValidator(100, 300))
        main.addLayout(self.centered_row(
            self.make_field("端口线程", self.input_workers, 58, 36),
            self.make_field("延迟", self.input_latency, 30, 42),
            self.make_field("V4采样", self.input_v4_sample, 50, 33),
            self.make_field("V6采样", self.input_v6_sample, 50, 42), spacing=5))

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

        status = QHBoxLayout()
        self.status_label, self.speed_label = QLabel("就绪"), QLabel("速度: 0 IP/秒")
        status.addWidget(self.status_label)
        status.addStretch()
        status.addWidget(self.speed_label)
        main.addLayout(status)

        tabs = QHBoxLayout()
        tabs.addStretch()
        self.tab_btns = [QPushButton("扫描日志"), QPushButton("测速结果")]
        for i, b in enumerate(self.tab_btns):
            b.setFixedSize(180, 32)
            b.setFont(FONT_BTN)
            b.clicked.connect(lambda _, idx=i: self.switch_tab(idx))
            tabs.addWidget(b)
        tabs.addStretch()
        main.addLayout(tabs)

        self.stacked = QStackedWidget()
        self.status_display = QTextEdit()
        self.status_display.setFont(FONT_STATUS)
        self.status_display.setReadOnly(True)
        self.stacked.addWidget(self.status_display)

        self.speed_scroll = QScrollArea()
        self.speed_scroll.setWidgetResizable(True)
        container = QWidget()
        container.setStyleSheet("background:transparent;")
        self.speed_layout = QVBoxLayout(container)
        self.speed_layout.setContentsMargins(0, 0, 0, 0)
        self.speed_layout.setSpacing(2)
        self.speed_layout.addStretch()
        self.speed_scroll.setWidget(container)
        self.stacked.addWidget(self.speed_scroll)
        main.addWidget(self.stacked, 1)

        self.update_cidr_label()

    # ---------- 主题 ----------
    def apply_theme(self):
        c = T()
        self.setStyleSheet(
            f"QWidget{{font-family:'{SYSTEM_FONT}';background:{c['bg']};}}"
            f"QLabel{{color:{c['text']};}}"
            f"QToolTip{{color:{c['text']};background:{c['input_bg']};border:1px solid {c['input_border']};}}")
        self.title_label.setText(
            f'<span style="color:#ff7a18;">CloudFlare</span> <span style="color:{c["text"]};">Scan</span>')
        link = f'style="color:{c["link"]};text-decoration:underline;font-size:15px;"'
        self.link_github.setText(f'<a href="{GITHUB_URL}" {link}>GitHub ⭐</a>')
        self.link_license.setText(f'<a href="license" {link}>开源许可</a>')
        self.btn_theme.setText("深色模式" if _theme == "light" else "浅色模式")
        self.btn_theme.setStyleSheet(
            f"QPushButton{{background:{c['input_bg']};color:{c['text']};"
            f"border:1px solid {c['input_border']};border-radius:13px;font-size:12px;}}")
        self.warn_label.setStyleSheet(
            f"color:{c['warn_fg']};background:{c['warn_bg']};font-size:14px;font-weight:bold;"
            f"padding:6px 14px;border-radius:6px;")
        for btn, color in self._btns:
            btn.setStyleSheet(
                f"QPushButton{{background:{color};color:white;border-radius:6px;font-family:'{SYSTEM_FONT}';}}"
                f"QPushButton:disabled{{background:{c['track']};color:{c['sub']};}}")
        for e in self._edits:
            e.setStyleSheet(line_edit_style())
        small = f"color:{c['sub']};font-size:12px;padding:5px;"
        self.status_label.setStyleSheet(small)
        self.speed_label.setStyleSheet(small)
        self.cidr_label.setStyleSheet(f"color:{c['sub']};font-size:12px;padding:0px 5px;")
        self.progress_bar.setStyleSheet(
            f"QProgressBar{{background:{c['track']};border-radius:5px;}}"
            f"QProgressBar::chunk{{background:#22C55E;border-radius:5px;}}")
        self.status_display.setStyleSheet(
            f"QTextEdit{{background:{c['panel']};border:1px solid {c['panel_border']};border-radius:6px;"
            f"padding:10px;color:{c['panel_text']};}}" + scrollbar_style())
        self.speed_scroll.setStyleSheet(
            f"QScrollArea{{background:{c['panel']};border:none;border-radius:6px;}}" + scrollbar_style())
        self.switch_tab(self.stacked.currentIndex())
        if self.speed_results:
            self.render_speed_cards(self.speed_results)

    def toggle_theme(self):
        global _theme
        _theme = "dark" if _theme == "light" else "light"
        self.settings.setValue("theme", _theme)
        self.apply_theme()

    def switch_tab(self, idx):
        c = T()
        self.stacked.setCurrentIndex(idx)
        for i, b in enumerate(self.tab_btns):
            bg, fg = (c['tab_active'], "white") if i == idx else (c['tab_off_bg'], c['sub'])
            b.setStyleSheet(f"background:{bg};color:{fg};border:none;border-radius:15px;")

    # ---------- 自定义 CIDR ----------
    def update_cidr_label(self):
        v4 = f"自定义 {len(self.custom_v4)} 条" if self.custom_v4 else "内置"
        v6 = f"自定义 {len(self.custom_v6)} 条" if self.custom_v6 else "内置"
        self.cidr_label.setText(f"IP段来源 — IPv4: {v4} | IPv6: {v6}")

    @staticmethod
    def read_text_file(path: str) -> str:
        data = open(path, "rb").read()
        for enc in ("utf-8-sig", "gbk"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                pass
        return data.decode("utf-8", errors="ignore")

    def import_cidr_files(self):
        if self.scanning or self.speed_testing:
            return
        files, _ = QFileDialog.getOpenFileNames(self, "选择包含CIDR的文本文件", "", "文本文件 (*.txt);;所有文件 (*)")
        add4, add6, bad_all = [], [], []
        for path in files:
            try:
                v4, v6, bad = parse_cidr_text(self.read_text_file(path))
            except Exception as e:
                self.status_display.append(f"读取失败 {os.path.basename(path)}: {e}")
                continue
            add4, add6, bad_all = add4 + v4, add6 + v6, bad_all + bad
            self.status_display.append(
                f"已读取 {os.path.basename(path)}：IPv4 {len(v4)} 条，IPv6 {len(v6)} 条，无效 {len(bad)} 条")
        if not files:
            return
        if not add4 and not add6:
            show_msg(self, "文件中没有识别到有效的 CIDR / IP 地址")
            return
        self.custom_v4 = list(dict.fromkeys(self.custom_v4 + add4))
        self.custom_v6 = list(dict.fromkeys(self.custom_v6 + add6))
        if bad_all:
            self.status_display.append(
                f"已忽略无效条目 {len(bad_all)} 个: {', '.join(bad_all[:5])}{' ...' if len(bad_all) > 5 else ''}")
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

    # ---------- 任务控制 ----------
    def confirm_stop(self):
        if (self.scanning or self.speed_testing) and show_msg(self, "确定要停止当前任务吗？", confirm=True):
            self.stop_all()

    def stop_all(self):
        self.user_stopped = True
        for w in (self.scan_worker, self.speed_test_worker):
            if w and w.isRunning():
                w.stop()
        self.btn_stop.setEnabled(False)
        self.status_label.setText("正在停止...")

    def closeEvent(self, event):
        self.stop_all()
        for w in (self.scan_worker, self.speed_test_worker):
            if w and w.isRunning():
                w.wait(3000)
        event.accept()

    def read_int(self, edit, default, lo, hi, name) -> Optional[int]:
        try:
            v = int(edit.text().strip() or default)
        except ValueError:
            v = default
        if not lo <= v <= hi:
            show_msg(self, f"{name}范围 {lo} ~ {hi}")
            return None
        return v

    def begin_task(self, scan: bool, status: str):
        self.user_stopped = False
        self.scanning, self.speed_testing = scan, not scan
        self.speed_results = []
        if scan:
            self.scan_results = []
            self.status_display.clear()
        self.update_ui_state(True)
        self.clear_speed_cards()
        self.progress_bar.setValue(0)
        self.status_label.setText(status)

    def start_scan(self, version):
        if self.scanning or self.speed_testing:
            return
        per_port = self.read_int(self.input_workers, WORKERS_DEFAULT, WORKERS_MIN, WORKERS_MAX, "单端口线程数")
        sample = (self.read_int(self.input_v4_sample, 1, 1, 5, "IPv4 采样数") if version == 4
                  else self.read_int(self.input_v6_sample, 100, 100, 300, "IPv6 采样数"))
        latency = self.read_int(self.input_latency, 220, 50, 999, "延迟阈值")
        if None in (per_port, sample, latency):
            return
        custom = self.custom_v4 if version == 4 else self.custom_v6
        cidrs = list(custom or (CF_IPV4_CIDRS if version == 4 else CF_IPV6_CIDRS))

        self.begin_task(True, f"IPv{version}扫描中...")
        self.status_display.append(f"正在开始IPv{version}扫描...")
        self.status_display.append(f"IP段来源: {f'自定义 ({len(custom)} 条)' if custom else '内置'}")
        self.status_display.append("=" * 25)
        self.speed_label.setText("速度: 0 IP/秒")

        w = ScanWorker(version, cidrs, per_port, latency, sample)
        w.progress_update.connect(self.update_progress)
        w.status_message.connect(self.update_status)
        w.scan_completed.connect(self.scan_finished)
        w.finished.connect(lambda: self.worker_finished("scan"))
        self.scan_worker = w
        w.start()

    def start_region_speed(self):
        region = self.input_region.text().strip().upper()
        if region:
            self._start_speed(region)
        else:
            self.status_display.append("错误：请输入地区码（如SJC、SIN等）")

    def _start_speed(self, region: Optional[str]):
        if self.speed_testing or self.scanning:
            return
        if not self.scan_results:
            self.status_display.append("错误：请先运行扫描获取IP列表！")
            return
        cnt = self.read_int(self.input_speed_count, 10, 1, 99, "测速数量")
        if cnt is None:
            return
        url = self.input_url.text().strip()
        try:
            parse_test_url(url)
        except ValueError:
            show_msg(self, "测速地址格式不正确，请填写如 https://example.com/file.bin，或留空使用内置地址")
            return

        self.begin_task(False, f"{region}地区测速中..." if region else "完全测速中...")
        self.status_display.append("")
        self.speed_label.setText("测速进度: 准备中")
        w = SpeedTestWorker(self.scan_results, region, cnt, url)
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
            self, "保存测速结果", f"cfs_results_{datetime.now():%Y%m%d}.csv", "CSV文件 (*.csv)")
        if not fname:
            return
        fname += "" if fname.endswith(".csv") else ".csv"
        try:
            with open(fname, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["排名", "IP地址", "端口", "地区码", "地区", "延迟(ms)", "下载速度(MB/s)", "测速类型"])
                for i, r in enumerate(self.speed_results, 1):
                    w.writerow([i, r["ip"], r["port"], r["iata_code"], r["chinese_name"],
                                f"{r['latency']:.2f}", f"{r['download_speed']:.2f}", r.get("test_type", "")])
            self.status_display.append(f"测速结果已成功导出到: {fname}")
            self.status_label.setText(f"结果已导出到: {os.path.basename(fname)}")
            QTimer.singleShot(3000, lambda: self.status_label.setText("就绪"))
        except Exception as e:
            self.status_display.append(f"导出失败: {e}")

    # ---------- 任务回调 ----------
    def scan_finished(self, results):
        self.scan_results = results
        self.show_scan_summary(results)

    def speed_test_finished(self, results):
        self.speed_results = results
        if not results:
            self.status_display.append("测速完成：没有有效的测速结果（可检查网络/代理，或在“测速地址”填写自定义地址）")
            return
        self.switch_tab(1)
        self.render_speed_cards(results)
        self.status_display.append(f"\n测速完成！保留 {len(results)} 条，"
                                   f"涉及端口: {', '.join(map(str, sorted({r['port'] for r in results})))}")

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
        ready = not busy and bool(self.scan_results)
        self.btn_stop.setEnabled(busy)
        self.btn_full.setEnabled(ready)
        self.btn_area.setEnabled(ready)
        self.btn_export.setEnabled(not busy and bool(self.speed_results))
        for b in (self.btn_ipv4, self.btn_ipv6, self.btn_import, self.btn_clear_cidr, *self._edits):
            b.setEnabled(not busy)
        if not busy:
            self.progress_bar.setValue(0)

    def update_progress(self, cur, total, ok, speed):
        self.progress_bar.setValue(int(cur / total * 100) if total else 0)
        self.status_label.setText(f"扫描中: {cur}/{total} ({ok}个可用)")
        self.speed_label.setText(f"速度: {speed:.1f} 任务/秒")

    def update_speed_progress(self, cur, total):
        self.progress_bar.setValue(int(cur / total * 100) if total else 0)
        self.status_label.setText(f"测速中: {cur}/{total}")
        self.speed_label.setText(f"测速进度: {cur}/{total}")

    def update_status(self, msg):
        self.status_display.append(msg)
        bar = self.status_display.verticalScrollBar()
        bar.setValue(bar.maximum())

    def show_scan_summary(self, results):
        log = self.status_display.append
        if not results:
            log("\n扫描完成！未找到任何可用的IP地址。")
            return
        ip_region = {r["ip"]: f"{r['iata_code']} ({r['chinese_name']})" for r in results}
        per_port = {p: sum(1 for r in results if r["port"] == p) for p in PORTS}
        v6 = sum(1 for ip in ip_region if ":" in ip)
        stats: Dict[str, int] = {}
        for region in ip_region.values():
            stats[region] = stats.get(region, 0) + 1
        log("\n" + "=" * 25 + "\n扫描完成！统计信息：")
        if len(ip_region) - v6:
            log(f"可用IPv4地址: {len(ip_region) - v6} 个")
        if v6:
            log(f"可用IPv6地址: {v6} 个")
        log("各端口可用数量：")
        for p in PORTS:
            log(f"  端口 {p}: {per_port[p]} 个")
        log(f"地区统计（共 {len(stats)} 个不同地区）：")
        for region, cnt in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            log(f"  {region}: {cnt}个IP")
        log("\n现在可以使用完全测速或地区测速功能。")

    # ---------- 测速结果展示 ----------
    def render_speed_cards(self, results):
        self.clear_speed_cards()
        for rank, r in enumerate(results, 1):
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
        for text, style in ((r["ip"], "color:white;font-size:13px;"),
                            (f"{r['iata_code']} {r['chinese_name']}  |  端口 {r['port']}", "color:#7DD3FC;font-size:12px;"),
                            (f"延迟: {r['latency']:.2f}ms  速度: {r['download_speed']:.2f} MB/s", "color:#D1D5DB;font-size:12px;")):
            lbl = QLabel(text)
            lbl.setStyleSheet(style)
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            info.addWidget(lbl)
        layout.addLayout(info, 1)

        hostport = f"[{r['ip']}]:{r['port']}" if ":" in r["ip"] else f"{r['ip']}:{r['port']}"
        btns = QVBoxLayout()
        btns.setSpacing(4)
        for text, value in (("复制IP", r["ip"]), ("复制IP:端口", hostport)):
            b = QPushButton(text)
            b.setFixedSize(84, 24)
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet("QPushButton{background:#8B5CF6;color:white;border-radius:4px;font-size:11px;}"
                            "QPushButton:hover{background:#7C3AED;}")
            b.clicked.connect(lambda _, t=value: self.copy_text(t))
            btns.addWidget(b)
        layout.addLayout(btns)
        return card

    def clear_speed_cards(self):
        while self.speed_layout.count():
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
if __name__ == "__main__":
    if platform.system() == "Darwin":
        os.environ["QT_MAC_WANTS_LAYER"] = "1"
    app = QApplication(sys.argv)
    dirs = [os.path.dirname(os.path.abspath(__file__)), getattr(sys, "_MEIPASS", "")]
    icon = next((p for d in dirs if d for n in ("cfs.ico", "cfs.icns")
                 if os.path.exists(p := os.path.join(d, n))), None)
    if icon:
        app.setWindowIcon(QIcon(icon))
    win = CloudflareScanUI()
    win.show()
    sys.exit(app.exec())
