import aiohttp
import asyncio
import random
import requests
import re
import time
import secrets
import os
import sys
import logging
from hashlib import md5
from time import time as T
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass
from urllib.parse import urlencode
from pathlib import Path
from telegram import Update, Bot
from telegram.ext import (
    Application, CommandHandler, ContextTypes, MessageHandler, filters
)
from telegram.constants import ParseMode

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# DEVICE FINGERPRINTING
# ─────────────────────────────────────────────

@dataclass
class DeviceInfo:
    model: str
    version: str
    api_level: int
    brand: str
    hardware: str
    manufacturer: str

class DeviceGenerator:
    DEVICES = [
        DeviceInfo("Pixel 6",    "13", 33, "Google",  "oriole",      "Google"),
        DeviceInfo("Pixel 7",    "14", 34, "Google",  "panther",     "Google"),
        DeviceInfo("Pixel 8",    "14", 34, "Google",  "shiba",       "Google"),
        DeviceInfo("SM-S901B",   "13", 33, "Samsung", "dm3q",        "samsung"),
        DeviceInfo("SM-S911B",   "14", 34, "Samsung", "e1s",         "samsung"),
        DeviceInfo("SM-S928B",   "14", 34, "Samsung", "e3q",         "samsung"),
        DeviceInfo("2201123C",   "13", 33, "Xiaomi",  "zeus",        "Xiaomi"),
        DeviceInfo("2210132C",   "14", 34, "Xiaomi",  "nuwa",        "Xiaomi"),
        DeviceInfo("23049RAD8G", "14", 34, "Xiaomi",  "aristotle",   "Xiaomi"),
        DeviceInfo("CPH2447",    "13", 33, "OPPO",    "OPPO",        "OPPO"),
        DeviceInfo("CPH2499",    "14", 34, "OPPO",    "OPPO",        "OPPO"),
        DeviceInfo("V2217",      "13", 33, "vivo",    "V2217",       "vivo"),
        DeviceInfo("V2309",      "14", 34, "vivo",    "V2309",       "vivo"),
        DeviceInfo("RMX3371",    "13", 33, "realme",  "RE5B6A",      "realme"),
        DeviceInfo("RMX3843",    "14", 34, "realme",  "RE58B6",      "realme"),
        DeviceInfo("LE2123",     "13", 33, "OnePlus", "OnePlus9Pro", "OnePlus"),
        DeviceInfo("CPH2451",    "14", 34, "OnePlus", "OnePlus11",   "OnePlus"),
        DeviceInfo("Pixel 5",    "11", 30, "Google",  "redfin",      "Google"),
        DeviceInfo("SM-G998B",   "13", 33, "Samsung", "p3s",         "samsung"),
    ]

    @classmethod
    def random_device(cls) -> DeviceInfo:
        return random.choice(cls.DEVICES)

    @classmethod
    def generate_device_id(cls) -> str:
        return str(random.randint(6800000000000000000, 6999999999999999999))

    @classmethod
    def generate_openudid(cls) -> str:
        return "".join(random.choices("abcdef0123456789", k=16))

    @classmethod
    def generate_cdids(cls) -> str:
        return "".join(random.choices("abcdef0123456789", k=16))


# ─────────────────────────────────────────────
# SIGNATURE (X-Gorgon)
# ─────────────────────────────────────────────

class Signature:
    KEY = [0xDF, 0x77, 0xB9, 0x40, 0xB9, 0x9B, 0x84, 0x83,
           0xD1, 0xB9, 0xCB, 0xD1, 0xF7, 0xC2, 0xB9, 0x85,
           0xC3, 0xD0, 0xFB, 0xC3]

    def __init__(self, params: str, data: str, cookies: str):
        self.params = params
        self.data = data
        self.cookies = cookies

    @staticmethod
    def _md5(s: str) -> str:
        return md5(s.encode()).hexdigest()

    @staticmethod
    def _reverse_byte(n: int) -> int:
        h = f"{n:02x}"
        return int(h[1] + h[0], 16)

    def generate(self) -> Dict[str, str]:
        g  = self._md5(self.params)
        g += self._md5(self.data)    if self.data    else "0" * 32
        g += self._md5(self.cookies) if self.cookies else "0" * 32
        g += "0" * 32

        ts = int(T())
        payload = []
        for i in range(0, 12, 4):
            chunk = g[8 * i: 8 * (i + 1)]
            for j in range(4):
                payload.append(int(chunk[j * 2:(j + 1) * 2], 16))

        payload.extend([0x0, 0x6, 0xB, 0x1C])
        payload.extend([
            (ts & 0xFF000000) >> 24,
            (ts & 0x00FF0000) >> 16,
            (ts & 0x0000FF00) >> 8,
            (ts & 0x000000FF),
        ])

        enc = [a ^ b for a, b in zip(payload, self.KEY)]
        for i in range(0x14):
            C = self._reverse_byte(enc[i])
            D = enc[(i + 1) % 0x14]
            F = int(bin(C ^ D)[2:].zfill(8)[::-1], 2)
            H = ((F ^ 0xFFFFFFFF) ^ 0x14) & 0xFF
            enc[i] = H

        sig = "".join(f"{x:02x}" for x in enc)
        return {
            "X-Gorgon":  "840280416000" + sig,
            "X-Khronos": str(ts),
        }


# ─────────────────────────────────────────────
# PROXY MANAGER
# ─────────────────────────────────────────────

def parse_proxy_line(line: str) -> Optional[str]:
    """
    Parse proxy line into a URL usable by aiohttp.
    Supported formats:
      ip:port
      ip:port:user:pass
      http://ip:port
      http://user:pass@ip:port
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Already a full URL
    if line.startswith("http://") or line.startswith("https://") or line.startswith("socks5://"):
        return line
    parts = line.split(":")
    if len(parts) == 2:
        # ip:port
        return f"http://{parts[0]}:{parts[1]}"
    elif len(parts) == 4:
        # ip:port:user:pass
        ip, port, user, pw = parts
        return f"http://{user}:{pw}@{ip}:{port}"
    return None


class ProxyManager:
    def __init__(self, proxy_list: List[str] = None):
        self.proxies = proxy_list or []
        self.idx = 0
        self.lock = asyncio.Lock()
        logger.info(f"ProxyManager: {len(self.proxies)} proxies loaded")

    async def get(self) -> Optional[str]:
        async with self.lock:
            if not self.proxies:
                return None
            p = self.proxies[self.idx]
            self.idx = (self.idx + 1) % len(self.proxies)
            return p

    def add(self, proxies: List[str]):
        self.proxies.extend(proxies)
        logger.info(f"ProxyManager: added {len(proxies)}, total={len(self.proxies)}")

    def clear(self):
        self.proxies.clear()
        self.idx = 0


# ─────────────────────────────────────────────
# BUNDLED PROXIES (embedded — luôn có sẵn khi deploy)
# ─────────────────────────────────────────────

# Proxyscrape premium HTTP proxies
_PROXYSCRAPE = """
209.50.186.232:3129
209.50.190.65:3129
209.50.174.243:3129
104.207.46.192:3129
216.26.230.189:3129
216.26.242.133:3129
65.111.1.81:3129
45.3.35.80:3129
151.123.177.201:3129
45.3.44.173:3129
217.181.91.29:3129
104.167.19.229:3129
209.50.188.173:3129
217.181.90.209:3129
104.207.51.21:3129
45.3.49.242:3129
209.50.165.243:3129
151.123.177.89:3129
65.111.9.35:3129
209.50.174.201:3129
45.3.32.96:3129
216.26.248.215:3129
45.3.33.202:3129
216.26.229.18:3129
216.26.250.91:3129
104.207.41.145:3129
209.50.181.96:3129
209.50.188.239:3129
209.50.167.127:3129
216.26.227.6:3129
195.63.31.63:3129
151.123.177.51:3129
65.111.7.113:3129
104.167.25.249:3129
216.26.245.255:3129
104.207.59.186:3129
216.26.252.207:3129
209.50.175.245:3129
104.207.54.51:3129
216.26.224.137:3129
216.26.225.250:3129
209.50.162.170:3129
104.207.44.193:3129
216.26.255.40:3129
45.3.51.48:3129
216.26.230.190:3129
151.123.178.97:3129
65.111.21.56:3129
104.207.59.113:3129
65.111.7.254:3129
216.26.253.176:3129
209.50.179.63:3129
209.50.172.227:3129
209.50.181.177:3129
65.111.13.215:3129
104.207.60.193:3129
104.207.45.231:3129
209.50.164.71:3129
209.50.176.216:3129
104.207.42.167:3129
216.26.231.149:3129
104.167.19.43:3129
65.111.3.56:3129
45.3.36.241:3129
216.26.248.3:3129
216.26.253.147:3129
45.3.36.151:3129
216.26.242.162:3129
104.207.52.104:3129
216.26.226.52:3129
209.50.189.197:3129
216.26.239.191:3129
104.207.60.223:3129
65.111.9.153:3129
209.50.183.133:3129
45.3.51.177:3129
104.207.51.28:3129
45.3.36.30:3129
104.207.57.216:3129
209.50.166.196:3129
45.3.55.134:3129
209.50.170.55:3129
104.207.59.243:3129
104.207.45.152:3129
104.207.36.99:3129
65.111.24.12:3129
216.26.243.198:3129
104.207.55.197:3129
216.26.243.15:3129
65.111.9.176:3129
216.26.236.223:3129
104.207.39.116:3129
216.26.254.144:3129
216.26.226.69:3129
65.111.0.108:3129
45.3.49.93:3129
45.3.34.72:3129
65.111.3.113:3129
104.207.60.76:3129
216.26.243.82:3129
""".strip()

# Webshare authenticated proxies (ip:port:user:pass)
_WEBSHARE = """
31.59.20.176:6754:wzkfpfxd:jb6xhihx9klb
23.95.150.145:6114:wzkfpfxd:jb6xhihx9klb
198.23.239.134:6540:wzkfpfxd:jb6xhihx9klb
45.38.107.97:6014:wzkfpfxd:jb6xhihx9klb
107.172.163.27:6543:wzkfpfxd:jb6xhihx9klb
198.105.121.200:6462:wzkfpfxd:jb6xhihx9klb
216.10.27.159:6837:wzkfpfxd:jb6xhihx9klb
142.111.67.146:5611:wzkfpfxd:jb6xhihx9klb
191.96.254.138:6185:wzkfpfxd:jb6xhihx9klb
31.58.9.4:6077:wzkfpfxd:jb6xhihx9klb
""".strip()


# ─────────────────────────────────────────────
# PROXY LOADER
# ─────────────────────────────────────────────

def load_proxies_from_env() -> List[str]:
    raw = os.getenv("PROXY_LIST", "")
    if not raw:
        return []
    proxies = []
    for item in re.split(r"[,\s]+", raw):
        p = parse_proxy_line(item)
        if p:
            proxies.append(p)
    logger.info(f"Loaded {len(proxies)} proxies from PROXY_LIST env")
    return proxies


def load_all_proxies() -> List[str]:
    """Load proxies from all sources: bundled lists + env variable."""
    all_proxies: List[str] = []

    # Load bundled proxy lists
    for raw_block in [_PROXYSCRAPE, _WEBSHARE]:
        for line in raw_block.splitlines():
            p = parse_proxy_line(line)
            if p:
                all_proxies.append(p)

    # Also try loading from external files if present
    base_dir = Path(__file__).parent
    for fname in ["proxyscrape_proxies.txt", "webshare_proxies.txt",
                  "proxyscrape_premium_http_proxies_1774854538314.txt",
                  "Webshare_10_proxies_1774854538316.txt"]:
        fpath = base_dir / fname
        if fpath.exists():
            try:
                for line in fpath.read_text(encoding="utf-8").splitlines():
                    p = parse_proxy_line(line)
                    if p:
                        all_proxies.append(p)
                logger.info(f"Loaded extra proxies from {fname}")
            except Exception as e:
                logger.warning(f"Could not read {fname}: {e}")

    # Load from env variable
    all_proxies.extend(load_proxies_from_env())

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in all_proxies:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    logger.info(f"Total proxies loaded: {len(unique)}")
    return unique


# ─────────────────────────────────────────────
# SERVER IP HELPER
# ─────────────────────────────────────────────

async def get_server_ip() -> str:
    """Fetch the public IP of the server."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("https://api.ipify.org?format=json", timeout=aiohttp.ClientTimeout(total=5)) as r:
                data = await r.json()
                return data.get("ip", "Không xác định")
    except Exception:
        pass
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get("https://ifconfig.me/ip", timeout=aiohttp.ClientTimeout(total=5)) as r:
                return (await r.text()).strip()
    except Exception:
        return "Không xác định"


# ─────────────────────────────────────────────
# TikTok API ENDPOINTS (fallback list)
# ─────────────────────────────────────────────

TIKTOK_ENDPOINTS = [
    "api16-core-c-alisg.tiktokv.com",
    "api16-normal-c-useast1a.tiktokv.com",
    "api22-core-c-alisg.tiktokv.com",
    "api19-core-c-alisg.tiktokv.com",
    "api21-core-c-alisg.tiktokv.com",
    "api31-core-c-alisg.tiktokv.com",
]


# ─────────────────────────────────────────────
# REQUEST BUILDER (standalone — dùng cho /test)
# ─────────────────────────────────────────────

def build_tiktok_request(video_id: str, endpoint_idx: int = 0):
    dev = DeviceGenerator.random_device()
    endpoint = TIKTOK_ENDPOINTS[endpoint_idx % len(TIKTOK_ENDPOINTS)]

    query_params = (
        f"channel=googleplay&aid=1233&app_name=musical_ly&version_code=400304"
        f"&version_name=40.3.4&device_platform=android"
        f"&device_type={dev.model.replace(' ', '+')}"
        f"&device_brand={dev.brand}"
        f"&device_manufacturer={dev.manufacturer}"
        f"&os_version={dev.version}&os_api={dev.api_level}"
        f"&device_id={DeviceGenerator.generate_device_id()}"
        f"&openudid={DeviceGenerator.generate_openudid()}"
        f"&app_language={random.choice(['vi','en','id','th','ms'])}"
        f"&tz_name=Asia%2FHo_Chi_Minh&tz_offset=25200"
        f"&carrier_region={random.choice(['VN','US','ID','TH','MY'])}"
        f"&sys_region={random.choice(['vn','us','id','th','my'])}"
        f"&ac={random.choice(['wifi','4g','5g'])}"
        f"&mcc_mnc={random.choice(['45201','310260','51010'])}"
        f"&pass-route=1"
    )
    url = f"https://{endpoint}/aweme/v1/aweme/stats/?{query_params}"

    data_dict = {
        "item_id":      video_id,
        "play_delta":   "1",
        "action_time":  str(int(time.time())),
        "source":       str(random.choice([1, 2, 3, 4])),
        "media_type":   "4",
        "content_type": "video",
    }
    body_str = urlencode(data_dict)

    session_id = secrets.token_hex(20)
    uid_val    = str(random.randint(1000000000, 9999999999))
    cdids_val  = DeviceGenerator.generate_cdids()
    cookie_str = f"sessionid={session_id}; uid={uid_val}; cdids={cdids_val}"

    sig = Signature(query_params, body_str, cookie_str).generate()

    headers = {
        "Content-Type":    "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent":      f"com.ss.android.ugc.trill/400304 (Linux; U; Android {dev.version}; {dev.model}; Build/PI; tt-ok/3.12.13)",
        "Accept-Encoding": "gzip",
        "Connection":      "Keep-Alive",
        "Host":            endpoint,
        "sdk-version":     "2",
        "x-tt-dm-status":  "login=0; launch=1",
        "Cookie":           cookie_str,
        **sig,
    }
    return url, body_str, headers


# ─────────────────────────────────────────────
# VIEW BOT SESSION
# ─────────────────────────────────────────────

class ViewBotSession:
    def __init__(self, video_id: str, proxies: List[str] = None):
        self.video_id = video_id
        self.is_running = False
        self.count = 0
        self.successful = 0
        self.failed = 0
        self.peak_speed = 0.0
        self.start_time = 0.0
        self.session: Optional[aiohttp.ClientSession] = None
        self.proxy_manager = ProxyManager(proxies)
        self._tasks: List[asyncio.Task] = []
        self._stats_lock = asyncio.Lock()
        self._endpoint_idx = 0
        # Track last status codes for diagnostics
        self._last_codes: List[int] = []
        self._codes_lock = asyncio.Lock()
        # Log first N responses with body so Railway logs show TikTok replies
        self._sample_logged = 0
        self._sample_limit = 5

    async def _record_code(self, code: int):
        async with self._codes_lock:
            self._last_codes.append(code)
            if len(self._last_codes) > 100:
                self._last_codes.pop(0)

    async def _send_one(self, semaphore: asyncio.Semaphore) -> bool:
        async with semaphore:
            proxy = await self.proxy_manager.get()
            self._endpoint_idx += 1
            url, body_str, headers = build_tiktok_request(self.video_id, self._endpoint_idx)

            for attempt in range(2):
                try:
                    async with self.session.post(
                        url,
                        data=body_str,
                        headers=headers,
                        proxy=proxy,
                        ssl=False,
                    ) as resp:
                        await self._record_code(resp.status)

                        # Log first few raw TikTok responses so Railway logs reveal what's happening
                        should_sample = self._sample_logged < self._sample_limit
                        body = await resp.text() if (should_sample or resp.status != 200) else None

                        if should_sample and body is not None:
                            self._sample_logged += 1
                            endpoint = url.split("/")[2]
                            logger.info(
                                f"[TikTok sample #{self._sample_logged}] "
                                f"status={resp.status} endpoint={endpoint} "
                                f"proxy={'yes' if proxy else 'no'} "
                                f"body={body[:200].replace(chr(10),'')!r}"
                            )

                        if resp.status == 200:
                            async with self._stats_lock:
                                self.count += 1
                                self.successful += 1
                            return True
                        elif resp.status == 429:
                            logger.warning(f"[TikTok] 429 rate-limit via proxy={proxy}")
                            await asyncio.sleep(1.0 + attempt)
                            continue
                        elif resp.status in (403, 401, 400):
                            if body:
                                logger.warning(f"[TikTok] {resp.status} rejected: {body[:150]!r}")
                            async with self._stats_lock:
                                self.failed += 1
                            return False
                        else:
                            if attempt == 0:
                                await asyncio.sleep(0.05)
                                continue
                            async with self._stats_lock:
                                self.failed += 1
                            return False

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt == 0:
                        await asyncio.sleep(0.02)
                        continue
                    async with self._stats_lock:
                        self.failed += 1
                    return False
                except Exception as e:
                    logger.debug(f"_send_one error: {e}")
                    async with self._stats_lock:
                        self.failed += 1
                    return False
            return False

    async def _sender_loop(self, semaphore: asyncio.Semaphore):
        """Each worker runs as fast as possible — no artificial delay."""
        consecutive_fail = 0
        while self.is_running:
            ok = await self._send_one(semaphore)
            if ok:
                consecutive_fail = 0
            else:
                consecutive_fail += 1
                if consecutive_fail >= 10:
                    await asyncio.sleep(0.5)
                    consecutive_fail = 0

    async def _log_stats_loop(self):
        """Periodically write stats summary to Railway server logs."""
        while self.is_running:
            await asyncio.sleep(60)
            if not self.is_running:
                break
            s = self.stats()
            from collections import Counter
            code_summary = dict(Counter(self._last_codes))
            logger.info(
                f"[Stats] video={self.video_id} "
                f"ok={s['ok']} fail={s['fail']} "
                f"vps={s['vps']:.1f} elapsed={s['elapsed']:.0f}s "
                f"codes={code_summary}"
            )

    async def start(self, workers: int = 500):
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # High connection limit — each proxy is a different host
        connector = aiohttp.TCPConnector(
            limit=0,                   # No global cap — limited by semaphore
            limit_per_host=0,          # No per-host cap — proxies are all different IPs
            ttl_dns_cache=600,
            ssl=ctx,
            force_close=True,          # Don't reuse connections through proxies
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=12, connect=5, sock_read=8)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar(),
        )

        self.is_running = True
        self.start_time = time.time()
        # Semaphore = number of truly concurrent requests in flight
        sem = asyncio.Semaphore(workers)

        self._tasks = [
            asyncio.create_task(self._sender_loop(sem))
            for _ in range(workers)
        ]
        # Background task: write stats to Railway server logs every 60s
        self._tasks.append(asyncio.create_task(self._log_stats_loop()))
        logger.info(f"Session started: video={self.video_id} workers={workers} sem={workers}")

    async def stop(self):
        self.is_running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self.session:
            await self.session.close()
        logger.info(f"Session stopped: video={self.video_id}")

    def stats(self) -> Dict:
        elapsed = time.time() - self.start_time if self.start_time else 1
        vps = self.count / elapsed if elapsed > 0 else 0
        if vps > self.peak_speed:
            self.peak_speed = vps
        total = self.successful + self.failed
        return {
            "total":   self.count,
            "elapsed": elapsed,
            "vps":     vps,
            "vpm":     vps * 60,
            "vph":     vps * 3600,
            "peak":    self.peak_speed,
            "ok":      self.successful,
            "fail":    self.failed,
            "rate":    (self.successful / total * 100) if total else 0,
        }

    def stats_text(self) -> str:
        s = self.stats()
        n = len(self.proxy_manager.proxies)
        proxy_info = f"🌐 Proxy: *{n} proxies*" if n else "⚠️ Proxy: *Không có*"
        # Show last response code distribution
        codes_info = ""
        if self._last_codes:
            from collections import Counter
            code_counts = Counter(self._last_codes)
            codes_info = "\n🔢 HTTP codes (50 req gần nhất): " + " | ".join(
                f"`{c}×{v}`" for c, v in sorted(code_counts.items())
            )
        return (
            f"📊 *Thống kê — Video ID:* `{self.video_id}`\n"
            f"{'─'*34}\n"
            f"👀 Tổng view: *{s['total']:,}*\n"
            f"⏱ Thời gian: *{s['elapsed']:.1f}s*\n"
            f"⚡ Tốc độ hiện tại: *{s['vps']:.1f} view/s*\n"
            f"🏆 Tốc độ cao nhất: *{s['peak']:.1f} view/s*\n"
            f"📈 Dự kiến/phút: *{s['vpm']:,.0f}*\n"
            f"🔥 Dự kiến/giờ: *{s['vph']:,.0f}*\n"
            f"✅ Thành công: *{s['ok']:,}*\n"
            f"❌ Thất bại: *{s['fail']:,}*\n"
            f"🎯 Tỷ lệ thành công: *{s['rate']:.1f}%*\n"
            f"{proxy_info}"
            f"{codes_info}\n"
            f"{'─'*34}\n"
            f"{'🟢 Đang chạy' if self.is_running else '🔴 Đã dừng'}"
        )


# ─────────────────────────────────────────────
# UTIL: extract video ID
# ─────────────────────────────────────────────

def get_video_id(url: str) -> Optional[str]:
    url_clean = url.split("?")[0]
    for pat in [r"/video/(\d+)", r"tiktok\.com/@[^/]+/(\d+)", r"(\d{18,19})"]:
        m = re.search(pat, url_clean)
        if m:
            return m.group(1)
    try:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        r = requests.get(url, headers=hdrs, timeout=15, allow_redirects=True)
        final_url = r.url.split("?")[0]
        for pat in [r"/video/(\d+)", r"tiktok\.com/@[^/]+/(\d+)"]:
            m = re.search(pat, final_url)
            if m:
                return m.group(1)
        for pat in [r'"id":"(\d{19})"', r'aweme_id["\']:\s*["\'](\d{19})', r'video/(\d{19})', r'(\d{19})']:
            m = re.search(pat, r.text)
            if m:
                return m.group(1)
    except Exception as e:
        logger.error(f"get_video_id fetch error: {e}")
    return None


# ─────────────────────────────────────────────
# TELEGRAM BOT STATE
# ─────────────────────────────────────────────

active_sessions: Dict[int, ViewBotSession] = {}
status_tasks: Dict[int, asyncio.Task] = {}
global_proxies: List[str] = []

AUTHORIZED_IDS_RAW = os.getenv("AUTHORIZED_CHAT_IDS", "")
AUTHORIZED_IDS = set()
if AUTHORIZED_IDS_RAW:
    for x in AUTHORIZED_IDS_RAW.split(","):
        x = x.strip()
        if x.lstrip("-").isdigit():
            AUTHORIZED_IDS.add(int(x))

def is_authorized(chat_id: int) -> bool:
    if not AUTHORIZED_IDS:
        return True
    return chat_id in AUTHORIZED_IDS


# ─────────────────────────────────────────────
# COMMAND HANDLERS
# ─────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    server_ip = await get_server_ip()
    proxy_status = f"✅ *{len(global_proxies)} proxies* đã nạp" if global_proxies else "⚠️ Chưa có proxy"

    await update.message.reply_text(
        "👋 *TikTok View Bot — Telegram Edition*\n\n"
        f"🖥 *Server IP:* `{server_ip}`\n"
        f"🌐 *Proxy:* {proxy_status}\n\n"
        "📋 *Danh sách lệnh:*\n"
        "`/view <URL>` — Bắt đầu gửi view\n"
        "`/stop` — Dừng session hiện tại\n"
        "`/stats` — Xem thống kê + HTTP codes\n"
        "`/workers <số>` — Đặt số workers (mặc định 500)\n"
        "`/test <URL>` — Test 1 request, xem response TikTok\n"
        "`/proxy` — Xem & quản lý proxy\n"
        "`/proxy add ip:port,...` — Thêm proxy\n"
        "`/proxy clear` — Xóa tất cả proxy\n"
        "`/proxy reload` — Tải lại proxy bundled\n"
        "`/help` — Hiển thị trợ giúp này\n\n"
        "⚠️ Chỉ dùng cho mục đích học tập.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_start(update, ctx)


async def cmd_proxy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    /proxy              — show current proxy list
    /proxy add ip:port,... — add proxies
    /proxy clear        — clear all proxies
    /proxy reload       — reload from bundled files
    """
    global global_proxies
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    args = ctx.args  # list of words after /proxy

    # ── /proxy add ───────────────────────────
    if args and args[0].lower() == "add":
        raw = " ".join(args[1:])
        if not raw.strip():
            await update.message.reply_text(
                "❌ Cú pháp: `/proxy add ip:port,ip:port,...`\n\n"
                "Hỗ trợ:\n"
                "• `ip:port` — proxy không auth\n"
                "• `ip:port:user:pass` — proxy có auth (Webshare)\n"
                "• `http://user:pass@ip:port` — URL đầy đủ",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        new_proxies = []
        for item in re.split(r"[,\s]+", raw):
            p = parse_proxy_line(item)
            if p:
                new_proxies.append(p)

        global_proxies.extend(new_proxies)
        # Remove duplicates (keep order)
        seen = set(); unique = []
        for p in global_proxies:
            if p not in seen:
                seen.add(p); unique.append(p)
        global_proxies[:] = unique

        await update.message.reply_text(
            f"✅ Đã thêm *{len(new_proxies)}* proxy.\n"
            f"📋 Tổng cộng: *{len(global_proxies)}* proxy.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # ── /proxy clear ─────────────────────────
    if args and args[0].lower() == "clear":
        count = len(global_proxies)
        global_proxies.clear()
        await update.message.reply_text(f"🗑 Đã xóa *{count}* proxy.", parse_mode=ParseMode.MARKDOWN)
        return

    # ── /proxy reload ────────────────────────
    if args and args[0].lower() == "reload":
        global_proxies[:] = load_all_proxies()
        await update.message.reply_text(
            f"🔄 Đã tải lại proxy từ file.\n"
            f"📋 Tổng cộng: *{len(global_proxies)}* proxy.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # ── /proxy (no args) — show list ─────────
    if not global_proxies:
        await update.message.reply_text(
            "📋 *Danh sách proxy:* Trống\n\n"
            "Dùng `/proxy add ip:port,...` để thêm.\n"
            "Hoặc `/proxy reload` để load từ file bundled.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    preview = global_proxies[:20]
    more = len(global_proxies) - 20
    text = f"📋 *Danh sách proxy ({len(global_proxies)} proxies):*\n"
    text += "\n".join(f"`{p}`" for p in preview)
    if more > 0:
        text += f"\n_...và {more} proxy khác_"
    text += "\n\n`/proxy add` · `/proxy clear` · `/proxy reload`"
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


async def cmd_view(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    if not ctx.args:
        await update.message.reply_text("❌ Cú pháp: `/view <URL>`", parse_mode=ParseMode.MARKDOWN)
        return

    url = ctx.args[0].strip()
    workers = int(ctx.bot_data.get(f"workers_{chat_id}", 300))

    if chat_id in active_sessions:
        await active_sessions[chat_id].stop()
        del active_sessions[chat_id]
    if chat_id in status_tasks:
        status_tasks[chat_id].cancel()
        del status_tasks[chat_id]

    msg = await update.message.reply_text("🔍 Đang lấy Video ID...")

    loop = asyncio.get_event_loop()
    video_id = await loop.run_in_executor(None, get_video_id, url)

    if not video_id:
        await msg.edit_text(
            "❌ Không tìm thấy Video ID. Kiểm tra lại URL!\n\n"
            "Thử dùng link đầy đủ:\n`https://www.tiktok.com/@user/video/1234567890`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    session = ViewBotSession(video_id, proxies=list(global_proxies))
    active_sessions[chat_id] = session

    proxy_warn = "" if global_proxies else "\n⚠️ *Chưa có proxy* — dùng `/proxy add` để thêm."
    await msg.edit_text(
        f"✅ Video ID: `{video_id}`\n"
        f"⚙️ Workers: *{workers:,}*\n"
        f"🌐 Proxies: *{len(global_proxies)}*"
        f"{proxy_warn}\n"
        f"🚀 Đang khởi động bot...",
        parse_mode=ParseMode.MARKDOWN,
    )

    await session.start(workers=workers)

    async def send_status_loop():
        while session.is_running:
            await asyncio.sleep(30)
            if not session.is_running:
                break
            try:
                await ctx.bot.send_message(
                    chat_id=chat_id,
                    text=session.stats_text(),
                    parse_mode=ParseMode.MARKDOWN,
                )
            except Exception as e:
                logger.warning(f"status update error: {e}")

    status_tasks[chat_id] = asyncio.create_task(send_status_loop())

    await ctx.bot.send_message(
        chat_id=chat_id,
        text=(
            f"🟢 *Bot đã chạy!*\n\n"
            f"📹 Video ID: `{video_id}`\n"
            f"⚙️ Workers: *{workers:,}*\n"
            f"🌐 Proxies: *{len(global_proxies)}*\n"
            f"📊 Thống kê cập nhật mỗi 30 giây.\n"
            f"Dùng /stop để dừng."
        ),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    if chat_id not in active_sessions:
        await update.message.reply_text("⚠️ Không có session nào đang chạy.")
        return

    session = active_sessions[chat_id]

    if chat_id in status_tasks:
        status_tasks[chat_id].cancel()
        del status_tasks[chat_id]

    final = session.stats_text()
    await session.stop()
    del active_sessions[chat_id]

    await update.message.reply_text(
        f"🔴 *Bot đã dừng.*\n\n{final}",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    if chat_id not in active_sessions:
        await update.message.reply_text("⚠️ Không có session nào đang chạy.")
        return

    await update.message.reply_text(
        active_sessions[chat_id].stats_text(),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_workers(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    if not ctx.args or not ctx.args[0].isdigit():
        await update.message.reply_text(
            "❌ Cú pháp: `/workers <số>` (VD: `/workers 300`)",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    n = int(ctx.args[0])
    n = max(50, min(n, 5000))
    ctx.bot_data[f"workers_{chat_id}"] = n
    await update.message.reply_text(
        f"✅ Số workers đặt thành *{n:,}* cho lần chạy tiếp theo.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_test(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    /test <URL hoặc video_id>
    Gửi 1 request thử đến TikTok và hiện response thô để debug.
    """
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    if not ctx.args:
        await update.message.reply_text(
            "❌ Cú pháp: `/test <URL hoặc video_id>`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    raw = ctx.args[0].strip()
    msg = await update.message.reply_text("🔍 Đang test...")

    # Resolve video ID
    loop = asyncio.get_event_loop()
    if raw.isdigit() and len(raw) >= 15:
        video_id = raw
    else:
        video_id = await loop.run_in_executor(None, get_video_id, raw)

    if not video_id:
        await msg.edit_text("❌ Không tìm thấy Video ID.")
        return

    proxy = global_proxies[0] if global_proxies else None
    results = []

    import ssl as ssl_mod
    ctx_ssl = ssl_mod.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode = ssl_mod.CERT_NONE

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=15),
        connector=aiohttp.TCPConnector(ssl=ctx_ssl, force_close=True),
        cookie_jar=aiohttp.DummyCookieJar(),
    ) as sess:
        for i, ep_idx in enumerate(range(min(3, len(TIKTOK_ENDPOINTS)))):
            try:
                url, body_str, headers = build_tiktok_request(video_id, ep_idx)
                endpoint = TIKTOK_ENDPOINTS[ep_idx % len(TIKTOK_ENDPOINTS)]
                async with sess.post(
                    url, data=body_str, headers=headers,
                    proxy=proxy, ssl=False,
                ) as resp:
                    body = await resp.text()
                    # Truncate body for display
                    body_preview = body[:300].replace("`", "'") if body else "(empty)"
                    results.append(
                        f"*Endpoint {i+1}:* `{endpoint}`\n"
                        f"HTTP: `{resp.status}`\n"
                        f"Body: `{body_preview}`"
                    )
            except Exception as e:
                results.append(f"*Endpoint {i+1}:* ❌ `{type(e).__name__}: {str(e)[:100]}`")

    proxy_info = f"`{proxy}`" if proxy else "_không có proxy_"
    text = (
        f"🧪 *Test Result — Video ID:* `{video_id}`\n"
        f"🌐 Proxy: {proxy_info}\n"
        f"{'─'*34}\n"
    ) + "\n\n".join(results)

    await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)


async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Telegram error: {ctx.error}", exc_info=ctx.error)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    global global_proxies

    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        sys.exit("TELEGRAM_BOT_TOKEN not set!")

    # Load proxies from bundled files + env variable
    global_proxies = load_all_proxies()

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("view",    cmd_view))
    app.add_handler(CommandHandler("stop",    cmd_stop))
    app.add_handler(CommandHandler("stats",   cmd_stats))
    app.add_handler(CommandHandler("workers", cmd_workers))
    app.add_handler(CommandHandler("proxy",   cmd_proxy))
    app.add_handler(CommandHandler("test",    cmd_test))
    app.add_error_handler(error_handler)

    logger.info(f"Bot starting... proxies={len(global_proxies)}")
    app.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
        close_loop=False,
    )


if __name__ == "__main__":
    main()
