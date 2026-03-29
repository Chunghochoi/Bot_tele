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
        DeviceInfo("SM-S901B",   "13", 33, "Samsung", "dm3q",        "samsung"),
        DeviceInfo("SM-S911B",   "14", 34, "Samsung", "e1s",         "samsung"),
        DeviceInfo("2201123C",   "13", 33, "Xiaomi",  "zeus",        "Xiaomi"),
        DeviceInfo("2210132C",   "14", 34, "Xiaomi",  "nuwa",        "Xiaomi"),
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
# SIGNATURE (X-Gorgon) — algorithm từ viewv3
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


# ─────────────────────────────────────────────
# VIEW BOT SESSION
# ─────────────────────────────────────────────

class ViewBotSession:
    """One active bot session per Telegram command."""

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

    # ── helpers ──────────────────────────────

    def _build_request(self) -> Tuple[str, dict, dict, dict]:
        dev = DeviceGenerator.random_device()
        params = (
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
        url = f"https://api16-core-c-alisg.tiktokv.com/aweme/v1/aweme/stats/?{params}"

        data = {
            "item_id":    self.video_id,
            "play_delta": 1,
            "action_time": int(time.time()),
            "source":     random.choice([1, 2, 3, 4]),
            "media_type": 4,
            "content_type": "video",
        }
        cookies = {
            "sessionid": secrets.token_hex(20),
            "uid":       str(random.randint(1000000000, 9999999999)),
            "cdids":     DeviceGenerator.generate_cdids(),
        }
        headers = {
            "Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent":    f"com.ss.android.ugc.trill/400304 (Linux; U; Android {dev.version}; {dev.model}; Build/PI; tt-ok/3.12.13)",
            "Accept-Encoding": "gzip",
            "Connection":    "Keep-Alive",
            "Host":          "api16-core-c-alisg.tiktokv.com",
            "sdk-version":   "2",
            "x-tt-dm-status": "login=1; launch=0",
        }
        return url, data, cookies, headers

    async def _send_one(self, semaphore: asyncio.Semaphore) -> bool:
        async with semaphore:
            proxy = await self.proxy_manager.get()
            proxy_url = f"http://{proxy}" if proxy else None

            for attempt in range(3):
                try:
                    url, data, cookies, base_hdrs = self._build_request()
                    sig = Signature(url.split("?")[1], str(data), str(cookies)).generate()
                    headers = {**base_hdrs, **sig}

                    async with self.session.post(
                        url, data=data, headers=headers,
                        cookies=cookies, proxy=proxy_url, ssl=False
                    ) as resp:
                        if resp.status == 200:
                            async with self._stats_lock:
                                self.count += 1
                                self.successful += 1
                            return True
                        elif resp.status == 429:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        else:
                            if attempt < 2:
                                await asyncio.sleep(0.1 * (attempt + 1))
                                continue
                            async with self._stats_lock:
                                self.failed += 1
                            return False

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    if attempt == 2:
                        async with self._stats_lock:
                            self.failed += 1
                        return False
                    await asyncio.sleep(0.05 * (attempt + 1))
                except Exception:
                    async with self._stats_lock:
                        self.failed += 1
                    return False
            return False

    async def _sender_loop(self, semaphore: asyncio.Semaphore):
        consecutive = 0
        base_delay = 0.001

        while self.is_running:
            ok = await self._send_one(semaphore)
            if ok:
                consecutive += 1
                delay = base_delay * (0.5 if consecutive > 100 else 0.7 if consecutive > 50 else 1.0)
            else:
                consecutive = 0
                delay = base_delay * 3

            spd = self.stats()["vps"]
            if spd > 500:
                delay *= 1.5
            elif spd > 1000:
                delay *= 2.0

            await asyncio.sleep(delay + random.uniform(0, 0.002))

    # ── lifecycle ─────────────────────────────

    async def start(self, workers: int = 1500):
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            limit=200, limit_per_host=20,
            ttl_dns_cache=300, ssl=ctx,
            force_close=False, enable_cleanup_closed=True
        )
        timeout = aiohttp.ClientTimeout(total=15, connect=5, sock_read=10)
        self.session = aiohttp.ClientSession(
            timeout=timeout, connector=connector,
            cookie_jar=aiohttp.DummyCookieJar()
        )

        self.is_running = True
        self.start_time = time.time()
        sem = asyncio.Semaphore(min(500, workers // 3))

        self._tasks = [
            asyncio.create_task(self._sender_loop(sem))
            for _ in range(workers)
        ]
        logger.info(f"Session started: video={self.video_id} workers={workers}")

    async def stop(self):
        self.is_running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self.session:
            await self.session.close()
        logger.info(f"Session stopped: video={self.video_id}")

    # ── stats ─────────────────────────────────

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
            f"{'─'*34}\n"
            f"{'🟢 Đang chạy' if self.is_running else '🔴 Đã dừng'}"
        )


# ─────────────────────────────────────────────
# UTIL: extract video ID
# ─────────────────────────────────────────────

def get_video_id(url: str) -> Optional[str]:
    url = url.split("?")[0]
    for pat in [r"/video/(\d+)", r"tiktok\.com/@[^/]+/(\d+)", r"(\d{18,19})"]:
        m = re.search(pat, url)
        if m:
            return m.group(1)
    try:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        r = requests.get(url, headers=hdrs, timeout=15)
        r.raise_for_status()
        for pat in [r'"id":"(\d{19})"', r'aweme_id["\']:\s*["\'](\d{19})', r'video/(\d{19})', r'(\d{19})']:
            m = re.search(pat, r.text)
            if m:
                return m.group(1)
    except Exception as e:
        logger.error(f"get_video_id fetch error: {e}")
    return None


# ─────────────────────────────────────────────
# TELEGRAM BOT
# ─────────────────────────────────────────────

# Map chat_id → ViewBotSession
active_sessions: Dict[int, ViewBotSession] = {}
# Map chat_id → periodic status task
status_tasks: Dict[int, asyncio.Task] = {}

AUTHORIZED_IDS_RAW = os.getenv("AUTHORIZED_CHAT_IDS", "")
AUTHORIZED_IDS = set()
if AUTHORIZED_IDS_RAW:
    for x in AUTHORIZED_IDS_RAW.split(","):
        x = x.strip()
        if x.lstrip("-").isdigit():
            AUTHORIZED_IDS.add(int(x))

def is_authorized(chat_id: int) -> bool:
    if not AUTHORIZED_IDS:
        return True  # open access when no whitelist configured
    return chat_id in AUTHORIZED_IDS


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 *TikTok View Bot — Telegram Edition*\n\n"
        "📋 *Danh sách lệnh:*\n"
        "`/view <URL>` — Bắt đầu gửi view\n"
        "`/stop` — Dừng session hiện tại\n"
        "`/stats` — Xem thống kê\n"
        "`/workers <số>` — Đặt số workers (mặc định 1500)\n"
        "`/help` — Hiển thị trợ giúp này\n\n"
        "⚠️ Chỉ dùng cho mục đích học tập.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_start(update, ctx)


async def cmd_view(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if not is_authorized(chat_id):
        await update.message.reply_text("⛔ Bạn không có quyền dùng bot này.")
        return

    if not ctx.args:
        await update.message.reply_text("❌ Cú pháp: `/view <URL>`", parse_mode=ParseMode.MARKDOWN)
        return

    url = ctx.args[0].strip()
    workers = int(ctx.bot_data.get(f"workers_{chat_id}", 1500))

    # Stop existing session
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
        await msg.edit_text("❌ Không tìm thấy Video ID. Kiểm tra lại URL!")
        return

    session = ViewBotSession(video_id)
    active_sessions[chat_id] = session

    await msg.edit_text(
        f"✅ Video ID: `{video_id}`\n"
        f"⚙️ Workers: *{workers:,}*\n"
        f"🚀 Đang khởi động bot...",
        parse_mode=ParseMode.MARKDOWN,
    )

    await session.start(workers=workers)

    # Start periodic status updates every 30s
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
            f"📊 Thống kê sẽ cập nhật mỗi 30 giây.\n"
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
        await update.message.reply_text("❌ Cú pháp: `/workers <số>` (VD: `/workers 2000`)", parse_mode=ParseMode.MARKDOWN)
        return

    n = int(ctx.args[0])
    n = max(100, min(n, 10000))
    ctx.bot_data[f"workers_{chat_id}"] = n
    await update.message.reply_text(f"✅ Số workers đặt thành *{n:,}* cho lần chạy tiếp theo.", parse_mode=ParseMode.MARKDOWN)


async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Telegram error: {ctx.error}", exc_info=ctx.error)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        sys.exit("TELEGRAM_BOT_TOKEN not set!")

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("view",    cmd_view))
    app.add_handler(CommandHandler("stop",    cmd_stop))
    app.add_handler(CommandHandler("stats",   cmd_stats))
    app.add_handler(CommandHandler("workers", cmd_workers))
    app.add_error_handler(error_handler)

    logger.info("Bot starting (polling)...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
