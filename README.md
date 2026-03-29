# TikTok View Bot — Telegram Edition

Bot TikTok View Bot được điều khiển qua Telegram. Tối ưu hóa từ 2 phiên bản script với:

- X-Gorgon signature chính xác (thuật toán từ viewv3)
- Device fingerprinting đa dạng (14+ thiết bị từ toolview1)
- Proxy rotation
- Adaptive rate limiting + retry
- Quản lý session qua Telegram commands

---

## Lệnh Telegram

| Lệnh | Mô tả |
|------|-------|
| `/start` | Hiển thị trợ giúp |
| `/view <URL>` | Bắt đầu gửi view cho video TikTok |
| `/stop` | Dừng session hiện tại |
| `/stats` | Xem thống kê real-time |
| `/workers <số>` | Đặt số workers (100–10000, mặc định 1500) |

---

## Deploy trên Render.com

### 1. Tạo Web Service mới trên Render

1. Đăng nhập [render.com](https://render.com)
2. Nhấn **New → Web Service**
3. Kết nối repo GitHub (push code lên GitHub trước)
4. Cấu hình:
   - **Name**: `tiktok-view-bot`
   - **Root Directory**: `tiktok-bot`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python bot.py`

### 2. Thêm Environment Variables

Trong tab **Environment** của Render service, thêm:

| Key | Value |
|-----|-------|
| `TELEGRAM_BOT_TOKEN` | Token từ @BotFather |
| `AUTHORIZED_CHAT_IDS` | Chat ID của bạn (tùy chọn, để trống = ai cũng dùng được) |

> Lấy Chat ID: Nhắn tin cho @userinfobot trên Telegram

### 3. Lấy Chat ID của bạn (nếu muốn giới hạn truy cập)

Nhắn `/start` cho [@userinfobot](https://t.me/userinfobot) trên Telegram — nó sẽ trả về ID của bạn.

Điền vào `AUTHORIZED_CHAT_IDS` để chỉ bạn mới dùng được bot.

---

## Chạy local (testing)

```bash
cd tiktok-bot
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="your_token_here"
python bot.py
```

---

## Lưu ý

- Bot chạy dưới dạng long-polling — Render Free tier có thể sleep sau 15 phút không có request HTTP. Dùng **Render Background Worker** thay vì Web Service để tránh bị sleep.
- Trên Render, chọn **Background Worker** để bot chạy liên tục 24/7 (cần paid plan hoặc dùng free tier với cron ping).
