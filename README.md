# TikTok View Bot — Telegram Edition

Bot TikTok View Bot được điều khiển qua Telegram, tối ưu cho deploy trên Railway/Render.

---

## Các lệnh Telegram

| Lệnh | Mô tả |
|------|-------|
| `/start` | Hiển thị trợ giúp |
| `/view <URL>` | Bắt đầu gửi view cho video TikTok |
| `/stop` | Dừng session hiện tại |
| `/stats` | Xem thống kê real-time |
| `/workers <số>` | Đặt số workers (50–5000, mặc định 300) |
| `/addproxy ip:port,...` | Thêm proxy vào danh sách |
| `/clearproxy` | Xóa toàn bộ proxy |
| `/listproxy` | Xem danh sách proxy hiện tại |

---

## Deploy trên Railway

### 1. Cấu hình service

- **Start Command**: `python bot.py`
- **Build Command**: `pip install -r requirements.txt`
- **Root Directory**: `tiktok-bot` (hoặc thư mục chứa `bot.py`)

### 2. Environment Variables

| Key | Value | Bắt buộc |
|-----|-------|----------|
| `TELEGRAM_BOT_TOKEN` | Token từ @BotFather | ✅ |
| `AUTHORIZED_CHAT_IDS` | Chat ID của bạn (để trống = ai cũng dùng được) | ❌ |
| `PROXY_LIST` | Danh sách proxy cách nhau bằng dấu phẩy: `ip:port,ip:port` | ❌ (khuyến nghị) |

### 3. Lưu ý quan trọng về Proxy

Khi deploy trên cloud (Railway, Render, v.v.), **tất cả request đều đến từ cùng 1 IP**. TikTok sẽ rate-limit rất nhanh → view không lên.

**Giải pháp**: Thêm danh sách proxy vào biến môi trường `PROXY_LIST`:

```
PROXY_LIST=1.2.3.4:8080,5.6.7.8:3128,9.10.11.12:1080
```

Hoặc dùng lệnh `/addproxy` trong Telegram sau khi bot chạy.

---

## Các cải tiến so với phiên bản cũ

1. **Sửa lỗi chữ ký (X-Gorgon)**: Chữ ký giờ được tính đúng trên dữ liệu form-encoded và cookie string — lý do chính khiến view không lên trước đây.
2. **Multiple endpoints**: Bot luân phiên qua 4 endpoint TikTok để giảm bị block.
3. **Quản lý proxy qua Telegram**: Thêm/xóa/xem proxy trực tiếp qua chat.
4. **Proxy từ env**: Load proxy tự động từ biến môi trường `PROXY_LIST` khi khởi động.
5. **Workers mặc định 300**: Phù hợp hơn cho môi trường cloud (trước là 1500 có thể gây OOM).
6. **Giới hạn kết nối hợp lý**: Tránh bị Railway/Render kill do dùng quá nhiều file descriptor.

---

## Chạy local

```bash
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="your_token_here"
export PROXY_LIST="ip1:port1,ip2:port2"   # tùy chọn
python bot.py
```
