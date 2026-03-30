import { Router, type IRouter, type Request, type Response } from "express";
import { Telegraf, Markup } from "telegraf";
import { message } from "telegraf/filters";
import { TikTokViewTask, MultiTikTokTask, getVideoId, type ViewStats } from "../lib/tiktok-viewer.js";
import {
  getProxyStats,
  getServerIp,
  addProxiesFromText,
  clearDynamicProxies,
  resetBlacklist,
  testProxiesBatch,
  STATIC_PROXIES_EXPORT,
  DYNAMIC_PROXIES_EXPORT,
} from "../lib/proxy-manager.js";

const router: IRouter = Router();

const token = process.env.TELEGRAM_BOT_TOKEN;
if (!token) throw new Error("TELEGRAM_BOT_TOKEN is not set");

export const bot = new Telegraf(token);

// ═══════════════════════════════════════════════════
// PER-USER TASK STORE + AUTO-STATUS TIMER
// ═══════════════════════════════════════════════════
const tasks      = new Map<number, TikTokViewTask>();
const multiTasks = new Map<number, MultiTikTokTask>();
const autoTimer  = new Map<number, ReturnType<typeof setInterval>>();

function stopAutoStatus(chatId: number): void {
  const timer = autoTimer.get(chatId);
  if (timer) {
    clearInterval(timer);
    autoTimer.delete(chatId);
  }
}

function startAutoStatus(chatId: number, intervalSec: number): void {
  stopAutoStatus(chatId);
  const timer = setInterval(async () => {
    const task = tasks.get(chatId);
    if (!task) { stopAutoStatus(chatId); return; }
    const stats = task.getStats();
    if (stats.status !== "running") { stopAutoStatus(chatId); return; }
    try {
      await bot.telegram.sendMessage(chatId, formatStats(stats), { parse_mode: "HTML" });
    } catch {
      stopAutoStatus(chatId);
    }
  }, intervalSec * 1000);
  autoTimer.set(chatId, timer);
}

// ═══════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

function formatStats(stats: ViewStats): string {
  const statusIcon = stats.status === "running" ? "🟢" : "🔴";
  const statusText = stats.status === "running" ? "Đang chạy" : "Đã dừng";
  const bar = buildSpeedBar(stats.viewsPerSecond);

  return (
    `<b>📊 SPY VIEW BOT PRO</b>\n\n` +
    `${statusIcon} <b>${statusText}</b> • ${formatDuration(stats.elapsedSeconds)}\n` +
    `🎯 Video: <code>${stats.videoId}</code>\n\n` +
    `👀 <b>Tổng view:</b> ${stats.totalViews.toLocaleString()}\n` +
    `⚡ <b>Tốc độ:</b> ${stats.viewsPerSecond} v/s  ${bar}\n` +
    `🏆 <b>Đỉnh:</b> ${stats.peakSpeed} v/s\n` +
    `📈 <b>Dự kiến:</b> ~${Number(stats.viewsPerMinute).toLocaleString()} v/phút\n` +
    `🔧 <b>Workers:</b> ${stats.currentWorkers}\n\n` +
    `✅ Thành công: ${stats.successfulRequests.toLocaleString()}  ` +
    `❌ Thất bại: ${stats.failedRequests.toLocaleString()}\n` +
    `📊 Tỷ lệ: <b>${stats.successRate}%</b>`
  );
}

function buildSpeedBar(vps: number): string {
  const max = 300;
  const filled = Math.min(10, Math.round((vps / max) * 10));
  return "█".repeat(filled) + "░".repeat(10 - filled);
}

function mainKeyboard() {
  return Markup.keyboard([
    ["/status", "/stop_bot"],
    ["/proxy list", "/speed"],
    ["/auto 60", "/check_proxy"],
  ]).resize();
}

// ═══════════════════════════════════════════════════
// /start
// ═══════════════════════════════════════════════════
bot.start(async (ctx) => {
  const px = getProxyStats();
  const serverIp = await getServerIp();
  const dynamicLine = px.dynamic > 0 ? `  • Custom: <b>${px.dynamic}</b>\n` : "";

  await ctx.replyWithHTML(
    `👋 Xin chào <b>${ctx.from?.first_name ?? "bạn"}</b>!\n\n` +
    `🤖 <b>SPY VIEW BOT PRO</b> sẵn sàng!\n\n` +
    `🖥 IP Server: <code>${serverIp}</code>\n\n` +
    `🌐 <b>Proxy Pool:</b> ${px.total} proxy (${px.active} active)\n` +
    dynamicLine +
    `  • HTTP: ${px.http}  • SOCKS4: ${px.socks4}  • SOCKS5: ${px.socks5}\n\n` +
    `📌 <b>Lệnh chính:</b>\n` +
    `/start_bot &lt;url&gt; — Bắt đầu buff view\n` +
    `/stop_bot — Dừng nhiệm vụ\n` +
    `/status — Thống kê chi tiết\n` +
    `/speed &lt;số&gt; — Đổi số workers\n` +
    `/auto &lt;giây&gt; — Bật auto-báo cáo\n` +
    `/proxy — Quản lý proxy\n` +
    `/check_proxy — Kiểm tra proxy sống`,
    mainKeyboard(),
  );
});

// ═══════════════════════════════════════════════════
// /start_bot <url>
// ═══════════════════════════════════════════════════
bot.command("start_bot", async (ctx) => {
  const chatId = ctx.chat.id;
  const args = ctx.message.text.split(" ").slice(1);
  const url = args[0];

  if (!url) {
    return ctx.replyWithHTML(
      "⚠️ Thiếu đường link!\n\nVí dụ:\n<code>/start_bot https://vt.tiktok.com/xxx</code>"
    );
  }

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return ctx.reply("⚠️ Link không hợp lệ. Phải bắt đầu bằng https://");
  }

  const existing = tasks.get(chatId);
  if (existing) {
    const s = existing.getStats();
    if (s.status === "running") {
      return ctx.replyWithHTML(
        `⚠️ <b>Đang có nhiệm vụ chạy!</b>\n\n` +
        `👀 View đã gửi: <b>${s.totalViews.toLocaleString()}</b>\n` +
        `⚡ Tốc độ: ${s.viewsPerSecond} v/s\n\n` +
        `Dùng /stop_bot để dừng trước.`
      );
    }
  }

  const processingMsg = await ctx.replyWithHTML(
    `🔍 Đang lấy Video ID từ link...\n<code>${url}</code>`
  );

  const videoId = await getVideoId(url);

  if (!videoId) {
    await ctx.telegram.editMessageText(
      chatId, processingMsg.message_id, undefined,
      `❌ Không thể lấy Video ID!\n\nKiểm tra lại link:\n${url}`
    );
    return;
  }

  const workerCount = 150;
  const task = new TikTokViewTask(videoId, url, workerCount);
  tasks.set(chatId, task);
  task.start();

  const px = getProxyStats();
  await ctx.telegram.editMessageText(
    chatId, processingMsg.message_id, undefined,
    `✅ Đã bắt đầu nhiệm vụ!\n\n` +
    `🎯 Video ID: ${videoId}\n` +
    `🔗 Link: ${url}\n` +
    `⚙️ Workers: ${workerCount} (adaptive)\n` +
    `🌐 Proxy: ${px.active}/${px.total} active\n\n` +
    `Dùng /status để xem tiến độ\nDùng /stop_bot để dừng\nDùng /auto 60 để bật tự báo cáo mỗi 60s`,
  );
});

// ═══════════════════════════════════════════════════
// /stop_bot
// ═══════════════════════════════════════════════════
bot.command("stop_bot", async (ctx) => {
  const chatId = ctx.chat.id;
  const task = tasks.get(chatId);
  stopAutoStatus(chatId);

  if (!task) {
    return ctx.reply("ℹ️ Không có nhiệm vụ nào đang chạy.");
  }

  const stats = task.getStats();
  if (stats.status !== "running") {
    return ctx.reply("ℹ️ Nhiệm vụ đã dừng trước đó.");
  }

  task.stop();
  const finalStats = task.getStats();

  await ctx.replyWithHTML(
    `🛑 <b>Đã dừng nhiệm vụ!</b>\n\n` +
    `👀 Tổng view đã gửi: <b>${finalStats.totalViews.toLocaleString()}</b>\n` +
    `⚡ Tốc độ trung bình: ${finalStats.viewsPerSecond} v/s\n` +
    `🏆 Tốc độ cao nhất: ${finalStats.peakSpeed} v/s\n` +
    `✅ Thành công: ${finalStats.successfulRequests.toLocaleString()}\n` +
    `❌ Thất bại: ${finalStats.failedRequests.toLocaleString()}\n` +
    `📊 Tỷ lệ: ${finalStats.successRate}%\n` +
    `⏱ Thời gian chạy: ${formatDuration(finalStats.elapsedSeconds)}`
  );
});

// ═══════════════════════════════════════════════════
// /status
// ═══════════════════════════════════════════════════
bot.command("status", async (ctx) => {
  const chatId = ctx.chat.id;
  const task = tasks.get(chatId);

  if (!task) {
    return ctx.reply("ℹ️ Chưa có nhiệm vụ nào.\n\nDùng /start_bot <url> để bắt đầu.");
  }

  await ctx.replyWithHTML(formatStats(task.getStats()));
});

// ═══════════════════════════════════════════════════
// /speed <n> — đổi số workers
// ═══════════════════════════════════════════════════
bot.command("speed", async (ctx) => {
  const chatId = ctx.chat.id;
  const args = ctx.message.text.split(" ").slice(1);
  const task = tasks.get(chatId);

  if (!args[0]) {
    const current = task ? task.getStats().currentWorkers : 150;
    return ctx.replyWithHTML(
      `⚙️ <b>Điều chỉnh số workers</b>\n\n` +
      `Hiện tại: <b>${current} workers</b>\n\n` +
      `Dùng: <code>/speed &lt;số&gt;</code>\n` +
      `Ví dụ: <code>/speed 200</code>\n` +
      `Phạm vi: 50 – 300`
    );
  }

  const n = parseInt(args[0], 10);
  if (isNaN(n) || n < 50 || n > 300) {
    return ctx.reply("⚠️ Số workers phải từ 50 đến 300.");
  }

  if (!task || task.getStats().status !== "running") {
    return ctx.reply("ℹ️ Không có nhiệm vụ nào đang chạy để điều chỉnh.");
  }

  task.setWorkers(n);
  return ctx.replyWithHTML(`✅ Đã đặt workers thành <b>${n}</b>. Hệ thống sẽ tự điều chỉnh.`);
});

// ═══════════════════════════════════════════════════
// /auto <giây> | /auto off — tự động báo cáo định kỳ
// ═══════════════════════════════════════════════════
bot.command("auto", async (ctx) => {
  const chatId = ctx.chat.id;
  const args = ctx.message.text.split(" ").slice(1);

  if (!args[0] || args[0] === "off") {
    stopAutoStatus(chatId);
    return ctx.reply("🔕 Đã tắt báo cáo tự động.");
  }

  const sec = parseInt(args[0], 10);
  if (isNaN(sec) || sec < 10 || sec > 3600) {
    return ctx.reply("⚠️ Khoảng thời gian phải từ 10 đến 3600 giây.");
  }

  const task = tasks.get(chatId);
  if (!task || task.getStats().status !== "running") {
    return ctx.reply("ℹ️ Không có nhiệm vụ đang chạy.");
  }

  startAutoStatus(chatId, sec);
  return ctx.replyWithHTML(`🔔 Đã bật báo cáo tự động mỗi <b>${sec}s</b>. Dùng /auto off để tắt.`);
});

// ═══════════════════════════════════════════════════
// /proxy — quản lý proxy
// ═══════════════════════════════════════════════════
bot.command("proxy", async (ctx) => {
  const text = ctx.message.text;
  const afterCommand = text.replace(/^\/proxy\s*/i, "").trim();

  if (!afterCommand || afterCommand === "list") {
    const px = getProxyStats();
    const serverIp = await getServerIp();
    return ctx.replyWithHTML(
      `🌐 <b>Proxy Pool</b>\n\n` +
      `🖥 IP Server: <code>${serverIp}</code>\n` +
      `📦 Tổng: <b>${px.total}</b>  ✅ Active: <b>${px.active}</b>  🚫 Blacklist: <b>${px.blacklisted}</b>\n` +
      `  • Custom: ${px.dynamic}\n` +
      `  • HTTP: ${px.http}  SOCKS4: ${px.socks4}  SOCKS5: ${px.socks5}\n\n` +
      `📊 Hiệu suất proxy: ${px.overallRate}% thành công\n` +
      `  ✅ ${px.totalSuccess.toLocaleString()} thành công  ❌ ${px.totalFail.toLocaleString()} thất bại\n\n` +
      `📌 <b>Lệnh:</b>\n` +
      `/proxy &lt;danh sách&gt; — Thêm proxy\n` +
      `/proxy clear — Xóa proxy custom\n` +
      `/proxy reset — Xóa blacklist\n` +
      `/check_proxy — Test proxy\n\n` +
      `<b>Định dạng:</b>\n` +
      `  ip:port\n` +
      `  ip:port:user:pass\n` +
      `  socks4://ip:port\n` +
      `  socks5://user:pass@ip:port`
    );
  }

  if (afterCommand === "clear") {
    const removed = clearDynamicProxies();
    return ctx.reply(
      removed > 0
        ? `🗑 Đã xóa ${removed} proxy custom.\n\nPool còn lại: ${getProxyStats().static} proxy tĩnh.`
        : `ℹ️ Không có proxy custom nào để xóa.`
    );
  }

  if (afterCommand === "reset") {
    const recovered = resetBlacklist();
    const px = getProxyStats();
    return ctx.replyWithHTML(
      `♻️ Đã reset blacklist: <b>${recovered}</b> proxy được phục hồi.\n` +
      `📦 Pool active: <b>${px.active}/${px.total}</b>`
    );
  }

  // Add proxies
  const result = addProxiesFromText(afterCommand);
  const px = getProxyStats();

  if (result.added === 0) {
    return ctx.reply(
      `❌ Không thể parse proxy nào.\n\nĐịnh dạng hỗ trợ:\n  ip:port\n  ip:port:user:pass\n  socks4://ip:port\n  socks5://ip:port\n  socks5://user:pass@ip:port`
    );
  }

  return ctx.replyWithHTML(
    `✅ Đã thêm <b>${result.added}</b> proxy!` +
    (result.failed > 0 ? ` (${result.failed} dòng lỗi bỏ qua)` : "") +
    `\n\n📦 Pool: <b>${px.total}</b> proxy (${px.active} active)\n` +
    `💡 Proxy custom được ưu tiên & chọn theo điểm hiệu suất.`
  );
});

// ═══════════════════════════════════════════════════
// /check_proxy — test một batch proxy
// ═══════════════════════════════════════════════════
bot.command("check_proxy", async (ctx) => {
  const chatId = ctx.chat.id;
  const args = ctx.message.text.split(" ").slice(1);
  const sampleSize = Math.min(30, parseInt(args[0] ?? "20", 10) || 20);

  const msg = await ctx.replyWithHTML(
    `🔍 Đang test <b>${sampleSize}</b> proxy ngẫu nhiên...\nVui lòng chờ (~30s)`
  );

  const allProxies = [...(DYNAMIC_PROXIES_EXPORT() || []), ...STATIC_PROXIES_EXPORT()];
  const sample = allProxies.sort(() => Math.random() - 0.5).slice(0, sampleSize);

  let done = 0;
  const { alive, dead } = await testProxiesBatch(sample, 10, (d) => {
    done = d;
  });

  const rate = sampleSize > 0 ? ((alive / sampleSize) * 100).toFixed(1) : "0";
  const px = getProxyStats();

  await ctx.telegram.editMessageText(
    chatId, msg.message_id, undefined,
    `✅ Kết quả test ${sampleSize} proxy:\n\n` +
    `🟢 Sống: ${alive}  🔴 Chết: ${dead}  (${rate}%)\n\n` +
    `📦 Pool active sau test: ${px.active}/${px.total}\n` +
    `🚫 Bị blacklist: ${px.blacklisted}\n\n` +
    `Dùng /proxy reset để phục hồi proxy bị blacklist.`,
    { parse_mode: "HTML" }
  );
});

// ═══════════════════════════════════════════════════
// /multi_start — Buff SIÊU CẤP nhiều video cùng lúc
// ═══════════════════════════════════════════════════
bot.command("multi_start", async (ctx) => {
  const chatId = ctx.chat.id;
  const text = ctx.message.text;
  const rawArgs = text.replace(/^\/multi_start\s*/i, "").trim().split(/\s+/).filter(Boolean);

  // Parse: url[:workers] pairs
  const pairs: Array<{url: string; workers: number}> = [];
  for (const arg of rawArgs) {
    const colonIdx = arg.lastIndexOf(":");
    if (colonIdx !== -1) {
      const maybeNum = parseInt(arg.slice(colonIdx + 1), 10);
      if (!isNaN(maybeNum) && maybeNum >= 10 && maybeNum <= 500) {
        pairs.push({ url: arg.slice(0, colonIdx), workers: maybeNum });
        continue;
      }
    }
    pairs.push({ url: arg, workers: 100 });
  }

  if (pairs.length === 0) {
    return ctx.replyWithHTML(
      `❌ <b>Thiếu URL video!</b>\n\n` +
      `Cách dùng:\n` +
      `<code>/multi_start url1 url2 url3</code>\n\n` +
      `Hoặc đặt số luồng riêng cho từng video:\n` +
      `<code>/multi_start url1:100 url2:150 url3:80</code>\n\n` +
      `Tối đa <b>10 video</b> cùng lúc.`
    );
  }

  if (pairs.length > 10) {
    return ctx.reply(`❌ Tối đa 10 video cùng lúc. Bạn nhập ${pairs.length}.`);
  }

  // Stop existing single task if any
  const existing = tasks.get(chatId);
  if (existing) { existing.stop(); tasks.delete(chatId); }

  // Get or create multi-task manager
  const manager = multiTasks.get(chatId) ?? new MultiTikTokTask();
  if (!multiTasks.has(chatId)) multiTasks.set(chatId, manager);

  const msg = await ctx.replyWithHTML(
    `⏳ Đang xử lý <b>${pairs.length}</b> video URL...\nĐang resolve video IDs...`
  );

  let added = 0, failed = 0;
  const lines: string[] = [];

  for (let i = 0; i < pairs.length; i++) {
    const { url, workers } = pairs[i];
    try {
      const vid = await getVideoId(url);
      if (!vid) { failed++; lines.push(`❌ ${i+1}. Không tìm thấy ID — ${url.slice(0, 40)}`); continue; }
      const ok = manager.addTask(vid, url, workers);
      if (ok) { added++; lines.push(`✅ ${i+1}. Video <code>${vid}</code> — ${workers} luồng`); }
      else { lines.push(`⚠️ ${i+1}. Video <code>${vid}</code> — Đang chạy rồi, bỏ qua`); }
    } catch { failed++; lines.push(`❌ ${i+1}. Lỗi kết nối — ${url.slice(0, 40)}`); }
  }

  const stats = manager.getAllStats();
  await ctx.telegram.editMessageText(
    chatId, msg.message_id, undefined,
    `🚀 <b>MULTI BUFF SIÊU CẤP BẮT ĐẦU!</b>\n\n` +
    lines.join("\n") + "\n\n" +
    `📊 Tổng task đang chạy: <b>${stats.activeTaskCount}/${stats.totalTaskCount}</b>\n` +
    `⚡ Tổng luồng: <b>${stats.totalWorkers}</b>\n\n` +
    `📌 Dùng /multi_status để xem chi tiết\n` +
    `/multi_stop &lt;số&gt; để dừng từng video`,
    { parse_mode: "HTML" }
  );
});

// ═══════════════════════════════════════════════════
// /multi_status — Trạng thái tất cả video đang buff
// ═══════════════════════════════════════════════════
bot.command("multi_status", async (ctx) => {
  const chatId = ctx.chat.id;
  const manager = multiTasks.get(chatId);

  if (!manager || manager.size() === 0) {
    return ctx.reply("📋 Không có multi-task nào đang chạy.\nDùng /multi_start để bắt đầu.");
  }

  const ms = manager.getAllStats();
  const lines: string[] = [];

  ms.tasks.forEach((t, i) => {
    const icon = t.status === "running" ? "🟢" : "🔴";
    lines.push(
      `${icon} <b>${i+1}. ${t.videoId}</b>\n` +
      `   👁 ${t.totalViews.toLocaleString()} views  ⚡ ${t.viewsPerSecond}/s  🏆 Peak ${t.peakSpeed}/s\n` +
      `   ✅ ${t.successRate}% thành công  🔧 ${t.currentWorkers} luồng`
    );
  });

  await ctx.replyWithHTML(
    `📊 <b>MULTI BUFF — CHI TIẾT</b>\n\n` +
    lines.join("\n\n") + "\n\n" +
    `━━━━━━━━━━━━━━━━━━━━━━\n` +
    `🔥 <b>TỔNG HỢP</b>\n` +
    `👁 Tổng views: <b>${ms.combinedViews.toLocaleString()}</b>\n` +
    `⚡ Tốc độ hiện tại: <b>${ms.combinedVps}/s</b> | ${(ms.combinedVps * 60).toFixed(0)}/phút\n` +
    `🏆 Peak: <b>${ms.combinedPeakVps}/s</b>\n` +
    `🔧 Tổng luồng: <b>${ms.totalWorkers}</b>\n` +
    `✅ Active: <b>${ms.activeTaskCount}/${ms.totalTaskCount}</b> task\n\n` +
    `/multi_stop &lt;số&gt; — Dừng task theo số thứ tự\n` +
    `/multi_stop all — Dừng tất cả`
  );
});

// ═══════════════════════════════════════════════════
// /multi_stop — Dừng một hoặc tất cả task
// ═══════════════════════════════════════════════════
bot.command("multi_stop", async (ctx) => {
  const chatId = ctx.chat.id;
  const manager = multiTasks.get(chatId);

  if (!manager || manager.size() === 0) {
    return ctx.reply("📋 Không có multi-task nào đang chạy.");
  }

  const arg = ctx.message.text.replace(/^\/multi_stop\s*/i, "").trim().toLowerCase();

  if (!arg || arg === "all") {
    const ms = manager.getAllStats();
    manager.stopAll();
    return ctx.replyWithHTML(
      `🛑 Đã dừng <b>tất cả ${ms.activeTaskCount}</b> task!\n\n` +
      `👁 Tổng views tích lũy: <b>${ms.combinedViews.toLocaleString()}</b>\n` +
      `⚡ Peak tốc độ: <b>${ms.combinedPeakVps}/s</b>\n\n` +
      `Dùng /multi_start để bắt đầu phiên mới.`
    );
  }

  const idx = parseInt(arg, 10) - 1; // 1-indexed → 0-indexed
  if (isNaN(idx)) return ctx.reply(`❌ Nhập số thứ tự task (1, 2, 3...) hoặc "all".`);
  const entry = manager.getTaskByIndex(idx);
  if (!entry) {
    const ms = manager.getAllStats();
    return ctx.reply(`❌ Không có task số ${idx + 1}. Hiện có ${ms.totalTaskCount} task.`);
  }

  const stats = entry.task.getStats();
  manager.removeTask(entry.videoId);
  return ctx.replyWithHTML(
    `✅ Đã dừng task <b>#${idx + 1}</b>: <code>${entry.videoId}</code>\n\n` +
    `👁 Views: <b>${stats.totalViews.toLocaleString()}</b>\n` +
    `⚡ Peak: <b>${stats.peakSpeed}/s</b>`
  );
});

// ═══════════════════════════════════════════════════
// /multi_speed — Điều chỉnh luồng cho tất cả task
// ═══════════════════════════════════════════════════
bot.command("multi_speed", async (ctx) => {
  const chatId = ctx.chat.id;
  const manager = multiTasks.get(chatId);
  if (!manager || manager.size() === 0) {
    return ctx.reply("📋 Không có multi-task nào đang chạy.");
  }
  const n = parseInt(ctx.message.text.replace(/^\/multi_speed\s*/i, "").trim(), 10);
  if (isNaN(n) || n < 10 || n > 500) {
    return ctx.reply("❌ Nhập số luồng từ 10–500.\nVí dụ: /multi_speed 150");
  }
  manager.setWorkersAll(n);
  return ctx.replyWithHTML(
    `⚡ Đã đặt <b>${n} luồng/video</b> cho tất cả task đang chạy.\n` +
    `📊 Tổng luồng ước tính: <b>${n * manager.getAllStats().activeTaskCount}</b>`
  );
});

// ═══════════════════════════════════════════════════
// /help — hiển thị trợ giúp
// ═══════════════════════════════════════════════════
bot.command("help", async (ctx) => {
  await ctx.replyWithHTML(
    `<b>📖 Hướng dẫn SPY VIEW BOT PRO</b>\n\n` +
    `<b>🚀 Buff view đơn:</b>\n` +
    `/start_bot &lt;url&gt; — Bắt đầu buff 1 video\n` +
    `/stop_bot — Dừng lại\n` +
    `/status — Xem trạng thái\n\n` +
    `<b>🔥 SIÊU CẤP — Buff nhiều video:</b>\n` +
    `/multi_start &lt;url1&gt; &lt;url2&gt; ... — Buff tối đa 10 video\n` +
    `/multi_start &lt;url1:100&gt; &lt;url2:200&gt; — Mỗi video 1 mức luồng\n` +
    `/multi_status — Xem chi tiết từng video\n` +
    `/multi_stop &lt;số&gt; — Dừng task theo số thứ tự\n` +
    `/multi_stop all — Dừng tất cả\n` +
    `/multi_speed &lt;n&gt; — Đặt n luồng cho mọi task\n\n` +
    `<b>⚙️ Điều chỉnh đơn:</b>\n` +
    `/speed &lt;50-500&gt; — Số luồng song song\n` +
    `/auto &lt;giây&gt; — Tự báo cáo định kỳ\n` +
    `/auto off — Tắt tự báo cáo\n\n` +
    `<b>🌐 Proxy:</b>\n` +
    `/proxy list — Xem pool proxy\n` +
    `/proxy &lt;list&gt; — Thêm proxy mới\n` +
    `/proxy clear — Xóa proxy custom\n` +
    `/proxy reset — Phục hồi proxy bị blacklist\n` +
    `/check_proxy &lt;n&gt; — Test n proxy ngẫu nhiên\n\n` +
    `<b>💡 Tip:</b> Dùng /multi_start để chạy 5-10 video song song với 100 luồng mỗi video → tốc độ cực đại!`
  );
});

// ═══════════════════════════════════════════════════
// CATCH-ALL
// ═══════════════════════════════════════════════════
bot.on(message("text"), (ctx) => {
  ctx.reply("❓ Không hiểu lệnh này. Dùng /help để xem danh sách lệnh.");
});

bot.catch((err, ctx) => {
  console.error(`Bot error for ${ctx.updateType}:`, err);
});

// ═══════════════════════════════════════════════════
// WEBHOOK ROUTES
// ═══════════════════════════════════════════════════
router.post("/webhook", async (req: Request, res: Response) => {
  try {
    await bot.handleUpdate(req.body);
    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error:", err);
    res.sendStatus(500);
  }
});

router.get("/webhook", (_req: Request, res: Response) => {
  res.json({ status: "Telegram webhook is active" });
});

export default router;
