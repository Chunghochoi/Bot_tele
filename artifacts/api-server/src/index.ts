import app from "./app";
import { logger } from "./lib/logger";
import { bot } from "./routes/telegram";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

async function startPolling(): Promise<void> {
  const MAX_RETRIES = 5;
  let attempt = 0;

  while (attempt < MAX_RETRIES) {
    try {
      logger.info({ attempt: attempt + 1 }, "Starting long polling...");
      await bot.launch({ dropPendingUpdates: true });
      return;
    } catch (err) {
      attempt++;
      const delay = Math.min(5000 * attempt, 30_000);
      logger.error({ err, attempt, retryInMs: delay }, "Polling failed, retrying...");
      if (attempt >= MAX_RETRIES) {
        logger.error("Max polling retries reached. Bot polling will not start.");
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}

async function registerWebhook(): Promise<void> {
  const renderUrl = process.env.RENDER_EXTERNAL_URL ?? process.env.RENDER_URL;

  try {
    await bot.telegram.deleteWebhook({ drop_pending_updates: true });
    logger.info("Cleared existing webhook and dropped pending updates");
  } catch (err) {
    logger.warn({ err }, "Could not delete existing webhook");
  }

  if (!renderUrl) {
    logger.info("No RENDER_EXTERNAL_URL set — starting long polling mode");
    startPolling().catch((err) => {
      logger.error({ err }, "Polling startup error (non-fatal)");
    });
    return;
  }

  const webhookUrl = `${renderUrl}/api/telegram/webhook`;

  try {
    await bot.telegram.setWebhook(webhookUrl, {
      drop_pending_updates: true,
      max_connections: 1,
    });
    logger.info({ webhookUrl }, "Telegram webhook registered");
  } catch (err) {
    logger.error({ err }, "Failed to register Telegram webhook");
  }
}

const server = app.listen(port, async (err?: Error) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");

  await registerWebhook();
});

function gracefulShutdown(signal: string): void {
  logger.info({ signal }, "Received shutdown signal, closing server...");

  try {
    bot.stop(signal);
  } catch (_) {}

  server.close((err) => {
    if (err) {
      logger.error({ err }, "Error during server close");
      process.exit(1);
    }
    logger.info("Server closed gracefully");
    process.exit(0);
  });

  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10_000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT",  () => gracefulShutdown("SIGINT"));

process.on("uncaughtException", (err) => {
  logger.error({ err }, "Uncaught exception");
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  logger.error({ reason }, "Unhandled promise rejection (non-fatal, continuing...)");
  // Không exit — chỉ log để server không crash vì lỗi phụ
});
