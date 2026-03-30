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

async function registerWebhook() {
  const renderUrl = process.env.RENDER_EXTERNAL_URL ?? process.env.RENDER_URL;

  try {
    await bot.telegram.deleteWebhook({ drop_pending_updates: true });
    logger.info("Cleared existing webhook and dropped pending updates");
  } catch (err) {
    logger.warn({ err }, "Could not delete existing webhook");
  }

  if (!renderUrl) {
    bot.launch({ dropPendingUpdates: true });
    logger.info("Development mode: started long polling");
    return false;
  }

  const webhookUrl = `${renderUrl}/api/telegram/webhook`;

  try {
    await bot.telegram.setWebhook(webhookUrl, {
      drop_pending_updates: true,
      max_connections: 1,
    });
    logger.info({ webhookUrl }, "Telegram webhook registered");
    return true;
  } catch (err) {
    logger.error({ err }, "Failed to register Telegram webhook");
    return false;
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

function gracefulShutdown(signal: string) {
  logger.info({ signal }, "Received shutdown signal, closing server...");

  bot.stop(signal);

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
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

process.on("uncaughtException", (err) => {
  logger.error({ err }, "Uncaught exception");
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  logger.error({ reason }, "Unhandled promise rejection");
  process.exit(1);
});
