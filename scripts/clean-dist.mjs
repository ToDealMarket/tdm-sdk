import { rm } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const DIST_PATH = join(process.cwd(), "dist");
const MAX_ATTEMPTS = 12;
const BASE_DELAY_MS = 120;
const MAX_DELAY_MS = 2_000;
const RETRYABLE_CODES = new Set(["EBUSY", "EPERM", "ENOTEMPTY", "UNKNOWN"]);

function isRetryableWindowsCleanupError(error) {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code =
    "code" in error && typeof error.code === "string" ? error.code : "";

  return RETRYABLE_CODES.has(code);
}

function formatErrorMessage(error) {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message.trim();
  }
  return String(error);
}

function getDelayForAttempt(attempt) {
  return Math.min(BASE_DELAY_MS * 2 ** attempt, MAX_DELAY_MS);
}

async function removeDistWithRetry() {
  let lastError = null;

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
    try {
      await rm(DIST_PATH, {
        recursive: true,
        force: true,
        maxRetries: 0,
      });
      return;
    } catch (error) {
      lastError = error;

      if (!isRetryableWindowsCleanupError(error)) {
        throw error;
      }

      const delayMs = getDelayForAttempt(attempt);
      await sleep(delayMs);
    }
  }

  throw lastError;
}

async function main() {
  try {
    await removeDistWithRetry();
  } catch (error) {
    const details = formatErrorMessage(error);
    const code =
      error &&
      typeof error === "object" &&
      "code" in error &&
      typeof error.code === "string"
        ? error.code
        : "UNKNOWN";

    console.error(`[TDM] Failed to clean dist after ${MAX_ATTEMPTS} attempts.`);
    console.error(`[TDM] Path: ${DIST_PATH}`);
    console.error(`[TDM] Error: ${details}`);

    if (code === "EBUSY" || code === "EPERM") {
      console.error(
        "[TDM] A file in dist is still locked. Close any running TDM CLI, launcher, watcher, terminal session, or editor process using dist/bin/cli.cjs and try again.",
      );
    }

    process.exitCode = 1;
  }
}

await main();
