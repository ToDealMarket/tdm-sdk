export interface Local402CircuitOptions {
  minBackoffMs?: number;
  maxBackoffMs?: number;
  maxStrikes?: number;
  gcIntervalMs?: number;
}

export interface Local402CircuitStatus {
  blocked: boolean;
  retryAfterMs: number;
}

interface CircuitEntry {
  strikes: number;
  blockedUntil: number;
  touchedAt: number;
}

const DEFAULT_MIN_BACKOFF_MS = 500;
const DEFAULT_MAX_BACKOFF_MS = 1_000;
const DEFAULT_MAX_STRIKES = 5;
const DEFAULT_GC_INTERVAL_MS = 60_000;
const ENTRY_TTL_MULTIPLIER = 3;

/**
 * Local in-memory 402 trap to prevent tight retry loops on the same operation key.
 * Key format should include exact operation + token/uuid identity.
 */
export class Local402Circuit {
  private readonly entries = new Map<string, CircuitEntry>();
  private readonly minBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly maxStrikes: number;
  private readonly gcTimer: ReturnType<typeof setInterval>;

  constructor(options: Local402CircuitOptions = {}) {
    this.minBackoffMs = options.minBackoffMs ?? DEFAULT_MIN_BACKOFF_MS;
    this.maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS;
    this.maxStrikes = options.maxStrikes ?? DEFAULT_MAX_STRIKES;
    const gcIntervalMs = options.gcIntervalMs ?? DEFAULT_GC_INTERVAL_MS;

    this.gcTimer = setInterval(() => {
      this.gc();
    }, gcIntervalMs);
    this.gcTimer.unref();
  }

  public static key(operation: string, tokenOrUuid: string): string {
    return `${operation}::${tokenOrUuid}`;
  }

  public check(key: string, now = Date.now()): Local402CircuitStatus {
    const entry = this.entries.get(key);
    if (!entry) {
      return { blocked: false, retryAfterMs: 0 };
    }

    entry.touchedAt = now;
    if (entry.blockedUntil <= now) {
      return { blocked: false, retryAfterMs: 0 };
    }

    return {
      blocked: true,
      retryAfterMs: Math.max(1, entry.blockedUntil - now),
    };
  }

  public record402(key: string, now = Date.now()): number {
    const existing = this.entries.get(key);
    const strikes = Math.min((existing?.strikes ?? 0) + 1, this.maxStrikes);
    const cooldown = Math.min(
      this.maxBackoffMs,
      this.minBackoffMs * 2 ** (strikes - 1),
    );

    this.entries.set(key, {
      strikes,
      blockedUntil: now + cooldown,
      touchedAt: now,
    });

    return cooldown;
  }

  public recordSuccess(key: string): void {
    this.entries.delete(key);
  }

  public reset(key: string): void {
    this.entries.delete(key);
  }

  public clear(): void {
    this.entries.clear();
  }

  public dispose(): void {
    clearInterval(this.gcTimer);
    this.clear();
  }

  private gc(now = Date.now()): void {
    const ttlMs = this.maxBackoffMs * ENTRY_TTL_MULTIPLIER;
    for (const [key, entry] of this.entries) {
      const staleSince = Math.max(entry.blockedUntil, entry.touchedAt);
      if (staleSince + ttlMs < now) {
        this.entries.delete(key);
      }
    }
  }
}

export const Global402Circuit = new Local402Circuit();
