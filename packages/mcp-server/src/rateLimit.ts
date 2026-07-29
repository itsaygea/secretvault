export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
}

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

class RateLimiter {
  private stores: Map<string, RateLimitRecord> = new Map();

  check(key: string, options: RateLimitOptions): { allowed: boolean; remaining: number; retryAfterSeconds: number } {
    const now = Date.now();
    const record = this.stores.get(key);

    if (!record || now >= record.resetTime) {
      this.stores.set(key, { count: 1, resetTime: now + options.windowMs });
      return { allowed: true, remaining: options.maxRequests - 1, retryAfterSeconds: 0 };
    }

    if (record.count >= options.maxRequests) {
      const retryAfterSeconds = Math.ceil((record.resetTime - now) / 1000);
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }

    record.count += 1;
    return {
      allowed: true,
      remaining: options.maxRequests - record.count,
      retryAfterSeconds: 0,
    };
  }

  reset(key: string): void {
    this.stores.delete(key);
  }

  clear(): void {
    this.stores.clear();
  }
}

export const rateLimiter = new RateLimiter();

export function getClientIp(req: { headers: Record<string, string | string[] | undefined>; socket?: { remoteAddress?: string } }): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0]?.trim() || "127.0.0.1";
  }
  return req.socket?.remoteAddress || "127.0.0.1";
}
