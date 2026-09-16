export interface SecurityManagerOptions {
  capacity?: number;
  refillRate?: number;
  banThreshold?: number;
  banDurationMs?: number;
}

export interface AllowedResult {
  allowed: boolean;
  reason?: string;
  tokensRemaining?: number;
  score: number;
}

export interface Bucket {
  tokens: number;
  lastRefill: number;
}

export interface Reputation {
  score: number;
  bannedUntil: number;
}

export class SecurityManager {
  private capacity: number;
  private refillRate: number;
  private banThreshold: number;
  private banDurationMs: number;
  private buckets: Map<string, Bucket>;
  private reputation: Map<string, Reputation>;

  constructor(options: SecurityManagerOptions = {}) {
    this.capacity = options.capacity || 100;
    this.refillRate = options.refillRate || 10;
    this.banThreshold = options.banThreshold || 0;
    this.banDurationMs = options.banDurationMs || 15 * 60 * 1000;

    this.buckets = new Map();
    this.reputation = new Map();
  }

  public isAllowed(ip: string): AllowedResult {
    const now = Date.now();

    const rep = this.getReputation(ip);
    if (rep.bannedUntil > now) {
      return { allowed: false, reason: "IP_BANNED", score: rep.score };
    }

    const bucket = this.getBucket(ip, now);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, tokensRemaining: Math.floor(bucket.tokens), score: rep.score };
    }

    this.penalize(ip, 10, "RATE_LIMIT_EXCEEDED");
    return { allowed: false, reason: "RATE_LIMITED", score: rep.score };
  }

  private getBucket(ip: string, now: number): Bucket {
    if (!this.buckets.has(ip)) {
      this.buckets.set(ip, { tokens: this.capacity, lastRefill: now });
    }

    const bucket = this.buckets.get(ip)!;
    const timePassedSec = (now - bucket.lastRefill) / 1000;

    bucket.tokens = Math.min(this.capacity, bucket.tokens + timePassedSec * this.refillRate);
    bucket.lastRefill = now;

    return bucket;
  }

  public getReputation(ip: string): Reputation {
    if (!this.reputation.has(ip)) {
      this.reputation.set(ip, { score: 100, bannedUntil: 0 });
    }
    return this.reputation.get(ip)!;
  }

  public penalize(ip: string, points: number, reason: string): void {
    const rep = this.getReputation(ip);
    rep.score = Math.max(0, rep.score - points);

    if (rep.score <= this.banThreshold) {
      rep.bannedUntil = Date.now() + this.banDurationMs;
      console.warn(`[SECURITY] IP ${ip} BANNED for ${this.banDurationMs / 1000}s. Reason: ${reason}`);
    }
  }

  public getMetrics(): { trackedIPs: number; activeBans: number } {
    const now = Date.now();
    let bannedCount = 0;

    for (const [_, data] of this.reputation) {
      if (data.bannedUntil > now) bannedCount++;
    }

    return {
      trackedIPs: this.buckets.size,
      activeBans: bannedCount,
    };
  }
}