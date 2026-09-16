export class SecurityManager {
  constructor(options = {}) {
    this.capacity = options.capacity || 100; // Maximum token capacity
    this.refillRate = options.refillRate || 10; // Tokens added per second
    this.banThreshold = options.banThreshold || 0; // Reputation score floor for banning
    this.banDurationMs = options.banDurationMs || 15 * 60 * 1000; // 15-minute ban

    // Storage maps
    this.buckets = new Map(); // ip -> { tokens, lastRefill }
    this.reputation = new Map(); // ip -> { score, bannedUntil }
  }

  /**
   * Evaluates whether an incoming IP connection is allowed.
   */
  isAllowed(ip) {
    const now = Date.now();

    // 1. Check existing IP ban status
    const rep = this.getReputation(ip);
    if (rep.bannedUntil > now) {
      return { allowed: false, reason: "IP_BANNED", score: rep.score };
    }

    // 2. Consume token bucket
    const bucket = this.getBucket(ip, now);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, tokensRemaining: Math.floor(bucket.tokens), score: rep.score };
    }

    // 3. Rate limit exceeded: penalize IP reputation
    this.penalize(ip, 10, "RATE_LIMIT_EXCEEDED");
    return { allowed: false, reason: "RATE_LIMITED", score: rep.score };
  }

  /**
   * Calculates and refills token balance for an IP address.
   */
  getBucket(ip, now) {
    if (!this.buckets.has(ip)) {
      this.buckets.set(ip, { tokens: this.capacity, lastRefill: now });
    }

    const bucket = this.buckets.get(ip);
    const timePassedSec = (now - bucket.lastRefill) / 1000;
    
    // Refill tokens based on elapsed time
    bucket.tokens = Math.min(this.capacity, bucket.tokens + timePassedSec * this.refillRate);
    bucket.lastRefill = now;
    
    return bucket;
  }

  /**
   * Retrieves or initializes IP reputation score (default: 100).
   */
  getReputation(ip) {
    if (!this.reputation.has(ip)) {
      this.reputation.set(ip, { score: 100, bannedUntil: 0 });
    }
    return this.reputation.get(ip);
  }

  /**
   * Deducts points from an IP and triggers auto-bans if score drops below threshold.
   */
  penalize(ip, points, reason) {
    const rep = this.getReputation(ip);
    rep.score = Math.max(0, rep.score - points);

    if (rep.score <= this.banThreshold) {
      rep.bannedUntil = Date.now() + this.banDurationMs;
      console.warn(`[SECURITY] IP ${ip} BANNED for ${this.banDurationMs / 1000}s. Reason: ${reason}`);
    }
  }

  /**
   * Returns current statistics for telemetry endpoints (Port 9091).
   */
  getMetrics() {
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