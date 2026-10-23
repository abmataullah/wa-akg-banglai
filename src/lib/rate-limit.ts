/**
 * Small in-memory fixed-window rate limiter (single-instance deployment).
 * Returns true if the action is allowed, false if the key exceeded `limit` within `windowMs`.
 */
const buckets = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    if (buckets.size > 10000) {
        for (const [k, b] of buckets) if (b.resetAt < now) buckets.delete(k);
    }
    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt < now) {
        buckets.set(key, { count: 1, resetAt: now + windowMs });
        return true;
    }
    bucket.count++;
    return bucket.count <= limit;
}
