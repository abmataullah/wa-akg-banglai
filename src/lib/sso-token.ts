import { createHmac, randomBytes, timingSafeEqual } from "crypto";

/**
 * One-time SSO tokens: HMAC-SHA256 signed with AUTH_SECRET, valid for 60 seconds, single use.
 * Issued by POST /api/auth/sso-token (SUPERADMIN, or RESELLER for its own sub-users),
 * redeemed by the "sso" credentials provider via /auth/sso?token=...
 */
const TTL_SECONDS = 60;
const usedTokens = new Map<string, number>(); // jti -> expiry (ms)

function secret(): string {
    const s = process.env.AUTH_SECRET;
    if (!s) throw new Error("AUTH_SECRET is not set");
    return s;
}

function sign(payload: string): string {
    return createHmac("sha256", secret()).update(payload).digest("base64url");
}

export function createSsoToken(userId: string): string {
    const payload = Buffer.from(JSON.stringify({
        sub: userId,
        jti: randomBytes(16).toString("base64url"),
        exp: Math.floor(Date.now() / 1000) + TTL_SECONDS,
    })).toString("base64url");
    return `${payload}.${sign(payload)}`;
}

/** Returns the user id if the token is valid, unexpired and unused; otherwise null. */
export function redeemSsoToken(token: string): string | null {
    const [payload, sig] = (token || "").split(".");
    if (!payload || !sig) return null;
    const expected = Buffer.from(sign(payload));
    const given = Buffer.from(sig);
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;

    let data: { sub?: string; jti?: string; exp?: number };
    try {
        data = JSON.parse(Buffer.from(payload, "base64url").toString());
    } catch {
        return null;
    }
    const now = Date.now();
    if (!data.sub || !data.jti || !data.exp || data.exp * 1000 < now) return null;

    for (const [jti, exp] of usedTokens) if (exp < now) usedTokens.delete(jti);
    if (usedTokens.has(data.jti)) return null;
    usedTokens.set(data.jti, data.exp * 1000);
    return data.sub;
}
