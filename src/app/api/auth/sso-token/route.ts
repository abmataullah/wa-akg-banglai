import { NextResponse, NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser, canManageUser } from "@/lib/api-auth";
import { createSsoToken } from "@/lib/sso-token";

/**
 * POST /api/auth/sso-token
 * Issue a one-time login link (valid 60 s, single use) for a user.
 *
 * Auth: x-api-key of a SUPERADMIN, or of a RESELLER for its own sub-users
 *       (e.g. amarshowroom.com opening a seller's WA dashboard).
 * Body: { userId } or { email }
 * Returns: { token, url }  -> redirect the browser to `url`.
 *
 * Replaces the old POST /api/auth/sso, which verified passwords sent from other apps.
 */
export async function POST(req: NextRequest) {
    const actor = await getAuthenticatedUser(req);
    if (!actor) {
        return NextResponse.json({ status: false, message: "Unauthorized" }, { status: 401 });
    }

    let body: { userId?: string; email?: string };
    try {
        body = await req.json();
    } catch {
        return NextResponse.json({ status: false, message: "Invalid JSON body" }, { status: 400 });
    }

    const target = body.userId
        ? await prisma.user.findUnique({ where: { id: body.userId }, select: { id: true } })
        : body.email
            ? await prisma.user.findUnique({ where: { email: body.email.toLowerCase() }, select: { id: true } })
            : null;

    if (!target || !(await canManageUser(actor.id, actor.role, target.id))) {
        return NextResponse.json({ status: false, message: "User not found or not managed by you" }, { status: 403 });
    }

    const token = createSsoToken(target.id);
    const base = (process.env.AUTH_URL || req.nextUrl.origin).replace(/\/$/, "");
    return NextResponse.json({
        status: true,
        message: "SSO token issued (valid 60 seconds, single use)",
        data: { token, url: `${base}/auth/sso?token=${encodeURIComponent(token)}` },
    });
}
