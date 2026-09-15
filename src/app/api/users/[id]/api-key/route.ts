import { NextResponse, NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser, isAdmin, generateApiKey } from "@/lib/api-auth";

/**
 * POST /api/users/[id]/api-key
 * Generate a new API key for any user (SUPERADMIN only).
 * Used by amarshowroom.com to auto-provision API keys for sellers.
 */
export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const user = await getAuthenticatedUser(request);

    if (!user || !isAdmin(user.role)) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    const { id } = await params;

    try {
        const targetUser = await prisma.user.findUnique({
            where: { id },
            select: { id: true, email: true, name: true }
        });

        if (!targetUser) {
            return NextResponse.json({ status: false, message: "User not found", error: "User not found" }, { status: 404 });
        }

        const newApiKey = generateApiKey();

        await prisma.user.update({
            where: { id },
            data: { apiKey: newApiKey }
        });

        return NextResponse.json({
            status: true,
            message: "API key generated successfully",
            data: { apiKey: newApiKey, userId: id, email: targetUser.email }
        });
    } catch (error) {
        console.error("Generate API key for user error:", error);
        return NextResponse.json({ status: false, message: "Failed to generate API key", error: "Failed to generate API key" }, { status: 500 });
    }
}

/**
 * GET /api/users/[id]/api-key
 * Get the current API key for a user (SUPERADMIN only).
 */
export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const user = await getAuthenticatedUser(request);

    if (!user || !isAdmin(user.role)) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    const { id } = await params;

    try {
        const targetUser = await prisma.user.findUnique({
            where: { id },
            select: { id: true, apiKey: true }
        });

        if (!targetUser) {
            return NextResponse.json({ status: false, message: "User not found", error: "User not found" }, { status: 404 });
        }

        return NextResponse.json({
            status: true,
            message: "API key fetched",
            data: { apiKey: targetUser.apiKey, userId: id }
        });
    } catch (error) {
        return NextResponse.json({ status: false, message: "Failed to fetch API key", error: "Failed to fetch API key" }, { status: 500 });
    }
}
