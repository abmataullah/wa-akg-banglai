import { NextResponse, NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser, isAdmin, isReseller } from "@/lib/api-auth";
import bcrypt from "bcryptjs";
import { z } from "zod";

const createUserSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(6),
    role: z.enum(["SUPERADMIN", "RESELLER", "OWNER", "STAFF"]).default("OWNER"),
});

export async function GET(request: NextRequest) {
    const user = await getAuthenticatedUser(request);

    // SUPERADMIN lists everyone; RESELLER lists only its own sub-users
    if (!user || !(isAdmin(user.role) || isReseller(user.role))) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    try {
        const users = await prisma.user.findMany({
            where: isAdmin(user.role) ? {} : { parentId: user.id },
            orderBy: { createdAt: 'desc' },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                parentId: true,
                createdAt: true,
                _count: {
                    select: { sessions: true }
                }
            }
        });

        return NextResponse.json({ status: true, message: "Users fetched successfully", data: users });
    } catch (error) {
        return NextResponse.json({ status: false, message: "Failed to fetch users", error: "Failed to fetch users" }, { status: 500 });
    }
}

export async function POST(request: NextRequest) {
    const user = await getAuthenticatedUser(request);

    // SUPERADMIN creates any user; RESELLER creates OWNER/STAFF sub-users only
    if (!user || !(isAdmin(user.role) || isReseller(user.role))) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    try {
        const body = await request.json();
        const parseResult = createUserSchema.safeParse(body);

        if (!parseResult.success) {
            return NextResponse.json({ status: false, message: "Validation error", error: parseResult.error.flatten() }, { status: 400 });
        }

        const { name, email, password, role } = parseResult.data;

        if (isReseller(user.role) && (role === "SUPERADMIN" || role === "RESELLER")) {
            return NextResponse.json({ status: false, message: "Resellers can only create OWNER or STAFF users", error: "Forbidden role" }, { status: 403 });
        }

        // Check if email exists
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) {
            return NextResponse.json({ status: false, message: "Email already exists", error: "Email already exists" }, { status: 400 });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
                role: role as any,
                parentId: isReseller(user.role) ? user.id : null
            },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                parentId: true,
                createdAt: true
            }
        });

        return NextResponse.json({ status: true, message: "User created successfully", data: newUser }, { status: 201 });

    } catch (error) {
        console.error("Create user error:", error);
        return NextResponse.json({ status: false, message: "Failed to create user", error: "Failed to create user" }, { status: 500 });
    }
}
