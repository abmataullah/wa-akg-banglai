import { NextResponse, NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser, isAdmin, canManageUser } from "@/lib/api-auth";
import bcrypt from "bcryptjs";

const ROLES = ["SUPERADMIN", "RESELLER", "OWNER", "STAFF"];

export async function PATCH(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const user = await getAuthenticatedUser(request);
    const { id } = await params;

    // SUPERADMIN updates anyone; RESELLER only its own sub-users
    if (!user || !(await canManageUser(user.id, user.role, id))) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    try {
        const body = await request.json();
        const { name, email, password, role } = body;

        if (role && (!ROLES.includes(role) || (!isAdmin(user.role) && !["OWNER", "STAFF"].includes(role)))) {
            return NextResponse.json({ status: false, message: "Role not allowed", error: "Forbidden role" }, { status: 403 });
        }

        // Prevent modifying own role to lock oneself out (optional safety)
        if (id === user.id && role && role !== "SUPERADMIN") {
            // Allow update but maybe warn? For now let it be.
        }

        const updateData: any = {};
        if (name) updateData.name = name;
        if (email) updateData.email = email;
        if (role) updateData.role = role;
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        const updatedUser = await prisma.user.update({
            where: { id },
            data: updateData,
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                updatedAt: true
            }
        });

        return NextResponse.json({ status: true, message: "User updated successfully", data: updatedUser });

    } catch (error) {
        console.error("Update user error:", error);
        return NextResponse.json({ status: false, message: "Failed to update user", error: "Failed to update user" }, { status: 500 });
    }
}

export async function DELETE(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const user = await getAuthenticatedUser(request);
    const { id } = await params;

    // SUPERADMIN deletes anyone; RESELLER only its own sub-users
    if (!user || !(await canManageUser(user.id, user.role, id))) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    if (id === user.id) {
        return NextResponse.json({ status: false, message: "Cannot delete yourself", error: "Cannot delete yourself" }, { status: 400 });
    }

    try {
        await prisma.user.delete({ where: { id } });
        return NextResponse.json({ status: true, message: "User deleted successfully" });
    } catch (error) {
        console.error("Delete user error:", error);
        return NextResponse.json({ status: false, message: "Failed to delete user", error: "Failed to delete user" }, { status: 500 });
    }
}
