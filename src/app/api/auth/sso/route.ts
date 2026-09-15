import { NextResponse, NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import bcrypt from "bcryptjs";

/**
 * POST /api/auth/sso
 * Single Sign-On from amarshowroom.com.
 *
 * Body: { email, password, apiKey }
 *
 * Verifies the credentials against the WA-AKG user database.
 * If valid, returns a success response that the frontend uses to
 * redirect to the dashboard (the NextAuth session is established
 * via the normal login flow).
 *
 * This endpoint is called by amarshowroom.com when a seller clicks
 * "Open WA-AKG Dashboard" — it auto-logs them in without manual
 * password entry.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { email, password } = body;

    if (!email || !password) {
      return NextResponse.json(
        { status: false, message: "Email and password are required" },
        { status: 400 }
      );
    }

    // Find the user by email
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      select: { id: true, email: true, name: true, role: true, password: true },
    });

    if (!user) {
      return NextResponse.json(
        { status: false, message: "Invalid credentials" },
        { status: 401 }
      );
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return NextResponse.json(
        { status: false, message: "Invalid credentials" },
        { status: 401 }
      );
    }

    // Return user info (the frontend will use this to establish a session
    // via the normal NextAuth credentials provider)
    return NextResponse.json({
      status: true,
      message: "SSO credentials verified",
      data: {
        email: user.email,
        name: user.name,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("SSO error:", error);
    return NextResponse.json(
      { status: false, message: "SSO failed" },
      { status: 500 }
    );
  }
}
