import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { authConfig } from "@/auth.config";
import { redeemSsoToken } from "@/lib/sso-token";
import { rateLimit } from "@/lib/rate-limit";

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;

          // Brute-force protection: max 10 attempts per email per 15 minutes
          if (!rateLimit(`login:${email.toLowerCase()}`, 10, 15 * 60 * 1000)) return null;
          
          const user = await prisma.user.findUnique({ where: { email } });
          if (!user) return null;

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) {
             return user;
          }
        }
        return null;
      },
    }),
    Credentials({
      id: "sso",
      name: "SSO token",
      credentials: {
        token: { label: "Token", type: "text" },
      },
      authorize: async (credentials) => {
        const userId = redeemSsoToken(String(credentials?.token || ""));
        if (!userId) return null;
        return prisma.user.findUnique({ where: { id: userId } });
      },
    }),
  ],
  secret: process.env.AUTH_SECRET,
});
