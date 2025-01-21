import { PrismaAdapter } from "@lucia-auth/adapter-prisma";
import { PrismaClient } from "@prisma/client";
import prisma from "./lib/prisma";
import { Lucia, Session, User } from "lucia";
import { cache } from "react";
import { cookies } from "next/headers";

const adapter = new PrismaAdapter(prisma.sessionsmp, prisma.usersmp);

export const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
  getUserAttributes(databasUserAttributes) {
    return {
      id: databasUserAttributes.id,
      email: databasUserAttributes.email,
      username: databasUserAttributes.username,
      displayName: databasUserAttributes.displayName,
      avatarUrl: databasUserAttributes.avatarUrl,
      googleId: databasUserAttributes.googleId,
    };
  },
});

declare module "lucia" {
  interface Register {
    Lucia: typeof lucia;
    DatabaseUserAttributes: DatabasUserAttributes;
  }
}

interface DatabasUserAttributes {
  id: string;
  email: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  googleId: string | null;
}

export const validateRequest = cache(
  async (): Promise<
    { user: User; session: Session } | { user: null; session: null }
  > => {
    const sessionId = cookies().get(lucia.sessionCookieName)?.value ?? null;
    if (sessionId === null) {
      return { user: null, session: null };
    }
    const result = await lucia.validateSession(sessionId);
    try {
      if (result.session && result.session.fresh) {
        const sessionCookie = lucia.createSessionCookie(result.session.id);
        cookies().set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes,
        );
      }
      if (!result.session) {
        const sessionCookie = lucia.createBlankSessionCookie();
        cookies().set(
          sessionCookie.name,
          sessionCookie.value,
          sessionCookie.attributes,
        );
      }
    } catch {}
    return result;
  },
);
