"use server";

import { lucia } from "@/auth";
import prisma from "@/lib/prisma";
import { signUpSchema, SignUpValues } from "@/lib/validation";
import { hash } from "@node-rs/argon2";
import { generateIdFromEntropySize } from "lucia";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { isRedirectError } from "next/dist/client/components/redirect";

export async function signUp(credentials: SignUpValues): Promise<string> {
  try {
    const { username, email, password }: SignUpValues = signUpSchema.parse(
      credentials,
    ) as SignUpValues;

    const passwordHash = await hash(password, {
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
      outputLen: 34,
    });

    const userId = generateIdFromEntropySize(10);

    const existingUsername = await prisma.usersmp.findFirst({
      where: {
        username: {
          equals: username,
          mode: "insensitive",
        },
      },
    });

    if (existingUsername) {
      return "Username is already taken";
    }

    const existingEmail = await prisma.usersmp.findFirst({
      where: {
        email: {
          equals: email,
          mode: "insensitive",
        },
      },
    });

    if (existingEmail) {
      return "Email is already taken";
    }

    await prisma.usersmp.create({
      data: {
        id: userId,
        username,
        email,
        displayName: username,
        passwordHash,
      },
    });

    const session = await lucia.createSession(userId, {});
    const sessionCookie = lucia.createSessionCookie(session.id);

    cookies().set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes,
    );

    return redirect("/");
  } catch (error: any) {
    if (isRedirectError(error)) throw error;
    console.error(error);
    return "An error occurred. Please try again later.";
  }
}

// if we didn't have the return redirect, we have to redirect the error manually
