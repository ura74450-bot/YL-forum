import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";

const sql = neon(process.env.DATABASE_URL);

export default async function handler(request) {
  if (request.method !== "POST") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405 }
    );
  }

  try {
    const body = await request.json();

    const username = body.username;
    const password = body.password;

    if (!username || !password) {
      return Response.json(
        { error: "Username and password are required" },
        { status: 400 }
      );
    }

    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
      return Response.json(
        { error: "Invalid username" },
        { status: 400 }
      );
    }

    if (password.length < 6) {
      return Response.json(
        { error: "Password must contain at least 6 characters" },
        { status: 400 }
      );
    }

    const existing = await sql
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER(${username})
      LIMIT 1
    ;

    if (existing.length > 0) {
      return Response.json(
        { error: "Username already exists" },
        { status: 409 }
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await sql
      INSERT INTO users
        (username, password_hash, role)
      VALUES
        (${username}, ${passwordHash}, 'user')
      RETURNING id, username, role, created_at
    ;

    return Response.json(
      {
        success: true,
        user: result[0]
      },
      { status: 201 }
    );

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return Response.json(
      {
        error: "Internal server error",
        details: error.message
      },
      { status: 500 }
    );
  }
}
