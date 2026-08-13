import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const sql = neon(process.env.DATABASE_URL);

function createToken(user) {
  const secret = process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error("SESSION_SECRET is not configured");
  }

  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      username: user.username,
      role: user.role
    })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || "";

  for (const part of cookies.split(";")) {
    const [key, ...values] = part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(values.join("="));
    }
  }

  return null;
}

export default async function handler(req, res) {

  if (req.method === "GET") {
    const token = getCookie(req, "yl_session");

    if (!token) {
      return res.status(401).json({
        user: null
      });
    }

    return res.status(200).json({
      user: null
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "Введите ник и пароль."
      });
    }

    const result = await sql`
      SELECT
        id,
        username,
        password_hash,
        role,
        created_at
      FROM users
      WHERE LOWER(username) = LOWER(${username})
      LIMIT 1
    `;

    if (!result.length) {
      return res.status(401).json({
        error: "Неверный ник или пароль."
      });
    }

    const user = result[0];

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        error: "Неверный ник или пароль."
      });
    }

    const safeUser = {
      id: user.id,
      username: user.username,
      role: user.role,
      created_at: user.created_at
    };

    const token = createToken(safeUser);

    res.setHeader(
      "Set-Cookie",
      `yl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    );

    return res.status(200).json({
      success: true,
      user: safeUser
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      error: error?.message || "Ошибка сервера."
    });
  }
}
