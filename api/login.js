import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";

const sql = neon(process.env.DATABASE_URL);

let sessions = new Map();

export default async function handler(req, res) {

  // Проверка текущей сессии
  if (req.method === "GET") {
    const token = req.headers.cookie?.match(/yl_session=([^;]+)/)?.[1];

    if (!token || !sessions.has(token)) {
      return res.status(401).json({ user: null });
    }

    return res.status(200).json({
      user: sessions.get(token)
    });
  }

  // Выход
  if (req.method === "DELETE") {
    const token = req.headers.cookie?.match(/yl_session=([^;]+)/)?.[1];

    if (token) sessions.delete(token);

    res.setHeader(
      "Set-Cookie",
      "yl_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
    );

    return res.status(200).json({ success: true });
  }

  // Вход
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { username, password } = req.body || {};

    const result = await sql`
      SELECT id, username, password_hash, role, created_at
      FROM users
      WHERE LOWER(username)=LOWER(${username})
      LIMIT 1
    `;

    if (!result.length) {
      return res.status(401).json({
        error: "Неверный ник или пароль"
      });
    }

    const user = result[0];

    const ok = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!ok) {
      return res.status(401).json({
        error: "Неверный ник или пароль"
      });
    }

    const safeUser = {
      id: user.id,
      username: user.username,
      role: user.role,
      created_at: user.created_at
    };

    const token =
      Math.random().toString(36).slice(2) +
      Date.now().toString(36);

    sessions.set(token, safeUser);

    res.setHeader(
      "Set-Cookie",
      `yl_session=${token}; Path=/; HttpOnly; SameSite=Lax`
    );

    return res.status(200).json({
      success: true,
      user: safeUser
    });

  } catch (e) {
    console.error(e);

    return res.status(500).json({
      error: e.message
    });
  }
}
