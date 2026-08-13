const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const sql = neon(process.env.DATABASE_URL);

const YL_PASSWORD = "asdfghjkl";

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

  return ${payload}.${signature};
}

function setCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    yl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800
  );
}

module.exports = async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {

    const body = req.body || {};

    const username =
      String(body.username || "").trim();

    const password =
      String(body.password || "");

    if (!username || !password) {

      return res.status(400).json({
        error: "Username and password are required"
      });

    }

    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {

      return res.status(400).json({
        error: "Ник может содержать только A-Z, a-z, 0-9 и _"
      });

    }

    /*
     * YL-аккаунты.
     */

    const isYL =
      username === "YLyura" ||
      username === "YLlev";

    if (isYL && password !== YL_PASSWORD) {

      return res.status(403).json({
        error: "Для этого YL-аккаунта используется специальный пароль."
      });

    }

    /*
     * Если это обычный аккаунт —
     * пароль минимум 6 символов.
     */

    if (!isYL && password.length < 6) {

      return res.status(400).json({
        error: "Пароль должен содержать минимум 6 символов."
      });

    }

    /*
     * Проверяем существование ника.
     */

    const existing = await sql
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER(${username})
      LIMIT 1
    ;

    if (existing.length > 0) {

      return res.status(409).json({
        error: "Этот ник уже зарегистрирован."
      });

    }

    /*
     * Роль.
     */

    const role = isYL ? "yl" : "user";

    /*
     * Хешируем пароль.
     */

    const passwordHash =
      await bcrypt.hash(password, 12);

    /*
     * Создаём пользователя.
     */

    const result = await sql
      INSERT INTO users
        (username, password_hash, role)
      VALUES
        (${username}, ${passwordHash}, ${role})
      RETURNING
        id,
        username,
        role,
        created_at
    ;

    const user = result[0];

    /*
     * Создаём авторизационную cookie.
     */

    const token =
      createToken(user);

    setCookie(res, token);

    return res.status(201).json({
      success: true,
      user
    });

  } catch (error) {

    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      error:
        error.message ||
        "Internal server error"
    });

  }

};
