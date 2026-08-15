import { neon } from "@neondatabase/serverless";
import crypto from "crypto";

const sql = neon(process.env.DATABASE_URL);

function getToken(req) {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(
    /(?:^|;\s*)yl_session=([^;]+)/
  );

  return match ? decodeURIComponent(match[1]) : null;
}

function getCurrentUser(req) {
  const token = getToken(req);

  if (!token) {
    return null;
  }

  try {
    const parts = token.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const [payload, signature] = parts;

    const secret = process.env.SESSION_SECRET;

    if (!secret) {
      console.error("SESSION_SECRET is missing");
      return null;
    }

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    if (signature.length !== expected.length) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    return JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

  } catch (error) {
    console.error("SESSION ERROR:", error);
    return null;
  }
}

export default async function handler(req, res) {

  // =========================
  // GET — получить новости
  // =========================

  if (req.method === "GET") {
    try {

      const posts = await sql`
        SELECT
          posts.id,
          posts.title,
          posts.content,
          posts.created_at,
          users.username,
          users.role
        FROM posts
        INNER JOIN users
          ON users.id = posts.author_id
        ORDER BY posts.created_at DESC
      `;

      return res.status(200).json({
        posts
      });

    } catch (error) {

      console.error("GET POSTS ERROR:", error);

      return res.status(500).json({
        error:
          error?.message ||
          "Не удалось загрузить новости."
      });
    }
  }

  // =========================
  // POST — создать новость
  // =========================

  if (req.method === "POST") {
    try {

      const user = getCurrentUser(req);

      if (!user) {
        return res.status(401).json({
          error:
            "Сессия не найдена. Войдите в аккаунт заново."
        });
      }

      // Проверяем пользователя в базе
      const dbUser = await sql`
        SELECT
          id,
          username,
          role
        FROM users
        WHERE id = ${user.id}
        LIMIT 1
      `;

      if (!dbUser.length) {
        return res.status(401).json({
          error: "Пользователь не найден."
        });
      }

      // Проверяем права YL
      if (dbUser[0].role !== "yl") {
        return res.status(403).json({
          error:
            "Публиковать новости могут только YL-аккаунты."
        });
      }

      const title = String(
        req.body?.title || ""
      ).trim();

      const content = String(
        req.body?.content || ""
      ).trim();

      if (!title) {
        return res.status(400).json({
          error:
            "Введите заголовок новости."
        });
      }

      if (!content) {
        return res.status(400).json({
          error:
            "Введите текст новости."
        });
      }

      if (title.length > 200) {
        return res.status(400).json({
          error:
            "Заголовок слишком длинный."
        });
      }

      if (content.length > 100000) {
        return res.status(400).json({
          error:
            "Новость слишком большая."
        });
      }

      // ВАЖНО:
      // В твоей таблице posts используется author_id,
      // а не user_id.
      const result = await sql`
        INSERT INTO posts (
          title,
          content,
          author_id,
          published
        )
        VALUES (
          ${title},
          ${content},
          ${dbUser[0].id},
          true
        )
        RETURNING
          id,
          title,
          content,
          author_id,
          published,
          created_at
      `;

      return res.status(201).json({
        success: true,

        post: {
          ...result[0],
          username: dbUser[0].username,
          role: dbUser[0].role
        }
      });

    } catch (error) {

      console.error(
        "CREATE POST ERROR:",
        error
      );

      return res.status(500).json({
        error:
          error?.message ||
          "Не удалось опубликовать новость."
      });
    }
  }

  return res.status(405).json({
    error: "Method not allowed"
  });
}
