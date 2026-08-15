import { neon } from "@neondatabase/serverless";
import crypto from "crypto";

const sql = neon(process.env.DATABASE_URL);

function getToken(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)yl_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

function getCurrentUser(req) {
  const token = getToken(req);
  if (!token) return null;

  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;

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

    if (signature.length !== expected.length) return null;

    if (!crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    )) return null;

    return JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );
  } catch (error) {
    console.error("SESSION ERROR:", error);
    return null;
  }
}

async function getYLUser(req, res) {
  const user = getCurrentUser(req);

  if (!user) {
    res.status(401).json({
      error: "Сессия не найдена. Войдите в аккаунт заново."
    });
    return null;
  }

  const dbUser = await sql`
    SELECT id, username, role
    FROM users
    WHERE id = ${user.id}
    LIMIT 1
  `;

  if (!dbUser.length) {
    res.status(401).json({ error: "Пользователь не найден." });
    return null;
  }

  if (dbUser[0].role !== "yl") {
    res.status(403).json({
      error: "Эта функция доступна только YL-аккаунтам."
    });
    return null;
  }

  return dbUser[0];
}

export default async function handler(req, res) {

  // GET — новости
  if (req.method === "GET") {
    try {
      const posts = await sql`
        SELECT
          posts.id,
          posts.title,
          posts.content,
          posts.author_id,
          posts.published,
          posts.pinned,
          posts.created_at,
          posts.updated_at,
          users.username,
          users.role
        FROM posts
        INNER JOIN users ON users.id = posts.author_id
        WHERE posts.published = true
        ORDER BY posts.pinned DESC, posts.created_at DESC
      `;

      return res.status(200).json({ posts });
    } catch (error) {
      console.error("GET POSTS ERROR:", error);
      return res.status(500).json({
        error: error?.message || "Не удалось загрузить новости."
      });
    }
  }

  // POST — создать новость
  if (req.method === "POST") {
    try {
      const dbUser = await getYLUser(req, res);
      if (!dbUser) return;

      const title = String(req.body?.title || "").trim();
      const content = String(req.body?.content || "").trim();

      if (!title) return res.status(400).json({
        error: "Введите заголовок новости."
      });

      if (!content) return res.status(400).json({
        error: "Введите текст новости."
      });

      if (title.length > 200) return res.status(400).json({
        error: "Заголовок слишком длинный."
      });

      if (content.length > 100000) return res.status(400).json({
        error: "Новость слишком большая."
      });

      const result = await sql`
        INSERT INTO posts (
          title, content, author_id, published, pinned
        )
        VALUES (
          ${title}, ${content}, ${dbUser.id}, true, false
        )
        RETURNING
          id, title, content, author_id, published,
          pinned, created_at, updated_at
      `;

      return res.status(201).json({
        success: true,
        post: {
          ...result[0],
          username: dbUser.username,
          role: dbUser.role
        }
      });
    } catch (error) {
      console.error("CREATE POST ERROR:", error);
      return res.status(500).json({
        error: error?.message || "Не удалось опубликовать новость."
      });
    }
  }

  // PATCH — редактирование или закрепление
  if (req.method === "PATCH") {
    try {
      const dbUser = await getYLUser(req, res);
      if (!dbUser) return;

      const id = Number(req.body?.id);
      const action = String(req.body?.action || "");

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: "Неверный ID поста." });
      }

      const existing = await sql`
        SELECT id, title, content, pinned
        FROM posts
        WHERE id = ${id}
        LIMIT 1
      `;

      if (!existing.length) {
        return res.status(404).json({ error: "Пост не найден." });
      }

      if (action === "pin") {
        const pinned = Boolean(req.body?.pinned);

        const result = await sql`
          UPDATE posts
          SET pinned = ${pinned}, updated_at = NOW()
          WHERE id = ${id}
          RETURNING
            id, title, content, author_id, published,
            pinned, created_at, updated_at
        `;

        return res.status(200).json({
          success: true,
          post: result[0]
        });
      }

      if (action === "edit") {
        const title = String(req.body?.title || "").trim();
        const content = String(req.body?.content || "").trim();

        if (!title) return res.status(400).json({
          error: "Введите заголовок новости."
        });

        if (!content) return res.status(400).json({
          error: "Введите текст новости."
        });

        if (title.length > 200) return res.status(400).json({
          error: "Заголовок слишком длинный."
        });

        if (content.length > 100000) return res.status(400).json({
          error: "Новость слишком большая."
        });

        const result = await sql`
          UPDATE posts
          SET
            title = ${title},
            content = ${content},
            updated_at = NOW()
          WHERE id = ${id}
          RETURNING
            id, title, content, author_id, published,
            pinned, created_at, updated_at
        `;

        return res.status(200).json({
          success: true,
          post: result[0]
        });
      }

      return res.status(400).json({
        error: "Неизвестное действие."
      });
    } catch (error) {
      console.error("UPDATE POST ERROR:", error);
      return res.status(500).json({
        error: error?.message || "Не удалось изменить пост."
      });
    }
  }

  // DELETE — удалить пост
  if (req.method === "DELETE") {
    try {
      const dbUser = await getYLUser(req, res);
      if (!dbUser) return;

      const id = Number(req.body?.id);

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: "Неверный ID поста." });
      }

      const existing = await sql`
        SELECT id
        FROM posts
        WHERE id = ${id}
        LIMIT 1
      `;

      if (!existing.length) {
        return res.status(404).json({ error: "Пост не найден." });
      }

      await sql`
        DELETE FROM posts
        WHERE id = ${id}
      `;

      return res.status(200).json({
        success: true,
        deleted_id: id
      });
    } catch (error) {
      console.error("DELETE POST ERROR:", error);
      return res.status(500).json({
        error: error?.message || "Не удалось удалить пост."
      });
    }
  }

  return res.status(405).json({
    error: "Method not allowed"
  });
}
