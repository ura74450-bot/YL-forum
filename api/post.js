import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.DATABASE_URL);

export default async function handler(req, res) {
  try {

    // Получение новостей
    if (req.method === "GET") {

      const posts = await sql
        SELECT
          posts.id,
          posts.title,
          posts.content,
          posts.created_at,
          users.username,
          users.role
        FROM posts
        JOIN users ON users.id = posts.author_id
        WHERE posts.published = TRUE
        ORDER BY posts.created_at DESC
      ;

      return res.status(200).json({
        posts
      });
    }

    // Создание новости
    if (req.method === "POST") {

      const { title, content, username } = req.body || {};

      if (!title  !content  !username) {
        return res.status(400).json({
          error: "Title, content and username are required"
        });
      }

      // Проверяем, что пользователь действительно YL
      const users = await sql
        SELECT id, username, role
        FROM users
        WHERE LOWER(username) = LOWER(${username})
        LIMIT 1
      ;

      if (users.length === 0) {
        return res.status(401).json({
          error: "User not found"
        });
      }

      const user = users[0];

      if (user.role !== "yl") {
        return res.status(403).json({
          error: "Only YL accounts can publish news"
        });
      }

      const result = await sql
        INSERT INTO posts
          (title, content, author_id, published)
        VALUES
          (${title}, ${content}, ${user.id}, TRUE)
        RETURNING id, title, content, created_at
      ;

      return res.status(201).json({
        success: true,
        post: result[0]
      });
    }

    return res.status(405).json({
      error: "Method not allowed"
    });

  } catch (error) {

    console.error(error);

    return res.status(500).json({
      error: "Internal server error"
    });
  }
}
