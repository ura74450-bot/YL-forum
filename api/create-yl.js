import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";

const sql = neon(process.env.DATABASE_URL);

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const passwordHash = await bcrypt.hash("asdfghjkl", 12);

    const accounts = ["YLyura", "YLlev"];

    const users = [];

    for (const username of accounts) {
      const existing = await sql`
        SELECT id
        FROM users
        WHERE LOWER(username) = LOWER(${username})
        LIMIT 1
      `;

      if (existing.length > 0) {
        const result = await sql`
          UPDATE users
          SET password_hash = ${passwordHash},
              role = 'yl'
          WHERE id = ${existing[0].id}
          RETURNING id, username, role
        `;

        users.push(result[0]);
      } else {
        const result = await sql`
          INSERT INTO users
            (username, password_hash, role)
          VALUES
            (${username}, ${passwordHash}, 'yl')
          RETURNING id, username, role
        `;

        users.push(result[0]);
      }
    }

    return res.status(200).json({
      success: true,
      users
    });

  } catch (error) {
    console.error("CREATE YL ERROR:", error);

    return res.status(500).json({
      error: error?.message || "Server error"
    });
  }
}
