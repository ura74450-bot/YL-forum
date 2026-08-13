const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");

const sql = neon(process.env.DATABASE_URL);

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: "Invalid username"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters"
      });
    }

    const existing = await sql
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER(${username})
      LIMIT 1
    ;

    if (existing.length > 0) {
      return res.status(409).json({
        error: "Username already exists"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await sql
      INSERT INTO users
        (username, password_hash, role)
      VALUES
        (${username}, ${passwordHash}, 'user')
      RETURNING id, username, role, created_at
    ;

    return res.status(201).json({
      success: true,
      user: result[0]
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      error: error.message || "Internal server error"
    });
  }
};
