const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const sql = neon(process.env.DATABASE_URL);

function createToken(user) {

  const secret =
    process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error(
      "SESSION_SECRET is not configured"
    );
  }

  const payload =
    Buffer.from(
      JSON.stringify({
        id: user.id,
        username: user.username,
        role: user.role
      })
    ).toString("base64url");

  const signature =
    crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

  return `${payload}.${signature}`;
}


function setCookie(res, token) {

  res.setHeader(
    "Set-Cookie",
    `yl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  );

}


function getCookie(req, name) {

  const cookies =
    req.headers.cookie || "";

  const parts =
    cookies.split(";");

  for (const part of parts) {

    const [key,...values] =
      part.trim().split("=");

    if (key === name) {

      return decodeURIComponent(
        values.join("=")
      );

    }

  }

  return null;
}


function verifyToken(token) {

  if (!token) return null;

  const secret =
    process.env.SESSION_SECRET;

  if (!secret) return null;

  const parts =
    token.split(".");

  if (parts.length !== 2)
    return null;

  const [
    payload,
    signature
  ] = parts;

  const expected =
    crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    )
  ) {

    return null;

  }

  try {

    return JSON.parse(
      Buffer.from(
        payload,
        "base64url"
      ).toString("utf8")
    );

  } catch {

    return null;

  }

}


module.exports = async function handler(req,res) {

  /*
   * GET — узнать текущего пользователя.
   */

  if (req.method === "GET") {

    const token =
      getCookie(
        req,
        "yl_session"
      );

    const user =
      verifyToken(token);

    if (!user) {

      return res.status(401).json({
        user: null
      });

    }

    return res.status(200).json({
      user
    });

  }


  /*
   * DELETE — выйти.
   */

  if (req.method === "DELETE") {

    res.setHeader(
      "Set-Cookie",
      "yl_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    );

    return res.status(200).json({
      success:true
    });

  }


  /*
   * POST — вход.
   */

  if (req.method !== "POST") {

    return res.status(405).json({
      error:"Method not allowed"
    });

  }


  try {

    const body =
      req.body || {};

    const username =
      String(
        body.username || ""
      ).trim();

    const password =
      String(
        body.password || ""
      );


    if (!username || !password) {

      return res.status(400).json({
        error:
          "Введите ник и пароль."
      });

    }


    const result =
      await sql`
        SELECT
          id,
          username,
          password_hash,
          role,
          created_at
        FROM users
        WHERE LOWER(username)=LOWER(${username})
        LIMIT 1
      `;


    if (!result.length) {

      return res.status(401).json({
        error:
          "Неверный ник или пароль."
      });

    }


    const user =
      result[0];


    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );


    if (!valid) {

      return res.status(401).json({
        error:
          "Неверный ник или пароль."
      });

    }


    const safeUser = {

      id:user.id,

      username:user.username,

      role:user.role,

      created_at:user.created_at

    };


    const token =
      createToken(safeUser);


    setCookie(
      res,
      token
    );


    return res.status(200).json({

      success:true,

      user:safeUser

    });


  } catch(error) {

    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({

      error:
        error.message ||
        "Internal server error"

    });

  }

};
