const { neon } = require("@neondatabase/serverless");
const crypto = require("crypto");

const sql = neon(process.env.DATABASE_URL);


function getCookie(req,name){

  const cookies =
    req.headers.cookie || "";

  for(
    const part of cookies.split(";")
  ){

    const [key,...values] =
      part.trim().split("=");

    if(key===name){

      return decodeURIComponent(
        values.join("=")
      );

    }

  }

  return null;

}


function verifyToken(token){

  if(!token)
    return null;

  const secret =
    process.env.SESSION_SECRET;

  if(!secret)
    return null;

  const parts =
    token.split(".");

  if(parts.length!==2)
    return null;

  const [
    payload,
    signature
  ] = parts;


  const expected =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(payload)
      .digest("base64url");


  if(
    signature.length !==
    expected.length
  ){

    return null;

  }


  if(
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    )
  ){

    return null;

  }


  try{

    return JSON.parse(
      Buffer.from(
        payload,
        "base64url"
      ).toString("utf8")
    );

  }catch{

    return null;

  }

}


function getCurrentUser(req){

  const token =
    getCookie(
      req,
      "yl_session"
    );

  return verifyToken(token);

}


module.exports = async function handler(req,res){

  /*
   * GET
   * Новости доступны всем.
   */

  if(req.method==="GET"){

    try{

      const posts =
        await sql`
          SELECT
            posts.id,
            posts.title,
            posts.content,
            posts.created_at,
            users.username,
            users.role
          FROM posts
          INNER JOIN users
            ON users.id = posts.user_id
          ORDER BY
            posts.created_at DESC
        `;


      return res.status(200).json({
        posts
      });


    }catch(error){

      console.error(
        "GET POSTS ERROR:",
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          "Не удалось загрузить новости."
      });

    }

  }


  /*
   * POST
   * Создавать новости могут
   * только YL-аккаунты.
   */

  if(req.method==="POST"){

    try{

      const user =
        getCurrentUser(req);


      if(!user){

        return res.status(401).json({
          error:
            "Сначала войдите в аккаунт."
        });

      }


      if(user.role!=="yl"){

        return res.status(403).json({
          error:
            "Публиковать новости могут только YL-аккаунты."
        });

      }


      /*
       * Дополнительная проверка,
       * чтобы пользователь действительно
       * существовал в базе.
       */

      const dbUser =
        await sql`
          SELECT
            id,
            username,
            role
          FROM users
          WHERE id=${user.id}
          LIMIT 1
        `;


      if(
        !dbUser.length ||
        dbUser[0].role!=="yl"
      ){

        return res.status(403).json({
          error:
            "У аккаунта нет прав YL."
        });

      }


      const body =
        req.body || {};


      const title =
        String(
          body.title || ""
        ).trim();


      const content =
        String(
          body.content || ""
        ).trim();


      if(!title){

        return res.status(400).json({
          error:
            "Введите заголовок."
        });

      }


      if(!content){

        return res.status(400).json({
          error:
            "Введите текст новости."
        });

      }


      if(title.length>200){

        return res.status(400).json({
          error:
            "Заголовок слишком длинный."
        });

      }


      if(content.length>100000){

        return res.status(400).json({
          error:
            "Новость слишком большая."
        });

      }


      const result =
        await sql`
          INSERT INTO posts
            (
              title,
              content,
              user_id
            )
          VALUES
            (
              ${title},
              ${content},
              ${user.id}
            )
          RETURNING
            id,
            title,
            content,
            created_at
        `;


      return res.status(201).json({

        success:true,

        post:{
          ...result[0],

          username:
            user.username,

          role:
            user.role

        }

      });


    }catch(error){

      console.error(
        "CREATE POST ERROR:",
        error
      );

      return res.status(500).json({

        error:
          error.message ||
          "Не удалось опубликовать новость."

      });

    }

  }


  return res.status(405).json({
    error:"Method not allowed"
  });

};
