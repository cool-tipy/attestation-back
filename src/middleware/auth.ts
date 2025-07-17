import Elysia from 'elysia'
import jwt from 'jsonwebtoken'

export const authMiddleware = new Elysia()
  .derive(async ({ headers, set }) =>  {
    const authHeader = headers["authorization"];

    if(!authHeader || !authHeader.startsWith("Bearer ")) {
      set.status = 401;
      return { message: "Супер сосать 1"}
    }

    const token = authHeader.split(" ")[1]

    try {
      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
      return { user: decoded }
    }catch (error) {
      set.status = 403;
      return { message: "Супер сосать 2"}
    }
  })