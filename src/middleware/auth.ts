import { Elysia } from "elysia"
import jwt from "jsonwebtoken"

export const authMiddleware = new Elysia().onBeforeHandle(({ headers, set }) => {
  const authHeader = headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    set.status = 401;
    return { message: "Нет токена авторизации" };
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
    return {
      user: decoded,
    };
  } catch {
    set.status = 401;
    return { message: "Невалидный токен" };
  }
});