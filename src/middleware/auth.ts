import { Elysia } from "elysia"
import jwt from "jsonwebtoken"

export const authMiddleware = new Elysia().onBeforeHandle(({ headers, set, error }) => {
  const authHeader = headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return error(401, { message: "Нет токена авторизации" });
  }

  const token = authHeader.split(" ")[1];

  // Проверяем, что токен не undefined или пустой
  if (!token || token === 'undefined') {
    return error(401, { message: "Нет токена авторизации" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
    return {
      user: decoded,
    };
  } catch {
    return error(401, { message: "Невалидный токен" });
  }
});