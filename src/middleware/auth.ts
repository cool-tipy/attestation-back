import { Elysia } from "elysia"
import jwt from "jsonwebtoken"

export const authMiddleware = new Elysia().derive(({ headers, set}) => {
  const authHeader = headers["Authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
     throw new Error( "Нет токена авторизации");
  }

  const token = authHeader.split(" ")[1];

  // Проверяем, что токен не undefined или пустой
  if (!token || token === 'undefined') {
     throw new Error("Нет токена авторизации" );
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);
    return {
      user: decoded,
    };
  } catch {
     throw new Error("Невалидный токен");
  }
}); 