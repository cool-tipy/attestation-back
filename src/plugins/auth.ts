import { Elysia } from "elysia"
import jwt from "jsonwebtoken"

function verifyAccessToken(token: string) {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) throw new Error("JWT_ACCESS_SECRET не установлен");
  return jwt.verify(token, secret);
}

export const isAuthenticated = new Elysia({ name: "isAuthenticated" })
  .derive(async ({ headers, set }) => {
     console.log("Received headers:", headers) // Логгируем заголовки

    const authHeader = headers["authorization"];
    if (!authHeader) {
      console.warn("Authorization header missing")
      set.status = 401;
      return { auth: { error: "Токен отсутствует" } };
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      console.warn("Invalid token format:", authHeader)
      set.status = 401;
      return { auth: { error: "Неверный формат токена" } };
    }

    const token = parts[1];
    try {
      const payload = verifyAccessToken(token) as { userId: number; login: string };
      return { 
        auth: { 
          userId: payload.userId, 
          login: payload.login 
        } 
      };
    } catch (error: any) {
      set.status = 401;
      return { auth: { error: "Невалидный токен: " + error.message } };
    }
  })
  .onBeforeHandle(({ set, auth }) => {
    if (auth?.error) {
      set.status = 401;
      return { message: auth.error };
    }
  });