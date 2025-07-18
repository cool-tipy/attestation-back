import { cookie } from "@elysiajs/cookie"
import cors from "@elysiajs/cors"
import swagger from "@elysiajs/swagger"
import { Elysia } from "elysia"
import { authHandler } from "./modules/auth/auth"
import { userHandler } from './modules/user/user'

// Проверка наличия секретов при старте
if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
  console.error("FATAL ERROR: JWT_ACCESS_SECRET or JWT_REFRESH_SECRET is not defined")
  process.exit(1)
}

const app = new Elysia()
  .use(swagger())
  .use(
    cors({
      origin: ["https://localhost:5173", "https://localhost:8080"],
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
    })
  )
  .use(cookie({ sameSite: "none", secure: true }))
  .onStart(({ server }) => {
    console.log(
      `🦊 Elysia is running at http://${server?.hostname}:${server?.port}`
    );
  })
  .get("/", () => "Welcome!!!")
  .use(authHandler)
  .use(userHandler)
  .listen({
    port: 3000,
  })