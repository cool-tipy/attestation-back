import { cookie } from "@elysiajs/cookie"
import cors from "@elysiajs/cors"
import swagger from "@elysiajs/swagger"
import { Elysia } from "elysia"
import { authMiddleware } from './middleware/auth'
import { authHandler } from "./modules/auth/auth"
import { userHandler } from './modules/user/user'

const protectedRoutes = new Elysia()
.use(authMiddleware)
.use(userHandler)

const app = new Elysia()
  .use(swagger())
  .use(
    cors({
      // Для продакшена лучше вынести в переменные окружения
      origin: ["https://localhost:5173", "https://localhost:8080"],
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
    })
  )
  .use(cookie({ sameSite: "none", secure: true }))
  // Хук onStart для корректного лога
  .onStart(({ server }) => {
    console.log(
      `🦊 Elysia is running at http://${server?.hostname}:${server?.port}`
    );
  })
  .get("/", () => "Welcome!!!")
  .use(authHandler)
  .use(protectedRoutes)
  .listen({
    port: 3000,
  })