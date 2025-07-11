import cookie from "@elysiajs/cookie";
import swagger from "@elysiajs/swagger";
import { Elysia } from "elysia";
import { authHandler } from "./modules/auth/auth";
import cors from "@elysiajs/cors";

const app = new Elysia()
  .use(swagger())
  .use(cors({
    origin: ['http://localhost:5173', 'http://localhost:8080'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  }))
  .use(cookie())
  .get('/', () => 'Welcome!!!')
  .use(authHandler)
  .listen(3000)

console.log(
  `🦊 Elysia is running at http://${app.server?.hostname}:${app.server?.port}`
);