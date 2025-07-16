import { cookie } from "@elysiajs/cookie";
import swagger from "@elysiajs/swagger";
import { Elysia } from "elysia";
import { authHandler } from "./modules/auth/auth";
import cors from "@elysiajs/cors";
import { readFileSync } from "fs";

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
  .get("/", () => "Welcome!!!")
  .use(authHandler)
  .listen({
    port: 3000,
    tls: {
      key: readFileSync("./localhost-key.pem"),
      cert: readFileSync("./localhost.pem"),
    },
  });

console.log(
  `🦊 Elysia is running at http://${app.server?.hostname}:${app.server?.port}`
);
