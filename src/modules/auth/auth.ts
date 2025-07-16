import { PrismaClient } from "@prisma/client"
import bcrypt from "bcryptjs"
import { Elysia, t } from "elysia"
import jwt from "jsonwebtoken"
import { sendVerificationEmail } from "../mail/email"

const prisma = new PrismaClient();

const registerBodySchema = t.Object({
  email: t.String({ format: "email" }),
  login: t.String({ minLength: 3 }),
  firstName: t.String(),
  lastName: t.String(),
  patronymic: t.Optional(t.String()),
  password: t.String({ minLength: 8 }),
});

const verifyEmailBodySchema = t.Object({
  email: t.String({ format: "email" }),
  code: t.String({ minLength: 6, maxLength: 6 }),
});

const loginBodySchema = t.Object({
  login: t.String(),
  password: t.String(),
});

const refreshBodySchema = t.Object({
  refreshToken: t.String(),
});

function generateTokens(userId: number, login: string) {
  const accessSecret = process.env.JWT_ACCESS_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;

  if (!accessSecret || !refreshSecret) {
    console.error("JWT secret or expiration not defined in .env file");
    throw new Error("JWT configuration is missing.");
  }

  const accessToken = jwt.sign({ userId, login }, accessSecret, {
    expiresIn: "15m",
  });

  const refreshToken = jwt.sign({ userId, login }, refreshSecret, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
}

export const authHandler = new Elysia({ prefix: "/auth" })
  .post(
    "/register",
    async ({ body, set }) => {
      const existingUser = await prisma.user.findFirst({
        where: { OR: [{ email: body.email }, { login: body.login }] },
      });

      if (existingUser) {
        set.status = 409;
        return {
          message: "Пользователь с таким email или login уже существует",
        };
      }

      const hashedPassword = await bcrypt.hash(body.password, 10);
      const verificationCode = Math.floor(
        100000 + Math.random() * 900000
      ).toString();

      try {
        await prisma.user.create({
          data: {
            ...body,
            password: hashedPassword,
            emailVerificationCode: verificationCode,
          },
        });

        await sendVerificationEmail(body.email, verificationCode);

        set.status = 201;
        return {
          message:
            "Регистрация успешна. Пожалуйста, проверьте вашу почту для подтверждения.",
        };
      } catch (error) {
        console.error(error);
        set.status = 500;
        return { message: "Произошла ошибка на сервере" };
      }
    },
    {
      body: registerBodySchema,
    }
  )
  .post(
    "/verify-email",
    async ({ body, set }) => {
      const user = await prisma.user.findUnique({
        where: { email: body.email },
      });

      if (!user || user.emailVerificationCode !== body.code) {
        set.status = 400;
        return { message: "Неверный email или код подтверждения" };
      }

      if (user.isEmailVerified) {
        set.status = 400;
        return { message: "Почта уже подтверждена" };
      }

      await prisma.user.update({
        where: { email: body.email },
        data: {
          isEmailVerified: true,
          emailVerificationCode: null,
        },
      });

      return { message: "Почта успешно подтверждена!" };
    },
    {
      body: verifyEmailBodySchema,
    }
  )
  .post(
    "/login",
    async ({ body, set }) => {
      const user = await prisma.user.findUnique({
        where: { login: body.login },
      });

      if (!user) {
        set.status = 404;
        return { message: "Пользователь с таким логином не найден!" };
      }

      if (!user.isEmailVerified) {
        set.status = 403;
        return { message: "Пожалуйста, подтвердите вашу почту перед входом" };
      }

      const isPasswordValid = await bcrypt.compare(
        body.password,
        user.password
      );

      if (!isPasswordValid) {
        set.status = 401;
        return { message: "Неверный пароль" };
      }

      const { accessToken, refreshToken } = generateTokens(user.id, user.login);

      await prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: refreshToken },
      });
			/**FIXME: Убрать если Булат разрешит */
      // cookie.refreshToken.set({
      //   value: refreshToken,
      //   httpOnly: true,
      //   maxAge: 7 * 86400,
      //   path: "/",
      //   sameSite: 'none',
      //   secure: true,
      // });

      return {
        message: "Вход успешен",
        accessToken: accessToken,
				refreshToken: refreshToken,
      };
    },
    {
      body: loginBodySchema,
    }
  )
  .post("/refresh", async ({ body, set }) => {
    const currentRefreshToken = body.refreshToken

    if (!currentRefreshToken) {
      set.status = 401;
      return { message: "Refresh токен не найден" };
    }

    const user = await prisma.user.findUnique({
      where: { refreshToken: currentRefreshToken },
    });

    if (!user) {
			/**FIXME: Убрать если Булат разрешит */
      // cookie.refreshToken.remove();
      set.status = 403;
      return { message: "Невалидный refresh токен" };
    }

    try {
      jwt.verify(currentRefreshToken, process.env.JWT_REFRESH_SECRET!);
    } catch (error) {
			/**FIXME: Убрать если Булат разрешит */
      // cookie.refreshToken.remove();
      set.status = 403;
      return { message: "Refresh токен истек или невалиден" };
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(
      user.id,
      user.login
    );

    await prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: newRefreshToken },
    });

		/**FIXME: Убрать если Булат разрешит */
    // cookie.refreshToken.set({
    //   value: newRefreshToken,
    //   httpOnly: true,
    //   maxAge: 7 * 86400,
    //   path: "/",
    //   sameSite: 'none',
    //   secure: true,
    // });

    return { accessToken: accessToken, refreshToken: newRefreshToken };
  },
	{
		body: refreshBodySchema
	}
)
  .post("/logout", async ({ body, set }) => {
    const currentRefreshToken = body.refreshToken
    if (!currentRefreshToken) {
      set.status = 204;
      return;
    }

    await prisma.user.updateMany({
      where: { refreshToken: currentRefreshToken },
      data: { refreshToken: null },
    });
		/**FIXME: Убрать если Булат разрешит */
    // cookie.refreshToken.remove();

    set.status = 200;
    return { message: "Выход выполнен успешно" };
  },
	{
		body: refreshBodySchema
	});
