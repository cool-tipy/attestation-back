import { Elysia, t } from 'elysia'
import { prisma } from '../../lib/prisma' // <-- Импортируем синглтон
import { authMiddleware } from '../../middleware/auth'

const userSchemaResponse = t.Object({
  id: t.Number(),
  email: t.String(),
  login: t.String(),
  firstName: t.String(),
  lastName: t.Optional(t.String()),
  patronymic: t.Optional(t.String()),
  isEmailVerified: t.Boolean(),
})

export const userHandler = new Elysia({ prefix: '/users' }) // <-- Добавим префикс для чистоты
  .use(authMiddleware) // <-- Теперь это работает правильно!
  .get(
    '/', // <-- Маршрут теперь /users/
    async ({ set, store }) => { // <-- Можно получить store и currentUser, если нужно
      // console.log('Current user:', store.currentUser)

      try {
        const users = await prisma.user.findMany({
          select: {
            id: true,
            email: true,
            login: true,
            firstName: true,
            lastName: true,
            patronymic: true,
            isEmailVerified: true,
          },
        })
        
        // Ваш map для обработки null в undefined абсолютно корректен для схемы
        return users.map(user => ({
          ...user,
          lastName: user.lastName ?? undefined,
          patronymic: user.patronymic ?? undefined
        }))

      } catch (error) {
        set.status = 500
        return { message: `Ошибка: ${error}` }
      }
    },
    {
      response: {
        500: t.Object({ message: t.String() }),
        401: t.Object({ message: t.String() }), // Добавим ответы от middleware
        403: t.Object({ message: t.String() }),
        200: t.Array(userSchemaResponse),
      },
    }
  )