import { PrismaClient } from '@prisma/client'
import { Elysia, t } from 'elysia'
import { verifyToken } from '../../utils/auth'

const prisma = new PrismaClient()

const userSchemaResponse = t.Object({
  id: t.Number(),
  email: t.String(),
  login: t.String(),
  firstName: t.String(),
  lastName: t.Optional(t.String()),
  patronymic: t.Optional(t.String()),
  isEmailVerified: t.Boolean(),
})

const currentUserBodySchema = t.Object({
  refreshToken: t.String()
})

export const userHandler = new Elysia()
  .get(
    '/users', 
    async ({ set, headers }) => { 
      try {
        verifyToken(headers, set)

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

        return users.map(user => ({
          
          ...user,
          lastName: user.lastName ?? undefined,
          patronymic: user.patronymic ?? undefined
        }))

      } catch (error: any) {
        set.status = error.status || 500
        return { message: error.message || 'Internal Server Error' }
      }
    },
    {
      response: {
        500: t.Object({ message: t.String() }),
        401: t.Object({ message: t.String() }), 
        403: t.Object({ message: t.String() }),
        200: t.Array(userSchemaResponse),
      },
    }
  )
  .get(
    '/currentUser', 
    async ({ set, headers, body}) => { 
      try {
        verifyToken(headers, set)

        const currentUser = await prisma.user.findUnique({
          where: { refreshToken: body.refreshToken },
          select: {
            id: true,
            email: true,
            login: true,
            firstName: true,
            lastName: true, 
            patronymic: true,
            isEmailVerified: true,
          }
        })

        if (!currentUser) {
          set.status = 404
          return { message: 'Пользователь не найден' }
      }

        return {
        ...currentUser,
        lastName: currentUser.lastName ?? undefined,
        patronymic: currentUser.patronymic ?? undefined
      }

      } catch (error: any) {
        set.status = error.status || 500
        return { message: error.message || 'Internal Server Error' }
      }
    },
    { 
      body: currentUserBodySchema,
      response: {
        500: t.Object({ message: t.String() }),
        401: t.Object({ message: t.String() }), 
        403: t.Object({ message: t.String() }),
        404: t.Object({ message: t.String() }),
        200: userSchemaResponse,
      },
    }
  )
 
