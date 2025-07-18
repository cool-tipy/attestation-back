import { PrismaClient } from '@prisma/client'
import { Elysia, t } from 'elysia'
import jwt from 'jsonwebtoken'

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

export const userHandler = new Elysia({ prefix: '/users' })
  .get('/', 
    async ({ set, headers}) => { 
      try {
        const token = headers["authorization"]

        if(!token){
          set.status = 500
          return { message: `Ошибка` }
        }

        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)

        if(!decoded){
          set.status = 500
          return { message: `Ошибка` }
        }

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

      } catch (error) {
        set.status = 500
        return { message: `Ошибка: ${error}` }
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