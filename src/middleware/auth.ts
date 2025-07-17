
import { PrismaClient } from '@prisma/client'
import { Elysia } from 'elysia'
import jwt from 'jsonwebtoken'

const prisma = new PrismaClient()

interface JWTPayload {
  userId: number
  login: string
  iat: number
  exp: number
}

export const authMiddleware = new Elysia()
  .derive(async ({ headers, set }) => {
    const authHeader = headers.authorization
    
    if (!authHeader) {
      set.status = 401
      throw new Error('Отсутствует заголовок Authorization')
    }

    if (!authHeader.startsWith('Bearer ')) {
      set.status = 401
      throw new Error('Неверный формат токена. Используйте Bearer <token>')
    }

    const token = authHeader.substring(7) 
    
    if (!token) {
      set.status = 401
      throw new Error('Токен не найден')
    }

    try {
      const accessSecret = process.env.JWT_ACCESS_SECRET
      
      if (!accessSecret) {
        console.error('JWT_ACCESS_SECRET не определен в переменных окружения')
        set.status = 500
        throw new Error('Ошибка конфигурации сервера')
      }

      const decoded = jwt.verify(token, accessSecret) as JWTPayload
      
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: {
          id: true,
          login: true,
          isEmailVerified: true,
        }
      })

      if (!user) {
        set.status = 401
        throw new Error('Пользователь не найден')
      }

      if (!user.isEmailVerified) {
        set.status = 403
        throw new Error('Почта не подтверждена')
      }

      return {
        currentUser: {
          id: user.id,
          login: user.login,
        }
      }
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        set.status = 401
        throw new Error('Токен истек')
      } else if (error instanceof jwt.JsonWebTokenError) {
        set.status = 401
        throw new Error('Невалидный токен')
      } else {

        throw error
      }
    }
  })
  .onError(({ error, set }) => {
    // Обработка ошибок аутентификации
    if (set.status === 401 || set.status === 403 || set.status === 500) {
      return { message: error }
    }
    
    // Для других ошибок возвращаем общую ошибку
    set.status = 500
    return { message: 'Внутренняя ошибка сервера' }
  })