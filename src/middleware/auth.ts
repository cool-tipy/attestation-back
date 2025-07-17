// middleware/auth.ts
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
  .onBeforeHandle(async ({ headers, set, store }) => {
    try {
      const authHeader = headers.authorization
      
      // Проверяем наличие заголовка Authorization
      if (!authHeader) {
        set.status = 401
        return { message: 'Отсутствует заголовок Authorization' }
      }

      // Проверяем формат Bearer token
      if (!authHeader.startsWith('Bearer ')) {
        set.status = 401
        return { message: 'Неверный формат токена. Используйте Bearer <token>' }
      }

      const token = authHeader.substring(7) // Убираем "Bearer "
      
      if (!token || token === 'undefined' || token === 'null') {
        set.status = 401
        return { message: 'Токен не найден или недействителен' }
      }

      // Проверяем валидность JWT токена
      const accessSecret = process.env.JWT_ACCESS_SECRET
      
      if (!accessSecret) {
        console.error('JWT_ACCESS_SECRET не определен в переменных окружения')
        set.status = 500
        return { message: 'Ошибка конфигурации сервера' }
      }

      const decoded = jwt.verify(token, accessSecret) as JWTPayload
      
      // Проверяем существование пользователя в базе данных
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
        return { message: 'Пользователь не найден' }
      }

      if (!user.isEmailVerified) {
        set.status = 403
        return { message: 'Почта не подтверждена' }
      }

      // Сохраняем информацию о пользователе в store для использования в route handler
      // @ts-ignore
      store.currentUser = {
        id: user.id,
        login: user.login,
      }

    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        set.status = 401
        return { message: 'Токен истек' }
      } else if (error instanceof jwt.JsonWebTokenError) {
        set.status = 401
        return { message: 'Невалидный токен' }
      } else {
        console.error('Ошибка аутентификации:', error)
        set.status = 500
        return { message: 'Внутренняя ошибка сервера' }
      }
    }
  })