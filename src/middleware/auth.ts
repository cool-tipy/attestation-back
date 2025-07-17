import { Elysia, t } from 'elysia'
import jwt from 'jsonwebtoken'
import { prisma } from '../lib/prisma' // <-- Импортируем синглтон

interface JWTPayload {
  userId: number
  login: string
  iat: number
  exp: number
}

// Создаем плагин, который добавляет state и decorate
export const authMiddleware = new Elysia({ name: 'auth.middleware' })
  // 1. Добавляем currentUser в `store` с правильным типом
  .state('currentUser', { id: 0, login: '' })
  // 2. Создаем производное состояние (derive), которое будет выполняться перед onBeforeHandle
  .derive(async ({ headers, store, set }) => {
    try {
      const authHeader = headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { isAuthenticated: false }
      }

      const token = authHeader.substring(7)
      if (!token || token === 'undefined' || token === 'null') {
        return { isAuthenticated: false }
      }

      const accessSecret = process.env.JWT_ACCESS_SECRET
      if (!accessSecret) {
        console.error('JWT_ACCESS_SECRET не определен')
        set.status = 500
        // ВАЖНО: В derive/onBeforeHandle нужно возвращать объект, а не вызывать return напрямую
        // Elysia остановит выполнение, если вы измените `set.status`
        return { isAuthenticated: false }
      }

      const decoded = jwt.verify(token, accessSecret) as JWTPayload
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: { id: true, login: true, isEmailVerified: true },
      })

      if (!user) {
        return { isAuthenticated: false }
      }

      // Если почта не подтверждена, мы можем передать эту информацию дальше
      if (!user.isEmailVerified) {
         set.status = 403
         // Можно даже передать сообщение об ошибке
         return { isAuthenticated: false, authError: 'Почта не подтверждена' }
      }
      
      // Обновляем store, который мы определили через .state()
      store.currentUser = { id: user.id, login: user.login }

      return { isAuthenticated: true }

    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        set.status = 401
        return { isAuthenticated: false, authError: 'Токен истек' }
      }
      if (error instanceof jwt.JsonWebTokenError) {
        set.status = 401
        return { isAuthenticated: false, authError: 'Невалидный токен' }
      }
      console.error('Ошибка аутентификации:', error)
      set.status = 500
      return { isAuthenticated: false, authError: 'Внутренняя ошибка сервера' }
    }
  })
  // 3. Добавляем локальный хук, который будет проверять результат из derive
  .onBeforeHandle(({ set, isAuthenticated, authError }) => {
      if (!isAuthenticated) {
          // Статус уже должен быть установлен в `derive`
          // Мы просто возвращаем сообщение, чтобы остановить выполнение
          return { message: authError || 'Требуется аутентификация' }
      }
  })