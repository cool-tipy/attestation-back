import { PrismaClient } from '@prisma/client'

// Создаем единственный экземпляр и экспортируем его
export const prisma = new PrismaClient()