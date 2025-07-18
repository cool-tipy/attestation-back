
import jwt from 'jsonwebtoken'

export function verifyToken(headers: Record<string, string | undefined>, set: any) {

  if(!headers){
    return
  }

  const token = headers['authorization']
  if (!token) {
    set.status = 401
    throw new Error('Token not provided')
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)
    return decoded
  } catch (err) {
    set.status = 401
    throw new Error('Invalid token')
  }
}