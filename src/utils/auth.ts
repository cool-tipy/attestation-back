
import jwt from 'jsonwebtoken'

export function verifyToken(headers: Record<string, string | undefined>, set: any) {

  if(!headers){
    return
  }

  const token = headers['authorization']
  if (!token) {
    return
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)
    return decoded
  } catch (err) {
    return
  }
}