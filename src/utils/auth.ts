import jwt from 'jsonwebtoken'

export function verifyToken(headers: Record<string, string | undefined>, set: any) {
  const token = headers['authorization']

  if (!token){
    const err = new Error('Unauthorized');
    (err as any).status = 401
    throw err
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)
    return decoded
  }catch {
    const err = new Error('Invalid token');
    (err as any).status = 403
    throw err
  }
}