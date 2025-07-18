import jwt from 'jsonwebtoken'

export function verifyToken(headers: Record<string, string | undefined>, set: any) {


  
  if(!headers){
    set.status = 401;
    return { message: "Unauthorized" };
  }

  const token = headers['authorization']

  if (!token) {
    set.status = 401;
    return { message: "Unauthorized" };
  }

  try{
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!)
    return decoded
  }catch{
    set.status = 403
    throw new Error('Invalid token')
  }
}