import nodemailer from 'nodemailer'

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  }
})

export async function sendVerificationEmail(to: string, code: string) {
  const mailOptions = {
    from: '"MyApp" <no-reply@myapp.com>',
    to: to,
    subject: 'Подтверждение адреса электронной почты',
    html: `
    <h2>Добро пожаловать в Виталика!</h2>
    <p>Ваш код для подтверждения почты:</p>
    <h3>${code}</h3>
    <p>Пожалуйста, используйте этот код для завершения регистрации.
    `,
  }

  try {
    await transporter.sendMail(mailOptions)
    console.log(`Verification email sent to ${to}`)
  } catch (error) {
    console.error(`Error sending email to ${to}: `, error)
    throw new Error('Could not send verification email')
  }
}