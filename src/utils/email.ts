import nodemailer from 'nodemailer';

export async function sendEmail(to: string, subject: string, text: string, html?: string) {
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.EMAIL_FROM || 'no-reply@howdy.app';

  if (!host || !port || !user || !pass) {
    console.log('📧 [DEV email fallback] To:', to);
    console.log('Subject:', subject);
    console.log('Text:', text);
    return;
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });

  await transporter.sendMail({ from, to, subject, text, html });
}


