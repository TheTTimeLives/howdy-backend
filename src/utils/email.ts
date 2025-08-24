import nodemailer from 'nodemailer';

export async function sendEmail(to: string, subject: string, text: string, html?: string) {
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.EMAIL_FROM || 'no-reply@howdy.app';
  const secure = typeof port === 'number' ? port === 465 : false;

  const sanitizedConfig = { host, port, secure, from };

  if (!host || !port || !user || !pass) {
    console.log('📧 [DEV email fallback] No SMTP configured. Email not actually sent.');
    console.log('↪️ Config:', sanitizedConfig);
    console.log('→ To:', to);
    console.log('→ Subject:', subject);
    console.log('→ Text:', text);
    return;
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });

  console.log('📧 Attempting to send email...', { to, subject, config: sanitizedConfig });

  try {
    const mailOptions: any = { from, to, subject, text, html, envelope: { from, to } };
    if (process.env.EMAIL_REPLY_TO) {
      mailOptions.replyTo = process.env.EMAIL_REPLY_TO;
    }
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Email sent', {
      to,
      subject,
      messageId: (info as any)?.messageId,
      accepted: (info as any)?.accepted,
      rejected: (info as any)?.rejected,
      response: (info as any)?.response,
      envelope: (info as any)?.envelope,
      config: sanitizedConfig,
    });
  } catch (err: any) {
    console.error('❌ Email send failed', {
      to,
      subject,
      error: err?.message || err,
      config: sanitizedConfig,
    });
    throw err;
  }
}


