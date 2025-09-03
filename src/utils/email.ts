import nodemailer from 'nodemailer';

function derivePlainTextFromHtml(html: string): string {
  try {
    let out = html;
    // Anchor tags: "<a href=\"URL\">TEXT</a>" -> "TEXT (URL)"
    out = out.replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gis, (_m, url, txt) => {
      // Strip any nested tags in link text
      const cleanTxt = String(txt || '').replace(/<[^>]+>/g, '');
      return `${cleanTxt} (${url})`;
    });
    // Replace <br> and block tags with newlines for readability
    out = out.replace(/<(?:br|br\s*\/)>/gi, '\n');
    out = out.replace(/<\/(?:p|div|li|h\d)>/gi, '\n');
    // Strip remaining tags
    out = out.replace(/<[^>]+>/g, '');
    // Decode a few common HTML entities
    out = out
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    // Normalize whitespace
    out = out.replace(/[\t\r]+/g, '').replace(/\n{3,}/g, '\n\n').trim();
    return out;
  } catch {
    return html;
  }
}

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
    // If HTML is provided but the text looks like HTML or is empty, derive a clean text alternative
    let finalText = text;
    if (html && (!finalText || /<\w+[^>]*>/.test(finalText))) {
      finalText = derivePlainTextFromHtml(html);
    }

    const mailOptions: any = { from, to, subject, text: finalText, html, envelope: { from, to } };
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


