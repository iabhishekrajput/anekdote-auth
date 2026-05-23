const MAILPIT_URL = process.env.MAILPIT_URL || 'http://localhost:8025';

interface MailpitMessage {
  ID: string;
  To: Array<{ Address: string }>;
  Subject: string;
  Snippet: string;
}

interface MailpitBody {
  HTML: string;
  Text: string;
}

async function fetchMessages(): Promise<MailpitMessage[]> {
  const res = await fetch(`${MAILPIT_URL}/api/v1/messages`);
  if (!res.ok) throw new Error(`Mailpit API error: ${res.status}`);
  const data = await res.json() as { messages: MailpitMessage[] };
  return data.messages || [];
}

async function fetchBody(id: string): Promise<MailpitBody> {
  const res = await fetch(`${MAILPIT_URL}/api/v1/message/${id}`);
  if (!res.ok) throw new Error(`Mailpit message fetch error: ${res.status}`);
  return res.json() as Promise<MailpitBody>;
}

async function deleteMessage(id: string): Promise<void> {
  await fetch(`${MAILPIT_URL}/api/v1/messages`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ IDs: [id] }),
  });
}

/** Delete all messages in Mailpit. Call before each test. */
export async function clearMailbox(): Promise<void> {
  await fetch(`${MAILPIT_URL}/api/v1/messages`, { method: 'DELETE' });
}

/** Poll Mailpit until a message for `toEmail` arrives, extract the 6-digit OTP. */
export async function waitForOTP(
  toEmail: string,
  timeoutMs = 15_000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const messages = await fetchMessages();
    const msg = messages.find((m) =>
      m.To.some((t) => t.Address.toLowerCase() === toEmail.toLowerCase()) &&
      m.Subject.toLowerCase().includes('verify'),
    );
    if (msg) {
      const body = await fetchBody(msg.ID);
      const text = body.Text || body.HTML;
      const match = text.match(/\b(\d{6})\b/);
      if (match) {
        await deleteMessage(msg.ID);
        return match[1];
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`waitForOTP: no OTP email for ${toEmail} within ${timeoutMs}ms`);
}

/** Poll Mailpit until a password reset message arrives, extract the reset link. */
export async function waitForResetLink(
  toEmail: string,
  timeoutMs = 15_000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const messages = await fetchMessages();
    const msg = messages.find((m) =>
      m.To.some((t) => t.Address.toLowerCase() === toEmail.toLowerCase()) &&
      m.Subject.toLowerCase().includes('reset'),
    );
    if (msg) {
      const body = await fetchBody(msg.ID);
      const text = body.Text || body.HTML;
      const match = text.match(/https?:\/\/[^\s"<]+reset-password[^\s"<]*/);
      if (match) {
        await deleteMessage(msg.ID);
        return match[0];
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`waitForResetLink: no reset email for ${toEmail} within ${timeoutMs}ms`);
}
