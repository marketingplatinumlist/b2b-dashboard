const crypto = require('crypto');

const PROJECT = 'b2b';
const REQ_COOKIE = 'soreq';
const AUTH_COOKIE = 'somauth';
const REQ_TTL_MS = 15 * 60 * 1000;
const AUTH_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_SUPABASE_URL = 'https://kwftlkfvtglnugxsyjci.supabase.co';
const DEFAULT_SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt3ZnRsa2Z2dGdsbm5neHN5amNpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDc2MzMzODUsImV4cCI6MjA2MzIwOTM4NX0.placeholder';

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

function parseCookie(req, key) {
  const raw = req.headers.cookie || '';
  if (!raw) return '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === key) return v.join('=');
  }
  return '';
}

function safeEqualHex(a, b) {
  const ab = Buffer.from(a || '', 'hex');
  const bb = Buffer.from(b || '', 'hex');
  if (!ab.length || !bb.length || ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function decodeSignedReq(raw, secret) {
  if (!raw || raw.length > 32768) return null;
  const [payloadEncoded, sig] = String(raw).split('.');
  if (!payloadEncoded || !sig) return null;
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadEncoded).digest('hex');
  if (!safeEqualHex(sig, expectedSig)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload?.iat || !payload?.p || !payload?.email) return null;
  if (payload.p !== PROJECT) return { error: 'project_mismatch' };
  if (Date.now() - Number(payload.iat) > REQ_TTL_MS) return { error: 'otp_request_expired' };
  return payload;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });

  const secret = process.env.OTP_SIGNING_SECRET;
  if (!secret || secret.length < 16) {
    return json(res, 500, { error: 'OTP_SIGNING_SECRET is missing or too short' });
  }

  // Parse body
  let body = '';
  for await (const chunk of req) body += chunk;
  let parsed;
  try { parsed = JSON.parse(body); } catch { return json(res, 400, { error: 'invalid_json' }); }

  const code = String(parsed?.code || '').trim();
  if (!code || !/^\d{6}$/.test(code)) {
    return json(res, 400, { error: 'invalid_code', message: 'Please enter a 6-digit code.' });
  }

  // Validate soreq cookie
  const reqCookie = parseCookie(req, REQ_COOKIE);
  if (!reqCookie) return json(res, 400, { error: 'otp_request_required' });
  const reqPayload = decodeSignedReq(reqCookie, secret);
  if (!reqPayload) return json(res, 400, { error: 'otp_request_required' });
  if (reqPayload.error) return json(res, 400, { error: reqPayload.error });
  const email = reqPayload.email;
  if (!email) return json(res, 400, { error: 'email_missing_from_request' });

  // Verify OTP via Supabase Auth
  const supabaseUrl = process.env.SUPABASE_URL || DEFAULT_SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_ANON_KEY || DEFAULT_SUPABASE_ANON_KEY;

  let verifyOk = false;
  try {
    const verifyResp = await fetch(`${supabaseUrl}/auth/v1/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': supabaseKey,
      },
      body: JSON.stringify({ email, token: code, type: 'magiclink' }),
    });
    verifyOk = verifyResp.ok;
    if (!verifyOk) {
      const errBody = await verifyResp.json().catch(() => ({}));
      const msg = errBody?.msg || errBody?.error_description || errBody?.error || 'verification_failed';
      return json(res, 400, { error: 'otp_incorrect', message: String(msg) });
    }
  } catch (e) {
    return json(res, 502, { error: 'supabase_verify_failed', message: String(e?.message || e) });
  }

  // Create auth cookie
  const expiresAt = Date.now() + AUTH_TTL_SECONDS * 1000;
  const authPayloadEncoded = Buffer.from(JSON.stringify({ e: email, x: expiresAt })).toString('base64url');
  const authSig = crypto.createHmac('sha256', secret).update(authPayloadEncoded).digest('hex');
  const authCookie = `${AUTH_COOKIE}=${authPayloadEncoded}.${authSig}; Max-Age=${AUTH_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`;
  const clearReqCookie = `${REQ_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;

  return json(
    res,
    200,
    { ok: true, email, expires_at: expiresAt },
    { 'Set-Cookie': [authCookie, clearReqCookie] },
  );
};
