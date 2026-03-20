// Cloudflare Pages Function
// POST /api/create-payment-intent
// Body: { invoice: 1001, token: "..." }
// Returns: { clientSecret: "pi_..._secret_..." }

// Stripe PaymentIntents create: https://docs.stripe.com/api/payment_intents/create

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const str = atob(b64 + pad);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes) {
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function hmacSha256(secret, msgBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

async function verifyToken(token, signingSecret) {
  const parts = token.split('.');
  if (parts.length !== 2) throw new Error('Invalid token format');

  const payloadB64 = parts[0];
  const sigB64 = parts[1];

  const payloadBytes = base64UrlToBytes(payloadB64);
  const expectedSig = await hmacSha256(signingSecret, payloadBytes);
  const expectedSigB64 = bytesToBase64Url(expectedSig);

  if (expectedSigB64 !== sigB64) throw new Error('Invalid token signature');

  const payloadJson = new TextDecoder().decode(payloadBytes);
  const payload = JSON.parse(payloadJson);

  if (typeof payload.exp !== 'number' || Date.now() / 1000 > payload.exp) {
    throw new Error('Payment link expired');
  }
  if (typeof payload.inv !== 'number' || typeof payload.amt !== 'number') {
    throw new Error('Invalid token payload');
  }
  return payload; // { inv, amt, exp, cur }
}

function formEncode(obj) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    params.append(k, String(v));
  }
  return params.toString();
}

export async function onRequestPost(context) {
  const { env } = context;

  const STRIPE_SECRET_KEY = env.STRIPE_SECRET_KEY; // sk_... or rk_...
  const PAYLINK_SIGNING_SECRET = env.PAYLINK_SIGNING_SECRET;
  const STRIPE_CURRENCY = env.STRIPE_CURRENCY || 'usd';

  if (!STRIPE_SECRET_KEY) {
    return new Response('Missing STRIPE_SECRET_KEY on server.', { status: 500 });
  }
  if (!PAYLINK_SIGNING_SECRET) {
    return new Response('Missing PAYLINK_SIGNING_SECRET on server.', { status: 500 });
  }

  let body;
  try {
    body = await context.request.json();
  } catch {
    return new Response('Invalid JSON body.', { status: 400 });
  }

  const invoice = Number(body.invoice);
  const token = String(body.token || '');
  if (!invoice || !token) {
    return new Response('Missing invoice or token.', { status: 400 });
  }

  let payload;
  try {
    payload = await verifyToken(token, PAYLINK_SIGNING_SECRET);
  } catch (e) {
    return new Response(e.message || 'Invalid token.', { status: 400 });
  }

  if (payload.inv !== invoice) {
    return new Response('Invoice mismatch.', { status: 400 });
  }

  const amount = payload.amt; // cents
  const currency = payload.cur || STRIPE_CURRENCY;

  // Create PaymentIntent on Stripe
  const piBody = formEncode({
    amount,
    currency,
    'payment_method_types[]': 'card',
    'metadata[invoice_number]': String(invoice),
  });

  const resp = await fetch('https://api.stripe.com/v1/payment_intents', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: piBody,
  });

  const text = await resp.text();
  if (!resp.ok) {
    return new Response(`Stripe error: ${resp.status} ${text}`, { status: 502 });
  }

  const json = JSON.parse(text);
  return new Response(JSON.stringify({ clientSecret: json.client_secret }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
