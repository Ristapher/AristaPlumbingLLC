// Cloudflare Pages Function
// POST /api/create-payment-intent
// Body: { invoice: 1001, token: "..." }
// Returns: { clientSecret: "pi_..._secret_...", amount: 12345, currency: "usd" }

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const str = atob(b64 + pad);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i += 1) bytes[i] = str.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes) {
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
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
  const parts = String(token || '').split('.');
  if (parts.length !== 2) throw new Error('Invalid token format.');

  const payloadB64 = parts[0];
  const sigB64 = parts[1];

  const payloadBytes = base64UrlToBytes(payloadB64);
  const expectedSig = await hmacSha256(signingSecret, payloadBytes);
  const expectedSigB64 = bytesToBase64Url(expectedSig);

  if (expectedSigB64 !== sigB64) throw new Error('Invalid payment link signature.');

  const payloadJson = new TextDecoder().decode(payloadBytes);
  const payload = JSON.parse(payloadJson);

  if (typeof payload.exp !== 'number' || Date.now() / 1000 > payload.exp) {
    throw new Error('This payment link has expired.');
  }
  if (typeof payload.inv !== 'number' || typeof payload.amt !== 'number') {
    throw new Error('Invalid payment link payload.');
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

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function onRequestPost(context) {
  const { env, request } = context;

  const STRIPE_SECRET_KEY = (env.STRIPE_SECRET_KEY || '').trim();
  const PAYLINK_SIGNING_SECRET = (env.PAYLINK_SIGNING_SECRET || '').trim();
  const STRIPE_CURRENCY = (env.STRIPE_CURRENCY || 'usd').trim().toLowerCase();

  if (!STRIPE_SECRET_KEY) {
    return jsonResponse({ error: 'Missing STRIPE_SECRET_KEY on the server.' }, 500);
  }
  if (!PAYLINK_SIGNING_SECRET) {
    return jsonResponse({ error: 'Missing PAYLINK_SIGNING_SECRET on the server.' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body.' }, 400);
  }

  const invoice = Number(body?.invoice);
  const token = String(body?.token || '');

  if (!invoice || !token) {
    return jsonResponse({ error: 'Missing invoice or token.' }, 400);
  }

  let payload;
  try {
    payload = await verifyToken(token, PAYLINK_SIGNING_SECRET);
  } catch (error) {
    return jsonResponse({ error: error?.message || 'Invalid payment link.' }, 400);
  }

  if (payload.inv !== invoice) {
    return jsonResponse({ error: 'Invoice mismatch.' }, 400);
  }

  const amount = Number(payload.amt);
  const currency = String(payload.cur || STRIPE_CURRENCY).toLowerCase();

  if (!Number.isInteger(amount) || amount <= 0) {
    return jsonResponse({ error: 'Invalid payment amount.' }, 400);
  }

  const stripeBody = formEncode({
    amount,
    currency,
    'payment_method_types[]': 'card',
    description: `Arista Plumbing invoice #${invoice}`,
    'metadata[invoice_number]': String(invoice),
    'metadata[source]': 'arista-payment-page',
  });

  const stripeResp = await fetch('https://api.stripe.com/v1/payment_intents', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: stripeBody,
  });

  const stripeText = await stripeResp.text();

  if (!stripeResp.ok) {
    return jsonResponse(
      { error: `Stripe error ${stripeResp.status}.`, detail: stripeText },
      502
    );
  }

  const stripeJson = JSON.parse(stripeText);

  return jsonResponse({
    clientSecret: stripeJson.client_secret,
    amount,
    currency,
  });
}
