// Cloudflare Pages Function
// POST /api/stripe-webhook
//
// Required environment variables:
// - STRIPE_WEBHOOK_SECRET
//
// This minimal version verifies Stripe's webhook signature and acknowledges
// successful payment events without sending email.

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i += 1) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}

function parseStripeSignature(header) {
  const parts = String(header || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);

  let timestamp = null;
  const signatures = [];

  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx);
    const value = part.slice(idx + 1);
    if (key === 't') timestamp = Number(value);
    if (key === 'v1') signatures.push(value);
  }

  return { timestamp, signatures };
}

async function computeStripeSignature(secret, timestamp, rawBody) {
  const signedPayload = `${timestamp}.${rawBody}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(signedPayload)
  );
  return bytesToHex(new Uint8Array(signature));
}

async function verifyStripeWebhook(rawBody, signatureHeader, endpointSecret) {
  const { timestamp, signatures } = parseStripeSignature(signatureHeader);

  if (!timestamp || signatures.length === 0) {
    throw new Error('Missing Stripe signature.');
  }

  const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (ageSeconds > 300) {
    throw new Error('Webhook timestamp is too old.');
  }

  const expected = await computeStripeSignature(endpointSecret, timestamp, rawBody);
  const matches = signatures.some((sig) => secureCompare(sig, expected));

  if (!matches) {
    throw new Error('Webhook signature verification failed.');
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const endpointSecret = (env.STRIPE_WEBHOOK_SECRET || '').trim();
  if (!endpointSecret) {
    return new Response('Missing STRIPE_WEBHOOK_SECRET.', { status: 500 });
  }

  const signatureHeader = request.headers.get('Stripe-Signature') || '';
  const rawBody = await request.text();

  try {
    await verifyStripeWebhook(rawBody, signatureHeader, endpointSecret);
  } catch (error) {
    return new Response(error?.message || 'Invalid signature.', { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response('Invalid JSON payload.', { status: 400 });
  }

  if (event?.type === 'payment_intent.succeeded') {
    console.log('Stripe payment succeeded', {
      id: event?.data?.object?.id,
      invoice: event?.data?.object?.metadata?.invoice_number || null,
      amount: event?.data?.object?.amount_received || event?.data?.object?.amount || null,
      currency: event?.data?.object?.currency || null,
    });
  }

  return new Response('OK', { status: 200 });
}
