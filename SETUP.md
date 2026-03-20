# Arista payment patch (no Resend)

This folder contains the payment files for a simple one-time card payment flow **without** any extra email service.

## Folder layout

- `functions/api/create-payment-intent.js`
- `functions/api/stripe-webhook.js`
- `pay.html`
- `paid.html`
- `cancel.html`
- `images/arista-logo.png`
- `.dev.vars.example`

## Cloudflare Pages secrets

Add these in **Workers & Pages → your Pages project → Settings → Variables and Secrets**:

- `STRIPE_SECRET_KEY`
- `PAYLINK_SIGNING_SECRET`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_CURRENCY` = `usd`

## Stripe setup

1. In Stripe, create a webhook endpoint pointing to:
   `https://your-domain.com/api/stripe-webhook`

2. Subscribe it to:
   - `payment_intent.succeeded`

3. Copy the webhook signing secret (`whsec_...`) into:
   - `STRIPE_WEBHOOK_SECRET`

4. Put your Stripe publishable key into:
   - `pay.html`
   - `paid.html`

## What this version gives you

- customer can open a signed payment link
- customer can pay once by card
- site shows payment confirmation status
- Stripe can call your webhook successfully
- no Resend account is required
- no extra email service secrets are required

## What this version does not do

- it does **not** email you after a payment
- it does **not** email the customer from your site code

If you want customer receipts, you can enable Stripe's own receipts in Stripe Dashboard later.
