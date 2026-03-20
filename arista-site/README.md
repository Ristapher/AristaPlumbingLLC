# Arista Plumbing — Invoice Payment Page (Stripe Elements + Cloudflare Pages)

This package lets customers pay an **invoice number (1001+)** on your site using a **card form** (Stripe Payment Element).

It uses:
- **Cloudflare Pages** for the static page (`/pay.html`)
- **Cloudflare Pages Functions** for a secure API endpoint (`/api/create-payment-intent`)
- **Stripe PaymentIntents** to create a payment and return a `client_secret` to the browser.

Stripe notes the client secret is used client-side to complete the payment flow, while sensitive fields remain server-side. (Stripe PaymentIntents) 

## 1) Deploy to Cloudflare Pages

Create a Pages project (or use your existing site repo).

Copy these files into your repo:

- `public/pay.html`
- `public/paid.html`
- `public/cancel.html`
- `functions/api/create-payment-intent.js`

Also add your logo as `public/logo.png` (optional).

### Set your Stripe publishable key

Edit `public/pay.html`:

```js
const STRIPE_PUBLISHABLE_KEY = "REPLACE_WITH_YOUR_PK_KEY";
```

## 2) Add Secrets / Variables in Cloudflare

In Cloudflare Dashboard → **Workers & Pages** → your Pages project → **Settings** → **Variables and Secrets**:

Add:

- `STRIPE_SECRET_KEY` = your Stripe **secret** key (`sk_...`) or **restricted** key (`rk_...`)
- `PAYLINK_SIGNING_SECRET` = a long random string (same value you will set on your PC)
- `STRIPE_CURRENCY` = `usd` (optional)

Cloudflare documents adding environment variables/secrets in the dashboard. 

## 3) Generate a Pay Link (on your PC)

Run the helper script `generate_paylink.py` next to your invoice app database (`app.db`).

### Windows CMD

```cmd
cd C:\path\to\your\invoice_app_folder
set PAYLINK_SIGNING_SECRET=some-long-random-string
python generate_paylink.py --invoice 1001 --base https://aristaplumbingllc.com
```

It reads `app.db`, calculates the **remaining amount due**, and prints a link like:

`https://aristaplumbingllc.com/pay.html?invoice=1001&t=...`

Send that link to the customer.

## 4) Customer pays

The customer opens the link, enters card details, and Stripe handles authentication (3DS) as needed.

## Next recommended step

Add a **Stripe webhook** (`payment_intent.succeeded`) so your system can automatically mark invoices paid.

