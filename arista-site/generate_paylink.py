"""Generate a secure pay link for an invoice number (1001+ format).

This script reads your local invoice app's SQLite database (app.db) and
computes the *remaining amount due* for a given invoice number.

It then generates a signed token that your Cloudflare Pages Function
(/api/create-payment-intent) can verify. The token prevents customers from
changing the amount in the browser.

Usage (Windows CMD):
  set PAYLINK_SIGNING_SECRET=some-long-random-string
  python generate_paylink.py --invoice 1001 --base https://aristaplumbingllc.com

Notes:
- Invoice display numbers are internal_id + 1000 (so internal 1 => 1001).
- You must set the SAME PAYLINK_SIGNING_SECRET in Cloudflare as a secret.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from typing import Tuple


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def sign_payload(payload_bytes: bytes, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    return b64url_encode(sig)


def make_token(invoice_number: int, amount_cents: int, secret: str, ttl_seconds: int, currency: str) -> str:
    payload = {
        "inv": int(invoice_number),
        "amt": int(amount_cents),
        "cur": currency,
        "exp": int(time.time()) + int(ttl_seconds),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = b64url_encode(payload_bytes)
    sig_b64 = sign_payload(payload_bytes, secret)
    return f"{payload_b64}.{sig_b64}"


def get_invoice_amount_due(db_path: str, invoice_number: int) -> Tuple[float, float, float]:
    """Return (total, paid, due) for the given invoice display number."""
    internal_id = invoice_number - 1000
    if internal_id <= 0:
        raise ValueError("Invoice number must be 1001 or higher.")

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT total FROM invoices WHERE id = ?", (internal_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Invoice {invoice_number} not found in DB.")
        total = float(row[0] or 0.0)

        cur.execute("SELECT COALESCE(SUM(amount), 0) FROM receipts WHERE invoice_id = ?", (internal_id,))
        paid = float(cur.fetchone()[0] or 0.0)

        due = total - paid
        return total, paid, due
    finally:
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--invoice", type=int, required=True, help="Invoice number (1001, 1002, …)")
    ap.add_argument("--base", type=str, required=True, help="Base website URL, e.g. https://aristaplumbingllc.com")
    ap.add_argument("--db", type=str, default="app.db", help="Path to app.db (default: app.db)")
    ap.add_argument("--ttl", type=int, default=7 * 24 * 3600, help="Link expiry in seconds (default: 7 days)")
    ap.add_argument("--currency", type=str, default=os.getenv("STRIPE_CURRENCY", "usd"), help="Currency (default: usd)")
    args = ap.parse_args()

    secret = os.getenv("PAYLINK_SIGNING_SECRET")
    if not secret:
        raise SystemExit("Missing PAYLINK_SIGNING_SECRET environment variable.")

    total, paid, due = get_invoice_amount_due(args.db, args.invoice)
    if due <= 0:
        raise SystemExit(f"Invoice {args.invoice} has no amount due (total={total:.2f}, paid={paid:.2f}).")

    amount_cents = int(round(due * 100))
    token = make_token(args.invoice, amount_cents, secret, args.ttl, args.currency)

    base = args.base.rstrip("/")
    pay_url = f"{base}/pay.html?invoice={args.invoice}&t={token}"

    print("Invoice:", args.invoice)
    print(f"Total: ${total:.2f}  Paid: ${paid:.2f}  Due: ${due:.2f}")
    print("Pay link (copy/paste into email/text):")
    print(pay_url)


if __name__ == "__main__":
    main()
