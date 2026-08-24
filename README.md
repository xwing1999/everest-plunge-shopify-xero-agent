# Everest Plunge Shopify → Xero Agent

Standalone automation service (Node/Express, no LLM in the write path — this
is a deterministic data mapping, not a question-answering agent). Everest
Plunge's first workflow-automation agent, separate from Kiwiseal's
Business-Brain-style chat agents.

## What it does

1. Shopify fires an `orders/paid` webhook the moment an order is paid.
2. This service verifies the webhook signature, matches or creates the
   customer as a Xero contact (by email), creates the matching Xero sales
   invoice (`ACCREC`), marks it paid against a Shopify Payments clearing
   account (since the money was already collected at checkout), and emails
   the invoice to the customer via Xero's own delivery.
3. On any failure, it flags the order in a persisted failed-order log and
   stops — it never deletes or retries a half-done write on its own. A
   human fixes the underlying problem (in Xero or Shopify), then calls
   `POST /admin/replay-order` to reprocess it. This mirrors the no-self-
   correction rule used across every write-capable Everest Plunge agent.

## Setup checklist

1. **Xero**: create a new Developer app at developer.xero.com pointed at
   Everest Plunge's own Xero organisation (not Kiwiseal's). Fill in
   `XERO_CLIENT_ID` / `XERO_CLIENT_SECRET` / `XERO_REDIRECT_URI` in
   Railway, deploy, then visit `/oauth/start` in a browser once and log in
   as Everest Plunge. Confirm the callback page shows the right org name.
2. **Chart of accounts**: fill in `XERO_SALES_ACCOUNT_CODE`,
   `XERO_TAX_TYPE`, and `XERO_SHOPIFY_PAYMENTS_ACCOUNT_CODE` — these are
   real values from your Xero org, not guesses. See `env-vars.txt` for what
   each one means and where to find it.
3. **Stock sheet integration (optional)**: if `everest-plunge-stock-sheet-agent`
   is deployed, set `STOCK_SHEET_AGENT_URL`/`STOCK_SHEET_AGENT_API_KEY` so
   this agent bumps the Stock Overview "New Orders" count for each SKU sold,
   right after invoicing. Assumes Shopify variant SKUs match the "SKU-xxx"
   codes in the Operations sheet — confirm that's actually true for your
   product catalog. Leave blank to skip this step entirely.
4. **Shopify**: in the Shopify admin, go to Settings > Notifications >
   Webhooks, add a webhook for topic "Order payment" (JSON format) pointing
   at `https://<this-service>/webhooks/shopify/orders-paid`. Copy the
   signing secret Shopify shows you into `SHOPIFY_WEBHOOK_SECRET`.
5. Send a real test order through Shopify checkout and confirm: a contact
   appears in Xero, an invoice is created and marked paid, and the
   customer actually receives the emailed invoice.

## Not yet confirmed — verify before relying on this live

- The `Invoices/{id}/Email` Xero endpoint is implemented per Xero's
  documented behaviour but has not been exercised against Everest Plunge's
  real Xero org yet (no credentials existed at write time). Confirm it
  actually sends an email once OAuth is connected.
- `LineAmountTypes: 'Inclusive'` assumes Shopify product prices already
  include GST, which is normal for NZ retail but confirm it's true for
  Everest Plunge's actual product setup — if prices are GST-exclusive,
  change this to `'Exclusive'`.
- Marking every invoice paid against a clearing account on creation is the
  standard e-commerce accounting pattern, but confirm your accountant is
  happy with this before going live. Leave `XERO_SHOPIFY_PAYMENTS_ACCOUNT_CODE`
  blank to skip this step and leave invoices as ordinary unpaid AUTHORISED
  invoices instead.

## Admin endpoints (require `x-api-key`)

- `GET /admin/failed-orders` — list flagged failures, resolved and not.
- `POST /admin/replay-order` — body `{ "orderName": "#1023" }`, reprocesses
  a previously failed order after you've fixed the underlying cause.

## Deployment

Same pattern as the Kiwiseal Simpro/Xero agents: push this repo to GitHub,
create a Railway service from it in the Everest Plunge Railway project
(separate from Kiwiseal's), paste env vars into Railway's Variables tab
(never into `env-vars.txt` or git), attach a small persistent volume at
`/data` so the Xero refresh token and failed-order log survive restarts.
