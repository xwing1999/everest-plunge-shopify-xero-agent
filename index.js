import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const app = express();

// ---------------------------------------------------------------------------
// Shopify webhook signature verification needs the RAW request body (HMAC is
// computed over the exact bytes Shopify sent) — must capture it before
// express.json() parses/reformats anything. Every other route gets the
// normal JSON body parser.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  if (req.path === '/webhooks/shopify/orders-paid') {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      req.rawBody = raw;
      try { req.body = JSON.parse(raw); } catch { req.body = {}; }
      next();
    });
  } else {
    express.json()(req, res, next);
  }
});

// ---------------------------------------------------------------------------
// AUTH — shared-secret pattern for admin/manual endpoints, same as the
// Kiwiseal agents. The Shopify webhook and Xero OAuth routes are exempt:
// Shopify signs its own requests (verified separately below via HMAC), and
// /oauth/* is a one-time browser flow with no header a redirect can carry.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  if (req.path === '/health' || req.path.startsWith('/oauth/') || req.path.startsWith('/webhooks/')) return next();
  const provided = req.header('x-api-key');
  if (!process.env.API_KEY || provided !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// ---------------------------------------------------------------------------
// XERO OAUTH TOKEN MANAGEMENT — same pattern as wellington-xero-agent, with
// WRITE scopes added (accounting.transactions, accounting.contacts) since
// this agent creates invoices, contacts, and payments, not just reads them.
// ---------------------------------------------------------------------------
const TOKEN_FILE = process.env.XERO_TOKEN_FILE || '/data/xero-token.json';

const tokenState = {
  accessToken: null,
  refreshToken: process.env.XERO_REFRESH_TOKEN || null,
  tenantId: process.env.XERO_TENANT_ID || null,
  expiresAt: 0
};

function loadPersistedToken() {
  try {
    const saved = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    if (saved.refreshToken) tokenState.refreshToken = saved.refreshToken;
    if (saved.tenantId) tokenState.tenantId = saved.tenantId;
    console.log('Loaded persisted Xero token from disk.');
  } catch {
    // No persisted file yet, or no volume mounted — fall back to env vars.
  }
}
loadPersistedToken();

function persistToken() {
  try {
    fs.mkdirSync(path.dirname(TOKEN_FILE), { recursive: true });
    fs.writeFileSync(TOKEN_FILE, JSON.stringify({
      refreshToken: tokenState.refreshToken,
      tenantId: tokenState.tenantId
    }));
  } catch (err) {
    console.warn(
      'Could not persist Xero token to disk (no volume mounted at ' + TOKEN_FILE + '?). ' +
      'Relying on in-memory cache + env var fallback. Error:', err.message
    );
  }
}

async function refreshAccessToken() {
  if (!tokenState.refreshToken) {
    throw new Error('No Xero refresh token available yet — visit /oauth/start in a browser to authorize this agent.');
  }
  const res = await fetch('https://identity.xero.com/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: 'Basic ' + Buffer.from(`${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`).toString('base64')
    },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokenState.refreshToken })
  });
  if (!res.ok) {
    throw new Error(`Xero token refresh failed ${res.status}: ${await res.text()}`);
  }
  const data = await res.json();
  tokenState.accessToken = data.access_token;
  tokenState.refreshToken = data.refresh_token; // rotated — must persist now
  tokenState.expiresAt = Date.now() + (data.expires_in - 60) * 1000;
  console.log('Xero access token refreshed. New refresh_token (fallback only — prefer the persisted file):', tokenState.refreshToken);
  persistToken();

  if (!tokenState.tenantId) {
    const connRes = await fetch('https://api.xero.com/connections', {
      headers: { Authorization: `Bearer ${tokenState.accessToken}` }
    });
    const conns = await connRes.json();
    if (!conns.length) throw new Error('No Xero tenant connections found for this token.');
    tokenState.tenantId = conns[0].tenantId;
    persistToken();
  }
}

async function getAccessToken() {
  if (!tokenState.accessToken || Date.now() >= tokenState.expiresAt) {
    await refreshAccessToken();
  }
  return tokenState.accessToken;
}

async function xeroRequest(pathSegment, { method = 'GET', params, body, headers = {} } = {}) {
  const token = await getAccessToken();
  const url = new URL(pathSegment, 'https://api.xero.com/api.xro/2.0/');
  if (params) Object.entries(params).forEach(([k, v]) => v != null && url.searchParams.set(k, v));
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Xero-tenant-id': tokenState.tenantId,
      Accept: 'application/json',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) {
    throw new Error(`Xero API error ${res.status} on ${method} ${pathSegment}: ${await res.text()}`);
  }
  // Some endpoints (e.g. Invoices/{id}/Email) return 204 with an empty body
  // on success — res.json() throws on that, which would make a successful
  // call look like a failure. Read as text first, only parse if non-empty.
  const text = await res.text();
  return text ? JSON.parse(text) : {};
}

// ---------------------------------------------------------------------------
// XERO OAUTH BOOTSTRAP — visit /oauth/start once after deploying, log into
// Xero as Everest Plunge, grant consent. Scopes are Xero's post-2026-03-02
// granular set (same discovery as wellington-xero-agent) plus the write
// scopes this agent actually needs: accounting.transactions (create
// invoices + payments) and accounting.contacts (create/match customers).
// ---------------------------------------------------------------------------
app.get('/oauth/start', (_req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.XERO_CLIENT_ID,
    redirect_uri: process.env.XERO_REDIRECT_URI,
    scope: 'accounting.transactions accounting.contacts offline_access',
    state: 'setup'
  });
  res.redirect(`https://login.xero.com/identity/connect/authorize?${params}`);
});

app.get('/oauth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.status(400).send(`Xero returned an error: ${error}`);
  if (!code) return res.status(400).send('Missing code parameter.');

  try {
    const tokenRes = await fetch('https://identity.xero.com/connect/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + Buffer.from(`${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`).toString('base64')
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.XERO_REDIRECT_URI
      })
    });
    if (!tokenRes.ok) throw new Error(await tokenRes.text());
    const data = await tokenRes.json();

    tokenState.accessToken = data.access_token;
    tokenState.refreshToken = data.refresh_token;
    tokenState.expiresAt = Date.now() + (data.expires_in - 60) * 1000;

    const connRes = await fetch('https://api.xero.com/connections', {
      headers: { Authorization: `Bearer ${tokenState.accessToken}` }
    });
    const conns = await connRes.json();
    tokenState.tenantId = conns[0]?.tenantId ?? null;
    persistToken();

    res.send(`
      <h2>Xero connected</h2>
      <p>Organisation: ${conns[0]?.tenantName ?? 'unknown'}</p>
      <p>Tenant ID: ${tokenState.tenantId ?? 'not found'}</p>
      <p>Confirm this says Everest Plunge, not Kiwiseal. This is saved. If this
      Railway service has no persistent volume attached, also copy this refresh
      token into the <code>XERO_REFRESH_TOKEN</code> Railway variable as a
      backup so a future restart doesn't strand this agent:</p>
      <pre>${tokenState.refreshToken}</pre>
      <p>You can close this tab.</p>
    `);
  } catch (err) {
    res.status(500).send(`Token exchange failed: ${err.message}`);
  }
});

// ---------------------------------------------------------------------------
// FAILED-ORDER LOG — the autonomy rule for this project is "flag and stop,
// never auto-retry-fix a write". If invoice creation fails partway, we do
// NOT delete/redo anything — we log it here for a human to fix directly in
// Xero/Shopify, and the next webhook retry (or a manual replay) picks it up
// once the underlying problem is fixed. Persisted to disk so a restart
// doesn't lose the flag.
// ---------------------------------------------------------------------------
const FAILED_LOG_FILE = process.env.FAILED_LOG_FILE || '/data/failed-orders.json';

function loadFailedLog() {
  try { return JSON.parse(fs.readFileSync(FAILED_LOG_FILE, 'utf8')); } catch { return []; }
}
function appendFailedLog(entry) {
  const log = loadFailedLog();
  log.push({ ...entry, at: new Date().toISOString() });
  try {
    fs.mkdirSync(path.dirname(FAILED_LOG_FILE), { recursive: true });
    fs.writeFileSync(FAILED_LOG_FILE, JSON.stringify(log, null, 2));
  } catch (err) {
    console.warn('Could not persist failed-order log to disk:', err.message);
  }
}

app.get('/admin/failed-orders', (_req, res) => {
  res.json({ failures: loadFailedLog() });
});

// Reprocess a flagged order after the underlying problem is fixed (e.g. the
// Xero account code was wrong, or a duplicate contact got merged). Never
// automatic — a human decides when to call this, per the project's
// flag-and-stop rule. Removes the entry from the failed log only on success.
app.post('/admin/replay-order', async (req, res) => {
  const { orderName } = req.body;
  if (!orderName) return res.status(400).json({ error: 'orderName is required' });

  const log = loadFailedLog();
  const entry = log.find((e) => e.orderName === orderName && !e.resolved);
  if (!entry) return res.status(404).json({ error: `No unresolved failure found for order ${orderName}` });
  if (!entry.order) return res.status(400).json({ error: 'This failure predates order-payload storage — can\'t replay, only Shopify has the data now.' });

  try {
    const invoice = await createInvoiceForOrder(entry.order);
    entry.resolved = true;
    entry.resolvedAt = new Date().toISOString();
    try {
      fs.writeFileSync(FAILED_LOG_FILE, JSON.stringify(log, null, 2));
    } catch (err) {
      console.warn('Could not persist resolved status to disk:', err.message);
    }
    res.json({ ok: true, invoiceId: invoice.InvoiceID, invoiceNumber: invoice.InvoiceNumber });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// SHOPIFY WEBHOOK VERIFICATION
// ---------------------------------------------------------------------------
function verifyShopifyWebhook(req) {
  const hmacHeader = req.header('X-Shopify-Hmac-Sha256');
  if (!hmacHeader || !process.env.SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac('sha256', process.env.SHOPIFY_WEBHOOK_SECRET)
    .update(req.rawBody, 'utf8')
    .digest('base64');
  const digestBuf = Buffer.from(digest);
  const headerBuf = Buffer.from(hmacHeader);
  // timingSafeEqual throws (rather than returning false) on a length
  // mismatch — a malformed/corrupted signature must not crash the handler.
  if (digestBuf.length !== headerBuf.length) return false;
  return crypto.timingSafeEqual(digestBuf, headerBuf);
}

// ---------------------------------------------------------------------------
// XERO CONTACT MATCH-OR-CREATE — by email, same as the Kiwiseal read agents'
// lookup pattern but with a create fallback since this one writes.
// ---------------------------------------------------------------------------
async function findOrCreateContact(shopifyOrder) {
  const email = shopifyOrder.email || shopifyOrder.contact_email;
  if (!email) throw new Error('Shopify order has no customer email — cannot match/create a Xero contact.');

  const existing = await xeroRequest('Contacts', { params: { where: `EmailAddress=="${email}"` } });
  if (existing.Contacts?.length) return existing.Contacts[0].ContactID;

  const addr = shopifyOrder.shipping_address || shopifyOrder.billing_address || {};
  const created = await xeroRequest('Contacts', {
    method: 'PUT',
    body: {
      Contacts: [{
        Name: [addr.name, shopifyOrder.customer?.first_name, shopifyOrder.customer?.last_name].filter(Boolean).join(' ') || email,
        EmailAddress: email,
        Addresses: addr.address1 ? [{
          AddressType: 'STREET',
          AddressLine1: addr.address1,
          AddressLine2: addr.address2 || '',
          City: addr.city || '',
          Region: addr.province || '',
          PostalCode: addr.zip || '',
          Country: addr.country || ''
        }] : []
      }]
    }
  });
  return created.Contacts[0].ContactID;
}

// ---------------------------------------------------------------------------
// SHOPIFY ORDER -> XERO INVOICE MAPPING
//
// ASSUMPTIONS — confirm against your actual Xero chart of accounts before
// relying on this in production, do not guess these:
//   - XERO_SALES_ACCOUNT_CODE: the account code line items post to (e.g. a
//     "Sales" revenue account).
//   - XERO_TAX_TYPE: matches how Shopify prices are entered (NZ retail
//     prices are normally GST-inclusive, so LineAmountType is "Inclusive"
//     below — if that's wrong for how your Shopify products are configured,
//     tell me and I'll flip it).
//   - XERO_SHOPIFY_PAYMENTS_ACCOUNT_CODE: a bank/clearing account
//     representing Shopify Payments payouts. This agent marks the invoice
//     PAID immediately against that account, since Shopify already
//     collected the money at checkout — otherwise every online sale would
//     sit in Xero as an outstanding unpaid receivable, which is wrong. This
//     is the standard e-commerce accounting pattern, but confirm the
//     account code (and that your accountant is fine with this) before
//     going live.
// ---------------------------------------------------------------------------
async function shopifyOrderToInvoice(order, contactId) {
  const lineItems = order.line_items.map((li) => ({
    Description: li.title + (li.variant_title ? ` (${li.variant_title})` : ''),
    Quantity: li.quantity,
    UnitAmount: Number(li.price),
    AccountCode: process.env.XERO_SALES_ACCOUNT_CODE,
    TaxType: process.env.XERO_TAX_TYPE
  }));

  const shippingTotal = Number(order.total_shipping_price_set?.shop_money?.amount ?? order.shipping_lines?.reduce((s, l) => s + Number(l.price), 0) ?? 0);
  if (shippingTotal > 0) {
    lineItems.push({
      Description: 'Shipping',
      Quantity: 1,
      UnitAmount: shippingTotal,
      AccountCode: process.env.XERO_SALES_ACCOUNT_CODE,
      TaxType: process.env.XERO_TAX_TYPE
    });
  }

  const today = new Date().toISOString().slice(0, 10);
  return {
    Type: 'ACCREC',
    Contact: { ContactID: contactId },
    LineAmountTypes: 'Inclusive',
    Date: today,
    DueDate: today,
    Reference: `Shopify ${order.name}`,
    Status: 'AUTHORISED',
    LineItems: lineItems
  };
}

async function createInvoiceForOrder(order) {
  // Idempotency guard: Shopify retries webhook deliveries, and a Railway
  // restart could replay an in-flight one. Check Xero for an invoice
  // already carrying this order's Reference before creating a duplicate.
  const already = await xeroRequest('Invoices', { params: { where: `Reference=="Shopify ${order.name}"` } });
  let invoice;

  if (already.Invoices?.length) {
    console.log(`Invoice already exists for ${order.name} (Reference match) — skipping invoice creation.`);
    invoice = already.Invoices[0];
  } else {
    const contactId = await findOrCreateContact(order);
    const invoicePayload = await shopifyOrderToInvoice(order, contactId);
    const created = await xeroRequest('Invoices', { method: 'PUT', body: { Invoices: [invoicePayload] } });
    invoice = created.Invoices[0];

    if (process.env.XERO_SHOPIFY_PAYMENTS_ACCOUNT_CODE) {
      await xeroRequest('Payments', {
        method: 'PUT',
        body: {
          Payments: [{
            Invoice: { InvoiceID: invoice.InvoiceID },
            Account: { Code: process.env.XERO_SHOPIFY_PAYMENTS_ACCOUNT_CODE },
            Date: invoice.DateString?.slice(0, 10) ?? new Date().toISOString().slice(0, 10),
            Amount: invoice.Total
          }]
        }
      });
    }

    // Sends the invoice to the customer via Xero's own email delivery — same
    // as clicking "Email" on the invoice in the Xero UI. NOT yet confirmed
    // against a live Xero org (no Everest Plunge credentials to test
    // against at write time) — verify this endpoint actually fires an
    // email once OAuth is connected, same discipline as every other
    // endpoint in this project: don't trust an unconfirmed guess.
    await xeroRequest(`Invoices/${invoice.InvoiceID}/Email`, { method: 'POST' });
  }

  // Always attempted, even when the invoice already existed (e.g. this is
  // a replay after a stock-only failure) — safe to call repeatedly because
  // recordStockForOrder tracks completion per (order, SKU) itself, see
  // below. Deliberately does NOT throw on failure — the invoice is the
  // part that actually matters and has already succeeded either way; a
  // stock sheet hiccup shouldn't get conflated with an invoicing failure.
  await recordStockForOrder(order);

  return invoice;
}

// ---------------------------------------------------------------------------
// STOCK SHEET INTEGRATION — optional. Only runs if STOCK_SHEET_AGENT_URL is
// configured, so this agent can be deployed and used on its own before the
// stock sheet agent exists. Only handles line items that carry a Shopify
// variant SKU matching a "SKU-xxx" row in the Operations sheet's Stock
// Overview tab — assumes Shopify product SKUs are kept in sync with that
// sheet's SKU column, which is standard practice but not something this
// agent can verify itself. A line item with no SKU, or one the stock sheet
// agent doesn't recognise, is skipped and flagged, not guessed at.
//
// The stock sheet's "record an order" call INCREMENTS a count rather than
// setting it, so it is NOT safe to call twice for the same line item. Since
// createInvoiceForOrder above calls this on every replay (not just the
// first attempt), completion is tracked per (order name, SKU) in a
// persisted set — only SKUs that haven't succeeded yet are attempted, so a
// replay after a partial failure doesn't double-count the ones that
// already went through.
// ---------------------------------------------------------------------------
const STOCK_RECORDED_FILE = process.env.STOCK_RECORDED_FILE || '/data/stock-recorded.json';

function loadStockRecordedSet() {
  try { return new Set(JSON.parse(fs.readFileSync(STOCK_RECORDED_FILE, 'utf8'))); } catch { return new Set(); }
}
function saveStockRecordedSet(set) {
  try {
    fs.mkdirSync(path.dirname(STOCK_RECORDED_FILE), { recursive: true });
    fs.writeFileSync(STOCK_RECORDED_FILE, JSON.stringify([...set]));
  } catch (err) {
    console.warn('Could not persist stock-recorded set to disk:', err.message);
  }
}

async function recordStockForOrder(order) {
  if (!process.env.STOCK_SHEET_AGENT_URL) return;
  const recorded = loadStockRecordedSet();

  for (const li of order.line_items) {
    if (!li.sku) {
      console.warn(`Order ${order.name}: line item "${li.title}" has no SKU — skipping stock update.`);
      continue;
    }
    const key = `${order.name}:${li.sku}`;
    if (recorded.has(key)) continue; // already recorded on a prior attempt

    try {
      const res = await fetch(`${process.env.STOCK_SHEET_AGENT_URL}/admin/record-order`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.STOCK_SHEET_AGENT_API_KEY },
        body: JSON.stringify({ sku: li.sku, quantity: li.quantity })
      });
      if (!res.ok) throw new Error(`Stock sheet agent error ${res.status}: ${await res.text()}`);
      recorded.add(key);
      saveStockRecordedSet(recorded);
    } catch (err) {
      console.error(`Order ${order.name}: failed to record stock for SKU ${li.sku}:`, err.message);
      appendFailedLog({
        orderName: order.name,
        orderId: order.id,
        order,
        error: `Invoice succeeded, but stock update failed for SKU ${li.sku}: ${err.message}`,
        stage: 'stock-update'
      });
    }
  }
}

// ---------------------------------------------------------------------------
// WEBHOOK ENDPOINT
// ---------------------------------------------------------------------------
app.post('/webhooks/shopify/orders-paid', async (req, res) => {
  if (!verifyShopifyWebhook(req)) {
    console.warn('Rejected webhook with invalid/missing HMAC signature.');
    return res.status(401).send('Invalid signature');
  }

  const order = req.body;
  // Ack immediately — Shopify expects a 2xx within 5s and the Xero calls
  // below (contact lookup, invoice create, payment, email) can exceed that.
  // Because we always return 200 here, Shopify will NOT retry this delivery
  // on failure — /admin/replay-order (below) is the only recovery path, not
  // a webhook resend.
  res.status(200).send('OK');

  try {
    const invoice = await createInvoiceForOrder(order);
    console.log(`Order ${order.name}: Xero invoice ${invoice.InvoiceNumber} (${invoice.InvoiceID}) ready.`);
  } catch (err) {
    console.error(`Order ${order.name} FAILED — flagging, not retrying automatically:`, err.message);
    appendFailedLog({ orderName: order.name, orderId: order.id, order, error: err.message });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3007;
app.listen(port, () => console.log(`Everest Plunge Shopify-Xero Agent listening on :${port}`));
