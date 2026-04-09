// BistroTrack Backend v2.0
// Deploy: Railway (railway up) or Render (connect GitHub)
// ──────────────────────────────────────────────────────

const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const Stripe   = require("stripe");
const webpush  = require("web-push");
const nodemailer = require("nodemailer");
const cron     = require("node-cron");

const app  = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const stripe   = Stripe(process.env.STRIPE_SECRET_KEY);

if (process.env.VAPID_PUBLIC_KEY) {
  webpush.setVapidDetails(
    "mailto:" + (process.env.SUPPORT_EMAIL || "hello@bistrotrack.co.uk"),
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
}

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.resend.com",
  port: parseInt(process.env.SMTP_PORT || "587"),
  auth: { user: process.env.SMTP_USER || "resend", pass: process.env.SMTP_PASS },
});

// Stripe webhook needs raw body first
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), handleStripeWebhook);

app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "2mb" }));

function auth(req, res, next) {
  const token = req.headers["x-bistrotrack-token"];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: "Invalid token" }); }
}

// ── REGISTER ─────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { restaurantName, email, managerPin, serverPin } = req.body;
  if (!email || !managerPin) return res.status(400).json({ error: "Missing fields" });
  const { data: existing } = await supabase.from("accounts").select("id").eq("email", email.toLowerCase()).single();
  if (existing) return res.status(409).json({ error: "An account with this email already exists" });
  const managerHash = await bcrypt.hash(managerPin, 10);
  const serverHash  = await bcrypt.hash(serverPin || managerPin, 10);
  const { data: account, error } = await supabase.from("accounts")
    .insert({ restaurant_name: restaurantName, email: email.toLowerCase(), manager_pin: managerHash, server_pin: serverHash, plan: "free" })
    .select().single();
  if (error) return res.status(500).json({ error: "Registration failed: " + error.message });
  const token = jwt.sign({ accountId: account.id, email: account.email }, process.env.JWT_SECRET, { expiresIn: "90d" });
  sendEmail(account.email, "Welcome to BistroTrack!", welcomeHtml(account.restaurant_name)).catch(console.warn);
  res.json({ token, account: { restaurant_name: account.restaurant_name, email: account.email, plan: "free" } });
});

// ── SIGN IN ───────────────────────────────────────────────────────
app.post("/api/auth/signin", async (req, res) => {
  const { email, pin, role } = req.body;
  const { data: account } = await supabase.from("accounts").select("*").eq("email", (email||"").toLowerCase()).single();
  if (!account) return res.status(401).json({ error: "No account found for this email" });
  const pinField = role === "server" ? "server_pin" : "manager_pin";
  const valid = await bcrypt.compare(pin, account[pinField]);
  if (!valid) return res.status(401).json({ error: "Incorrect PIN" });
  await supabase.from("accounts").update({ last_login: new Date().toISOString() }).eq("id", account.id);
  const token = jwt.sign({ accountId: account.id, email: account.email }, process.env.JWT_SECRET, { expiresIn: "90d" });
  res.json({ token, role, account: { restaurant_name: account.restaurant_name, email: account.email, plan: account.plan } });
});

// ── FORGOT PIN ────────────────────────────────────────────────────
app.post("/api/auth/forgot-pin", async (req, res) => {
  res.json({ ok: true }); // always 200
  const { data: account } = await supabase.from("accounts").select("*").eq("email", (req.body.email||"").toLowerCase()).single();
  if (!account) return;
  const resetToken = jwt.sign({ accountId: account.id, purpose: "pin-reset" }, process.env.JWT_SECRET, { expiresIn: "1h" });
  const resetUrl   = (process.env.APP_URL || "https://bistrotrack.co.uk") + "?reset=" + resetToken;
  sendEmail(account.email, "Reset your BistroTrack PIN",
    `<p>Hi ${account.restaurant_name},</p><p><a href="${resetUrl}" style="background:#e8633a;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block">Reset my PIN</a></p><p style="color:#888;font-size:12px">Expires in 1 hour.</p>`
  ).catch(console.warn);
});

// ── SETTINGS ──────────────────────────────────────────────────────
app.put("/api/settings", auth, async (req, res) => {
  const { restaurantName, managerPin, serverPin, currency } = req.body;
  const updates = {};
  if (restaurantName) updates.restaurant_name = restaurantName;
  if (currency)       updates.currency = currency;
  if (managerPin)     updates.manager_pin = await bcrypt.hash(managerPin, 10);
  if (serverPin)      updates.server_pin  = await bcrypt.hash(serverPin, 10);
  await supabase.from("accounts").update(updates).eq("id", req.user.accountId);
  res.json({ ok: true });
});

// ── INVENTORY ─────────────────────────────────────────────────────
app.get("/api/inventory", auth, async (req, res) => {
  const { data } = await supabase.from("inventory").select("*").eq("account_id", req.user.accountId).order("name");
  res.json(data || []);
});
app.put("/api/inventory", auth, async (req, res) => {
  const rows = (req.body.inventory || []).map(it => ({ ...it, account_id: req.user.accountId }));
  if (rows.length) await supabase.from("inventory").upsert(rows, { onConflict: "id" });
  res.json({ ok: true });
});
app.patch("/api/inventory/:id", auth, async (req, res) => {
  await supabase.from("inventory").update({ ...req.body, updated_at: new Date().toISOString() }).eq("id", req.params.id).eq("account_id", req.user.accountId);
  res.json({ ok: true });
});

// ── MENU ──────────────────────────────────────────────────────────
app.get("/api/menu", auth, async (req, res) => {
  const { data: categories } = await supabase.from("menu_categories").select("*").eq("account_id", req.user.accountId).order("sort_order");
  const { data: items }      = await supabase.from("menu_items").select("*").eq("account_id", req.user.accountId).order("sort_order");
  res.json({ categories: categories || [], items: items || [] });
});

// ── SUPPLIERS ─────────────────────────────────────────────────────
app.get("/api/suppliers", auth, async (req, res) => {
  const { data } = await supabase.from("suppliers").select("*").eq("account_id", req.user.accountId).order("name");
  res.json(data || []);
});
app.put("/api/suppliers", auth, async (req, res) => {
  await supabase.from("suppliers").delete().eq("account_id", req.user.accountId);
  const rows = (req.body.suppliers || []).map(s => ({ ...s, account_id: req.user.accountId }));
  if (rows.length) await supabase.from("suppliers").insert(rows);
  res.json({ ok: true });
});

// ── ORDERS ────────────────────────────────────────────────────────
app.post("/api/orders", auth, async (req, res) => {
  await supabase.from("orders").insert({ account_id: req.user.accountId, ...req.body, items: JSON.stringify(req.body.items) });
  res.json({ ok: true });
});
app.get("/api/orders/today", auth, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const { data } = await supabase.from("orders").select("*").eq("account_id", req.user.accountId).gte("created_at", today).order("created_at");
  res.json(data || []);
});
app.post("/api/reset-day", auth, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  await supabase.from("orders").delete().eq("account_id", req.user.accountId).gte("created_at", today);
  await supabase.from("waste_log").delete().eq("account_id", req.user.accountId).gte("created_at", today);
  await supabase.from("inventory").update({ used_today: 0, waste_today: 0 }).eq("account_id", req.user.accountId);
  res.json({ ok: true });
});

// ── WASTE ─────────────────────────────────────────────────────────
app.post("/api/waste", auth, async (req, res) => {
  await supabase.from("waste_log").insert({ account_id: req.user.accountId, ...req.body });
  res.json({ ok: true });
});
app.get("/api/waste/today", auth, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const { data } = await supabase.from("waste_log").select("*").eq("account_id", req.user.accountId).gte("created_at", today).order("created_at");
  res.json(data || []);
});

// ── PLATFORM PRICING ──────────────────────────────────────────────
app.get("/api/platform-pricing", auth, async (req, res) => {
  const { data } = await supabase.from("platform_pricing").select("*").eq("account_id", req.user.accountId);
  res.json(data || []);
});
app.put("/api/platform-pricing", auth, async (req, res) => {
  await supabase.from("platform_pricing").delete().eq("account_id", req.user.accountId);
  const rows = (req.body.pricing || []).map(p => ({ ...p, account_id: req.user.accountId }));
  if (rows.length) await supabase.from("platform_pricing").insert(rows);
  res.json({ ok: true });
});

// ── STRIPE — web checkout (Apple-safe: no in-app payment) ─────────
app.post("/api/stripe/create-checkout-session", auth, async (req, res) => {
  const { data: account } = await supabase.from("accounts").select("*").eq("id", req.user.accountId).single();
  let customerId = account.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({ email: account.email, name: account.restaurant_name });
    customerId = customer.id;
    await supabase.from("accounts").update({ stripe_customer_id: customerId }).eq("id", account.id);
  }
  const session = await stripe.checkout.sessions.create({
    customer:   customerId,
    mode:       "subscription",
    line_items: [{ price: process.env.STRIPE_PRO_PRICE_ID, quantity: 1 }],
    success_url: (process.env.APP_URL || "https://bistrotrack.co.uk") + "?upgraded=true&session={CHECKOUT_SESSION_ID}",
    cancel_url:  (process.env.APP_URL || "https://bistrotrack.co.uk") + "?upgrade_cancelled=true",
    metadata:    { accountId: account.id },
    allow_promotion_codes: true,
    billing_address_collection: "auto",
  });
  res.json({ url: session.url });
});

app.post("/api/stripe/portal", auth, async (req, res) => {
  const { data: account } = await supabase.from("accounts").select("stripe_customer_id").eq("id", req.user.accountId).single();
  if (!account?.stripe_customer_id) return res.status(400).json({ error: "No billing account" });
  const session = await stripe.billingPortal.sessions.create({
    customer: account.stripe_customer_id,
    return_url: process.env.APP_URL || "https://bistrotrack.co.uk",
  });
  res.json({ url: session.url });
});

async function handleStripeWebhook(req, res) {
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET); }
  catch(e) { return res.status(400).json({ error: "Webhook signature failed" }); }
  if (event.type === "checkout.session.completed") {
    const s = event.data.object;
    if (s.metadata?.accountId) await supabase.from("accounts").update({ plan: "pro", stripe_subscription_id: s.subscription }).eq("id", s.metadata.accountId);
  }
  if (event.type === "customer.subscription.deleted" || event.type === "invoice.payment_failed") {
    const sub = event.data.object;
    await supabase.from("accounts").update({ plan: "free" }).eq("stripe_subscription_id", sub.id || sub.subscription);
  }
  if (event.type === "invoice.payment_succeeded") {
    const inv = event.data.object;
    if (inv.subscription) await supabase.from("accounts").update({ plan: "pro" }).eq("stripe_subscription_id", inv.subscription);
  }
  res.json({ received: true });
}

// ── PUSH NOTIFICATIONS ────────────────────────────────────────────
app.post("/api/push/subscribe", auth, async (req, res) => {
  const { subscription, deviceType, critOnly } = req.body;
  await supabase.from("push_subscriptions").upsert({
    account_id: req.user.accountId, endpoint: subscription.endpoint,
    subscription: JSON.stringify(subscription), device_type: deviceType || "web",
    crit_only: critOnly || false, updated_at: new Date().toISOString(),
  }, { onConflict: "endpoint" });
  res.json({ ok: true });
});
app.delete("/api/push/subscribe", auth, async (req, res) => {
  await supabase.from("push_subscriptions").delete().eq("account_id", req.user.accountId);
  res.json({ ok: true });
});
app.patch("/api/push/preferences", auth, async (req, res) => {
  await supabase.from("push_subscriptions").update({ crit_only: req.body.critOnly }).eq("account_id", req.user.accountId);
  res.json({ ok: true });
});
app.post("/api/push/send", auth, async (req, res) => {
  const { title, body, type } = req.body;
  const { data: subs } = await supabase.from("push_subscriptions").select("*").eq("account_id", req.user.accountId);
  let delivered = 0;
  for (const sub of (subs || [])) {
    if (sub.crit_only && type !== "critical") continue;
    try { await webpush.sendNotification(JSON.parse(sub.subscription), JSON.stringify({ title, body, type })); delivered++; }
    catch(e) { if (e.statusCode === 410) await supabase.from("push_subscriptions").delete().eq("endpoint", sub.endpoint); }
  }
  res.json({ delivered });
});

// ── EMAIL ─────────────────────────────────────────────────────────
app.post("/api/email/send-digest", auth, async (req, res) => {
  const { to, subject, html } = req.body;
  if (!to) return res.status(400).json({ error: "Missing recipient" });
  try {
    await sendEmail(to, subject, html);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

async function sendEmail(to, subject, html) {
  return mailer.sendMail({
    from: `"BistroTrack" <${process.env.FROM_EMAIL || "hello@bistrotrack.co.uk"}>`,
    to, subject, html,
  });
}

function welcomeHtml(name) {
  return `<div style="font-family:Georgia,serif;max-width:560px;margin:0 auto">
    <div style="background:#1a1a2e;padding:24px;border-radius:12px 12px 0 0">
      <span style="font-size:22px;color:#f0eff4;font-weight:300">Bistro<em style="color:#e8633a">Track</em></span>
    </div>
    <div style="border:1px solid #e8e8ee;border-top:none;border-radius:0 0 12px 12px;padding:24px">
      <p>Hi ${name}, welcome to BistroTrack!</p>
      <p>Head to <strong>Setup</strong> to add your menu and ingredients, then you're ready to go.</p>
      <p>Reply to this email if you need any help.</p>
      <p style="color:#888;font-size:12px">BistroTrack · hello@bistrotrack.co.uk</p>
    </div>
  </div>`;
}

// Monday 8am digest reminder push
cron.schedule("0 8 * * 1", async () => {
  const { data: accounts } = await supabase.from("accounts").select("id").eq("digest_enabled", true);
  for (const account of (accounts || [])) {
    const { data: subs } = await supabase.from("push_subscriptions").select("*").eq("account_id", account.id);
    for (const sub of (subs || [])) {
      webpush.sendNotification(JSON.parse(sub.subscription), JSON.stringify({
        title: "Weekly digest ready", body: "Open BistroTrack to review your week.", type: "digest"
      })).catch(() => {});
    }
  }
});

app.get("/health", (req, res) => res.json({ ok: true, version: "2.0.0" }));
app.listen(PORT, () => console.log("BistroTrack backend on port", PORT));
