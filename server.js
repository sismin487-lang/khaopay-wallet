require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
});

const THB_TO_MMK_RATE = Number(process.env.THB_TO_MMK_RATE || 120);
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_PIN_ATTEMPTS = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;

const otpStore = new Map();         // phoneE164 -> { code, expiresAt, attempts }
const pinFailStore = new Map();     // userId -> { fails, lockedUntil }
const idempotencyStore = new Map(); // key -> { expiresAt, response }

async function ensureExtraTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cash_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      phone_e164 TEXT NOT NULL,
      req_type TEXT NOT NULL CHECK (req_type IN ('CASH_IN', 'CASH_OUT')),
      channel TEXT NOT NULL CHECK (channel IN ('KPAY', 'WAVEPAY')),
      target_phone TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'MMK',
      amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
      tx_ref TEXT,
      slip_image_url TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    );
  `);
}

ensureExtraTables().catch((err) => {
  console.error('Failed to ensure cash_requests table:', err.message);
});

function signToken(payload) {
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const data = Buffer.from(JSON.stringify({ ...payload, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
  if (!parsed.exp || Date.now() > parsed.exp) return null;
  return parsed;
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const payload = verifyToken(token);
  if (!payload || !payload.userId) {
    return res.status(401).json({ success: false, message: 'Login Session သက်တမ်းကုန်ဆုံးနေပါသည် (သို့မဟုတ်) မရှိပါ။' });
  }
  req.authUserId = payload.userId;
  next();
}

function requireAdmin(req, res, next) {
  const provided = String(req.headers['x-admin-secret'] || req.body?.adminSecret || '');
  if (!ADMIN_SECRET) {
    return res.status(503).json({ success: false, message: 'Server တွင် ADMIN_SECRET မသတ်မှတ်ရသေးပါ။' });
  }
  if (!provided || provided.length !== ADMIN_SECRET.length || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(ADMIN_SECRET))) {
    return res.status(403).json({ success: false, message: 'Admin Authorization မအောင်မြင်ပါ။' });
  }
  next();
}

function checkIdempotency(req, res, next) {
  const key = String(req.headers['x-idempotency-key'] || '').trim();
  if (!key) return next();
  const cached = idempotencyStore.get(key);
  if (cached && Date.now() < cached.expiresAt) {
    return res.status(cached.status).json(cached.body);
  }
  const origJson = res.json.bind(res);
  res.json = (body) => {
    idempotencyStore.set(key, {
      expiresAt: Date.now() + 10 * 60 * 1000,
      status: res.statusCode || 200,
      body
    });
    return origJson(body);
  };
  next();
}

function assertPinNotLocked(userId) {
  const rec = pinFailStore.get(userId);
  if (rec && rec.lockedUntil && Date.now() < rec.lockedUntil) {
    const mins = Math.ceil((rec.lockedUntil - Date.now()) / 60000);
    throw new Error(`PIN မှားယွင်းမှု များနေသဖြင့် ${mins} မိနစ် ခေတ္တပိတ်ထားပါသည်။`);
  }
}

function recordPinFailure(userId) {
  const rec = pinFailStore.get(userId) || { fails: 0, lockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= MAX_PIN_ATTEMPTS) {
    rec.lockedUntil = Date.now() + PIN_LOCK_MS;
    rec.fails = 0;
  }
  pinFailStore.set(userId, rec);
}

function clearPinFailure(userId) {
  pinFailStore.delete(userId);
}

async function sendOtpViaProvider(phoneE164, code) {
  if (process.env.OTP_WEBHOOK_URL) {
    const resp = await fetch(process.env.OTP_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        phone: phoneE164,
        otp: code,
        message: `Your KhaoPay verification code is ${code}. Valid for 5 minutes.`
      })
    });
    if (!resp.ok) {
      throw new Error('OTP ပို့ဆောင်ရာတွင် Gateway ဘက်မှ အဆင်မပြေပါ။');
    }
    return { delivered: true };
  }
  return { delivered: false };
}

function normalizePhone(countryCode, rawPhone) {
  let cleaned = String(rawPhone || '').replace(/\D/g, '');
  if (!cleaned) throw new Error('ဖုန်းနံပါတ် ထည့်သွင်းပါ။');

  if (countryCode === 'TH') {
    if (cleaned.startsWith('66')) cleaned = cleaned.slice(2);
    if (cleaned.startsWith('0')) cleaned = cleaned.slice(1);
    if (cleaned.length < 8 || cleaned.length > 10) throw new Error('ထိုင်းဖုန်းနံပါတ် မှားယွင်းနေပါသည်။');
    return `+66${cleaned}`;
  }

  if (countryCode === 'MM') {
    if (cleaned.startsWith('95')) cleaned = cleaned.slice(2);
    if (cleaned.startsWith('0')) cleaned = cleaned.slice(1);
    if (cleaned.length < 8 || cleaned.length > 10) throw new Error('မြန်မာဖုန်းနံပါတ် မှားယွင်းနေပါသည်။');
    return `+95${cleaned}`;
  }

  throw new Error('Country Code ကို TH သို့မဟုတ် MM သာ ရွေးချယ်ပါ။');
}

function normalizeNrc(nrc) {
  return String(nrc || '').trim().toUpperCase().replace(/\s+/g, '');
}

async function getFullUserState(dbOrClient, userId) {
  const userRes = await dbOrClient.query(
    'SELECT id, phone_e164, phone_country, kyc_status FROM users WHERE id = $1',
    [userId]
  );
  if (userRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');

  const walletsRes = await dbOrClient.query(
    'SELECT currency, balance FROM wallets WHERE user_id = $1 ORDER BY currency',
    [userId]
  );
  const kycRes = await dbOrClient.query(
    'SELECT id_type, nrc_normalized, full_name, status, reject_reason FROM kyc_submissions WHERE user_id = $1',
    [userId]
  );
  const cashReqRes = await dbOrClient.query(
    `SELECT id, phone_e164, req_type, channel, target_phone, currency, amount, tx_ref, status, admin_note, created_at, reviewed_at
     FROM cash_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
    [userId]
  );
  const txRes = await dbOrClient.query(
    `SELECT t.*, u_send.phone_e164 AS sender_phone, u_recv.phone_e164 AS receiver_phone
     FROM transactions t
     LEFT JOIN users u_send ON t.sender_user_id = u_send.id
     LEFT JOIN users u_recv ON t.receiver_user_id = u_recv.id
     WHERE t.sender_user_id = $1 OR t.receiver_user_id = $1
     ORDER BY t.created_at DESC LIMIT 30`,
    [userId]
  );

  const wallets = { MMK: 0, THB: 0 };
  for (const w of walletsRes.rows) {
    wallets[w.currency] = Number(w.balance);
  }

  return {
    user: {
      id: userRes.rows[0].id,
      phoneE164: userRes.rows[0].phone_e164,
      phoneCountry: userRes.rows[0].phone_country,
      kycStatus: userRes.rows[0].kyc_status
    },
    wallets,
    kyc: kycRes.rows[0] || null,
    cashRequests: cashReqRes.rows,
    transactions: txRes.rows
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'KhaoPay', rate: THB_TO_MMK_RATE });
});

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    rate: THB_TO_MMK_RATE,
    otpGatewayConfigured: Boolean(process.env.OTP_WEBHOOK_URL),
    payoutGatewayConfigured: Boolean(process.env.PAYMENT_GATEWAY_URL && process.env.PAYMENT_GATEWAY_KEY)
  });
});

app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { countryCode, phone } = req.body;
    const phoneE164 = normalizePhone(countryCode, phone);
    const code = String(crypto.randomInt(100000, 999999));

    otpStore.set(phoneE164, {
      code,
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0
    });

    const providerRes = await sendOtpViaProvider(phoneE164, code);

    const payload = {
      success: true,
      phoneE164,
      expiresInSeconds: 300,
      message: providerRes.delivered
        ? `${phoneE164} သို့ OTP ပို့ပြီးပါပြီ (၅ မိနစ်အတွင်း အသုံးပြုပါ)။`
        : `${phoneE164} အတွက် OTP ထုတ်ပေးပြီးပါပြီ (OTP Gateway မချိတ်ရသေး၍ Test OTP: ${code})`
    };

    if (!providerRes.delivered && process.env.NODE_ENV !== 'production') {
      payload.devOtp = code;
    }

    res.json(payload);
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/auth/register-or-login', async (req, res) => {
  const { countryCode, phone, otp, pin } = req.body;
  if (!/^\d{6}$/.test(String(pin || ''))) {
    return res.status(400).json({ success: false, message: 'PIN သည် ဂဏန်း ၆ လုံး ဖြစ်ရပါမည်။' });
  }

  const client = await pool.connect();
  let userId;
  let txOpen = false;
  try {
    const phoneE164 = normalizePhone(countryCode, phone);
    const otpRec = otpStore.get(phoneE164);

    if (!otpRec || Date.now() > otpRec.expiresAt) {
      return res.status(400).json({ success: false, message: 'OTP သက်တမ်းကုန်သွားပါပြီ (သို့မဟုတ် OTP အသစ်ပြန်တောင်းပါ)။' });
    }
    if (otpRec.attempts >= 5) {
      otpStore.delete(phoneE164);
      return res.status(429).json({ success: false, message: 'OTP မှားယွင်းမှု များလွန်းသဖြင့် OTP အသစ်ပြန်တောင်းပါ။' });
    }
    if (String(otp || '').trim() !== otpRec.code) {
      otpRec.attempts += 1;
      return res.status(400).json({ success: false, message: 'OTP ကုဒ် မှားယွင်းနေပါသည်။' });
    }

    otpStore.delete(phoneE164);

    const existing = await client.query('SELECT * FROM users WHERE phone_e164 = $1', [phoneE164]);

    if (existing.rows.length > 0) {
      const u = existing.rows[0];
      assertPinNotLocked(u.id);
      const ok = await bcrypt.compare(String(pin), u.pin_hash);
      if (!ok) {
        recordPinFailure(u.id);
        return res.status(401).json({ success: false, message: 'PIN မှားယွင်းနေပါသည်။' });
      }
      clearPinFailure(u.id);
      userId = u.id;
    } else {
      await client.query('BEGIN');
      txOpen = true;
      const pinHash = await bcrypt.hash(String(pin), 10);
      const inserted = await client.query(
        `INSERT INTO users (phone_e164, phone_country, pin_hash)
         VALUES ($1, $2, $3) RETURNING id`,
        [phoneE164, countryCode, pinHash]
      );
      userId = inserted.rows[0].id;
      await client.query(
        `INSERT INTO wallets (user_id, currency, balance) VALUES ($1, 'MMK', 0), ($1, 'THB', 0)`,
        [userId]
      );
      await client.query('COMMIT');
      txOpen = false;
    }

    const token = signToken({ userId });
    const state = await getFullUserState(pool, userId);
    res.json({ success: true, token, ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/wallet/:userId', requireAuth, async (req, res) => {
  if (String(req.params.userId) !== String(req.authUserId)) {
    return res.status(403).json({ success: false, message: 'အခြားအကောင့် အချက်အလက်ကို ကြည့်ခွင့်မရှိပါ။' });
  }
  try {
    const state = await getFullUserState(pool, req.authUserId);
    res.json({ success: true, ...state });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/kyc/submit', requireAuth, async (req, res) => {
  const userId = req.authUserId;
  const { fullName, nrcNumber, frontImageUrl, backImageUrl, selfieImageUrl } = req.body;
  if (!fullName || !nrcNumber || !frontImageUrl || !backImageUrl || !selfieImageUrl) {
    return res.status(400).json({ success: false, message: 'အမည်၊ မှတ်ပုံတင်နံပါတ်နှင့် ဓာတ်ပုံ ၃ ပုံလုံး ပြည့်စုံစွာ ထည့်ပါ။' });
  }

  const nrcNormalized = normalizeNrc(nrcNumber);
  const client = await pool.connect();
  let txOpen = false;
  try {
    await client.query('BEGIN');
    txOpen = true;

    const uRes = await client.query('SELECT id, phone_e164 FROM users WHERE id = $1', [userId]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');

    const dup = await client.query(
      'SELECT user_id FROM kyc_submissions WHERE nrc_normalized = $1 AND user_id <> $2',
      [nrcNormalized, userId]
    );
    if (dup.rows.length > 0) {
      throw new Error('ဤမြန်မာမှတ်ပုံတင်နံပါတ်ကို အခြားအကောင့်တစ်ခုတွင် သုံးထားပြီး ဖြစ်ပါသည်။');
    }

    await client.query(
      `INSERT INTO kyc_submissions
        (user_id, id_type, nrc_normalized, full_name, front_image_url, back_image_url, selfie_image_url, status, reject_reason)
       VALUES ($1, 'MYANMAR_NRC', $2, $3, $4, $5, $6, 'PENDING', NULL)
       ON CONFLICT (user_id) DO UPDATE SET
        nrc_normalized = EXCLUDED.nrc_normalized,
        full_name = EXCLUDED.full_name,
        front_image_url = EXCLUDED.front_image_url,
        back_image_url = EXCLUDED.back_image_url,
        selfie_image_url = EXCLUDED.selfie_image_url,
        status = 'PENDING',
        reject_reason = NULL,
        created_at = CURRENT_TIMESTAMP`,
      [userId, nrcNormalized, String(fullName).trim(), frontImageUrl, backImageUrl, selfieImageUrl]
    );
    await client.query(`UPDATE users SET kyc_status = 'PENDING' WHERE id = $1`, [userId]);
    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, userId);
    res.json({
      success: true,
      message: `${uRes.rows[0].phone_e164} အကောင့်အတွက် မြန်မာမှတ်ပုံတင် (NRC) KYC တင်သွင်းပြီးပါပြီ။`,
      ...state
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

async function callExternalWalletPayout({ channel, phone, amount, refId }) {
  if (process.env.PAYMENT_GATEWAY_URL && process.env.PAYMENT_GATEWAY_KEY) {
    const resp = await fetch(`${process.env.PAYMENT_GATEWAY_URL}/payout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.PAYMENT_GATEWAY_KEY}`
      },
      body: JSON.stringify({
        provider: channel,
        receiver_phone: phone,
        amount,
        currency: 'MMK',
        reference_id: refId
      })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || data.success === false) {
      throw new Error(data.message || `${channel} တိုက်ရိုက် ငွေလွှဲမှု မအောင်မြင်ပါ။`);
    }
    return data.transaction_id || refId;
  }
  return `MANUAL_${channel}_${Date.now()}`;
}

// Create KPay / WavePay CASH_IN or CASH_OUT request strictly tied to the logged-in user's registered account phone
app.post('/api/wallet/direct-cash', requireAuth, checkIdempotency, async (req, res) => {
  const userId = req.authUserId;
  const { type, channel, targetPhone, amount, txRef, slipImageUrl, pin } = req.body;
  const numAmount = Number(amount);

  if (!['CASH_IN', 'CASH_OUT'].includes(type)) {
    return res.status(400).json({ success: false, message: 'လုပ်ဆောင်ချက် မှားယွင်းနေပါသည်။' });
  }
  if (!['KPAY', 'WAVEPAY'].includes(channel)) {
    return res.status(400).json({ success: false, message: 'KPay သို့မဟုတ် WavePay ကိုသာ ရွေးချယ်ပါ။' });
  }
  if (!(numAmount > 0)) {
    return res.status(400).json({ success: false, message: 'ငွေပမာဏ မှန်ကန်စွာ ထည့်ပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    assertPinNotLocked(userId);
    await client.query('BEGIN');
    txOpen = true;

    const uRes = await client.query('SELECT id, phone_e164, pin_hash, kyc_status FROM users WHERE id = $1', [userId]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');
    const user = uRes.rows[0];

    if (user.kyc_status !== 'VERIFIED') {
      throw new Error('KPay / WavePay ဝန်ဆောင်မှုသုံးရန် မြန်မာမှတ်ပုံတင် (KYC) VERIFIED ဖြစ်ရပါမည်။');
    }
    const pinOk = await bcrypt.compare(String(pin || ''), user.pin_hash);
    if (!pinOk) {
      recordPinFailure(userId);
      await client.query('COMMIT');
      txOpen = false;
      return res.status(401).json({ success: false, message: 'လုံခြုံရေး PIN မှားယွင်းနေပါသည်။' });
    }
    clearPinFailure(userId);

    const accountPhone = user.phone_e164;
    const effectivePhone = targetPhone && String(targetPhone).trim()
      ? String(targetPhone).trim()
      : accountPhone;

    if (type === 'CASH_OUT') {
      const wRes = await client.query(
        `SELECT balance FROM wallets WHERE user_id = $1 AND currency = 'MMK'`,
        [userId]
      );
      if (wRes.rows.length === 0 || Number(wRes.rows[0].balance) < numAmount) {
        throw new Error('MMK လက်ကျန်ငွေ မလုံလောက်ပါ။');
      }
    }

    const created = await client.query(
      `INSERT INTO cash_requests
        (user_id, phone_e164, req_type, channel, target_phone, currency, amount, tx_ref, slip_image_url, status)
       VALUES ($1, $2, $3, $4, $5, 'MMK', $6, $7, $8, 'PENDING')
       RETURNING *`,
      [
        userId,
        accountPhone,
        type,
        channel,
        effectivePhone,
        numAmount,
        txRef ? String(txRef).trim() : null,
        slipImageUrl || null
      ]
    );

    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, userId);
    const msg =
      type === 'CASH_IN'
        ? `${accountPhone} အကောင့်အတွက် ${channel} ငွေသွင်း (${numAmount.toLocaleString()} MMK) Request တင်ပြီးပါပြီ။ Admin Approve လုပ်ပြီးမှ Balance တက်ပါမည်။`
        : `${accountPhone} အကောင့်မှ ${channel} (${effectivePhone}) သို့ ${numAmount.toLocaleString()} MMK ငွေထုတ် Request တင်ပြီးပါပြီ။`;

    res.json({ success: true, message: msg, request: created.rows[0], ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

// Admin list pending cash requests
app.get('/api/admin/pending-cash', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT c.id, c.user_id, c.phone_e164, c.req_type, c.channel, c.target_phone, c.currency, c.amount, c.tx_ref, c.status, c.created_at, u.kyc_status
       FROM cash_requests c
       JOIN users u ON c.user_id = u.id
       WHERE c.status = 'PENDING'
       ORDER BY c.created_at ASC`
    );
    res.json({ success: true, requests: r.rows });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// Admin approve or reject CASH_IN / CASH_OUT request for the user's account
app.post('/api/admin/cash-review', requireAdmin, checkIdempotency, async (req, res) => {
  const { requestId, status, adminNote } = req.body;
  const reqIdNum = Number(requestId);
  if (!Number.isInteger(reqIdNum) || reqIdNum <= 0 || !['APPROVED', 'REJECTED'].includes(status)) {
    return res.status(400).json({ success: false, message: 'requestId နှင့် status (APPROVED / REJECTED) မှန်ကန်စွာ ထည့်ပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await client.query('BEGIN');
    txOpen = true;

    const crRes = await client.query(
      `SELECT * FROM cash_requests WHERE id = $1 FOR UPDATE`,
      [reqIdNum]
    );
    if (crRes.rows.length === 0) {
      throw new Error('Cash Request မတွေ့ပါ။');
    }
    const cr = crRes.rows[0];
    if (cr.status !== 'PENDING') {
      throw new Error(`ဤ Request မှာ ${cr.status} ဖြစ်ပြီးသား ဖြစ်ပါသည်။`);
    }

    if (status === 'REJECTED') {
      await client.query(
        `UPDATE cash_requests
         SET status = 'REJECTED', admin_note = $1, reviewed_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [adminNote || 'Admin မှ ပယ်ချခဲ့ပါသည်။', reqIdNum]
      );
      await client.query('COMMIT');
      txOpen = false;
      return res.json({ success: true, message: `Request #${reqIdNum} ကို ပယ်ချပြီးပါပြီ။` });
    }

    const wRes = await client.query(
      `SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'MMK' FOR UPDATE`,
      [cr.user_id]
    );
    if (wRes.rows.length === 0) {
      throw new Error('User ၏ MMK Wallet မတွေ့ပါ။');
    }

    const amount = Number(cr.amount);
    if (cr.req_type === 'CASH_IN') {
      await client.query(
        `UPDATE wallets SET balance = balance + $1 WHERE id = $2`,
        [amount, wRes.rows[0].id]
      );
      await client.query(
        `INSERT INTO transactions (receiver_user_id, tx_type, currency, amount, note)
         VALUES ($1, 'DIRECT_CASH_IN', 'MMK', $2, $3)`,
        [
          cr.user_id,
          amount,
          `Approved ${cr.channel} (${cr.phone_e164}) • Ref: ${cr.tx_ref || 'REQ-' + cr.id}`
        ]
      );
    } else if (cr.req_type === 'CASH_OUT') {
      if (Number(wRes.rows[0].balance) < amount) {
        throw new Error('အကောင့်၏ MMK လက်ကျန်ငွေ မလုံလောက်ပါ။');
      }
      await client.query(
        `UPDATE wallets SET balance = balance - $1 WHERE id = $2`,
        [amount, wRes.rows[0].id]
      );
      const extTxId = await callExternalWalletPayout({
        channel: cr.channel,
        phone: cr.target_phone,
        amount,
        refId: `REQ_${cr.id}_${Date.now()}`
      });
      await client.query(
        `INSERT INTO transactions (sender_user_id, tx_type, currency, amount, note)
         VALUES ($1, 'DIRECT_TRANSFER_OUT', 'MMK', $2, $3)`,
        [
          cr.user_id,
          amount,
          `Approved ${cr.channel} (${cr.target_phone}) • Tx: ${extTxId}`
        ]
      );
    }

    await client.query(
      `UPDATE cash_requests
       SET status = 'APPROVED', admin_note = $1, reviewed_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [adminNote || 'Approved', reqIdNum]
    );

    await client.query('COMMIT');
    txOpen = false;

    res.json({
      success: true,
      message: `${cr.phone_e164} အကောင့်၏ ${cr.req_type} (${amount.toLocaleString()} MMK) ကို Approve လုပ်ပြီးပါပြီ။`
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/transfer', requireAuth, checkIdempotency, async (req, res) => {
  const senderUserId = req.authUserId;
  const { receiverCountryCode, receiverPhone, currency, amount, note, pin } = req.body;
  const numAmount = Number(amount);

  if (!['MMK', 'THB'].includes(currency) || !(numAmount > 0)) {
    return res.status(400).json({ success: false, message: 'ငွေကြေး သို့မဟုတ် ငွေပမာဏ မှားယွင်းနေပါသည်။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    assertPinNotLocked(senderUserId);
    await client.query('BEGIN');
    txOpen = true;

    const sRes = await client.query('SELECT id, phone_e164, pin_hash, kyc_status FROM users WHERE id = $1', [senderUserId]);
    if (sRes.rows.length === 0) throw new Error('ပေးပို့သူ အကောင့် မတွေ့ပါ။');
    const sender = sRes.rows[0];

    if (sender.kyc_status !== 'VERIFIED') {
      throw new Error('ငွေလွှဲရန် မြန်မာမှတ်ပုံတင် (KYC) VERIFIED ဖြစ်ရပါမည်။');
    }
    const pinOk = await bcrypt.compare(String(pin || ''), sender.pin_hash);
    if (!pinOk) {
      recordPinFailure(senderUserId);
      await client.query('COMMIT');
      txOpen = false;
      return res.status(401).json({ success: false, message: 'လုံခြုံရေး PIN မှားယွင်းနေပါသည်။' });
    }
    clearPinFailure(senderUserId);

    const receiverE164 = normalizePhone(receiverCountryCode, receiverPhone);
    if (receiverE164 === sender.phone_e164) throw new Error('မိမိအကောင့်သို့ ပြန်လွှဲ၍ မရပါ။');

    const rRes = await client.query('SELECT id, phone_e164 FROM users WHERE phone_e164 = $1', [receiverE164]);
    if (rRes.rows.length === 0) throw new Error(`${receiverE164} အကောင့် မရှိသေးပါ။`);
    const receiverId = rRes.rows[0].id;

    const firstId = senderUserId < receiverId ? senderUserId : receiverId;
    const secondId = senderUserId < receiverId ? receiverId : senderUserId;

    await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 FOR UPDATE`, [firstId, currency]);
    await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 FOR UPDATE`, [secondId, currency]);

    const swRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2`, [senderUserId, currency]);
    const rwRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2`, [receiverId, currency]);

    if (Number(swRes.rows[0].balance) < numAmount) {
      throw new Error(`${currency} လက်ကျန်ငွေ မလုံလောက်ပါ။`);
    }

    await client.query(`UPDATE wallets SET balance = balance - $1 WHERE id = $2`, [numAmount, swRes.rows[0].id]);
    await client.query(`UPDATE wallets SET balance = balance + $1 WHERE id = $2`, [numAmount, rwRes.rows[0].id]);
    await client.query(
      `INSERT INTO transactions (sender_user_id, receiver_user_id, tx_type, currency, amount, note)
       VALUES ($1, $2, 'P2P_TRANSFER', $3, $4, $5)`,
      [senderUserId, receiverId, currency, numAmount, note || '']
    );

    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, senderUserId);
    res.json({ success: true, message: `${receiverE164} သို့ ${numAmount} ${currency} လွှဲပြီးပါပြီ။`, ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/swap', requireAuth, checkIdempotency, async (req, res) => {
  const userId = req.authUserId;
  const { pair, amount, pin } = req.body;
  const numAmount = Number(amount);

  if (!['MMK_TO_THB', 'THB_TO_MMK'].includes(pair) || !(numAmount > 0)) {
    return res.status(400).json({ success: false, message: 'ငွေလဲ အချက်အလက် မှားယွင်းနေပါသည်။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    assertPinNotLocked(userId);
    await client.query('BEGIN');
    txOpen = true;

    const uRes = await client.query('SELECT id, pin_hash, kyc_status FROM users WHERE id = $1', [userId]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');
    const user = uRes.rows[0];
    if (user.kyc_status !== 'VERIFIED') {
      throw new Error('ငွေလဲရန် မြန်မာမှတ်ပုံတင် (KYC) VERIFIED ဖြစ်ရပါမည်။');
    }
    const pinOk = await bcrypt.compare(String(pin || ''), user.pin_hash);
    if (!pinOk) {
      recordPinFailure(userId);
      await client.query('COMMIT');
      txOpen = false;
      return res.status(401).json({ success: false, message: 'လုံခြုံရေး PIN မှားယွင်းနေပါသည်။' });
    }
    clearPinFailure(userId);

    const mmkRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'MMK' FOR UPDATE`, [userId]);
    const thbRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'THB' FOR UPDATE`, [userId]);

    let msg = '';
    if (pair === 'MMK_TO_THB') {
      if (Number(mmkRes.rows[0].balance) < numAmount) throw new Error('MMK လက်ကျန်ငွေ မလုံလောက်ပါ။');
      const thbOut = Number((numAmount / THB_TO_MMK_RATE).toFixed(2));
      if (!(thbOut > 0)) throw new Error('ပမာဏ နည်းလွန်းပါသည်။');
      await client.query(`UPDATE wallets SET balance = balance - $1 WHERE id = $2`, [numAmount, mmkRes.rows[0].id]);
      await client.query(`UPDATE wallets SET balance = balance + $1 WHERE id = $2`, [thbOut, thbRes.rows[0].id]);
      await client.query(
        `INSERT INTO transactions (sender_user_id, receiver_user_id, tx_type, currency, amount, note)
         VALUES ($1, $1, 'CURRENCY_SWAP', 'THB', $2, $3)`,
        [userId, thbOut, `${numAmount.toLocaleString()} MMK -> ${thbOut.toFixed(2)} THB @ ${THB_TO_MMK_RATE}`]
      );
      msg = `${numAmount.toLocaleString()} MMK ကို ${thbOut.toFixed(2)} THB သို့ လဲလှယ်ပြီးပါပြီ။`;
    } else {
      if (Number(thbRes.rows[0].balance) < numAmount) throw new Error('THB လက်ကျန်ငွေ မလုံလောက်ပါ။');
      const mmkOut = Number((numAmount * THB_TO_MMK_RATE).toFixed(2));
      await client.query(`UPDATE wallets SET balance = balance - $1 WHERE id = $2`, [numAmount, thbRes.rows[0].id]);
      await client.query(`UPDATE wallets SET balance = balance + $1 WHERE id = $2`, [mmkOut, mmkRes.rows[0].id]);
      await client.query(
        `INSERT INTO transactions (sender_user_id, receiver_user_id, tx_type, currency, amount, note)
         VALUES ($1, $1, 'CURRENCY_SWAP', 'MMK', $2, $3)`,
        [userId, mmkOut, `${numAmount.toFixed(2)} THB -> ${mmkOut.toLocaleString()} MMK @ ${THB_TO_MMK_RATE}`]
      );
      msg = `${numAmount.toFixed(2)} THB ကို ${mmkOut.toLocaleString()} MMK သို့ လဲလှယ်ပြီးပါပြီ။`;
    }

    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, userId);
    res.json({ success: true, message: msg, ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/admin/pending-kyc', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT k.user_id, k.id_type, k.nrc_normalized, k.full_name, k.status, u.phone_e164, u.phone_country
       FROM kyc_submissions k JOIN users u ON k.user_id = u.id
       WHERE k.status = 'PENDING' ORDER BY k.created_at ASC`
    );
    res.json({ success: true, kycs: r.rows });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/admin/kyc-review', requireAdmin, async (req, res) => {
  const { userId, status, rejectReason } = req.body;
  const uidNum = Number(userId);
  if (!Number.isInteger(uidNum) || uidNum <= 0 || !['VERIFIED', 'REJECTED'].includes(status)) {
    return res.status(400).json({ success: false, message: 'userId နှင့် status (VERIFIED / REJECTED) မှန်ကန်စွာ ထည့်ပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await client.query('BEGIN');
    txOpen = true;

    const uCheck = await client.query('SELECT id, phone_e164 FROM users WHERE id = $1', [uidNum]);
    if (uCheck.rows.length === 0) {
      throw new Error('User အကောင့် မတွေ့ပါ။');
    }

    await client.query(
      `UPDATE kyc_submissions SET status = $1, reject_reason = $2, reviewed_at = CURRENT_TIMESTAMP WHERE user_id = $3`,
      [status, status === 'REJECTED' ? (rejectReason || 'အချက်အလက် မကိုက်ညီပါ။') : null, uidNum]
    );
    await client.query(`UPDATE users SET kyc_status = $1 WHERE id = $2`, [status, uidNum]);
    await client.query('COMMIT');
    txOpen = false;

    res.json({
      success: true,
      message: `${uCheck.rows[0].phone_e164} အကောင့်၏ KYC ကို ${status} ပြောင်းပြီးပါပြီ။`
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`KhaoPay server running on port ${PORT}`));
