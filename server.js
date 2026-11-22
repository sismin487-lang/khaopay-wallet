require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '25mb' }));

if (!process.env.DATABASE_URL) {
  console.warn('Warning: DATABASE_URL is not set in environment variables.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: Number(process.env.PG_POOL_MAX || 15),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const rawRate = Number(process.env.THB_TO_MMK_RATE || 120);
const THB_TO_MMK_RATE = Number.isFinite(rawRate) && rawRate > 0 ? rawRate : 120;
const MAX_TX_AMOUNT = Number(process.env.MAX_TX_AMOUNT || 100000000);
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_OTP_CHAT_ID = process.env.TELEGRAM_OTP_CHAT_ID || '';

// KBZ Bank Reserve / Receiving Account Config
const KBZ_ACCOUNT_NAME = process.env.KBZ_ACCOUNT_NAME || 'KhaoPay Reserve Account';
const KBZ_ACCOUNT_NUMBER = process.env.KBZ_ACCOUNT_NUMBER || '';
const KBZ_BANK_NOTE = process.env.KBZ_BANK_NOTE || 'KBZ Bank Transfer / Mobile Banking';

const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_PIN_ATTEMPTS = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;
const IDEMPOTENCY_TTL_MS = 10 * 60 * 1000;

const otpStore = new Map();
const pinFailStore = new Map();
const idempotencyStore = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otpStore.entries()) {
    if (!v || now > v.expiresAt) otpStore.delete(k);
  }
  for (const [k, v] of idempotencyStore.entries()) {
    if (!v || now > v.expiresAt) idempotencyStore.delete(k);
  }
  for (const [k, v] of pinFailStore.entries()) {
    if (!v || (v.lockedUntil && now > v.lockedUntil)) pinFailStore.delete(k);
  }
}, 60 * 1000).unref();

let dbInitialized = false;
let initPromise = null;

function roundMoney(val) {
  const n = Number(val);
  if (!Number.isFinite(n)) return NaN;
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

function validateAmount(rawAmount) {
  const amt = roundMoney(rawAmount);
  if (!Number.isFinite(amt) || !(amt > 0)) {
    throw new Error('ငွေပမာဏ မှန်ကန်စွာ ထည့်ပါ။');
  }
  if (amt > MAX_TX_AMOUNT) {
    throw new Error(`တစ်ကြိမ်လျှင် အများဆုံး ${MAX_TX_AMOUNT.toLocaleString()} အထိသာ လုပ်ဆောင်နိုင်ပါသည်။`);
  }
  return amt;
}

function sanitizeText(val, maxLen = 255) {
  if (val === undefined || val === null) return null;
  const str = String(val).trim();
  if (!str) return null;
  return str.slice(0, maxLen);
}

async function initDatabase() {
  if (dbInitialized) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          phone_e164 TEXT UNIQUE NOT NULL,
          phone_country TEXT NOT NULL CHECK (phone_country IN ('TH', 'MM')),
          pin_hash TEXT NOT NULL,
          kyc_status TEXT NOT NULL DEFAULT 'UNVERIFIED' CHECK (kyc_status IN ('UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED')),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS wallets (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          currency TEXT NOT NULL CHECK (currency IN ('MMK', 'THB')),
          balance NUMERIC(18, 2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
          UNIQUE (user_id, currency)
        );

        CREATE TABLE IF NOT EXISTS kyc_submissions (
          id SERIAL PRIMARY KEY,
          user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          phone_e164 TEXT,
          id_type TEXT NOT NULL DEFAULT 'MYANMAR_NRC',
          nrc_normalized TEXT UNIQUE NOT NULL,
          full_name TEXT NOT NULL,
          front_image_url TEXT NOT NULL,
          back_image_url TEXT NOT NULL,
          selfie_image_url TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'VERIFIED', 'REJECTED')),
          reject_reason TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          reviewed_at TIMESTAMPTZ
        );

        ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS phone_e164 TEXT;
        ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

        CREATE TABLE IF NOT EXISTS transactions (
          id SERIAL PRIMARY KEY,
          sender_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
          receiver_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
          tx_type TEXT NOT NULL,
          currency TEXT NOT NULL CHECK (currency IN ('MMK', 'THB')),
          amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
          note TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      const idColRes = await client.query(`
        SELECT data_type, udt_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'id'
      `);

      let userIdSqlType = 'INTEGER';
      if (idColRes.rows.length > 0) {
        const udt = idColRes.rows[0].udt_name;
        if (udt === 'uuid') userIdSqlType = 'UUID';
        else if (udt === 'int8') userIdSqlType = 'BIGINT';
        else if (udt === 'int4') userIdSqlType = 'INTEGER';
        else if (udt === 'text' || udt === 'varchar') userIdSqlType = 'TEXT';
      }

      await client.query(`
        CREATE TABLE IF NOT EXISTS cash_requests (
          id SERIAL PRIMARY KEY,
          user_id ${userIdSqlType} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          phone_e164 TEXT NOT NULL,
          req_type TEXT NOT NULL CHECK (req_type IN ('CASH_IN', 'CASH_OUT')),
          channel TEXT NOT NULL CHECK (channel IN ('KPAY', 'WAVEPAY', 'KBZ_BANK')),
          target_phone TEXT NOT NULL,
          bank_account_no TEXT,
          bank_account_name TEXT,
          currency TEXT NOT NULL DEFAULT 'MMK',
          amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
          tx_ref TEXT,
          slip_image_url TEXT,
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
          admin_note TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          reviewed_at TIMESTAMPTZ
        );

        ALTER TABLE cash_requests ADD COLUMN IF NOT EXISTS bank_account_no TEXT;
        ALTER TABLE cash_requests ADD COLUMN IF NOT EXISTS bank_account_name TEXT;

        ALTER TABLE cash_requests DROP CONSTRAINT IF EXISTS cash_requests_channel_check;
        ALTER TABLE cash_requests ADD CONSTRAINT cash_requests_channel_check
          CHECK (channel IN ('KPAY', 'WAVEPAY', 'KBZ_BANK'));

        CREATE INDEX IF NOT EXISTS idx_cash_requests_user_id ON cash_requests(user_id);
        CREATE INDEX IF NOT EXISTS idx_cash_requests_status ON cash_requests(status);
        CREATE INDEX IF NOT EXISTS idx_cash_requests_phone ON cash_requests(phone_e164);
        CREATE INDEX IF NOT EXISTS idx_cash_requests_channel ON cash_requests(channel);
        CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender_user_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_receiver ON transactions(receiver_user_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);
      `);

      await client.query('COMMIT');
      dbInitialized = true;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
      initPromise = null;
    }
  })();

  return initPromise;
}

initDatabase().catch((err) => {
  console.error('Database init error:', err.message);
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
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!parsed || !parsed.exp || Date.now() > parsed.exp) return null;
    return parsed;
  } catch (_) {
    return null;
  }
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
  const provBuf = Buffer.from(provided);
  const secretBuf = Buffer.from(ADMIN_SECRET);
  if (!provided || provBuf.length !== secretBuf.length || !crypto.timingSafeEqual(provBuf, secretBuf)) {
    return res.status(403).json({ success: false, message: 'Admin Authorization မအောင်မြင်ပါ။' });
  }
  next();
}

function checkIdempotency(req, res, next) {
  const key = String(req.headers['x-idempotency-key'] || '').trim();
  if (!key) return next();
  const scopedKey = `${req.authUserId || 'anon'}:${req.path}:${key}`;
  const cached = idempotencyStore.get(scopedKey);
  if (cached && Date.now() < cached.expiresAt) {
    return res.status(cached.status).json(cached.body);
  }
  const origJson = res.json.bind(res);
  res.json = (body) => {
    idempotencyStore.set(scopedKey, {
      expiresAt: Date.now() + IDEMPOTENCY_TTL_MS,
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

async function verifyUserPinOrThrow(client, userId, rawPin) {
  assertPinNotLocked(userId);
  const uRes = await client.query(
    'SELECT id, phone_e164, phone_country, pin_hash, kyc_status FROM users WHERE id = $1',
    [userId]
  );
  if (uRes.rows.length === 0) {
    throw new Error('User မတွေ့ပါ။');
  }
  const user = uRes.rows[0];
  const pinOk = await bcrypt.compare(String(rawPin || ''), user.pin_hash);
  if (!pinOk) {
    recordPinFailure(userId);
    const err = new Error('PIN မှားယွင်းနေပါသည်။');
    err.statusCode = 401;
    throw err;
  }
  clearPinFailure(userId);
  return user;
}

async function sendOtpViaProvider(phoneE164, code) {
  if (TELEGRAM_BOT_TOKEN && TELEGRAM_OTP_CHAT_ID) {
    const resp = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_OTP_CHAT_ID,
        text: `🔐 KhaoPay OTP\nPhone: ${phoneE164}\nCode: ${code}\n(၅ မိနစ်အတွင်း အသုံးပြုပါ)`
      })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || data.ok === false) {
      throw new Error(data.description || 'Telegram OTP ပို့ဆောင်ရာတွင် အဆင်မပြေပါ။');
    }
    return { delivered: true };
  }

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

function normalizeAnyPhoneToE164(fallbackCountryCode, rawPhone) {
  const s = String(rawPhone || '').trim();
  if (!s) return null;
  if (s.startsWith('+66')) return normalizePhone('TH', s);
  if (s.startsWith('+95')) return normalizePhone('MM', s);
  const digits = s.replace(/\D/g, '');
  if (digits.startsWith('66')) return normalizePhone('TH', digits);
  if (digits.startsWith('95')) return normalizePhone('MM', digits);
  return normalizePhone(fallbackCountryCode, digits);
}

function normalizeBankAccountNo(rawAcct) {
  const cleaned = String(rawAcct || '').replace(/[^0-9A-Za-z-]/g, '').trim();
  if (!cleaned || cleaned.length < 6 || cleaned.length > 30) {
    throw new Error('KBZ ဘဏ်အကောင့်နံပါတ် မှန်ကန်စွာ ထည့်သွင်းပါ။');
  }
  return cleaned;
}

function normalizeNrc(nrc) {
  return String(nrc || '').trim().toUpperCase().replace(/\s+/g, '');
}

async function ensureUserWallets(client, userId) {
  await client.query(
    `INSERT INTO wallets (user_id, currency, balance)
     VALUES ($1, 'MMK', 0), ($1, 'THB', 0)
     ON CONFLICT (user_id, currency) DO NOTHING`,
    [userId]
  );
}

async function getFullUserState(dbOrClient, userId) {
  const userRes = await dbOrClient.query(
    'SELECT id, phone_e164, phone_country, kyc_status, created_at FROM users WHERE id = $1',
    [userId]
  );
  if (userRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');

  const walletsRes = await dbOrClient.query(
    'SELECT currency, balance FROM wallets WHERE user_id = $1 ORDER BY currency',
    [userId]
  );
  const kycRes = await dbOrClient.query(
    'SELECT id_type, phone_e164, nrc_normalized, full_name, status, reject_reason, created_at, reviewed_at FROM kyc_submissions WHERE user_id = $1',
    [userId]
  );
  const cashReqRes = await dbOrClient.query(
    `SELECT id, phone_e164, req_type, channel, target_phone, bank_account_no, bank_account_name, currency, amount, tx_ref, status, admin_note, created_at, reviewed_at
     FROM cash_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30`,
    [userId]
  );
  const txRes = await dbOrClient.query(
    `SELECT t.*, u_send.phone_e164 AS sender_phone, u_recv.phone_e164 AS receiver_phone
     FROM transactions t
     LEFT JOIN users u_send ON t.sender_user_id = u_send.id
     LEFT JOIN users u_recv ON t.receiver_user_id = u_recv.id
     WHERE t.sender_user_id = $1 OR t.receiver_user_id = $1
     ORDER BY t.created_at DESC, t.id DESC LIMIT 30`,
    [userId]
  );

  const wallets = { MMK: 0, THB: 0 };
  for (const w of walletsRes.rows) {
    wallets[w.currency] = roundMoney(w.balance);
  }

  return {
    user: {
      id: userRes.rows[0].id,
      phoneE164: userRes.rows[0].phone_e164,
      phoneCountry: userRes.rows[0].phone_country,
      kycStatus: userRes.rows[0].kyc_status,
      createdAt: userRes.rows[0].created_at
    },
    wallets,
    kyc: kycRes.rows[0] || null,
    cashRequests: cashReqRes.rows,
    transactions: txRes.rows
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'KhaoPay', rate: THB_TO_MMK_RATE, dbInitialized });
});

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    rate: THB_TO_MMK_RATE,
    maxTxAmount: MAX_TX_AMOUNT,
    kbzBank: {
      enabled: Boolean(KBZ_ACCOUNT_NUMBER || process.env.KBZ_PAYOUT_URL),
      accountName: KBZ_ACCOUNT_NAME,
      accountNumber: KBZ_ACCOUNT_NUMBER,
      note: KBZ_BANK_NOTE
    },
    otpGatewayConfigured: Boolean((TELEGRAM_BOT_TOKEN && TELEGRAM_OTP_CHAT_ID) || process.env.OTP_WEBHOOK_URL),
    payoutGatewayConfigured: Boolean(
      (process.env.PAYMENT_GATEWAY_URL && process.env.PAYMENT_GATEWAY_KEY) ||
      (process.env.KBZ_PAYOUT_URL && process.env.KBZ_PAYOUT_KEY)
    )
  });
});

app.get('/api/bank/kbz-info', requireAuth, (req, res) => {
  res.json({
    success: true,
    bank: 'KBZ_BANK',
    accountName: KBZ_ACCOUNT_NAME,
    accountNumber: KBZ_ACCOUNT_NUMBER,
    note: KBZ_BANK_NOTE
  });
});

app.post('/api/auth/send-otp', async (req, res) => {
  try {
    await initDatabase();
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
        ? `${phoneE164} အတွက် OTP ကို ပို့ပြီးပါပြီ (၅ မိနစ်အတွင်း အသုံးပြုပါ)။`
        : `${phoneE164} အတွက် OTP ထုတ်ပေးပြီးပါပြီ (Test OTP: ${code})`
    };

    if (!providerRes.delivered) {
      payload.devOtp = code;
    }

    res.json(payload);
  } catch (err) {
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
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
    await initDatabase();
    const phoneE164 = normalizePhone(countryCode, phone);
    const otpRec = otpStore.get(phoneE164);

    if (!otpRec || Date.now() > otpRec.expiresAt) {
      return res.status(400).json({ success: false, message: 'OTP သက်တမ်းကုန်သွားပါပြီ။ OTP အသစ်ပြန်တောင်းပါ။' });
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
      await ensureUserWallets(client, u.id);
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
      await ensureUserWallets(client, userId);
      await client.query('COMMIT');
      txOpen = false;
    }

    const token = signToken({ userId });
    const state = await getFullUserState(pool, userId);
    res.json({ success: true, token, ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    await initDatabase();
    const state = await getFullUserState(pool, req.authUserId);
    res.json({ success: true, ...state });
  } catch (err) {
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  }
});

app.get('/api/wallet/:userId', requireAuth, async (req, res) => {
  if (String(req.params.userId) !== String(req.authUserId)) {
    return res.status(403).json({ success: false, message: 'အခြားအကောင့် အချက်အလက်ကို ကြည့်ခွင့်မရှိပါ။' });
  }
  try {
    await initDatabase();
    const state = await getFullUserState(pool, req.authUserId);
    res.json({ success: true, ...state });
  } catch (err) {
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  }
});

app.get('/api/qr/my', requireAuth, async (req, res) => {
  try {
    await initDatabase();
    const r = await pool.query(
      'SELECT id, phone_e164, phone_country, kyc_status FROM users WHERE id = $1',
      [req.authUserId]
    );
    if (r.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User မတွေ့ပါ။' });
    }
    const u = r.rows[0];
    const payload = {
      app: 'KhaoPay',
      version: 1,
      userId: u.id,
      phoneE164: u.phone_e164,
      phoneCountry: u.phone_country
    };
    res.json({
      success: true,
      qrPayload: JSON.stringify(payload),
      data: payload
    });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/kyc/submit', requireAuth, async (req, res) => {
  const userId = req.authUserId;
  const { fullName, nrcNumber, frontImageUrl, backImageUrl, selfieImageUrl } = req.body;
  if (!fullName || !nrcNumber || !frontImageUrl || !backImageUrl || !selfieImageUrl) {
    return res.status(400).json({ success: false, message: 'အမည်၊ မှတ်ပုံတင်နံပါတ်နှင့် ဓာတ်ပုံ ၃ ပုံလုံး ထည့်ပါ။' });
  }

  const cleanName = sanitizeText(fullName, 120);
  if (!cleanName) {
    return res.status(400).json({ success: false, message: 'အမည် ထည့်သွင်းပါ။' });
  }

  const nrcNormalized = normalizeNrc(nrcNumber);
  if (!nrcNormalized) {
    return res.status(400).json({ success: false, message: 'မှတ်ပုံတင်နံပါတ် ထည့်သွင်းပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    await client.query('BEGIN');
    txOpen = true;

    const uRes = await client.query('SELECT id, phone_e164 FROM users WHERE id = $1', [userId]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');
    const accountPhone = uRes.rows[0].phone_e164;

    const dup = await client.query(
      'SELECT user_id FROM kyc_submissions WHERE nrc_normalized = $1 AND user_id <> $2',
      [nrcNormalized, userId]
    );
    if (dup.rows.length > 0) {
      throw new Error('ဤမှတ်ပုံတင်နံပါတ်ကို အခြားအကောင့်တွင် သုံးထားပြီး ဖြစ်ပါသည်။');
    }

    await client.query(
      `INSERT INTO kyc_submissions
        (user_id, phone_e164, id_type, nrc_normalized, full_name, front_image_url, back_image_url, selfie_image_url, status, reject_reason)
       VALUES ($1, $2, 'MYANMAR_NRC', $3, $4, $5, $6, $7, 'PENDING', NULL)
       ON CONFLICT (user_id) DO UPDATE SET
        phone_e164 = EXCLUDED.phone_e164,
        nrc_normalized = EXCLUDED.nrc_normalized,
        full_name = EXCLUDED.full_name,
        front_image_url = EXCLUDED.front_image_url,
        back_image_url = EXCLUDED.back_image_url,
        selfie_image_url = EXCLUDED.selfie_image_url,
        status = 'PENDING',
        reject_reason = NULL,
        reviewed_at = NULL,
        created_at = CURRENT_TIMESTAMP`,
      [userId, accountPhone, nrcNormalized, cleanName, String(frontImageUrl), String(backImageUrl), String(selfieImageUrl)]
    );
    await client.query(`UPDATE users SET kyc_status = 'PENDING' WHERE id = $1`, [userId]);
    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, userId);
    res.json({
      success: true,
      message: `${accountPhone} အကောင့်အတွက် KYC တင်ပြီးပါပြီ။`,
      ...state
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

async function callExternalWalletPayout({ channel, phone, bankAccountNo, bankAccountName, amount, refId }) {
  if (channel === 'KBZ_BANK' && process.env.KBZ_PAYOUT_URL && process.env.KBZ_PAYOUT_KEY) {
    const baseUrl = String(process.env.KBZ_PAYOUT_URL).replace(/\/+$/, '');
    const resp = await fetch(`${baseUrl}/payout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.KBZ_PAYOUT_KEY}`
      },
      body: JSON.stringify({
        bank: 'KBZ_BANK',
        account_number: bankAccountNo,
        account_name: bankAccountName,
        phone,
        amount,
        currency: 'MMK',
        reference_id: refId
      })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || data.success === false) {
      throw new Error(data.message || 'KBZ Bank ငွေလွှဲမှု မအောင်မြင်ပါ။');
    }
    return data.transaction_id || refId;
  }

  if (process.env.PAYMENT_GATEWAY_URL && process.env.PAYMENT_GATEWAY_KEY) {
    const baseUrl = String(process.env.PAYMENT_GATEWAY_URL).replace(/\/+$/, '');
    const resp = await fetch(`${baseUrl}/payout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.PAYMENT_GATEWAY_KEY}`
      },
      body: JSON.stringify({
        provider: channel,
        receiver_phone: phone,
        bank_account_no: bankAccountNo || null,
        bank_account_name: bankAccountName || null,
        amount,
        currency: 'MMK',
        reference_id: refId
      })
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok || data.success === false) {
      throw new Error(data.message || `${channel} ငွေလွှဲမှု မအောင်မြင်ပါ။`);
    }
    return data.transaction_id || refId;
  }

  return `MANUAL_${channel}_${Date.now()}`;
}

async function createCashRequestHandler(req, res, forcedChannel = null) {
  const userId = req.authUserId;
  const { type, targetPhone, bankAccountNo, bankAccountName, amount, txRef, slipImageUrl, pin } = req.body;
  const channel = forcedChannel || req.body.channel;

  if (!['CASH_IN', 'CASH_OUT'].includes(type)) {
    return res.status(400).json({ success: false, message: 'လုပ်ဆောင်ချက် မှားယွင်းနေပါသည်။' });
  }
  if (!['KPAY', 'WAVEPAY', 'KBZ_BANK'].includes(channel)) {
    return res.status(400).json({ success: false, message: 'KPay, WavePay သို့မဟုတ် KBZ_BANK ရွေးချယ်ပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    const numAmount = validateAmount(amount);

    let cleanAcctNo = null;
    let cleanAcctName = null;
    if (channel === 'KBZ_BANK') {
      cleanAcctNo = normalizeBankAccountNo(bankAccountNo);
      cleanAcctName = sanitizeText(bankAccountName, 120);
      if (type === 'CASH_OUT' && !cleanAcctName) {
        throw new Error('KBZ ငွေထုတ်ရန် ဘဏ်အကောင့်ပိုင်ရှင် အမည် ထည့်သွင်းပါ။');
      }
    }

    await client.query('BEGIN');
    txOpen = true;

    const user = await verifyUserPinOrThrow(client, userId, pin);
    if (user.kyc_status !== 'VERIFIED') {
      throw new Error('KYC VERIFIED ဖြစ်ပြီးမှ အသုံးပြုနိုင်ပါမည်။');
    }

    await ensureUserWallets(client, userId);

    const accountPhone = user.phone_e164;
    let effectivePhone = accountPhone;

    if (targetPhone && String(targetPhone).trim()) {
      const normalizedTarget = normalizeAnyPhoneToE164(user.phone_country, targetPhone);
      if (normalizedTarget !== accountPhone) {
        throw new Error(`အကောင့်ဖုန်းနံပါတ် (${accountPhone}) နှင့်သာ ကိုက်ညီသော နံပါတ်ကို သုံးပါ။`);
      }
      effectivePhone = normalizedTarget;
    }

    if (type === 'CASH_OUT') {
      const wRes = await client.query(
        `SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'MMK' FOR UPDATE`,
        [userId]
      );
      if (wRes.rows.length === 0 || roundMoney(wRes.rows[0].balance) < numAmount) {
        throw new Error('MMK လက်ကျန်ငွေ မလုံလောက်ပါ။');
      }
      await client.query(
        `UPDATE wallets SET balance = balance - $1 WHERE id = $2`,
        [numAmount, wRes.rows[0].id]
      );
    }

    const created = await client.query(
      `INSERT INTO cash_requests
        (user_id, phone_e164, req_type, channel, target_phone, bank_account_no, bank_account_name, currency, amount, tx_ref, slip_image_url, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'MMK', $8, $9, $10, 'PENDING')
       RETURNING id, user_id, phone_e164, req_type, channel, target_phone, bank_account_no, bank_account_name, currency, amount, tx_ref, status, created_at`,
      [
        userId,
        accountPhone,
        type,
        channel,
        effectivePhone,
        cleanAcctNo,
        cleanAcctName,
        numAmount,
        sanitizeText(txRef, 100),
        slipImageUrl ? String(slipImageUrl) : null
      ]
    );

    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, userId);
    const channelLabel = channel === 'KBZ_BANK' ? `KBZ Bank (${cleanAcctNo})` : channel;
    const msg =
      type === 'CASH_IN'
        ? `${accountPhone} (${channelLabel}) ငွေသွင်း ${numAmount.toLocaleString()} MMK တင်ပြီးပါပြီ။`
        : `${accountPhone} (${channelLabel}) ငွေထုတ် ${numAmount.toLocaleString()} MMK တင်ပြီးပါပြီ။`;

    res.json({ success: true, message: msg, request: created.rows[0], ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
}

app.post('/api/wallet/direct-cash', requireAuth, checkIdempotency, async (req, res) => {
  await createCashRequestHandler(req, res, null);
});

app.post('/api/wallet/bank-cash', requireAuth, checkIdempotency, async (req, res) => {
  await createCashRequestHandler(req, res, 'KBZ_BANK');
});

app.get('/api/admin/pending-cash', requireAdmin, async (req, res) => {
  try {
    await initDatabase();
    const r = await pool.query(
      `SELECT c.id, c.user_id, c.phone_e164, c.req_type, c.channel, c.target_phone, c.bank_account_no, c.bank_account_name, c.currency, c.amount, c.tx_ref, c.slip_image_url, c.status, c.created_at, u.kyc_status
       FROM cash_requests c
       JOIN users u ON c.user_id = u.id
       WHERE c.status = 'PENDING'
       ORDER BY c.created_at ASC, c.id ASC`
    );
    res.json({ success: true, requests: r.rows });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.get('/api/admin/cash-requests', requireAdmin, async (req, res) => {
  try {
    await initDatabase();
    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
    const channelFilter = req.query.channel ? String(req.query.channel).toUpperCase() : null;
    const params = [];
    let whereSql = '';
    if (channelFilter && ['KPAY', 'WAVEPAY', 'KBZ_BANK'].includes(channelFilter)) {
      params.push(channelFilter);
      whereSql = `WHERE c.channel = $${params.length}`;
    }
    params.push(limit);

    const r = await pool.query(
      `SELECT c.id, c.user_id, c.phone_e164, c.req_type, c.channel, c.target_phone, c.bank_account_no, c.bank_account_name, c.currency, c.amount, c.tx_ref, c.status, c.admin_note, c.created_at, c.reviewed_at
       FROM cash_requests c
       ${whereSql}
       ORDER BY c.created_at DESC, c.id DESC
       LIMIT $${params.length}`,
      params
    );
    res.json({ success: true, requests: r.rows });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/admin/cash-review', requireAdmin, checkIdempotency, async (req, res) => {
  const { requestId, status, adminNote } = req.body;
  const reqIdNum = Number(requestId);
  if (!Number.isInteger(reqIdNum) || reqIdNum <= 0 || !['APPROVED', 'REJECTED'].includes(status)) {
    return res.status(400).json({ success: false, message: 'requestId နှင့် status (APPROVED / REJECTED) ထည့်ပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    await client.query('BEGIN');
    txOpen = true;

    const crRes = await client.query(
      `SELECT * FROM cash_requests WHERE id = $1 FOR UPDATE`,
      [reqIdNum]
    );
    if (crRes.rows.length === 0) throw new Error('Cash Request မတွေ့ပါ။');
    const cr = crRes.rows[0];
    if (cr.status !== 'PENDING') throw new Error(`ဤ Request မှာ ${cr.status} ဖြစ်ပြီးသား ဖြစ်ပါသည်။`);

    await ensureUserWallets(client, cr.user_id);

    const wRes = await client.query(
      `SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'MMK' FOR UPDATE`,
      [cr.user_id]
    );
    if (wRes.rows.length === 0) throw new Error('User ၏ MMK Wallet မတွေ့ပါ။');

    const amount = roundMoney(cr.amount);
    const cleanNote = sanitizeText(adminNote, 250);
    const destLabel = cr.channel === 'KBZ_BANK'
      ? `KBZ ${cr.bank_account_no}${cr.bank_account_name ? ' (' + cr.bank_account_name + ')' : ''}`
      : `${cr.channel} (${cr.target_phone})`;

    if (status === 'REJECTED') {
      if (cr.req_type === 'CASH_OUT') {
        await client.query(
          `UPDATE wallets SET balance = balance + $1 WHERE id = $2`,
          [amount, wRes.rows[0].id]
        );
      }
      await client.query(
        `UPDATE cash_requests
         SET status = 'REJECTED', admin_note = $1, reviewed_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [cleanNote || 'Rejected', reqIdNum]
      );
      await client.query('COMMIT');
      txOpen = false;
      return res.json({ success: true, message: `Request #${reqIdNum} ကို ပယ်ချပြီးပါပြီ။` });
    }

    let finalAdminNote = cleanNote || 'Approved';

    if (cr.req_type === 'CASH_IN') {
      await client.query(
        `UPDATE wallets SET balance = balance + $1 WHERE id = $2`,
        [amount, wRes.rows[0].id]
      );
      await client.query(
        `INSERT INTO transactions (receiver_user_id, tx_type, currency, amount, note)
         VALUES ($1, $2, 'MMK', $3, $4)`,
        [
          cr.user_id,
          cr.channel === 'KBZ_BANK' ? 'KBZ_CASH_IN' : 'DIRECT_CASH_IN',
          amount,
          `${destLabel} • Ref: ${cr.tx_ref || 'REQ-' + cr.id}`
        ]
      );
    } else if (cr.req_type === 'CASH_OUT') {
      const extTxId = await callExternalWalletPayout({
        channel: cr.channel,
        phone: cr.target_phone,
        bankAccountNo: cr.bank_account_no,
        bankAccountName: cr.bank_account_name,
        amount,
        refId: `REQ_${cr.id}_${Date.now()}`
      });
      finalAdminNote = cleanNote ? `${cleanNote} • Tx: ${extTxId}` : `Approved • Tx: ${extTxId}`;
      await client.query(
        `INSERT INTO transactions (sender_user_id, tx_type, currency, amount, note)
         VALUES ($1, $2, 'MMK', $3, $4)`,
        [
          cr.user_id,
          cr.channel === 'KBZ_BANK' ? 'KBZ_CASH_OUT' : 'DIRECT_TRANSFER_OUT',
          amount,
          `${destLabel} • Tx: ${extTxId}`
        ]
      );
    }

    await client.query(
      `UPDATE cash_requests
       SET status = 'APPROVED', admin_note = $1, reviewed_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [finalAdminNote, reqIdNum]
    );

    await client.query('COMMIT');
    txOpen = false;

    res.json({
      success: true,
      message: `${cr.phone_e164} (${destLabel}) ${amount.toLocaleString()} MMK Approve ပြီးပါပြီ။`
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

async function executeP2PTransfer(client, { senderUserId, receiverE164, currency, amount, note }) {
  if (!['MMK', 'THB'].includes(currency)) {
    throw new Error('ငွေကြေး မှားယွင်းနေပါသည်။');
  }

  const sRes = await client.query('SELECT id, phone_e164, kyc_status FROM users WHERE id = $1', [senderUserId]);
  if (sRes.rows.length === 0) throw new Error('ပေးပို့သူ အကောင့် မတွေ့ပါ။');
  const sender = sRes.rows[0];

  if (sender.kyc_status !== 'VERIFIED') {
    throw new Error('KYC VERIFIED ဖြစ်ပြီးမှ ငွေလွှဲနိုင်ပါမည်။');
  }
  if (receiverE164 === sender.phone_e164) {
    throw new Error('မိမိအကောင့်သို့ ပြန်လွှဲ၍ မရပါ။');
  }

  const rRes = await client.query('SELECT id, phone_e164 FROM users WHERE phone_e164 = $1', [receiverE164]);
  if (rRes.rows.length === 0) throw new Error(`${receiverE164} အကောင့် မရှိသေးပါ။`);
  const receiverId = rRes.rows[0].id;

  await ensureUserWallets(client, senderUserId);
  await ensureUserWallets(client, receiverId);

  const firstId = senderUserId < receiverId ? senderUserId : receiverId;
  const secondId = senderUserId < receiverId ? receiverId : senderUserId;

  await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 FOR UPDATE`, [firstId, currency]);
  await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 FOR UPDATE`, [secondId, currency]);

  const swRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2`, [senderUserId, currency]);
  const rwRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2`, [receiverId, currency]);

  if (roundMoney(swRes.rows[0].balance) < amount) {
    throw new Error(`${currency} လက်ကျန်ငွေ မလုံလောက်ပါ။`);
  }

  await client.query(`UPDATE wallets SET balance = balance - $1 WHERE id = $2`, [amount, swRes.rows[0].id]);
  await client.query(`UPDATE wallets SET balance = balance + $1 WHERE id = $2`, [amount, rwRes.rows[0].id]);
  await client.query(
    `INSERT INTO transactions (sender_user_id, receiver_user_id, tx_type, currency, amount, note)
     VALUES ($1, $2, 'P2P_TRANSFER', $3, $4, $5)`,
    [senderUserId, receiverId, currency, amount, sanitizeText(note, 250) || '']
  );

  return { receiverE164 };
}

app.post('/api/transfer', requireAuth, checkIdempotency, async (req, res) => {
  const senderUserId = req.authUserId;
  const { receiverCountryCode, receiverPhone, currency, amount, note, pin } = req.body;

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    const numAmount = validateAmount(amount);
    const receiverE164 = normalizePhone(receiverCountryCode, receiverPhone);

    await client.query('BEGIN');
    txOpen = true;

    await verifyUserPinOrThrow(client, senderUserId, pin);
    await executeP2PTransfer(client, {
      senderUserId,
      receiverE164,
      currency,
      amount: numAmount,
      note
    });

    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, senderUserId);
    res.json({ success: true, message: `${receiverE164} သို့ ${numAmount.toLocaleString()} ${currency} လွှဲပြီးပါပြီ။`, ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/qr/pay', requireAuth, checkIdempotency, async (req, res) => {
  const senderUserId = req.authUserId;
  const { qrPayload, currency, amount, note, pin } = req.body;

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    const numAmount = validateAmount(amount);

    let receiverE164 = '';
    if (qrPayload && typeof qrPayload === 'object') {
      receiverE164 = qrPayload.phoneE164 || '';
    } else if (typeof qrPayload === 'string' && qrPayload.trim().startsWith('{')) {
      const parsed = JSON.parse(qrPayload.trim());
      if (parsed.app && parsed.app !== 'KhaoPay') {
        throw new Error('KhaoPay QR ကုဒ် မဟုတ်ပါ။');
      }
      receiverE164 = parsed.phoneE164 || '';
    } else if (typeof qrPayload === 'string') {
      receiverE164 = normalizeAnyPhoneToE164('MM', qrPayload) || '';
    }

    if (!receiverE164) {
      throw new Error('QR Data မှ ဖုန်းနံပါတ် မတွေ့ပါ။');
    }

    await client.query('BEGIN');
    txOpen = true;

    await verifyUserPinOrThrow(client, senderUserId, pin);
    await executeP2PTransfer(client, {
      senderUserId,
      receiverE164,
      currency,
      amount: numAmount,
      note: note || 'QR Payment'
    });

    await client.query('COMMIT');
    txOpen = false;

    const state = await getFullUserState(pool, senderUserId);
    res.json({ success: true, message: `${receiverE164} သို့ QR ဖြင့် ${numAmount.toLocaleString()} ${currency} ပေးချေပြီးပါပြီ။`, ...state });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/swap', requireAuth, checkIdempotency, async (req, res) => {
  const userId = req.authUserId;
  const { pair, amount, pin } = req.body;

  if (!['MMK_TO_THB', 'THB_TO_MMK'].includes(pair)) {
    return res.status(400).json({ success: false, message: 'ငွေလဲ အချက်အလက် မှားယွင်းနေပါသည်။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    const numAmount = validateAmount(amount);

    await client.query('BEGIN');
    txOpen = true;

    const user = await verifyUserPinOrThrow(client, userId, pin);
    if (user.kyc_status !== 'VERIFIED') {
      throw new Error('KYC VERIFIED ဖြစ်ပြီးမှ ငွေလဲနိုင်ပါမည်။');
    }

    await ensureUserWallets(client, userId);

    const mmkRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'MMK' FOR UPDATE`, [userId]);
    const thbRes = await client.query(`SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'THB' FOR UPDATE`, [userId]);

    let msg = '';
    if (pair === 'MMK_TO_THB') {
      if (roundMoney(mmkRes.rows[0].balance) < numAmount) throw new Error('MMK လက်ကျန်ငွေ မလုံလောက်ပါ။');
      const thbOut = roundMoney(numAmount / THB_TO_MMK_RATE);
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
      if (roundMoney(thbRes.rows[0].balance) < numAmount) throw new Error('THB လက်ကျန်ငွေ မလုံလောက်ပါ။');
      const mmkOut = roundMoney(numAmount * THB_TO_MMK_RATE);
      if (!(mmkOut > 0)) throw new Error('ပမာဏ နည်းလွန်းပါသည်။');
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
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/admin/pending-kyc', requireAdmin, async (req, res) => {
  try {
    await initDatabase();
    const r = await pool.query(
      `SELECT k.user_id, k.id_type, k.nrc_normalized, k.full_name, k.front_image_url, k.back_image_url, k.selfie_image_url, k.status, k.created_at, u.phone_e164, u.phone_country
       FROM kyc_submissions k JOIN users u ON k.user_id = u.id
       WHERE k.status = 'PENDING' ORDER BY k.created_at ASC, k.id ASC`
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
    return res.status(400).json({ success: false, message: 'userId နှင့် status (VERIFIED / REJECTED) ထည့်ပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    await client.query('BEGIN');
    txOpen = true;

    const uCheck = await client.query('SELECT id, phone_e164 FROM users WHERE id = $1', [uidNum]);
    if (uCheck.rows.length === 0) throw new Error('User အကောင့် မတွေ့ပါ။');

    const kCheck = await client.query('SELECT id FROM kyc_submissions WHERE user_id = $1', [uidNum]);
    if (kCheck.rows.length === 0) throw new Error('ဤ User အတွက် KYC တင်ထားခြင်း မရှိသေးပါ။');

    await client.query(
      `UPDATE kyc_submissions
       SET status = $1, reject_reason = $2, reviewed_at = CURRENT_TIMESTAMP
       WHERE user_id = $3`,
      [status, status === 'REJECTED' ? (sanitizeText(rejectReason, 250) || 'Rejected') : null, uidNum]
    );
    await client.query(`UPDATE users SET kyc_status = $1 WHERE id = $2`, [status, uidNum]);
    await client.query('COMMIT');
    txOpen = false;

    res.json({
      success: true,
      message: `${uCheck.rows[0].phone_e164} KYC ${status} ဖြစ်ပါပြီ။`
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    await initDatabase();
    const r = await pool.query(
      `SELECT u.id, u.phone_e164, u.phone_country, u.kyc_status, u.created_at,
              COALESCE(MAX(CASE WHEN w.currency = 'MMK' THEN w.balance END), 0) AS mmk_balance,
              COALESCE(MAX(CASE WHEN w.currency = 'THB' THEN w.balance END), 0) AS thb_balance
       FROM users u
       LEFT JOIN wallets w ON u.id = w.user_id
       GROUP BY u.id
       ORDER BY u.id DESC
       LIMIT 100`
    );
    res.json({ success: true, users: r.rows });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/admin/adjust-balance', requireAdmin, checkIdempotency, async (req, res) => {
  const { userId, currency, action, amount, note } = req.body;
  const uidNum = Number(userId);
  if (!Number.isInteger(uidNum) || uidNum <= 0) {
    return res.status(400).json({ success: false, message: 'userId မှန်ကန်စွာ ထည့်ပါ။' });
  }
  if (!['MMK', 'THB'].includes(currency)) {
    return res.status(400).json({ success: false, message: 'currency ကို MMK သို့မဟုတ် THB ရွေးပါ။' });
  }
  if (!['CREDIT', 'DEBIT'].includes(action)) {
    return res.status(400).json({ success: false, message: 'action ကို CREDIT သို့မဟုတ် DEBIT ရွေးပါ။' });
  }

  const client = await pool.connect();
  let txOpen = false;
  try {
    await initDatabase();
    const numAmount = validateAmount(amount);

    await client.query('BEGIN');
    txOpen = true;

    const uRes = await client.query('SELECT id, phone_e164 FROM users WHERE id = $1', [uidNum]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');

    await ensureUserWallets(client, uidNum);
    const wRes = await client.query(
      `SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = $2 FOR UPDATE`,
      [uidNum, currency]
    );
    const curBal = roundMoney(wRes.rows[0].balance);

    if (action === 'DEBIT' && curBal < numAmount) {
      throw new Error(`${currency} လက်ကျန်ငွေ မလုံလောက်ပါ။`);
    }

    const delta = action === 'CREDIT' ? numAmount : -numAmount;
    await client.query(`UPDATE wallets SET balance = balance + $1 WHERE id = $2`, [delta, wRes.rows[0].id]);
    await client.query(
      `INSERT INTO transactions (sender_user_id, receiver_user_id, tx_type, currency, amount, note)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        action === 'DEBIT' ? uidNum : null,
        action === 'CREDIT' ? uidNum : null,
        action === 'CREDIT' ? 'ADMIN_CREDIT' : 'ADMIN_DEBIT',
        currency,
        numAmount,
        sanitizeText(note, 250) || `Admin ${action}`
      ]
    );

    await client.query('COMMIT');
    txOpen = false;

    res.json({
      success: true,
      message: `${uRes.rows[0].phone_e164} (${currency}) ${action} ${numAmount.toLocaleString()} ပြီးပါပြီ။`
    });
  } catch (err) {
    if (txOpen) await client.query('ROLLBACK').catch(() => {});
    res.status(err.statusCode || 400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, message: 'Request JSON Format မှားယွင်းနေပါသည်။' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, message: 'Data ပမာဏ ကြီးလွန်းပါသည်။' });
  }
  console.error('Unhandled server error:', err);
  res.status(500).json({ success: false, message: 'Server Error ဖြစ်ပွားပါသည်။' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`KhaoPay server running on port ${PORT}`));
