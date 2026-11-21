require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
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

async function getFullUserState(client, userId) {
  const userRes = await client.query(
    'SELECT id, phone_e164, phone_country, kyc_status FROM users WHERE id = $1',
    [userId]
  );
  if (userRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');

  const walletsRes = await client.query(
    'SELECT currency, balance FROM wallets WHERE user_id = $1 ORDER BY currency',
    [userId]
  );
  const kycRes = await client.query(
    'SELECT id_type, nrc_normalized, full_name, status, reject_reason FROM kyc_submissions WHERE user_id = $1',
    [userId]
  );
  const txRes = await client.query(
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
    transactions: txRes.rows
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'KhaoPay', rate: THB_TO_MMK_RATE });
});

app.post('/api/auth/send-otp', (req, res) => {
  try {
    const { countryCode, phone } = req.body;
    const phoneE164 = normalizePhone(countryCode, phone);
    res.json({
      success: true,
      phoneE164,
      demoOtp: '123456',
      message: `${phoneE164} သို့ OTP ပို့ပြီးပါပြီ (OTP: 123456)`
    });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/auth/register-or-login', async (req, res) => {
  const { countryCode, phone, otp, pin } = req.body;
  if (String(otp) !== '123456') {
    return res.status(400).json({ success: false, message: 'OTP ကုဒ် မှားယွင်းနေပါသည် (123456 ဖြင့် စမ်းသပ်ပါ)။' });
  }
  if (!/^\d{6}$/.test(String(pin || ''))) {
    return res.status(400).json({ success: false, message: 'PIN သည် ဂဏန်း ၆ လုံး ဖြစ်ရပါမည်။' });
  }

  const client = await pool.connect();
  try {
    const phoneE164 = normalizePhone(countryCode, phone);
    const existing = await client.query('SELECT * FROM users WHERE phone_e164 = $1', [phoneE164]);

    let userId;
    if (existing.rows.length > 0) {
      const u = existing.rows[0];
      const ok = await bcrypt.compare(String(pin), u.pin_hash);
      if (!ok) {
        return res.status(401).json({ success: false, message: 'PIN မှားယွင်းနေပါသည်။' });
      }
      userId = u.id;
    } else {
      await client.query('BEGIN');
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
    }

    const state = await getFullUserState(client, userId);
    res.json({ success: true, ...state });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/wallet/:userId', async (req, res) => {
  const client = await pool.connect();
  try {
    const state = await getFullUserState(client, req.params.userId);
    res.json({ success: true, ...state });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/kyc/submit', async (req, res) => {
  const { userId, fullName, nrcNumber, frontImageUrl, backImageUrl, selfieImageUrl } = req.body;
  if (!userId || !fullName || !nrcNumber || !frontImageUrl || !backImageUrl || !selfieImageUrl) {
    return res.status(400).json({ success: false, message: 'အမည်၊ မှတ်ပုံတင်နံပါတ်နှင့် ဓာတ်ပုံ ၃ ပုံလုံး ပြည့်စုံစွာ ထည့်ပါ။' });
  }

  const nrcNormalized = normalizeNrc(nrcNumber);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
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

    const state = await getFullUserState(client, userId);
    res.json({ success: true, message: 'မြန်မာမှတ်ပုံတင် (NRC) KYC တင်သွင်းပြီးပါပြီ။', ...state });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
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
  return `DIRECT_${channel}_${Date.now()}`;
}

app.post('/api/wallet/direct-cash', async (req, res) => {
  const { userId, type, channel, targetPhone, amount, pin } = req.body;
  const numAmount = Number(amount);

  if (!['CASH_IN', 'CASH_OUT'].includes(type)) {
    return res.status(400).json({ success: false, message: 'လုပ်ဆောင်ချက် မှားယွင်းနေပါသည်။' });
  }
  if (!['KPAY', 'WAVEPAY'].includes(channel)) {
    return res.status(400).json({ success: false, message: 'KPay သို့မဟုတ် WavePay ကိုသာ ရွေးချယ်ပါ။' });
  }
  if (!targetPhone || !(numAmount > 0)) {
    return res.status(400).json({ success: false, message: 'ဖုန်းနံပါတ်နှင့် ငွေပမာဏ ပြည့်စုံစွာ ထည့်ပါ။' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const uRes = await client.query('SELECT id, phone_e164, pin_hash, kyc_status FROM users WHERE id = $1', [userId]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');
    const user = uRes.rows[0];

    if (user.kyc_status !== 'VERIFIED') {
      throw new Error('KPay / WavePay ဝန်ဆောင်မှုသုံးရန် မြန်မာမှတ်ပုံတင် (KYC) VERIFIED ဖြစ်ရပါမည်။');
    }
    const pinOk = await bcrypt.compare(String(pin || ''), user.pin_hash);
    if (!pinOk) throw new Error('လုံခြုံရေး PIN မှားယွင်းနေပါသည်။');

    const wRes = await client.query(
      `SELECT id, balance FROM wallets WHERE user_id = $1 AND currency = 'MMK' FOR UPDATE`,
      [userId]
    );
    if (wRes.rows.length === 0) throw new Error('MMK Wallet မတွေ့ပါ။');

    const refId = `${type}_${Date.now()}`;
    let msg = '';

    if (type === 'CASH_IN') {
      await client.query(`UPDATE wallets SET balance = balance + $1 WHERE id = $2`, [numAmount, wRes.rows[0].id]);
      await client.query(
        `INSERT INTO transactions (receiver_user_id, tx_type, currency, amount, note)
         VALUES ($1, 'DIRECT_CASH_IN', 'MMK', $2, $3)`,
        [userId, numAmount, `From ${channel} (${targetPhone}) • Ref: ${refId}`]
      );
      msg = `${channel} (${targetPhone}) မှ ${numAmount.toLocaleString()} MMK ထည့်ပြီးပါပြီ။`;
    } else {
      if (Number(wRes.rows[0].balance) < numAmount) {
        throw new Error('MMK လက်ကျန်ငွေ မလုံလောက်ပါ။');
      }
      await client.query(`UPDATE wallets SET balance = balance - $1 WHERE id = $2`, [numAmount, wRes.rows[0].id]);
      const extTxId = await callExternalWalletPayout({
        channel,
        phone: String(targetPhone).trim(),
        amount: numAmount,
        refId
      });
      await client.query(
        `INSERT INTO transactions (sender_user_id, tx_type, currency, amount, note)
         VALUES ($1, 'DIRECT_TRANSFER_OUT', 'MMK', $2, $3)`,
        [userId, numAmount, `To ${channel} (${targetPhone}) • Tx: ${extTxId}`]
      );
      msg = `KhaoPay မှ ${channel} (${targetPhone}) သို့ ${numAmount.toLocaleString()} MMK တိုက်ရိုက်လွှဲပြီးပါပြီ။`;
    }

    await client.query('COMMIT');
    const state = await getFullUserState(client, userId);
    res.json({ success: true, message: msg, ...state });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/transfer', async (req, res) => {
  const { senderUserId, receiverCountryCode, receiverPhone, currency, amount, note, pin } = req.body;
  const numAmount = Number(amount);

  if (!['MMK', 'THB'].includes(currency) || !(numAmount > 0)) {
    return res.status(400).json({ success: false, message: 'ငွေကြေး သို့မဟုတ် ငွေပမာဏ မှားယွင်းနေပါသည်။' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sRes = await client.query('SELECT id, phone_e164, pin_hash, kyc_status FROM users WHERE id = $1', [senderUserId]);
    if (sRes.rows.length === 0) throw new Error('ပေးပို့သူ အကောင့် မတွေ့ပါ။');
    const sender = sRes.rows[0];

    if (sender.kyc_status !== 'VERIFIED') {
      throw new Error('ငွေလွှဲရန် မြန်မာမှတ်ပုံတင် (KYC) VERIFIED ဖြစ်ရပါမည်။');
    }
    const pinOk = await bcrypt.compare(String(pin || ''), sender.pin_hash);
    if (!pinOk) throw new Error('လုံခြုံရေး PIN မှားယွင်းနေပါသည်။');

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
    const state = await getFullUserState(client, senderUserId);
    res.json({ success: true, message: `${receiverE164} သို့ ${numAmount} ${currency} လွှဲပြီးပါပြီ။`, ...state });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.post('/api/swap', async (req, res) => {
  const { userId, pair, amount, pin } = req.body;
  const numAmount = Number(amount);

  if (!['MMK_TO_THB', 'THB_TO_MMK'].includes(pair) || !(numAmount > 0)) {
    return res.status(400).json({ success: false, message: 'ငွေလဲ အချက်အလက် မှားယွင်းနေပါသည်။' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const uRes = await client.query('SELECT id, pin_hash, kyc_status FROM users WHERE id = $1', [userId]);
    if (uRes.rows.length === 0) throw new Error('User မတွေ့ပါ။');
    const user = uRes.rows[0];
    if (user.kyc_status !== 'VERIFIED') {
      throw new Error('ငွေလဲရန် မြန်မာမှတ်ပုံတင် (KYC) VERIFIED ဖြစ်ရပါမည်။');
    }
    const pinOk = await bcrypt.compare(String(pin || ''), user.pin_hash);
    if (!pinOk) throw new Error('လုံခြုံရေး PIN မှားယွင်းနေပါသည်။');

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
    const state = await getFullUserState(client, userId);
    res.json({ success: true, message: msg, ...state });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/admin/pending-kyc', async (req, res) => {
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

app.post('/api/admin/kyc-review', async (req, res) => {
  const { userId, status, rejectReason } = req.body;
  if (!['VERIFIED', 'REJECTED'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Status မှားယွင်းနေပါသည်။' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE kyc_submissions SET status = $1, reject_reason = $2, reviewed_at = CURRENT_TIMESTAMP WHERE user_id = $3`,
      [status, status === 'REJECTED' ? (rejectReason || 'အချက်အလက် မကိုက်ညီပါ။') : null, userId]
    );
    await client.query(`UPDATE users SET kyc_status = $1 WHERE id = $2`, [status, userId]);
    await client.query('COMMIT');
    res.json({ success: true, message: `KYC ${status} ဖြစ်သွားပါပြီ။` });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(400).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`KhaoPay server running on port ${PORT}`));
