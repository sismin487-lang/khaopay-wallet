CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ၁။ အသုံးပြုသူ အကောင့်များ (ထိုင်း +66 နှင့် မြန်မာ +95 နှစ်မျိုးလုံး)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_e164 VARCHAR(20) UNIQUE NOT NULL,
    phone_country VARCHAR(5) NOT NULL CHECK (phone_country IN ('TH', 'MM')),
    pin_hash TEXT NOT NULL,
    kyc_status VARCHAR(20) NOT NULL DEFAULT 'UNVERIFIED' CHECK (kyc_status IN ('UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ၂။ မြန်မာမှတ်ပုံတင် (NRC) KYC စနစ် (ထိုင်းဆင်းကဒ်အကောင့်များလည်း သုံးနိုင်သည်)
CREATE TABLE IF NOT EXISTS kyc_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_e164 VARCHAR(20),
    id_type VARCHAR(30) NOT NULL DEFAULT 'MYANMAR_NRC',
    nrc_normalized VARCHAR(60) UNIQUE NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    front_image_url TEXT NOT NULL,
    back_image_url TEXT NOT NULL,
    selfie_image_url TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    reject_reason TEXT,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ၃။ MMK နှင့် THB Wallet လက်ကျန်ငွေများ
CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    currency VARCHAR(10) NOT NULL CHECK (currency IN ('MMK', 'THB')),
    balance NUMERIC(18, 2) NOT NULL DEFAULT 0.00 CHECK (balance >= 0),
    UNIQUE(user_id, currency)
);

-- ၄။ ငွေလွှဲ / ငွေသွင်း / ငွေထုတ် / ငွေလဲ မှတ်တမ်းများ
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    receiver_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    tx_type VARCHAR(30) NOT NULL,
    currency VARCHAR(10) NOT NULL CHECK (currency IN ('MMK', 'THB')),
    amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ၅။ KPay / WavePay / KBZ Bank Cash-In & Cash-Out တောင်းဆိုမှုများ
CREATE TABLE IF NOT EXISTS cash_requests (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_e164 VARCHAR(20) NOT NULL,
    req_type VARCHAR(20) NOT NULL CHECK (req_type IN ('CASH_IN', 'CASH_OUT')),
    channel VARCHAR(20) NOT NULL CHECK (channel IN ('KPAY', 'WAVEPAY', 'KBZ_BANK')),
    target_phone VARCHAR(20) NOT NULL,
    bank_account_no VARCHAR(40),
    bank_account_name VARCHAR(120),
    currency VARCHAR(10) NOT NULL DEFAULT 'MMK',
    amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
    tx_ref VARCHAR(120),
    slip_image_url TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    admin_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cash_requests_user_id ON cash_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_cash_requests_status ON cash_requests(status);
CREATE INDEX IF NOT EXISTS idx_cash_requests_phone ON cash_requests(phone_e164);
CREATE INDEX IF NOT EXISTS idx_cash_requests_channel ON cash_requests(channel);
CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender_user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_receiver ON transactions(receiver_user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at DESC);
