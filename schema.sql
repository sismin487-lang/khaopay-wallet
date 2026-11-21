CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ၁။ အသုံးပြုသူ အကောင့်များ (ထိုင်း +66 နှင့် မြန်မာ +95 နှစ်မျိုးလုံး)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_e164 VARCHAR(20) UNIQUE NOT NULL,
    phone_country VARCHAR(5) NOT NULL CHECK (phone_country IN ('TH', 'MM')),
    pin_hash TEXT NOT NULL,
    kyc_status VARCHAR(20) DEFAULT 'UNVERIFIED' CHECK (kyc_status IN ('UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ၂။ မြန်မာမှတ်ပုံတင် (NRC) KYC စနစ် (ထိုင်းဆင်းကဒ်အကောင့်များလည်း သုံးနိုင်သည်)
CREATE TABLE IF NOT EXISTS kyc_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    id_type VARCHAR(30) DEFAULT 'MYANMAR_NRC',
    nrc_normalized VARCHAR(60) UNIQUE NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    front_image_url TEXT NOT NULL,
    back_image_url TEXT NOT NULL,
    selfie_image_url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    reject_reason TEXT,
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ၃။ MMK နှင့် THB Wallet လက်ကျန်ငွေများ
CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    currency VARCHAR(10) NOT NULL CHECK (currency IN ('MMK', 'THB')),
    balance DECIMAL(18, 2) DEFAULT 0.00 CHECK (balance >= 0),
    UNIQUE(user_id, currency)
);

-- ၄။ ငွေလွှဲ / ငွေသွင်း / ငွေထုတ် / ငွေလဲ မှတ်တမ်းများ
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_user_id UUID REFERENCES users(id),
    receiver_user_id UUID REFERENCES users(id),
    tx_type VARCHAR(30) NOT NULL,
    currency VARCHAR(10) NOT NULL CHECK (currency IN ('MMK', 'THB')),
    amount DECIMAL(18, 2) NOT NULL CHECK (amount > 0),
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
