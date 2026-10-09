-- Multi-company (SaaS): every user and group belongs to exactly one company, and people can
-- only communicate inside their own company. Companies subscribe to a plan (seat limit) and
-- pay through Chapa, or are approved by a platform admin.

CREATE TABLE IF NOT EXISTS plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    max_users INTEGER CHECK (max_users IS NULL OR max_users > 0), -- NULL = unlimited
    price_monthly NUMERIC(12, 2) NOT NULL CHECK (price_monthly >= 0),
    price_yearly NUMERIC(12, 2) NOT NULL CHECK (price_yearly >= 0),
    currency VARCHAR(3) NOT NULL DEFAULT 'ETB',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Starting prices; platform admins change them in the admin console.
INSERT INTO plans (code, name, description, max_users, price_monthly, price_yearly, sort_order) VALUES
    ('starter', 'Starter', 'For small teams getting started', 10, 1500, 15000, 1),
    ('business', 'Business', 'For growing companies', 50, 6000, 60000, 2),
    ('enterprise', 'Enterprise', 'Unlimited members', NULL, 20000, 200000, 3)
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS companies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(150) NOT NULL,
    slug VARCHAR(60) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending_payment'
        CHECK (status IN ('pending_payment', 'pending_approval', 'active', 'suspended', 'expired', 'rejected')),
    plan_id UUID REFERENCES plans(id),
    billing_cycle VARCHAR(10) NOT NULL DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'yearly')),
    contact_email VARCHAR(255) NOT NULL,
    contact_phone VARCHAR(30),
    current_period_end TIMESTAMP, -- NULL: no expiry (e.g. the platform's own company)
    approved_at TIMESTAMP,
    approved_by UUID REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_companies_status ON companies(status);

-- Existing data becomes the first company.
INSERT INTO companies (name, slug, status, plan_id, contact_email, approved_at)
SELECT 'BinTalk', 'default', 'active', (SELECT id FROM plans WHERE code = 'enterprise'),
       COALESCE((SELECT email FROM users WHERE role = 'admin' AND deleted_at IS NULL ORDER BY created_at LIMIT 1),
                'admin@bintalk.local'),
       CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM companies WHERE slug = 'default');

ALTER TABLE users ADD COLUMN IF NOT EXISTS company_id UUID REFERENCES companies(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS company_role VARCHAR(20) NOT NULL DEFAULT 'member'
    CHECK (company_role IN ('owner', 'admin', 'member'));
UPDATE users SET company_id = (SELECT id FROM companies WHERE slug = 'default') WHERE company_id IS NULL;
UPDATE users SET company_role = 'owner' WHERE role = 'admin';
ALTER TABLE users ALTER COLUMN company_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);

ALTER TABLE groups ADD COLUMN IF NOT EXISTS company_id UUID REFERENCES companies(id);
UPDATE groups g SET company_id = u.company_id FROM users u WHERE u.id = g.owner_id AND g.company_id IS NULL;
UPDATE groups SET company_id = (SELECT id FROM companies WHERE slug = 'default') WHERE company_id IS NULL;
ALTER TABLE groups ALTER COLUMN company_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_groups_company_type ON groups(company_id, group_type);

CREATE TABLE IF NOT EXISTS payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id),
    plan_id UUID NOT NULL REFERENCES plans(id),
    billing_cycle VARCHAR(10) NOT NULL CHECK (billing_cycle IN ('monthly', 'yearly')),
    tx_ref VARCHAR(100) UNIQUE NOT NULL,
    amount NUMERIC(12, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'success', 'failed')),
    provider VARCHAR(20) NOT NULL DEFAULT 'chapa',
    provider_reference VARCHAR(100),
    checkout_url TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payments_company ON payments(company_id, created_at DESC);

CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id),
    email VARCHAR(255) NOT NULL,
    company_role VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (company_role IN ('admin', 'member')),
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    invited_by UUID REFERENCES users(id),
    expires_at TIMESTAMP NOT NULL,
    accepted_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_invitations_company ON invitations(company_id, created_at DESC);
-- One open invitation per address and company.
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_open
    ON invitations(company_id, lower(email)) WHERE accepted_at IS NULL AND revoked_at IS NULL;
