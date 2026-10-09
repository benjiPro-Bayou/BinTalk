# BinTalk - Enterprise Communication Platform

**BinTalk** is a multi-company (SaaS) team chat in the spirit of Slack. Companies subscribe from
the landing page and pay with **Chapa** (Telebirr, CBE Birr, cards), or are approved by a platform
admin. Each company gets its own isolated workspace: its people can only see and talk to colleagues
from the same company.

Inside a workspace: **channels** (#, open to the whole company), private **groups** (🔒, members
only) and **direct messages**, with threads, @mentions, read receipts, presence, encrypted file
sharing, voice/video calls, and an admin console.

### How it works

| Who | What they do |
|-----|--------------|
| **Platform admin** (runs BinTalk) | Approves, suspends and extends companies, registers companies directly, edits plans and prices, sees payments. |
| **Company owner / admin** | Invites colleagues by email, manages members and roles, handles abuse reports, renews or changes the plan. |
| **Member** | Chats in channels, groups and DMs with people of their own company. |

1. A company signs up on the landing page (company name, plan, owner account) and is sent to
   Chapa's checkout. When Chapa confirms the payment, the workspace becomes **active** (or waits
   for a platform admin when `COMPANY_REQUIRE_APPROVAL=true`). Without `CHAPA_SECRET_KEY`, every
   new company waits for a platform admin's approval.
2. The owner invites colleagues (**Admin → Invitations**). Each invitation link works once, for one
   email address, for 7 days, and counts toward the plan's seat limit.
3. Subscriptions run monthly or yearly. When the paid period plus a grace period
   (`SUBSCRIPTION_GRACE_DAYS`, default 3) ends, the workspace expires and its members are signed
   out until the owner renews (in the admin console, or with *Renew / complete payment* on the
   landing page).

## Architecture

### Tech Stack
- **Backend**: Go with the Gin framework (a modular monolith)
- **Client**: plain HTML/CSS/JS web app in [`web/`](web/), served by Nginx
- **Database**: PostgreSQL
- **Sessions, rate limits**: Redis (opaque access tokens; not JWTs)
- **Events**: Kafka producer (no consumer ships with BinTalk yet)
- **Keys**: HashiCorp Vault (Transit + KV)
- **Gateway**: Nginx (TLS 1.2/1.3)
- **Containers**: Docker Compose

### What is implemented

| Area | Status |
|------|--------|
| Encryption **at rest** (messages, phone numbers, files): AES-256-GCM data keys wrapped by Vault Transit, rotated every 90 days | ✅ |
| End-to-end encryption | ❌ The server can read message content; it encrypts it before storing it. |
| Real-time delivery (WebSocket), presence, read receipts, threads, mentions | ✅ |
| Voice/video calls (WebRTC, peer-to-peer; small groups) | ✅ |
| Rate limiting (per client IP, and per account for failed sign-ins) | ✅ |
| Audit log of admin and password events | ✅ (message and file activity is not audited) |
| Companies with isolated workspaces, plans with seat limits, Chapa payments, approval by platform admins | ✅ |
| Joining a company by email invitation only | ✅ |
| Uploaded file virus scanning | ❌ Files are **not scanned**; downloads are sent as attachments with `nosniff`. |
| MFA, SSO, message search, data retention/export, account deletion | ❌ Planned |
| Mobile app | ❌ Not supported (an unbuildable React Native scaffold is kept in [`archive/`](archive/)) |
| More than one API instance | ❌ Run **one** API instance: WebSockets, calls and uploads are held by that process. |

---

## Quick Start (Development)

### Prerequisites
- Docker & Docker Compose v2.24+
- Go 1.27+ (only to build or test the backend outside Docker)
- OpenSSL (for certificate generation)

### 1. Generate TLS Certificates

```bash
cd BinTalk

# Generate self-signed certificates for development
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost"

# Generate client certificate (optional for mTLS)
openssl genrsa -out certs/client.key 4096
openssl req -new \
  -key certs/client.key \
  -out certs/client.csr \
  -subj "/C=US/ST=State/L=City/O=BinTalk/CN=bintalk-client"

openssl x509 -req -days 365 \
  -in certs/client.csr \
  -CA certs/server.crt \
  -CAkey certs/server.key \
  -CAcreateserial \
  -out certs/client.crt
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Required: set DB_PASSWORD and REDIS_PASSWORD (any long random strings), and
# BOOTSTRAP_ADMIN_PASSWORD for the first platform admin. For online payments also set
# CHAPA_SECRET_KEY (see "Payments with Chapa"). For example:
#   openssl rand -base64 24
# vi .env
```

### 3. Start All Services

```bash
# Build and start containers
docker compose up -d

# Verify services are running
docker compose ps

# Check service health
curl -s http://localhost:8200/v1/sys/health | jq .
curl -sk https://localhost/health | jq .
```

### 4. Vault & Encryption Keys

Nothing to set up: Vault runs with **persistent file storage** and is initialized and unsealed
automatically by [`vault/bootstrap.sh`](vault/bootstrap.sh). It also issues the API's Vault token,
limited to the `bintalk-api` policy ([`vault/policy.hcl`](vault/policy.hcl)), and shares it with the
API through a Docker volume; the API renews it. The API creates any missing keys.

How messages stay readable:

- Message text, phone numbers and files are encrypted with versioned AES-256-GCM **data keys**.
  Every message/file records which key version encrypted it.
- Each data key is stored in Postgres *wrapped* (encrypted) by the Vault Transit key
  `database-encryption`. Vault keeps every Transit key version, so rotating keys never makes
  existing data unreadable.
- A new data key version is created automatically every `KEY_ROTATION_INTERVAL` days (default 90).

Rotate keys on demand (Transit key + new data key; old messages stay readable):

```bash
docker exec bintalk_api_server ./api-server rotate-keys
```

For admins, the Status button in the web app shows Vault's storage type and all data key versions.

> **Back up the `bintalk_vault_data` volume.** It holds the keys. If it is lost, encrypted
> messages and files cannot be recovered. `docker-compose down -v` deletes it.
>
> **Development only:** the unseal key and root token are kept in the `bintalk_vault_keys` volume
> so Vault can unseal itself. Production should use Vault auto-unseal (cloud KMS/HSM). Earlier
> versions gave the API the root token `ROOT_TOKEN_DEV_ONLY`; the bootstrap now revokes it.

### 5. Use the Web App

Open **https://localhost** in your browser. The certificate is self-signed, so accept the
browser warning once (Chrome: *Advanced → Proceed to localhost*).

To try it with two people, create two accounts and use a normal window for one and a
private/incognito window for the other. The web app supports:

- Creating an account, signing in and out (the session survives page reloads)
- Searching people and direct messaging, with new messages arriving live over WebSocket
- Groups: create a group, add members, group chat
- Sending files (📎) and downloading them; files are encrypted on the server
- **Unread** badges per chat (an orange **@** when you were mentioned), the unread total in the tab
  title, and a "New messages" divider when you open a chat
- **@mentions**: type `@` for suggestions; mentions of you are highlighted
- **Threads** in groups: right-click a message (or ⋯) → *Reply in thread*; replies can have attachments
- **Attachment notes**: attach a file, then type a note before sending; edit it later via right-click
- **Audio & video players**: audio and video attachments play inline (up to 50 MB; files over 8 MB
  load when you press ▶ Play)
- **Read receipts**: ✓ sent, ✓✓ read (a message counts as read once it was on screen in a visible
  tab); in groups right-click your message → *Read by…*
- **Status** button: encryption status (Vault details for admins)

The web app is plain HTML/CSS/JS in [`web/`](web/), served by Nginx. Edits show up on a page reload,
no build step or container restart needed.

### Admin console

If no platform admin exists, one is created on startup for `BOOTSTRAP_ADMIN_EMAIL` (default
`admin@bintalk.local`) with the `BOOTSTRAP_ADMIN_PASSWORD` from `.env`, which must be changed at
first sign-in. It belongs to the built-in company "BinTalk", which also holds all data from before
companies existed. An account that someone already registered with that email is **not** promoted
automatically. To make an existing account a platform admin:

```bash
docker exec bintalk_api_server ./api-server make-admin someone@example.com
```

Company owners and admins, and platform admins, get an **Admin** button in the top bar:

- **Members**: suspend/reactivate, make admin/member, **reset password** (a one-time temporary
  password; the person must choose a new one at their next sign-in). The owner cannot be changed
  by company admins.
- **Invitations**: invite people by email; the link is emailed and can also be copied.
- **Billing**: plan, seats used, paid-until date, payment history, and *Pay with Chapa* to renew or
  change plans.
- **Reports**: messages people reported (right-click a message → *Report…*). Resolve with
  *Delete the message* and/or *Suspend* the sender, or dismiss.
- **Overview** and **Activity log**.

Platform admins also see **Companies** (approve, reject, suspend, extend by a month or a year,
change plan, register a company directly), **Plans** (prices in ETB, seat limits, which plans the
landing page offers), **Payments** and **All users**.

### Payments with Chapa

1. Create an account at <https://dashboard.chapa.co> and copy the secret key (test keys start with
   `CHASECK_TEST-`) into `CHAPA_SECRET_KEY` in `.env`.
2. Set `APP_BASE_URL` to the public address of BinTalk (Chapa sends customers back to
   `<APP_BASE_URL>/#payment=…` and calls `<APP_BASE_URL>/api/v1/public/payments/chapa/callback`).
3. Optional: in Chapa's dashboard, add the webhook URL
   `<APP_BASE_URL>/api/v1/public/payments/chapa/webhook` with a secret, and set the same secret
   in `CHAPA_WEBHOOK_SECRET`.
4. `docker compose up -d api-server`.

BinTalk never trusts a callback, webhook or redirect by itself: it always asks Chapa's verify API
whether the transaction succeeded, for the expected amount and currency, before activating a
company.

### Passwords

- **Forgot password?** on the sign-in screen emails a single-use link valid for 30 minutes.
- **Email delivery:** BinTalk runs its **own mail server** (the `postfix` container: Postfix + DKIM
  signing) that delivers directly to each recipient's mail server. No Gmail or third-party account
  is involved. A copy of every email lands in **Mailpit** (<http://localhost:8025>) so you can always
  see what was sent.

  ```bash
  docker exec bintalk_api_server ./api-server send-test-email you@example.com
  docker logs bintalk_postfix 2>&1 | grep status=     # the recipient server's verdict
  ```

  For Gmail/Outlook to **accept** mail from a self-hosted server you need:
  1. A domain you control: set `MAIL_DOMAIN` (and `MAIL_HOSTNAME`) in `.env`, then
     `docker compose up -d postfix api-server`.
  2. The DNS records printed by `./scripts/mail-dns-records.sh` (A, SPF, DKIM, DMARC).
  3. A static public IP with a reverse DNS (PTR) record matching `MAIL_HOSTNAME`, that is not on
     residential blocklists (Spamhaus PBL) and may send on port 25. Home/mobile connections usually
     do not qualify; run the stack on a VPS or server with a business IP.

  Alternatively, set `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASSWORD`/`SMTP_FROM` in `.env` to use
  an external SMTP provider. The admin console's Overview shows where email is going.
- **Change password** is in the ⚙ account menu (signs out your other devices).
- Passwords are stored as bcrypt hashes, so nobody (including admins) can see them; admins can only reset them.

### 6. Test the API

```bash
# Automated end-to-end check of the whole API (prints PASS/FAIL per check). It creates
# accounts and temporarily grants admin rights, so only run it against a disposable stack.
BINTALK_DISPOSABLE=1 ./scripts/smoke-test.sh

# Health check (no login needed)
curl -k https://localhost/health

# Register (all four fields are required)
curl -k -X POST https://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "full_name": "Test User"
  }'

# Log in and keep the access token (valid for 15 minutes)
TOKEN=$(curl -sk -X POST https://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecurePassword123!"}' | jq -r .token)

# Endpoints under /api/v1 (except register, login, refresh and public-key) need the token
curl -k https://localhost/api/v1/encryption/status -H "Authorization: Bearer $TOKEN"
```

### 7. Access Services

Only the gateway (80/443) is reachable from other machines; the others listen on 127.0.0.1.

| Service | URL | Credentials |
|---------|-----|-------------|
| Web App | https://localhost | Create an account, or the bootstrap admin (see Admin console) |
| API Gateway | https://localhost/api/v1 | Bearer token from `/auth/login` |
| Vault UI | http://localhost:8200 | Root token: `docker exec bintalk_vault cat /vault/keys/init.json` |
| Mailpit (dev email inbox) | http://localhost:8025 | None |
| PostgreSQL | localhost:5432 | `bintalk` / `DB_PASSWORD` from `.env` |
| Redis | localhost:6379 | `REDIS_PASSWORD` from `.env` |

The API server itself is not published; it is reached through the gateway, which sets the client
IP the API uses for rate limits and audit entries.

---

## Project Structure

```
BinTalk/
├── backend/
│   ├── cmd/api-server/        # Server entry point and CLI commands (rotate-keys, make-admin, ...)
│   ├── internal/
│   │   ├── config/            # Configuration (validated at startup)
│   │   ├── handlers/          # HTTP/WebSocket handlers, calls, presence
│   │   ├── middleware/        # Authentication, header encryption, limits, logging
│   │   ├── models/            # Data structures
│   │   └── services/          # Encryption service
│   ├── pkg/                   # PostgreSQL, Redis, Kafka, Vault and SMTP clients
│   ├── migrations/            # Numbered schema migrations (init.sql is the base schema)
│   ├── go.mod                 # Go dependencies
│   └── Dockerfile             # Docker image (runs as a non-root user)
│
├── web/                       # Browser client (served by Nginx at https://localhost)
├── scripts/                   # smoke-test.sh (end-to-end API test), mail DNS helper
├── nginx/                     # Gateway configuration and shared security headers
├── vault/                     # Vault config, bootstrap and the bintalk-api policy
├── mail/                      # Local Postfix + DKIM mail server
├── archive/                   # Unused files kept for reference (mobile scaffold, old nginx.conf)
├── certs/                     # TLS certificates (not committed)
│
├── docker-compose.yml         # Development stack
├── docker-compose.prod.yml    # Production overrides (publishes only the gateway)
├── .env.example               # Environment template
├── .gitignore                 # Git ignore rules
├── README.md                  # This file
└── DEPLOYMENT.md              # Production deployment guide
```

---

## API Documentation

### Authentication Endpoints

#### Register
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "invite_token": "<token from the invitation link>",
  "username": "user123",
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "User One"
}
```

Accounts are only created from an invitation (the email must match it), or as the owner of a new
company with `POST /api/v1/public/signup`. Usernames are 3-50 letters, digits, `_`, `.` or `-`,
unique regardless of case.

#### Companies and payments (no sign-in needed)
```http
GET  /api/v1/public/plans
POST /api/v1/public/signup             {company_name, plan_code, billing_cycle, full_name, username, email, password, phone?}
POST /api/v1/public/checkout           {email, password, plan_code?, billing_cycle?}   (owners: finish or renew)
GET  /api/v1/public/payments/{tx_ref}  (verifies with Chapa while pending)
GET  /api/v1/public/invitations/{token}
```

#### Channels and groups
```http
GET  /api/v1/channels                  (all channels of your company, with is_member)
POST /api/v1/groups                    {name, description, group_type: "channel" | "team"}
POST /api/v1/groups/{id}/join          (channels only)
POST /api/v1/groups/{id}/leave
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}

Response:
{
  "token": "<opaque access token, valid SESSION_TTL seconds>",
  "refresh_token": "<single-use refresh token>",
  "user": { "id": "uuid", "email": "user@example.com", ... }
}
```

After repeated failed sign-ins for an account, sign-in is refused with `429` for 15 minutes.

### Message Endpoints

#### Send Message
```http
POST /api/v1/messages
Authorization: Bearer <token>
Content-Type: application/json

{
  "receiver_id": "uuid",
  "content": "Hello!",
  "message_type": "text",
  "client_id": "uuid generated once per message"
}
```

`client_id` is optional; when a send is retried with the same `client_id`, the original message is
returned (`200`, `"duplicate": true`) instead of being sent twice. `message_type` is `text`, `file`,
`image`, `video` or `voice` (`system` messages are created by the server only).

#### Get Messages
```http
GET /api/v1/messages/{conversationId}
Authorization: Bearer <token>
```

Fetching has no side effects. Acknowledge what was displayed, which sends read receipts:

```http
POST /api/v1/messages/{conversationId}/read          {"up_to": "<newest message id shown>"}
POST /api/v1/messages/{parentMessageId}/thread/read  {"up_to": "<newest reply id shown>"}
```

#### Real-time events (WebSocket)
```http
POST /api/v1/ws-ticket            → {"ticket": "...", "expires_in": 30}
GET  /ws/chat/{userId}?ticket=... (WebSocket upgrade)
```

The ticket works once, within 30 seconds, so access tokens never appear in URLs or logs.
Non-browser clients may instead send `Authorization: Bearer <token>` on the upgrade request. The
socket closes when its session expires or is revoked (sign-out, password change, suspension).

### Group Endpoints

#### Create Group
```http
POST /api/v1/groups
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Marketing Team",
  "description": "Team for marketing campaigns",
  "group_type": "team"
}
```

#### Get Group
```http
GET /api/v1/groups/{groupId}
Authorization: Bearer <token>
```

---

## Security Features

### Encryption
- **Transport**: TLS 1.2/1.3 at the gateway; TLS 1.3 between the gateway and the API
- **At rest**: message content, phone numbers and files are encrypted with AES-256-GCM data keys
  wrapped by Vault Transit. The server decrypts them to serve them: this is **not** end-to-end
  encryption.
- **Optional header/response encryption**: RSA-OAEP-SHA256 (only `Authorization` may be sent
  encrypted) and AES-256-GCM responses
- **Keys**: Vault-managed, with automatic data key rotation

### Authentication
- **Access tokens**: opaque random tokens stored hashed in Redis (`SESSION_TTL`, default 15 minutes)
- **Refresh tokens**: single-use, stored hashed (`SESSION_REFRESH_TTL`, default 24 hours)
- **Revocation**: changing or resetting a password, or suspending an account, ends every session
  and WebSocket of that user, including sessions issued at the same moment
- **Passwords**: bcrypt; failed sign-ins are throttled per account
- **MFA**: not implemented

### Protection
- **Rate limiting**: per client IP (Nginx and the API) and per account for sign-ins
- **Request limits**: JSON bodies 1 MB (`MAX_JSON_BODY_SIZE`), uploads `MAX_REQUEST_SIZE`, storage
  quota per user (`STORAGE_QUOTA_PER_USER`, default 5 GB), WebSocket connections and frame rate
- **Client IP**: taken from the gateway only (`TRUSTED_PROXIES`)
- **CSRF**: not applicable (bearer tokens, no cookies)
- **SQL injection**: parameterized queries
- **XSS**: strict Content-Security-Policy; the web client never builds HTML from strings

### Not provided
- Virus scanning of uploads
- Data retention policies, export and account deletion
- Auditing of message and file activity

---

## Key Rotation & Maintenance

### Automatic Key Rotation
A new data key version is created every `KEY_ROTATION_INTERVAL` days (default 90). To rotate now:

```bash
docker exec bintalk_api_server ./api-server rotate-keys
```

Admins see the key versions with the Status button, or at `GET /api/v1/admin/encryption/status`.

---

## Monitoring & Logs

### View Service Logs
```bash
# API Server logs (LOG_LEVEL: debug, info, warn, error)
docker compose logs -f api-server

# Vault logs
docker compose logs -f vault

# Nginx logs
docker compose logs -f api-gateway

# All logs
docker compose logs -f
```

### Health Checks
```bash
# Liveness (through the gateway)
curl -k https://localhost/health

# Readiness: database, Redis and encryption keys (inside the API container; also its healthcheck)
docker exec bintalk_api_server wget -qO- --no-check-certificate https://127.0.0.1:8000/ready

# Individual services
docker compose exec postgres pg_isready
docker compose exec redis redis-cli ping
docker compose exec kafka kafka-broker-api-versions
```

---

## Development

### Running Tests
```bash
cd backend

# Unit tests (CI also runs them with -race, plus golangci-lint and govulncheck)
go test ./...
go test -race ./...

# Known vulnerabilities in dependencies
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Specific test
go test -run TestEncryption ./...
```

### Building Backend
```bash
cd backend

# Build binary
go build -o api-server ./cmd/api-server

# Run locally (requires database)
./api-server
```

---

## Troubleshooting

### Common Issues

#### "Connection refused" error
```bash
# Check if services are running
docker compose ps

# Start services if needed
docker compose up -d
```

#### "Certificate verification failed"
```bash
# Use -k flag to skip verification in development
curl -k https://localhost/health

# For production, use valid certificates
```

#### "Vault unreachable"
```bash
# Check Vault is running and healthy
docker compose exec vault vault status

# Restart Vault
docker compose restart vault
```

#### "Database connection error"
```bash
# Check PostgreSQL is running
docker compose exec postgres pg_isready

# View database logs
docker compose logs postgres
```

---

## Production Deployment

For production deployment, see [DEPLOYMENT.md](./DEPLOYMENT.md)

Key considerations:
- Start with `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`, which publishes
  only the gateway
- Run a **single** API instance
- Valid CA-signed TLS certificates
- Back up PostgreSQL, Vault storage and the uploads volume **together**, and test restores
- Vault auto-unseal instead of the development unseal key

---

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## License

This project is proprietary and confidential. Unauthorized copying is prohibited.

---

## Support

For issues and support:
- Email: support@bintalk.com
- Documentation: https://docs.bintalk.com
- Issue Tracker: https://github.com/bintalk/bintalk-clone/issues

---

## Changelog

### Unreleased
- Multi-company SaaS: landing page with plans, company sign-up with Chapa payments, platform and
  company admin roles, invitations, seat limits, subscription expiry, and isolation between
  companies (search, profiles, messages, calls, groups, presence)
- Slack-style workspace: channels, private groups and direct messages in separate sidebar sections
  with icons, channel browser, grouped message rows, redesigned admin console
- Security and reliability fixes from the October 2026 codebase audit: crash fix for concurrent
  calls, scoped Vault token, loopback-only development ports, session revocation that also closes
  WebSockets, WebSocket tickets, trusted client IPs, dependency and base image upgrades, explicit
  read acknowledgements, idempotent sends, graceful shutdown and readiness checks

### v1.0.0 (2026-10-07)
- Initial release
- Direct and group messaging, threads, mentions, read receipts
- Encrypted file sharing (encryption at rest)
- Vault integration
- WebSocket real-time features

---

**BinTalk** - Enterprise Communication, Reimagined
