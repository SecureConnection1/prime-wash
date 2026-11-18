# Prime Wash invitation-only registration

A minimal Node.js + Express + PostgreSQL authentication service where only a database-verified `boss` can invite members. There is no public signup route.

## Setup

```bash
npm install
cp .env.example .env
# Set DATABASE_URL, JWT_SECRET, and APP_URL in .env
psql "$DATABASE_URL" -f sql/schema.sql
```

Create the initial boss account once from a trusted administration environment:

```bash
npm run seed:boss
```

The seed script refuses to overwrite an existing account and hashes passwords with Argon2id. Do not pass passwords on the command line in production; use a secret manager or hidden prompt.

Start the service:

```bash
npm start
```

## Flow

1. The boss logs in at `POST /auth/login` and receives a short-lived access token.
2. The boss calls `POST /admin/invitations` with `Authorization: Bearer <token>` and `{ "email": "member@example.com" }`.
3. The service generates a 256-bit random invitation token, stores only its SHA-256 hash, and expires it after `INVITATION_TTL_HOURS`.
4. Replace `sendInvitationEmail` in `src/server.js` with your email provider. The raw registration URL is passed to that adapter and is never stored.
5. The invited person submits the token and a password to `POST /auth/register`. Registration always creates a `member` role, marks the invitation used in the same transaction, and rejects expired, revoked, or reused invitations.

Example login:

```bash
curl -s http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"boss@example.com","password":"a-strong-password"}'
```

Example boss-only invite:

```bash
curl -s http://localhost:3000/admin/invitations \
  -H "authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"email":"member@example.com"}'
```

Example registration request:

```bash
curl -s http://localhost:3000/auth/register \
  -H 'content-type: application/json' \
  -d '{"token":"token-from-email","password":"a-strong-member-password"}'
```

## Security notes

- Authorization is checked server-side against the current database role, not only the JWT claim.
- Invitation token hashes, not raw tokens, are stored.
- Registration uses `SELECT ... FOR UPDATE` and a transaction to prevent concurrent token reuse.
- User emails are unique and registration never accepts a caller-supplied role.
- Put the API behind HTTPS, configure a real email provider, add audit logging, and use secure HttpOnly cookies instead of bearer tokens when appropriate for your client.
