import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
import pg from "pg";
import { z } from "zod";

const { Pool } = pg;
const port = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET || !process.env.APP_URL) {
  throw new Error("DATABASE_URL, JWT_SECRET, and APP_URL are required");
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const emailSchema = z.string().trim().email().transform((value) => value.toLowerCase());
const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(200)
});
const inviteSchema = z.object({ email: emailSchema });
const registrationSchema = z.object({
  token: z.string().min(20).max(200),
  password: z.string().min(12).max(200)
});

function hashInvitationToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createInvitationToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id },
    process.env.JWT_SECRET,
    { algorithm: "HS256", expiresIn: "15m" }
  );
}

async function sendInvitationEmail({ recipient, registrationUrl, expiresAt }) {
  // Replace this adapter with SES, Resend, Postmark, or another provider.
  // Never log registrationUrl in production: it contains the raw token.
  if (process.env.NODE_ENV !== "production") {
    console.info(`Invitation created for ${recipient}; expires ${expiresAt.toISOString()}`);
  }
  void registrationUrl;
  console.warn("Email provider not configured; invitation delivery is disabled");
}

export function createApp({ db = pool, sendEmail = sendInvitationEmail } = {}) {
  const app = express();
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false
  });

  app.use(helmet());
  app.use(express.json({ limit: "16kb" }));

  function requireAuth(req, res, next) {
    const header = req.get("authorization");
    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Authentication required" });
    }

    try {
      req.auth = jwt.verify(header.slice(7), process.env.JWT_SECRET, {
        algorithms: ["HS256"]
      });
      next();
    } catch {
      return res.status(401).json({ error: "Invalid or expired access token" });
    }
  }

  async function requireCurrentBoss(req, res, next) {
    try {
      const result = await db.query(
        "SELECT id, email, role FROM users WHERE id = $1",
        [req.auth.sub]
      );
      const user = result.rows[0];

      if (!user) return res.status(401).json({ error: "User no longer exists" });
      if (user.role !== "boss") {
        return res.status(403).json({ error: "Only the boss can invite members" });
      }

      req.currentUser = user;
      next();
    } catch (error) {
      next(error);
    }
  }

  app.get("/health", (_req, res) => res.json({ ok: true }));

  app.post("/auth/login", authLimiter, async (req, res, next) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Invalid credentials" });

    try {
      const result = await db.query(
        "SELECT id, email, password_hash, role FROM users WHERE email = $1",
        [parsed.data.email]
      );
      const user = result.rows[0];
      const valid = user && await argon2.verify(user.password_hash, parsed.data.password);

      if (!valid) return res.status(401).json({ error: "Invalid credentials" });

      res.json({
        accessToken: signAccessToken(user),
        user: { id: user.id, email: user.email, role: user.role }
      });
    } catch (error) {
      next(error);
    }
  });

  // There is intentionally no public signup route. This is the only invitation-creation route.
  app.post("/admin/invitations", authLimiter, requireAuth, requireCurrentBoss, async (req, res, next) => {
    const parsed = inviteSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "A valid email is required" });

    const { email } = parsed.data;
    const rawToken = createInvitationToken();
    const tokenHash = hashInvitationToken(rawToken);
    const ttlHours = Number(process.env.INVITATION_TTL_HOURS || 24);
    const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000);
    const client = await db.connect();

    try {
      await client.query("BEGIN");

      const existingUser = await client.query("SELECT 1 FROM users WHERE email = $1", [email]);
      if (existingUser.rowCount) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "This email cannot be invited" });
      }

      await client.query(
        `UPDATE invitations
         SET revoked_at = now()
         WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL`,
        [email]
      );

      await client.query(
        `INSERT INTO invitations (email, token_hash, invited_by, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [email, tokenHash, req.currentUser.id, expiresAt]
      );

      await client.query("COMMIT");

      const registrationUrl = `${process.env.APP_URL}/register?token=${encodeURIComponent(rawToken)}`;
      await sendEmail({ recipient: email, registrationUrl, expiresAt });
      return res.status(201).json({ message: "Invitation sent" });
    } catch (error) {
      await client.query("ROLLBACK");
      next(error);
    } finally {
      client.release();
    }
  });

  // Registration is valid only with an unexpired, unrevoked, one-time invitation.
  app.post("/auth/register", authLimiter, async (req, res, next) => {
    const parsed = registrationSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "A valid invitation and password are required" });
    }

    const tokenHash = hashInvitationToken(parsed.data.token);
    const client = await db.connect();

    try {
      await client.query("BEGIN");
      const result = await client.query(
        `SELECT id, email, expires_at
         FROM invitations
         WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL
         FOR UPDATE`,
        [tokenHash]
      );
      const invitation = result.rows[0];

      if (!invitation || new Date(invitation.expires_at) <= new Date()) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "Invalid or expired invitation" });
      }

      const passwordHash = await argon2.hash(parsed.data.password, { type: argon2.argon2id });
      const userResult = await client.query(
        `INSERT INTO users (email, password_hash, role)
         VALUES ($1, $2, 'member')
         RETURNING id, email, role`,
        [invitation.email, passwordHash]
      );

      await client.query("UPDATE invitations SET accepted_at = now() WHERE id = $1", [invitation.id]);
      await client.query("COMMIT");

      return res.status(201).json({ user: userResult.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") {
        return res.status(400).json({ error: "This invitation can no longer be used" });
      }
      next(error);
    } finally {
      client.release();
    }
  });

  app.use((error, _req, res, _next) => {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}

export { pool };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = createApp();
  app.listen(port, () => console.log(`Invitation auth API listening on port ${port}`));
}
