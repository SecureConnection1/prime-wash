import assert from "node:assert/strict";
import { test } from "node:test";
import supertest from "supertest";

process.env.DATABASE_URL ||= "postgres://test:test@localhost/test";
process.env.JWT_SECRET ||= "test-secret-that-is-long-enough";
process.env.APP_URL ||= "http://localhost:3000";
process.env.INVITATION_TTL_HOURS = "24";

const { createApp } = await import("../src/server.js");

function fixture({ role = "boss" } = {}) {
  const state = {
    role,
    invitation: null,
    accepted: false,
    insertedUser: null,
    sentEmail: null,
    commits: 0,
    rollbacks: 0
  };

  const client = {
    async query(sql, params = []) {
      if (sql === "BEGIN") return;
      if (sql === "COMMIT") {
        state.commits += 1;
        return;
      }
      if (sql === "ROLLBACK") {
        state.rollbacks += 1;
        return;
      }
      if (sql.includes("SELECT 1 FROM users")) return { rowCount: 0, rows: [] };
      if (sql.includes("SET revoked_at")) return { rowCount: 0, rows: [] };
      if (sql.includes("INSERT INTO invitations")) {
        state.invitation = {
          id: "invite-1",
          email: params[0],
          tokenHash: params[1],
          expiresAt: params[3],
          acceptedAt: false,
          revokedAt: false
        };
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes("FROM invitations") && sql.includes("FOR UPDATE")) {
        const invitation = state.invitation;
        if (!invitation || invitation.acceptedAt || invitation.revokedAt) {
          return { rowCount: 0, rows: [] };
        }
        return {
          rowCount: 1,
          rows: [{
            id: invitation.id,
            email: invitation.email,
            expires_at: invitation.expiresAt
          }]
        };
      }
      if (sql.includes("INSERT INTO users")) {
        state.insertedUser = { id: "member-1", email: params[0], role: "member" };
        return { rowCount: 1, rows: [state.insertedUser] };
      }
      if (sql.includes("UPDATE invitations SET accepted_at")) {
        state.accepted = true;
        state.invitation.acceptedAt = true;
        return { rowCount: 1, rows: [] };
      }
      throw new Error(`Unhandled client query: ${sql}`);
    },
    release() {}
  };

  const db = {
    async query(sql) {
      if (sql.includes("SELECT id, email, role FROM users")) {
        return {
          rowCount: 1,
          rows: [{ id: "boss-1", email: "boss@example.com", role: state.role }]
        };
      }
      throw new Error(`Unhandled pool query: ${sql}`);
    },
    async connect() {
      return client;
    }
  };

  const app = createApp({
    db,
    sendEmail: async (message) => {
      state.sentEmail = message;
    }
  });

  return { app, state };
}

test("rejects invitation creation by a non-boss", async () => {
  const { app } = fixture({ role: "member" });
  const jwt = (await import("jsonwebtoken")).default;
  const accessToken = jwt.sign({ sub: "member-1" }, process.env.JWT_SECRET, { expiresIn: "15m" });
  const response = await supertest(app)
    .post("/admin/invitations")
    .set("Authorization", `Bearer ${accessToken}`)
    .send({ email: "new@example.com" });

  assert.equal(response.status, 403);
  assert.equal(response.body.error, "Only the boss can invite members");
});

test("boss can create an invitation and receives no raw token in the response", async () => {
  const { app, state } = fixture();
  const jwt = (await import("jsonwebtoken")).default;
  const accessToken = jwt.sign({ sub: "boss-1" }, process.env.JWT_SECRET, { expiresIn: "15m" });

  const response = await supertest(app)
    .post("/admin/invitations")
    .set("Authorization", `Bearer ${accessToken}`)
    .send({ email: "member@example.com" });

  assert.equal(response.status, 201);
  assert.deepEqual(response.body, { message: "Invitation sent" });
  assert.match(state.sentEmail.registrationUrl, /\/register\?token=/);
  assert.equal(state.commits, 1);
});

test("valid invitation creates a member account and consumes the invitation", async () => {
  const { app, state } = fixture();
  const jwt = (await import("jsonwebtoken")).default;
  const accessToken = jwt.sign({ sub: "boss-1" }, process.env.JWT_SECRET, { expiresIn: "15m" });

  await supertest(app)
    .post("/admin/invitations")
    .set("Authorization", `Bearer ${accessToken}`)
    .send({ email: "member@example.com" });

  const token = new URL(state.sentEmail.registrationUrl).searchParams.get("token");
  const response = await supertest(app)
    .post("/auth/register")
    .send({ token, password: "a-strong-member-password" });

  assert.equal(response.status, 201);
  assert.equal(response.body.user.role, "member");
  assert.equal(response.body.user.email, "member@example.com");
  assert.equal(state.accepted, true);
});

test("reused invitation is rejected", async () => {
  const { app, state } = fixture();
  const jwt = (await import("jsonwebtoken")).default;
  const accessToken = jwt.sign({ sub: "boss-1" }, process.env.JWT_SECRET, { expiresIn: "15m" });

  await supertest(app)
    .post("/admin/invitations")
    .set("Authorization", `Bearer ${accessToken}`)
    .send({ email: "member@example.com" });

  const token = new URL(state.sentEmail.registrationUrl).searchParams.get("token");
  const payload = { token, password: "a-strong-member-password" };
  const first = await supertest(app).post("/auth/register").send(payload);
  const second = await supertest(app).post("/auth/register").send(payload);

  assert.equal(first.status, 201);
  assert.equal(second.status, 400);
  assert.equal(second.body.error, "Invalid or expired invitation");
});

test("registration without an invitation is rejected", async () => {
  const { app } = fixture();
  const response = await supertest(app)
    .post("/auth/register")
    .send({ token: "not-a-real-invitation-token", password: "a-strong-member-password" });

  assert.equal(response.status, 400);
  assert.equal(response.body.error, "Invalid or expired invitation");
});
