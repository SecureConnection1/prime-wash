import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import argon2 from "argon2";
import pg from "pg";

const { Pool } = pg;

const rl = readline.createInterface({ input, output });
const email = (process.env.BOSS_EMAIL || await rl.question("Boss email: ")).trim().toLowerCase();
const password = process.env.BOSS_PASSWORD || await rl.question("Boss password (use a secret manager in production): ");
rl.close();

if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error("Invalid email");
if (password.length < 12) throw new Error("Password must be at least 12 characters");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const client = await pool.connect();

try {
  await client.query("BEGIN");
  const existing = await client.query("SELECT 1 FROM users WHERE email = $1 FOR UPDATE", [email]);
  if (existing.rowCount) throw new Error("User already exists; no changes made");

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  const result = await client.query(
    `INSERT INTO users (email, password_hash, role)
     VALUES ($1, $2, 'boss')
     RETURNING id, email, role`,
    [email, passwordHash]
  );
  await client.query("COMMIT");
  console.log("Boss account created:", result.rows[0]);
} catch (error) {
  await client.query("ROLLBACK");
  throw error;
} finally {
  client.release();
  await pool.end();
}
