import bcrypt from "bcryptjs";
import { pool } from "../db/pool.js";

const BCRYPT_ROUNDS = 12;
// Compared against when the username doesn't exist, so response time doesn't
// reveal which usernames are valid.
const DUMMY_HASH = bcrypt.hashSync("dummy-password-for-timing", BCRYPT_ROUNDS);

/** @typedef {"admin" | "demo"} Role */

/**
 * Create a user if the username is not taken. Never overwrites an existing
 * password; use `npm run user:set` for that.
 * @param {import("pg").Pool | import("pg").PoolClient} db
 * @param {{ username: string, password: string, role: Role }} user
 * @returns {Promise<boolean>} true if created
 */
export async function createUserIfMissing(db, { username, password, role }) {
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const result = await db.query(
    `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
     ON CONFLICT (username) DO NOTHING`,
    [username, hash, role]
  );
  return (result.rowCount ?? 0) > 0;
}

/**
 * Create or update a user's password and role.
 * @param {import("pg").Pool} db
 * @param {{ username: string, password: string, role: Role }} user
 */
export async function upsertUser(db, { username, password, role }) {
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  await db.query(
    `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role`,
    [username, hash, role]
  );
}

/**
 * @param {string} username
 * @param {string} password
 * @returns {Promise<{ id: string, username: string, role: Role } | null>}
 */
export async function verifyCredentials(username, password) {
  const result = await pool.query(
    "SELECT id, username, password_hash, role FROM users WHERE username = $1",
    [username]
  );
  const row = result.rows[0];
  const ok = await bcrypt.compare(password, row?.password_hash ?? DUMMY_HASH);
  if (!row || !ok) return null;

  await pool.query("UPDATE users SET last_login_at = NOW() WHERE id = $1", [row.id]);
  return { id: String(row.id), username: row.username, role: row.role };
}
