import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS_DIR = path.resolve(__dirname, "../../migrations");

// Arbitrary constant so concurrent deploys don't run migrations twice.
const MIGRATION_LOCK_ID = 727274;

/**
 * @param {string} dir
 * @returns {Promise<{ version: string, file: string, sql: string, checksum: string }[]>}
 */
export async function loadMigrations(dir = MIGRATIONS_DIR) {
  const files = (await fs.readdir(dir)).filter((f) => /^\d{3}_[\w-]+\.sql$/.test(f)).sort();
  return Promise.all(
    files.map(async (file) => {
      const sql = await fs.readFile(path.join(dir, file), "utf8");
      return {
        version: file.slice(0, 3),
        file,
        sql,
        // Hash with normalized line endings so a Windows (autocrlf) checkout and
        // a Linux CI/container produce the same checksum.
        checksum: crypto.createHash("sha256").update(sql.replace(/\r\n/g, "\n")).digest("hex")
      };
    })
  );
}

/**
 * Apply pending migrations, each in its own transaction.
 * @param {import("pg").Pool} pool
 * @param {{ dir?: string, log?: (msg: string) => void }} [options]
 * @returns {Promise<string[]>} files applied in this run
 */
export async function runMigrations(pool, { dir = MIGRATIONS_DIR, log = console.log } = {}) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    TEXT PRIMARY KEY,
      file       TEXT NOT NULL,
      checksum   TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const migrations = await loadMigrations(dir);
  const applied = [];

  for (const migration of migrations) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [MIGRATION_LOCK_ID]);
      const existing = await client.query(
        "SELECT checksum FROM schema_migrations WHERE version = $1",
        [migration.version]
      );

      if (existing.rowCount) {
        if (existing.rows[0].checksum !== migration.checksum) {
          log(`WARNING: ${migration.file} changed after it was applied; write a new migration instead.`);
        }
        await client.query("COMMIT");
        continue;
      }

      await client.query(migration.sql);
      await client.query(
        "INSERT INTO schema_migrations (version, file, checksum) VALUES ($1, $2, $3)",
        [migration.version, migration.file, migration.checksum]
      );
      await client.query("COMMIT");
      applied.push(migration.file);
      log(`Applied migration ${migration.file}`);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw new Error(`Migration ${migration.file} failed: ${/** @type {Error} */ (error).message}`);
    } finally {
      client.release();
    }
  }

  return applied;
}
