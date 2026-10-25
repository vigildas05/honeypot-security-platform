import { env } from "../config/env.js";
import { createUserIfMissing } from "../services/userService.js";
import { runMigrations } from "./migrations.js";
import { closePools, getDirectPool } from "./pool.js";

// Migrations and admin scripts need a direct (non-pooled) connection.
const pool = getDirectPool();

const WEAK_PASSWORDS = new Set(["admin", "admin123", "password", "changeme", "demo"]);

/**
 * @param {string} username
 * @param {string} password
 * @param {"admin" | "demo"} role
 */
async function seedUser(username, password, role) {
  if (!username || !password) return;
  if (env.isProduction && (password.length < 12 || WEAK_PASSWORDS.has(password))) {
    throw new Error(`Refusing to seed ${role} user "${username}" with a weak password in production`);
  }
  if (await createUserIfMissing(pool, { username, password, role })) {
    console.log(`Created ${role} user "${username}".`);
  }
}

async function migrate() {
  await runMigrations(pool);
  await seedUser(env.seedAdminUser, env.seedAdminPassword, "admin");
  await seedUser(env.seedDemoUser, env.seedDemoPassword, "demo");
  console.log("Database schema is ready.");
  await closePools();
}

migrate().catch(async (error) => {
  console.error(error);
  await closePools();
  process.exit(1);
});
