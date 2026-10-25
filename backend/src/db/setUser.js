// Usage: npm run user:set -- <username> <admin|demo>
// The password is read from the DASHBOARD_SET_PASSWORD env var so it never
// lands in shell history or process listings.
import { upsertUser } from "../services/userService.js";
import { closePools, getDirectPool } from "./pool.js";

// Migrations and admin scripts need a direct (non-pooled) connection.
const pool = getDirectPool();

const [username, role] = process.argv.slice(2);
const password = process.env.DASHBOARD_SET_PASSWORD ?? "";

if (!username || (role !== "admin" && role !== "demo") || password.length < 12) {
  console.error(
    "Usage: DASHBOARD_SET_PASSWORD=<12+ chars> npm run user:set -- <username> <admin|demo>"
  );
  process.exit(1);
}

try {
  await upsertUser(pool, { username, password, role });
  console.log(`User "${username}" saved with role ${role}.`);
} finally {
  await closePools();
}
