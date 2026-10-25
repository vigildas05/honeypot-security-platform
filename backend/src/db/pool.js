import pg from "pg";
import { env } from "../config/env.js";

export const pool = new pg.Pool({
  connectionString: env.databaseUrl,
  max: Number(process.env.DATABASE_POOL_MAX ?? 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});
