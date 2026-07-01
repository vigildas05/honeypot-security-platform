import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "./pool.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.resolve(__dirname, "../../sql/schema.sql");

async function migrate() {
  const sql = await fs.readFile(schemaPath, "utf8");
  await pool.query(sql);
  console.log("Database schema is ready.");
  await pool.end();
}

migrate().catch(async (error) => {
  console.error(error);
  await pool.end();
  process.exit(1);
});
