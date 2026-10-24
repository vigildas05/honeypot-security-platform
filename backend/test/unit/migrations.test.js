import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadMigrations } from "../../src/db/migrations.js";

describe("loadMigrations", () => {
  it("produces the same checksum for CRLF and LF checkouts", async () => {
    const lf = await fs.mkdtemp(path.join(os.tmpdir(), "mig-lf-"));
    const crlf = await fs.mkdtemp(path.join(os.tmpdir(), "mig-crlf-"));
    await fs.writeFile(path.join(lf, "001_x.sql"), "SELECT 1;\nSELECT 2;\n");
    await fs.writeFile(path.join(crlf, "001_x.sql"), "SELECT 1;\r\nSELECT 2;\r\n");
    const [a] = await loadMigrations(lf);
    const [b] = await loadMigrations(crlf);
    expect(a.checksum).toBe(b.checksum);
  });

  it("orders migrations and ignores non-migration files", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mig-order-"));
    for (const f of ["002_b.sql", "001_a.sql", "README.md", "10_bad.sql"]) await fs.writeFile(path.join(dir, f), "SELECT 1;");
    expect((await loadMigrations(dir)).map((m) => m.file)).toEqual(["001_a.sql", "002_b.sql"]);
  });
});
