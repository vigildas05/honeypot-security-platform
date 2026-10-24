/**
 * Increment daily counters (UTC day). Shared across processes via Postgres.
 * @param {import("pg").Pool | import("pg").PoolClient} db
 * @param {Record<string, number>} increments
 */
export async function incrementCounters(db, increments) {
  const entries = Object.entries(increments).filter(([, v]) => v);
  if (entries.length === 0) return;
  const names = entries.map(([k]) => k);
  const values = entries.map(([, v]) => v);
  await db.query(
    `INSERT INTO metric_counters (day, name, value)
     SELECT (NOW() AT TIME ZONE 'UTC')::date, n, v FROM unnest($1::text[], $2::bigint[]) AS t(n, v)
     ON CONFLICT (day, name) DO UPDATE SET value = metric_counters.value + EXCLUDED.value`,
    [names, values]
  );
}
