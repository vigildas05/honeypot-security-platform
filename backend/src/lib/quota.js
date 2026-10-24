/**
 * Two-level rate limiting for external APIs:
 *  - per-minute sliding window, in memory (per process)
 *  - per-day cap, reserved atomically in Postgres (shared, survives restarts)
 */

/**
 * @param {number} perMinute 0 or less disables the minute window
 * @param {() => number} [now]
 */
export function createMinuteWindow(perMinute, now = Date.now) {
  /** @type {number[]} */
  const hits = [];
  return {
    /** @returns {boolean} true if a call may be made now (and records it) */
    tryTake() {
      if (perMinute <= 0) return true;
      const t = now();
      while (hits.length && hits[0] <= t - 60_000) hits.shift();
      if (hits.length >= perMinute) return false;
      hits.push(t);
      return true;
    }
  };
}

/**
 * Atomically reserve one call from today's (UTC) quota.
 * @param {import("pg").Pool | import("pg").PoolClient} db
 * @param {string} provider
 * @param {number} dailyLimit
 * @returns {Promise<boolean>} false if the quota is exhausted
 */
export async function reserveDailyCall(db, provider, dailyLimit) {
  if (dailyLimit <= 0) return false;
  const result = await db.query(
    `INSERT INTO provider_usage (provider, day, calls)
     VALUES ($1, (NOW() AT TIME ZONE 'UTC')::date, 1)
     ON CONFLICT (provider, day) DO UPDATE
       SET calls = provider_usage.calls + 1
       WHERE provider_usage.calls < $2
     RETURNING calls`,
    [provider, dailyLimit]
  );
  return (result.rowCount ?? 0) > 0;
}

/**
 * @param {import("pg").Pool} db
 * @param {string} provider
 */
export async function getDailyUsage(db, provider) {
  const result = await db.query(
    `SELECT calls, tokens FROM provider_usage
     WHERE provider = $1 AND day = (NOW() AT TIME ZONE 'UTC')::date`,
    [provider]
  );
  return { calls: Number(result.rows[0]?.calls ?? 0), tokens: Number(result.rows[0]?.tokens ?? 0) };
}
