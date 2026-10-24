// Shared event reporter for sensors. Buffers events in a bounded in-memory
// queue and ships them to the backend ingest API in batches, so a slow or
// unreachable backend never blocks the honeypot's request/auth handlers.
//
// The sensor holds exactly one secret: its ingest token.

const DEFAULT_DEV_TOKEN = "dev-honeypot-token";

/** Backend-only secrets. A sensor refuses to start if any of these is set. */
export const FORBIDDEN_SENSOR_ENV = [
  "DATABASE_URL", "POSTGRES_PASSWORD", "PGPASSWORD", "JWT_SECRET_KEY", "SENSOR_TOKENS",
  "DASHBOARD_ADMIN_PASSWORD", "DASHBOARD_DEMO_PASSWORD",
  "LLM_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "NVIDIA_API_KEY",
  "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "GREYNOISE_API_KEY", "IPINFO_TOKEN",
  "EDL_TOKEN", "EDL_BASIC_PASSWORD"
];

/**
 * Read and validate sensor config from env. Fails closed in production.
 * @param {NodeJS.ProcessEnv} env
 */
export function loadSensorConfig(env) {
  const isProduction = env.NODE_ENV === "production";
  const ingestUrl = env.SENSOR_INGEST_URL ?? "http://localhost:8000/ingest/v1/events";
  const token = env.SENSOR_INGEST_TOKEN ?? env.HONEYPOT_API_TOKEN ?? (isProduction ? "" : DEFAULT_DEV_TOKEN);
  const sensorId = env.SENSOR_ID ?? "";

  const problems = [];
  // The sensor is the attacked host: it must hold nothing but its ingest token.
  const leaked = FORBIDDEN_SENSOR_ENV.filter((name) => env[name]);
  if (leaked.length > 0) {
    problems.push(`backend secrets must never be given to a sensor; remove: ${leaked.join(", ")}`);
  }
  let url;
  try {
    url = new URL(ingestUrl);
  } catch {
    problems.push("SENSOR_INGEST_URL is not a valid URL");
  }
  if (isProduction) {
    if (url && url.protocol !== "https:" && env.ALLOW_INSECURE_INGEST !== "true") {
      problems.push("SENSOR_INGEST_URL must use https in production");
    }
    if (token.length < 24 || token === DEFAULT_DEV_TOKEN) {
      problems.push("SENSOR_INGEST_TOKEN must be a random value of at least 24 characters");
    }
  }
  if (sensorId && !/^[a-zA-Z0-9_.-]{1,64}$/.test(sensorId)) {
    problems.push("SENSOR_ID may only contain letters, digits, '.', '_' and '-'");
  }
  if (problems.length > 0) {
    throw new Error(`Refusing to start sensor:\n - ${problems.join("\n - ")}`);
  }

  return { ingestUrl, token, sensorId: sensorId || undefined, isProduction };
}

/**
 * @param {{
 *   ingestUrl: string,
 *   token: string,
 *   sensorId?: string,
 *   batchSize?: number,
 *   flushIntervalMs?: number,
 *   maxQueue?: number,
 *   timeoutMs?: number,
 *   fetchImpl?: typeof fetch,
 *   log?: (msg: string) => void
 * }} options
 */
export function createReporter({
  ingestUrl,
  token,
  sensorId,
  batchSize = 50,
  flushIntervalMs = 1000,
  maxQueue = 5000,
  timeoutMs = 5000,
  fetchImpl = fetch,
  log = (msg) => console.error(msg)
}) {
  /** @type {Record<string, unknown>[]} */
  const queue = [];
  const stats = { sent: 0, dropped: 0, rejected: 0, failedFlushes: 0 };
  let flushing = false;
  let backoffUntil = 0;
  /** @type {NodeJS.Timeout | undefined} */
  let timer;

  /** @param {Record<string, unknown>} event */
  function enqueue(event) {
    queue.push(sensorId ? { ...event, sensor_id: sensorId } : event);
    while (queue.length > maxQueue) {
      queue.shift();
      stats.dropped += 1;
    }
    if (queue.length >= batchSize) void flush();
  }

  async function flush() {
    if (flushing || queue.length === 0 || Date.now() < backoffUntil) return;
    flushing = true;
    const batch = queue.splice(0, batchSize);
    try {
      const response = await fetchImpl(ingestUrl, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({ events: batch }),
        signal: AbortSignal.timeout(timeoutMs)
      });

      if (response.status === 202 || response.status === 400) {
        // 400 means every event was rejected by validation; retrying won't help.
        const body = /** @type {any} */ (await response.json().catch(() => ({})));
        const rejected = Array.isArray(body.rejected) ? body.rejected.length : 0;
        stats.sent += batch.length - rejected;
        stats.rejected += rejected;
        if (rejected > 0) log(`reporter: backend rejected ${rejected} event(s)`);
        backoffUntil = 0;
      } else if (response.status === 401 || response.status === 403 || response.status === 413) {
        stats.dropped += batch.length;
        log(`reporter: backend refused batch (HTTP ${response.status}); dropping it`);
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      // Transient failure: put the batch back (bounded) and back off.
      queue.unshift(...batch);
      while (queue.length > maxQueue) {
        queue.pop();
        stats.dropped += 1;
      }
      stats.failedFlushes += 1;
      backoffUntil = Date.now() + Math.min(30_000, 1000 * 2 ** Math.min(stats.failedFlushes, 5));
      log(`reporter: flush failed (${/** @type {Error} */ (error).message}); ${queue.length} queued`);
    } finally {
      flushing = false;
    }
  }

  function start() {
    timer ??= setInterval(() => void flush(), flushIntervalMs);
    timer.unref?.();
  }

  async function stop() {
    if (timer) clearInterval(timer);
    timer = undefined;
    backoffUntil = 0;
    await flush();
  }

  return { enqueue, flush, start, stop, stats, get queued() { return queue.length; } };
}

/** @param {string | undefined} address */
export function cleanRemoteAddress(address) {
  if (!address) return "0.0.0.0";
  return address.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, "");
}

/** @param {string} ip */
export function isLoopback(ip) {
  return ip === "::1" || ip.startsWith("127.");
}
