// Minimal structured logger for the sensors: one JSON object per line on
// stdout/stderr. Deliberately dependency-free to keep the attack surface small.
// Never pass attacker-controlled strings here; those go to the backend only.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const threshold = LEVELS[/** @type {keyof typeof LEVELS} */ (process.env.LOG_LEVEL)] ?? LEVELS.info;

/**
 * @param {string} service
 */
export function createSensorLogger(service) {
  /** @param {keyof typeof LEVELS} level @param {string} msg @param {Record<string, unknown>} [fields] */
  const write = (level, msg, fields = {}) => {
    if (LEVELS[level] < threshold) return;
    const line = JSON.stringify({ time: new Date().toISOString(), level, service, msg, ...fields });
    (level === "error" || level === "warn" ? process.stderr : process.stdout).write(`${line}\n`);
  };
  return {
    /** @param {string} msg @param {Record<string, unknown>} [f] */ debug: (msg, f) => write("debug", msg, f),
    /** @param {string} msg @param {Record<string, unknown>} [f] */ info: (msg, f) => write("info", msg, f),
    /** @param {string} msg @param {Record<string, unknown>} [f] */ warn: (msg, f) => write("warn", msg, f),
    /** @param {string} msg @param {Record<string, unknown>} [f] */ error: (msg, f) => write("error", msg, f)
  };
}
