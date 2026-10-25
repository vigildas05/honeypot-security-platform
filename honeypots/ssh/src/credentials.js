export const DEFAULT_ACCEPTED_CREDENTIALS =
  "root:123456,root:password,root:root,admin:admin,ubuntu:ubuntu,pi:raspberry,test:test";

/**
 * Parse "user:pass,user2:pass2" into a Set of "user\0pass" keys.
 * Splits on the first ':' so passwords may contain colons.
 * @param {string} value
 */
export function parseAcceptedCredentials(value) {
  const set = new Set();
  for (const entry of value.split(",")) {
    const idx = entry.indexOf(":");
    if (idx <= 0) continue;
    set.add(`${entry.slice(0, idx).trim()}\0${entry.slice(idx + 1)}`);
  }
  return set;
}

/**
 * @param {Set<string>} accepted
 * @param {string} username
 * @param {string} password
 */
export function isAccepted(accepted, username, password) {
  return accepted.has(`${username}\0${password}`);
}
