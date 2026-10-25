/**
 * Content-Security-Policy for the built dashboard. Injected as a <meta> tag at
 * build time so it works on any static host (nginx, Vercel). The hosts also
 * send frame-ancestors etc. as real headers (meta CSP can't carry those).
 *
 * No 'unsafe-inline' and no third-party origins: even if an attacker string
 * somehow reached the DOM as markup, inline scripts/handlers would not run.
 * Only applied to production builds; Vite's dev server needs inline scripts.
 * @param {string} apiBase
 */
export function buildCsp(apiBase) {
  let apiOrigin = "";
  try {
    apiOrigin = new URL(apiBase).origin;
  } catch {
    throw new Error(`VITE_API_BASE_URL must be an absolute URL, got "${apiBase}"`);
  }
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${apiOrigin}`,
    "base-uri 'none'",
    "form-action 'self'",
    "object-src 'none'",
    "manifest-src 'self'"
  ].join("; ");
}
