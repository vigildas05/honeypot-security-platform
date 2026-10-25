// Reduce an incident's events into plain counters/lists the rules operate on.
// Pure function: easy to unit-test with fixture events.

/**
 * @typedef {object} EventRow
 * @property {string} protocol
 * @property {string} event_type
 * @property {Date | string} ts
 * @property {string | null} [username]
 * @property {string | null} [password]
 * @property {boolean | null} [auth_success]
 * @property {string | null} [auth_method]
 * @property {string | null} [command]
 * @property {string | null} [http_method]
 * @property {string | null} [http_path]
 * @property {string | null} [user_agent]
 * @property {Record<string, string> | null} [http_headers]
 * @property {string | null} [session_id]
 */

/**
 * @param {Map<string, number>} map
 * @param {number} n
 */
function top(map, n) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

/** @param {Map<string, number>} map @param {string | null | undefined} key */
function bump(map, key) {
  if (key === null || key === undefined) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/**
 * @param {EventRow[]} events
 */
export function computeFeatures(events) {
  const usernames = new Map();
  const passwords = new Map();
  const commands = new Map();
  const paths = new Map();
  const methods = new Map();
  const userAgents = new Map();
  const sessions = new Set();
  let failedLogins = 0;
  let successfulLogins = 0;
  let httpCredentialPosts = 0;
  let connects = 0;
  let sshEvents = 0;
  let httpEvents = 0;
  let first = Infinity;
  let last = -Infinity;
  /** @type {string[]} */
  const allCommands = [];
  /** @type {string[]} */
  const allPaths = [];
  /** @type {string[]} */
  const httpBlobs = [];

  for (const e of events) {
    const t = new Date(e.ts).getTime();
    if (t < first) first = t;
    if (t > last) last = t;
    if (e.session_id) sessions.add(e.session_id);

    if (e.protocol === "ssh") {
      sshEvents += 1;
      if (e.event_type === "connect") connects += 1;
      if (e.event_type === "auth_attempt") {
        bump(usernames, e.username);
        if (e.auth_method !== "publickey") bump(passwords, e.password ?? "");
        if (e.auth_success) successfulLogins += 1;
        else failedLogins += 1;
      }
      if (e.event_type === "command" && e.command) {
        bump(commands, e.command);
        allCommands.push(e.command);
      }
    } else if (e.protocol === "http") {
      httpEvents += 1;
      bump(methods, e.http_method);
      bump(userAgents, e.user_agent);
      if (e.http_path) {
        bump(paths, e.http_path);
        allPaths.push(e.http_path);
      }
      if (e.password) {
        httpCredentialPosts += 1;
        bump(usernames, e.username);
        bump(passwords, e.password);
      }
      httpBlobs.push(
        [e.http_path, e.user_agent, ...Object.values(e.http_headers ?? {})].filter(Boolean).join("\n")
      );
    }
  }

  return {
    total_events: events.length,
    ssh_events: sshEvents,
    http_events: httpEvents,
    ssh_connects: connects,
    sessions: sessions.size,
    failed_logins: failedLogins,
    successful_logins: successfulLogins,
    http_credential_posts: httpCredentialPosts,
    distinct_usernames: usernames.size,
    distinct_passwords: passwords.size,
    command_count: allCommands.length,
    distinct_commands: commands.size,
    http_requests: httpEvents,
    distinct_paths: paths.size,
    first_seen: Number.isFinite(first) ? new Date(first).toISOString() : null,
    last_seen: Number.isFinite(last) ? new Date(last).toISOString() : null,
    duration_seconds: Number.isFinite(first) ? Math.round((last - first) / 1000) : 0,
    top_usernames: top(usernames, 10),
    top_passwords: top(passwords, 10),
    top_commands: top(commands, 15),
    top_paths: top(paths, 15),
    top_methods: top(methods, 5),
    top_user_agents: top(userAgents, 5),
    /** Full lists for rule matching; not persisted in incident.stats. */
    _commands: allCommands,
    _paths: allPaths,
    _http_blobs: httpBlobs
  };
}

/** @typedef {ReturnType<typeof computeFeatures>} IncidentFeatures */

/**
 * Strip the bulky `_` fields before persisting features on the incident.
 * @param {IncidentFeatures} features
 */
export function persistableFeatures(features) {
  return Object.fromEntries(Object.entries(features).filter(([k]) => !k.startsWith("_")));
}
