import crypto from "node:crypto";
import fs from "node:fs";
import dotenv from "dotenv";
import ssh2 from "ssh2";
import {
  cleanRemoteAddress,
  createReporter,
  isLoopback,
  loadSensorConfig
} from "../../common/reporter.js";
import { DEFAULT_ACCEPTED_CREDENTIALS, isAccepted, parseAcceptedCredentials } from "./credentials.js";
import { createShellState, prompt, runLine } from "./fakeShell.js";

dotenv.config();

const { Server } = ssh2;

const port = Number(process.env.SSH_HONEYPOT_PORT ?? 2222);
const hostKeyPath = process.env.SSH_HOST_KEY_PATH ?? "/data/ssh_host_rsa_key";
const hostname = process.env.SSH_FAKE_HOSTNAME ?? "srv-web-01";
const accepted = parseAcceptedCredentials(process.env.SSH_ACCEPT_CREDENTIALS ?? DEFAULT_ACCEPTED_CREDENTIALS);

const LIMITS = {
  maxConnections: Number(process.env.SSH_MAX_CONNECTIONS ?? 200),
  maxConnectionsPerIp: Number(process.env.SSH_MAX_CONNECTIONS_PER_IP ?? 10),
  maxAuthAttempts: 10,
  maxLineLength: 4096,
  maxCommandsPerSession: 300,
  idleTimeoutMs: 3 * 60 * 1000,
  maxSessionMs: 15 * 60 * 1000
};

const config = loadSensorConfig(process.env);
const reporter = createReporter(config);
reporter.start();

/** Load a persistent host key so the fingerprint is stable across restarts. */
function loadHostKey() {
  try {
    return fs.readFileSync(hostKeyPath);
  } catch {
    const key = crypto.generateKeyPairSync("rsa", {
      modulusLength: 3072,
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
      privateKeyEncoding: { type: "pkcs1", format: "pem" }
    }).privateKey;
    try {
      fs.writeFileSync(hostKeyPath, key, { mode: 0o600 });
    } catch {
      console.warn(`Could not persist host key to ${hostKeyPath}; using an ephemeral key.`);
    }
    return key;
  }
}

/** @type {Map<string, number>} */
const perIp = new Map();
let totalConnections = 0;

/**
 * @param {{ ip: string, port: number, sessionId: string }} conn
 * @param {string} eventType
 * @param {Record<string, unknown>} [ssh]
 * @param {string} [raw]
 */
function report(conn, eventType, ssh = {}, raw) {
  if (isLoopback(conn.ip)) return; // container healthchecks
  reporter.enqueue({
    timestamp: new Date().toISOString(),
    protocol: "ssh",
    event_type: eventType,
    src_ip: conn.ip,
    src_port: conn.port,
    session_id: conn.sessionId,
    ssh,
    ...(raw ? { raw } : {})
  });
}

const server = new Server(
  { hostKeys: [loadHostKey()], ident: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" },
  (client, info) => {
    const conn = {
      ip: cleanRemoteAddress(info.ip),
      port: info.port,
      sessionId: crypto.randomUUID()
    };

    const ipCount = (perIp.get(conn.ip) ?? 0) + 1;
    if (totalConnections >= LIMITS.maxConnections || ipCount > LIMITS.maxConnectionsPerIp) {
      client.end();
      return;
    }
    totalConnections += 1;
    perIp.set(conn.ip, ipCount);

    const start = Date.now();
    let authAttempts = 0;
    let commandCount = 0;
    /** @type {string} */
    let authedUser = "";

    report(conn, "connect");

    const hardTimeout = setTimeout(() => client.end(), LIMITS.maxSessionMs);
    hardTimeout.unref();

    client.on("authentication", (ctx) => {
      authAttempts += 1;
      if (authAttempts > LIMITS.maxAuthAttempts) {
        client.end();
        return;
      }

      if (ctx.method === "password") {
        const ok = isAccepted(accepted, ctx.username, ctx.password);
        report(conn, "auth_attempt", {
          username: ctx.username,
          password: ctx.password,
          auth_method: "password",
          auth_success: ok
        });
        if (ok) {
          authedUser = ctx.username;
          ctx.accept();
        } else {
          ctx.reject(["password", "keyboard-interactive"]);
        }
        return;
      }

      if (ctx.method === "keyboard-interactive") {
        ctx.prompt([{ prompt: "Password: ", echo: false }], (answers) => {
          const password = answers?.[0] ?? "";
          const ok = isAccepted(accepted, ctx.username, password);
          report(conn, "auth_attempt", {
            username: ctx.username,
            password,
            auth_method: "keyboard-interactive",
            auth_success: ok
          });
          if (ok) {
            authedUser = ctx.username;
            ctx.accept();
          } else {
            ctx.reject(["password", "keyboard-interactive"]);
          }
        });
        return;
      }

      if (ctx.method === "publickey") {
        report(conn, "auth_attempt", {
          username: ctx.username,
          auth_method: "publickey",
          auth_success: false
        });
      }
      ctx.reject(["password", "keyboard-interactive"]);
    });

    client.on("ready", () => {
      client.on("session", (acceptSession) => {
        const session = acceptSession();
        let hasPty = false;

        session.on("pty", (accept) => {
          hasPty = true;
          accept?.();
        });
        session.on("env", (accept) => accept?.());
        session.on("window-change", (accept) => accept?.());
        // Never offer file transfer or X11.
        session.on("subsystem", (_accept, reject) => reject?.());
        session.on("x11", (_accept, reject) => reject?.());
        session.on("auth-agent", (_accept, reject) => reject?.());

        session.on("exec", (accept, _reject, execInfo) => {
          const stream = accept();
          const state = createShellState({ username: authedUser, hostname });
          const command = execInfo.command.slice(0, LIMITS.maxLineLength);
          commandCount += 1;
          report(conn, "command", { username: authedUser, command });
          const { output } = runLine(state, command);
          if (output) stream.write(`${output}\n`);
          stream.exit(0);
          stream.end();
        });

        session.on("shell", (accept) => {
          const stream = accept();
          const state = createShellState({ username: authedUser, hostname });
          let buffer = "";
          let escape = false;
          /** @type {NodeJS.Timeout} */
          let idle;
          const resetIdle = () => {
            clearTimeout(idle);
            idle = setTimeout(() => stream.close(), LIMITS.idleTimeoutMs);
            idle.unref();
          };
          const nl = hasPty ? "\r\n" : "\n";
          const write = (/** @type {string} */ text) => stream.write(text.replace(/\r?\n/g, nl));

          write(`Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n\nLast login: Thu Apr 18 09:12:44 2024 from 10.0.0.12\n`);
          write(prompt(state));
          resetIdle();

          const runBuffered = () => {
            const line = buffer;
            buffer = "";
            if (hasPty) write("\n");
            if (line.trim()) {
              commandCount += 1;
              report(conn, "command", { username: authedUser, command: line });
            }
            const { output, exit } = runLine(state, line);
            if (output) write(`${output}\n`);
            if (exit || commandCount >= LIMITS.maxCommandsPerSession) {
              if (exit) write("logout\n");
              stream.exit(0);
              stream.end();
              return;
            }
            write(prompt(state));
          };

          stream.on("data", (/** @type {Buffer} */ data) => {
            resetIdle();
            for (const ch of data.toString("utf8")) {
              if (escape) {
                // Swallow ANSI escape sequences (arrow keys etc.).
                if (/[A-Za-z~]/.test(ch)) escape = false;
                continue;
              }
              if (ch === "\x1b") {
                escape = true;
              } else if (ch === "\r" || ch === "\n") {
                runBuffered();
              } else if (ch === "\x7f" || ch === "\b") {
                if (buffer.length > 0) {
                  buffer = buffer.slice(0, -1);
                  if (hasPty) stream.write("\b \b");
                }
              } else if (ch === "\x03") {
                buffer = "";
                write(`^C\n${prompt(state)}`);
              } else if (ch === "\x04") {
                if (buffer.length === 0) {
                  write("logout\n");
                  stream.exit(0);
                  stream.end();
                  return;
                }
              } else if (ch >= " " || ch === "\t") {
                if (buffer.length < LIMITS.maxLineLength) {
                  buffer += ch;
                  if (hasPty) stream.write(ch);
                }
              }
            }
          });
          stream.on("close", () => clearTimeout(idle));
        });
      });
    });

    // Never let the honeypot be used as a proxy or pivot.
    client.on("tcpip", (_accept, reject) => reject());
    client.on("openssh.streamlocal", (_accept, reject) => reject());
    client.on("request", (_accept, reject) => reject?.());

    client.on("error", () => {});
    client.on("close", () => {
      clearTimeout(hardTimeout);
      totalConnections -= 1;
      const remaining = (perIp.get(conn.ip) ?? 1) - 1;
      if (remaining <= 0) perIp.delete(conn.ip);
      else perIp.set(conn.ip, remaining);
      report(
        conn,
        "session_closed",
        authedUser ? { username: authedUser } : {},
        `duration_ms=${Date.now() - start} auth_attempts=${authAttempts} commands=${commandCount}`
      );
    });
  }
);

server.on("error", (/** @type {Error} */ error) => console.error("SSH server error:", error.message));

server.listen(port, "0.0.0.0", () => {
  console.log(`SSH honeypot listening on port ${port}`);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, async () => {
    server.close();
    await reporter.stop();
    process.exit(0);
  });
}
