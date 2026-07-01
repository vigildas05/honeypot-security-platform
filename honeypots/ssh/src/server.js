import crypto from "node:crypto";
import dotenv from "dotenv";
import ssh2 from "ssh2";

dotenv.config();

const { Server } = ssh2;

const port = Number(process.env.SSH_HONEYPOT_PORT ?? 2222);
const backendEndpoint =
  process.env.BACKEND_ATTACK_ENDPOINT ?? "http://localhost:8000/attack";
const honeypotToken = process.env.HONEYPOT_API_TOKEN ?? "dev-honeypot-token";

const hostKey = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "pkcs1", format: "pem" },
  privateKeyEncoding: { type: "pkcs1", format: "pem" }
}).privateKey;

function cleanIp(ip) {
  return ip?.replace("::ffff:", "") ?? "unknown";
}

async function reportLoginAttempt({ ip, username, password, method, durationMs }) {
  const payload = {
    ip: cleanIp(ip),
    protocol: "SSH",
    service: "ssh-honeypot",
    username,
    password,
    status: "rejected",
    connectionDurationMs: durationMs,
    metadata: {
      authMethod: method,
      note: "Fake SSH server. Credentials were never accepted."
    }
  };

  try {
    await fetch(backendEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-honeypot-token": honeypotToken
      },
      body: JSON.stringify(payload)
    });
  } catch (error) {
    console.error("Failed to report SSH attack", error.message);
  }
}

const server = new Server({ hostKeys: [hostKey] }, (client, info) => {
  const start = Date.now();
  const ip = info.ip;

  client.on("authentication", async (ctx) => {
    const durationMs = Date.now() - start;

    await reportLoginAttempt({
      ip,
      username: ctx.username,
      password: ctx.password,
      method: ctx.method,
      durationMs
    });

    ctx.reject(["password"], false);
  });

  client.on("ready", () => {
    client.end();
  });

  client.on("error", () => {});
});

server.listen(port, "0.0.0.0", () => {
  console.log(`SSH honeypot listening on port ${port}`);
});
