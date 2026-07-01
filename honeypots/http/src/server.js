import dotenv from "dotenv";
import express from "express";

dotenv.config();

const app = express();
const port = Number(process.env.HTTP_HONEYPOT_PORT ?? 8080);
const backendEndpoint =
  process.env.BACKEND_ATTACK_ENDPOINT ?? "http://localhost:8000/attack";
const honeypotToken = process.env.HONEYPOT_API_TOKEN ?? "dev-honeypot-token";

app.use(express.text({ type: "*/*", limit: "100kb" }));

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress?.replace("::ffff:", "") ?? "unknown";
}

async function reportAttack(req) {
  const payload = {
    ip: getClientIp(req),
    protocol: "HTTP",
    service: "http-honeypot",
    userAgent: req.headers["user-agent"],
    method: req.method,
    path: req.originalUrl,
    headers: req.headers,
    metadata: {
      bodyPreview: typeof req.body === "string" ? req.body.slice(0, 500) : ""
    },
    status: "captured"
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
    console.error("Failed to report HTTP attack", error.message);
  }
}

app.all("*", async (req, res) => {
  await reportAttack(req);

  res.status(200).type("html").send(`
    <!doctype html>
    <html>
      <head><title>Admin Console</title></head>
      <body>
        <h1>Admin Console</h1>
        <form method="post" action="/login">
          <input name="username" placeholder="Username" />
          <input name="password" placeholder="Password" type="password" />
          <button>Login</button>
        </form>
      </body>
    </html>
  `);
});

app.listen(port, () => {
  console.log(`HTTP honeypot listening on port ${port}`);
});
