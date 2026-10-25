import dotenv from "dotenv";
import express from "express";
import { createReporter, isLoopback, loadSensorConfig } from "../../common/reporter.js";
import { createSensorLogger } from "../../common/log.js";
import { buildHttpEvent } from "./capture.js";

dotenv.config();

const port = Number(process.env.HTTP_HONEYPOT_PORT ?? 8080);
const log = createSensorLogger("http-sensor");
const config = loadSensorConfig(process.env);
const reporter = createReporter({ ...config, log: (msg) => log.warn(msg) });
reporter.start();

const app = express();
app.disable("x-powered-by");
app.disable("etag");
// Deliberately NOT setting "trust proxy": the socket address is the only source of truth.

app.use(express.urlencoded({ extended: false, limit: "64kb" }));
app.use(express.text({ type: () => true, limit: "64kb" }));

const LOGIN_PAGE = `<!doctype html>
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
`;

app.all("*", (req, res) => {
  res.set("Server", "nginx/1.18.0 (Ubuntu)");
  const status = req.method === "POST" && req.path === "/login" ? 401 : 200;
  res.status(status).type("html").send(LOGIN_PAGE);

  const event = buildHttpEvent(req);
  if (!isLoopback(event.src_ip)) reporter.enqueue(event);
});

// Malformed bodies etc. still get logged; never leak stack traces.
app.use(
  /**
   * @param {any} _err
   * @param {import("express").Request} req
   * @param {import("express").Response} res
   * @param {import("express").NextFunction} _next
   */
  (_err, req, res, _next) => {
    res.status(400).type("html").send("<h1>400 Bad Request</h1>");
    const event = buildHttpEvent(req);
    if (!isLoopback(event.src_ip)) reporter.enqueue(event);
  }
);

const server = app.listen(port, () => {
  log.info("listening", { port, sensorId: config.sensorId ?? null });
});
server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;
server.maxConnections = Number(process.env.HTTP_MAX_CONNECTIONS ?? 500);

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, async () => {
    server.close();
    await reporter.stop();
    process.exit(0);
  });
}
