import { app } from "./app.js";
import { env } from "./config/env.js";
import { logger } from "./lib/logger.js";

app.listen(env.port, () => {
  logger.info({ port: env.port }, "backend listening");
});

// Free-tier hosting (e.g. one Render web service): run the background worker
// in the same process. Prefer a separate worker process when you can.
if (process.env.EMBEDDED_WORKER === "true") {
  logger.info("EMBEDDED_WORKER=true: starting the worker in the API process");
  await import("./worker.js");
}
