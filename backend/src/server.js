import { app } from "./app.js";
import { env } from "./config/env.js";

app.listen(env.port, () => {
  console.log(`Honeypot backend listening on port ${env.port}`);
});

// Free-tier hosting (e.g. one Render web service): run the background worker
// in the same process. Prefer a separate worker process when you can.
if (process.env.EMBEDDED_WORKER === "true") {
  console.log("EMBEDDED_WORKER=true: starting the worker in the API process");
  await import("./worker.js");
}
