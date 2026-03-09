import express from "express";
import cors from "cors";
import path from "path";
import { config } from "./config";
import scansRouter from "./routes/scans";
import hostsRouter from "./routes/hosts";
import reportsRouter from "./routes/reports";
import { getDb } from "./db";
import { startScheduler } from "./services/scheduler";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// API routes
app.use("/api/scans", scansRouter);
app.use("/api/hosts", hostsRouter);
app.use("/api/reports", reportsRouter);

// Root serves the minimal UI
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

// Static assets (for UI)
app.use(
  "/static",
  express.static(path.join(__dirname, "..", "public"), {
    fallthrough: true,
  })
);

export function startServer() {
  // Ensure DB is initialized and migrations applied
  getDb();

  // Start cron-based recurring scan scheduler
  startScheduler();

  app.listen(config.port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server listening on port ${config.port}`);
  });
}

if (require.main === module) {
  startServer();
}

