import { Router } from "express";
import { getDb } from "../db";
import { generateAndStoreReportForLatestCompletedScan } from "../services/llmReportService";

const router = Router();

router.get("/", (_req, res) => {
  try {
    const db = getDb();
    const reports = db
      .prepare(
        `SELECT id, scope, generated_at, llm_model
         FROM reports
         ORDER BY id DESC
         LIMIT 50`
      )
      .all();

    res.json(reports);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: "Failed to list reports" });
  }
});

router.get("/:id", (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) {
      res.status(400).json({ error: "Invalid report id" });
      return;
    }

    const db = getDb();
    const report = db
      .prepare(
        `SELECT id, scope, generated_at, llm_model, prompt_metadata, content
         FROM reports
         WHERE id = ?`
      )
      .get(id);

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    res.json(report);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: "Failed to load report" });
  }
});

router.post("/generate", async (_req, res) => {
  try {
    const result = await generateAndStoreReportForLatestCompletedScan();
    res.status(201).json(result);
  } catch (err: any) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({
      error: "Failed to generate report",
      details: err?.message ?? String(err),
    });
  }
});

export default router;

