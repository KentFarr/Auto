import { Router } from "express";
import { getDb } from "../db";
import { config } from "../config";
import { runNmapScan } from "../services/nmapRunner";
import { processScanResults } from "../services/scanProcessor";

const router = Router();

router.get("/", (_req, res) => {
  try {
    const db = getDb();
    const scans = db
      .prepare(
        `SELECT
           sr.id,
           sr.started_at,
           sr.finished_at,
           sr.status,
           t.name AS target_name,
           t.cidr_or_host,
           sp.name AS profile_name,
           (
             SELECT COUNT(DISTINCT h.id)
             FROM hosts h
             WHERE h.scan_run_id = sr.id
           ) AS host_count,
           (
             SELECT COUNT(DISTINCT p.id)
             FROM hosts h2
             JOIN ports p ON p.host_id = h2.id AND p.state = 'open'
             WHERE h2.scan_run_id = sr.id
           ) AS open_port_count
         FROM scan_runs sr
         JOIN targets t ON t.id = sr.target_id
         JOIN scan_profiles sp ON sp.id = sr.profile_id
         ORDER BY sr.id DESC
         LIMIT 50`
      )
      .all();
    res.json(scans);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: "Failed to list scans" });
  }
});

router.post("/trigger", async (req, res) => {
  try {
    const { target = config.defaultCidr, flags = "-T3 -sV -Pn" } = req.body || {};
    const db = getDb();

    const profileStmt = db.prepare(
      "INSERT INTO scan_profiles (name, nmap_flags, description) VALUES (?, ?, ?)"
    );
    const profileInfo = profileStmt.run(
      "ad-hoc",
      flags,
      "Ad-hoc scan triggered via API"
    );

    const targetStmt = db.prepare(
      "INSERT INTO targets (name, cidr_or_host, enabled) VALUES (?, ?, 1)"
    );
    const targetInfo = targetStmt.run("ad-hoc", target);

    const scanRunStmt = db.prepare(
      "INSERT INTO scan_runs (target_id, profile_id, started_at, status) VALUES (?, ?, ?, ?)"
    );
    const startedAt = new Date().toISOString();
    const scanRunInfo = scanRunStmt.run(
      targetInfo.lastInsertRowid,
      profileInfo.lastInsertRowid,
      startedAt,
      "running"
    );

    const scanRunId = Number(scanRunInfo.lastInsertRowid);

    const result = await runNmapScan({ target, flags });

    await processScanResults(scanRunId, result.stdoutPath);

    const updateStmt = db.prepare(
      "UPDATE scan_runs SET finished_at = ?, status = ?, raw_output_path = ? WHERE id = ?"
    );
    updateStmt.run(new Date().toISOString(), "completed", result.stdoutPath, scanRunId);

    res.json({
      scanRunId,
      command: result.command,
      outputPath: result.stdoutPath,
      stderr: result.stderr,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: "Failed to execute scan" });
  }
});

export default router;

