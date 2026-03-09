import cron, { ScheduledTask } from "node-cron";
import { getDb } from "../db";
import { runNmapScan } from "./nmapRunner";
import { processScanResults } from "./scanProcessor";

interface ScheduledJobRecord {
  id: number;
  target_id: number;
  profile_id: number;
  cron_expression: string;
  enabled: number;
  target: string;
  flags: string;
}

const scheduledTasks: ScheduledTask[] = [];

export function startScheduler() {
  const db = getDb();

  const rows = db
    .prepare(
      `
      SELECT
        sj.id,
        sj.target_id,
        sj.profile_id,
        sj.cron_expression,
        sj.enabled,
        t.cidr_or_host AS target,
        sp.nmap_flags AS flags
      FROM scheduled_jobs sj
      JOIN targets t ON t.id = sj.target_id
      JOIN scan_profiles sp ON sp.id = sj.profile_id
      WHERE sj.enabled = 1
    `
    )
    .all() as ScheduledJobRecord[];

  for (const job of rows) {
    if (!cron.validate(job.cron_expression)) {
      // eslint-disable-next-line no-console
      console.warn(
        `Skipping scheduled job ${job.id} due to invalid cron expression: ${job.cron_expression}`
      );
      continue;
    }

    const task = cron.schedule(job.cron_expression, async () => {
      const dbInner = getDb();

      // Double-check the job is still enabled before running.
      const latest = dbInner
        .prepare(
          `
          SELECT
            sj.id,
            sj.target_id,
            sj.profile_id,
            sj.cron_expression,
            sj.enabled,
            t.cidr_or_host AS target,
            sp.nmap_flags AS flags
          FROM scheduled_jobs sj
          JOIN targets t ON t.id = sj.target_id
          JOIN scan_profiles sp ON sp.id = sj.profile_id
          WHERE sj.id = ?
        `
        )
        .get(job.id) as ScheduledJobRecord | undefined;

      if (!latest || latest.enabled !== 1) {
        return;
      }

      const insertScanRun = dbInner.prepare(
        "INSERT INTO scan_runs (target_id, profile_id, started_at, status) VALUES (?, ?, ?, ?)"
      );

      const startedAt = new Date().toISOString();

      try {
        const scanRunInfo = insertScanRun.run(
          latest.target_id,
          latest.profile_id,
          startedAt,
          "running"
        );

        const scanRunId = Number(scanRunInfo.lastInsertRowid);

        const result = await runNmapScan({
          target: latest.target,
          flags: latest.flags,
        });

        await processScanResults(scanRunId, result.stdoutPath);

        const updateStmt = dbInner.prepare(
          "UPDATE scan_runs SET finished_at = ?, status = ?, raw_output_path = ? WHERE id = ?"
        );
        updateStmt.run(
          new Date().toISOString(),
          "completed",
          result.stdoutPath,
          scanRunId
        );
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(
          `Scheduled job ${job.id} failed to execute scan:`,
          err
        );

        const failUpdate = dbInner.prepare(
          "UPDATE scan_runs SET finished_at = ?, status = ? WHERE id = ? AND status = 'running'"
        );
        failUpdate.run(new Date().toISOString(), "failed", latest.id);
      }
    });

    scheduledTasks.push(task);
  }

  if (scheduledTasks.length > 0) {
    // eslint-disable-next-line no-console
    console.log(
      `Scheduler started with ${scheduledTasks.length} recurring scan job(s).`
    );
  } else {
    // eslint-disable-next-line no-console
    console.log("Scheduler started with no enabled recurring scan jobs.");
  }
}

