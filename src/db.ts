import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { config } from "./config";

let dbInstance: Database.Database | null = null;

function ensureDir(filePath: string) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export function getDb() {
  if (!dbInstance) {
    ensureDir(config.dbPath);
    dbInstance = new Database(config.dbPath);
    dbInstance.pragma("journal_mode = WAL");
    migrate(dbInstance);
  }
  return dbInstance;
}

function migrate(db: Database.Database) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      cidr_or_host TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      tags TEXT
    );

    CREATE TABLE IF NOT EXISTS scan_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      nmap_flags TEXT NOT NULL,
      description TEXT,
      timeout INTEGER,
      aggressiveness_level INTEGER
    );

    CREATE TABLE IF NOT EXISTS scan_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id INTEGER NOT NULL,
      profile_id INTEGER NOT NULL,
      started_at TEXT NOT NULL,
      finished_at TEXT,
      status TEXT NOT NULL,
      raw_output_path TEXT,
      FOREIGN KEY (target_id) REFERENCES targets(id),
      FOREIGN KEY (profile_id) REFERENCES scan_profiles(id)
    );

    CREATE TABLE IF NOT EXISTS hosts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_run_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      hostname TEXT,
      os_guess TEXT,
      is_up INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
    );

    CREATE TABLE IF NOT EXISTS ports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_id INTEGER NOT NULL,
      port INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      state TEXT NOT NULL,
      service_name TEXT,
      service_version TEXT,
      FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    CREATE TABLE IF NOT EXISTS vulnerability_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      port_id INTEGER NOT NULL,
      summary TEXT NOT NULL,
      severity TEXT,
      source TEXT NOT NULL,
      FOREIGN KEY (port_id) REFERENCES ports(id)
    );

    CREATE TABLE IF NOT EXISTS cve_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL,
      cvss_score REAL,
      severity TEXT,
      description TEXT,
      source_url TEXT
    );

    CREATE TABLE IF NOT EXISTS host_cves (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host_id INTEGER NOT NULL,
      cve_record_id INTEGER NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      FOREIGN KEY (host_id) REFERENCES hosts(id),
      FOREIGN KEY (cve_record_id) REFERENCES cve_records(id)
    );

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scope TEXT,
      generated_at TEXT NOT NULL,
      llm_model TEXT,
      prompt_metadata TEXT,
      content TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scheduled_jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id INTEGER NOT NULL,
      profile_id INTEGER NOT NULL,
      cron_expression TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (target_id) REFERENCES targets(id),
      FOREIGN KEY (profile_id) REFERENCES scan_profiles(id)
    );
  `);
}

