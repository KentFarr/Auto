import { getDb } from "../db";
import { config } from "../config";
import Anthropic from "@anthropic-ai/sdk";

interface HostSummary {
  id: number;
  ip: string;
  hostname?: string | null;
  osGuess?: string | null;
  isUp: boolean;
  openPorts: {
    port: number;
    protocol: string;
    serviceName?: string | null;
    serviceVersion?: string | null;
  }[];
  vulnerabilities: {
    summary: string;
    severity?: string | null;
  }[];
  cves: {
    cveId: string;
    severity?: string | null;
    cvssScore?: number | null;
  }[];
}

interface ScanSummary {
  scanRunId: number;
  startedAt: string;
  finishedAt?: string | null;
  status: string;
  targetName: string;
  targetCidrOrHost: string;
  profileName: string;
  profileFlags: string;
  hosts: HostSummary[];
}

function getAnthropicClient() {
  if (!config.claudeApiKey) {
    throw new Error(
      "Claude API key is not configured. Set CLAUDE_API_KEY or ANTHROPIC_API_KEY in your environment."
    );
  }

  return new Anthropic({
    apiKey: config.claudeApiKey,
  });
}

function loadLatestCompletedScan(): ScanSummary | null {
  const db = getDb();

  const scan = db
    .prepare(
      `SELECT
         sr.id,
         sr.started_at,
         sr.finished_at,
         sr.status,
         t.name AS target_name,
         t.cidr_or_host,
         sp.name AS profile_name,
         sp.nmap_flags
       FROM scan_runs sr
       JOIN targets t ON t.id = sr.target_id
       JOIN scan_profiles sp ON sp.id = sr.profile_id
       WHERE sr.status = 'completed'
       ORDER BY sr.id DESC
       LIMIT 1`
    )
    .get() as
    | {
        id: number;
        started_at: string;
        finished_at: string | null;
        status: string;
        target_name: string;
        cidr_or_host: string;
        profile_name: string;
        nmap_flags: string;
      }
    | undefined;

  if (!scan) {
    return null;
  }

  const hostRows = db
    .prepare(
      `SELECT
         h.id,
         h.ip,
         h.hostname,
         h.os_guess,
         h.is_up
       FROM hosts h
       WHERE h.scan_run_id = ?
       ORDER BY h.id`
    )
    .all(scan.id) as {
    id: number;
    ip: string;
    hostname: string | null;
    os_guess: string | null;
    is_up: number;
  }[];

  const hosts: HostSummary[] = hostRows.map((h) => ({
    id: h.id,
    ip: h.ip,
    hostname: h.hostname,
    osGuess: h.os_guess,
    isUp: !!h.is_up,
    openPorts: [],
    vulnerabilities: [],
    cves: [],
  }));

  if (hosts.length === 0) {
    return {
      scanRunId: scan.id,
      startedAt: scan.started_at,
      finishedAt: scan.finished_at,
      status: scan.status,
      targetName: scan.target_name,
      targetCidrOrHost: scan.cidr_or_host,
      profileName: scan.profile_name,
      profileFlags: scan.nmap_flags,
      hosts: [],
    };
  }

  const hostIdToIndex = new Map<number, number>();
  hosts.forEach((h, idx) => hostIdToIndex.set(h.id, idx));

  const portRows = db
    .prepare(
      `SELECT
         p.host_id,
         p.port,
         p.protocol,
         p.state,
         p.service_name,
         p.service_version
       FROM ports p
       WHERE p.host_id IN (${hosts.map(() => "?").join(",")})
         AND p.state = 'open'
       ORDER BY p.host_id, p.port`
    )
    .all(...hosts.map((h) => h.id)) as {
    host_id: number;
    port: number;
    protocol: string;
    state: string;
    service_name: string | null;
    service_version: string | null;
  }[];

  for (const row of portRows) {
    const idx = hostIdToIndex.get(row.host_id);
    if (idx === undefined) continue;
    hosts[idx].openPorts.push({
      port: row.port,
      protocol: row.protocol,
      serviceName: row.service_name,
      serviceVersion: row.service_version,
    });
  }

  const vulnRows = db
    .prepare(
      `SELECT
         h.id AS host_id,
         vf.summary,
         vf.severity
       FROM vulnerability_findings vf
       JOIN ports p ON p.id = vf.port_id
       JOIN hosts h ON h.id = p.host_id
       WHERE h.scan_run_id = ?`
    )
    .all(scan.id) as {
    host_id: number;
    summary: string;
    severity: string | null;
  }[];

  for (const row of vulnRows) {
    const idx = hostIdToIndex.get(row.host_id);
    if (idx === undefined) continue;
    hosts[idx].vulnerabilities.push({
      summary: row.summary,
      severity: row.severity,
    });
  }

  const cveRows = db
    .prepare(
      `SELECT
         h.id AS host_id,
         cr.cve_id,
         cr.severity,
         cr.cvss_score
       FROM host_cves hc
       JOIN hosts h ON h.id = hc.host_id
       JOIN cve_records cr ON cr.id = hc.cve_record_id
       WHERE h.scan_run_id = ?`
    )
    .all(scan.id) as {
    host_id: number;
    cve_id: string;
    severity: string | null;
    cvss_score: number | null;
  }[];

  for (const row of cveRows) {
    const idx = hostIdToIndex.get(row.host_id);
    if (idx === undefined) continue;
    hosts[idx].cves.push({
      cveId: row.cve_id,
      severity: row.severity,
      cvssScore: row.cvss_score,
    });
  }

  return {
    scanRunId: scan.id,
    startedAt: scan.started_at,
    finishedAt: scan.finished_at,
    status: scan.status,
    targetName: scan.target_name,
    targetCidrOrHost: scan.cidr_or_host,
    profileName: scan.profile_name,
    profileFlags: scan.nmap_flags,
    hosts,
  };
}

async function generateReportFromSummary(summary: ScanSummary): Promise<string> {
  const anthropic = getAnthropicClient();

  const systemPrompt = [
    "You are an experienced network security analyst.",
    "You are given the results of an Nmap-based network security scan,",
    "including detected hosts, open ports, services, and associated CVEs/vulnerabilities.",
    "",
    "Your task is to produce a clear, structured security report with:",
    "- An executive summary and overall risk rating (Low / Medium / High / Critical).",
    "- A list of top critical and high-risk issues with concrete remediation steps.",
    "- Notable changes or interesting observations about the attack surface.",
    "- (Optional) A short technical appendix per host if it helps clarity.",
    "",
    "Do NOT invent hosts, ports, or vulnerabilities that are not present in the input.",
    "If the scan data is sparse, clearly state the limitations.",
  ].join("\n");

  const userContext = {
    scan_metadata: {
      scan_run_id: summary.scanRunId,
      target_name: summary.targetName,
      target_cidr_or_host: summary.targetCidrOrHost,
      profile_name: summary.profileName,
      profile_flags: summary.profileFlags,
      started_at: summary.startedAt,
      finished_at: summary.finishedAt,
      status: summary.status,
    },
    hosts: summary.hosts,
  };

  const userPrompt = [
    "Here is the serialized scan summary as JSON.",
    "Base your report strictly on this data.",
    "",
    "=== BEGIN JSON ===",
    JSON.stringify(userContext, null, 2),
    "=== END JSON ===",
  ].join("\n");

  const response = await anthropic.messages.create({
    model: config.claudeModel,
    max_tokens: 2000,
    system: systemPrompt,
    messages: [
      {
        role: "user",
        content: userPrompt,
      },
    ],
  });

  const textParts: string[] = [];
  for (const block of response.content) {
    if (block.type === "text") {
      textParts.push(block.text);
    }
  }

  return textParts.join("\n\n").trim();
}

export async function generateAndStoreReportForLatestCompletedScan() {
  const db = getDb();

  const summary = loadLatestCompletedScan();
  if (!summary) {
    throw new Error("No completed scans found to generate a report from.");
  }

  const content = await generateReportFromSummary(summary);

  const scope = `scan_run:${summary.scanRunId}`;
  const generatedAt = new Date().toISOString();

  const promptMetadata = JSON.stringify(
    {
      model: config.claudeModel,
      scope,
      scanRunId: summary.scanRunId,
    },
    null,
    2
  );

  const stmt = db.prepare(
    "INSERT INTO reports (scope, generated_at, llm_model, prompt_metadata, content) VALUES (?, ?, ?, ?, ?)"
  );
  const info = stmt.run(scope, generatedAt, config.claudeModel, promptMetadata, content);

  const reportId = Number(info.lastInsertRowid);

  return {
    reportId,
    scanRunId: summary.scanRunId,
    scope,
    generatedAt,
    llmModel: config.claudeModel,
    content,
  };
}

