import { getDb } from "../db";
import { parseNmapXml } from "./nmapParser";
import { lookupCvesForService, PortServiceDescriptor } from "./cveLookup";

export async function processScanResults(scanRunId: number, xmlPath: string) {
  const db = getDb();
  const hosts = await parseNmapXml(xmlPath);

  const insertHost = db.prepare(
    "INSERT INTO hosts (scan_run_id, ip, hostname, os_guess, is_up) VALUES (?, ?, ?, ?, ?)"
  );
  const insertPort = db.prepare(
    "INSERT INTO ports (host_id, port, protocol, state, service_name, service_version) VALUES (?, ?, ?, ?, ?, ?)"
  );

  const insertCveRecord = db.prepare(
    "INSERT INTO cve_records (cve_id, cvss_score, severity, description, source_url) VALUES (?, ?, ?, ?, ?)"
  );
  const selectCveRecord = db.prepare(
    "SELECT id, cve_id, cvss_score, severity, description, source_url FROM cve_records WHERE cve_id = ? LIMIT 1"
  );
  const updateCveRecord = db.prepare(
    "UPDATE cve_records SET cvss_score = ?, severity = ?, description = ?, source_url = ? WHERE id = ?"
  );

  const insertHostCve = db.prepare(
    "INSERT INTO host_cves (host_id, cve_record_id, first_seen, last_seen) VALUES (?, ?, ?, ?)"
  );
  const selectHostCve = db.prepare(
    "SELECT id, first_seen, last_seen FROM host_cves WHERE host_id = ? AND cve_record_id = ? LIMIT 1"
  );
  const updateHostCveLastSeen = db.prepare(
    "UPDATE host_cves SET last_seen = ? WHERE id = ?"
  );

  const insertVulnFinding = db.prepare(
    "INSERT INTO vulnerability_findings (port_id, summary, severity, source) VALUES (?, ?, ?, ?)"
  );
  const selectExistingVulnFinding = db.prepare(
    "SELECT id FROM vulnerability_findings WHERE port_id = ? AND summary = ? AND source = ? LIMIT 1"
  );

  const portsForLookup: PortServiceDescriptor[] = [];

  const tx = db.transaction(() => {
    for (const h of hosts) {
      const hostInfo = insertHost.run(
        scanRunId,
        h.address,
        h.hostname ?? null,
        h.osGuess ?? null,
        h.isUp ? 1 : 0
      );
      const hostId = Number(hostInfo.lastInsertRowid);

      for (const p of h.ports) {
        const portInfo = insertPort.run(
          hostId,
          p.port,
          p.protocol,
          p.state,
          p.serviceName ?? null,
          p.serviceVersion ?? null
        );

        const portId = Number(portInfo.lastInsertRowid);

        portsForLookup.push({
          hostId,
          hostIp: h.address,
          portId,
          port: p.port,
          protocol: p.protocol,
          serviceName: p.serviceName,
          serviceVersion: p.serviceVersion,
        });
      }
    }
  });

  tx();

  const nowIso = new Date().toISOString();

  for (const svc of portsForLookup) {
    // Only attempt CVE lookup for open ports with a known service name.
    if (!svc.serviceName) {
      continue;
    }

    // eslint-disable-next-line no-await-in-loop
    const cves = await lookupCvesForService(svc);

    for (const cve of cves) {
      // Ensure there is a cve_records row for this CVE.
      const existingCve = selectCveRecord.get(cve.cveId) as
        | {
            id: number;
            cve_id: string;
            cvss_score: number | null;
            severity: string | null;
            description: string | null;
            source_url: string | null;
          }
        | undefined;

      let cveRecordId: number;

      if (!existingCve) {
        const info = insertCveRecord.run(
          cve.cveId,
          cve.cvssScore ?? null,
          cve.severity ?? null,
          cve.description ?? null,
          cve.sourceUrl ?? null
        );
        cveRecordId = Number(info.lastInsertRowid);
      } else {
        const mergedCvss =
          cve.cvssScore !== undefined ? cve.cvssScore : existingCve.cvss_score;
        const mergedSeverity =
          cve.severity !== undefined ? cve.severity : existingCve.severity;
        const mergedDescription =
          cve.description !== undefined
            ? cve.description
            : existingCve.description;
        const mergedSourceUrl =
          cve.sourceUrl !== undefined ? cve.sourceUrl : existingCve.source_url;

        updateCveRecord.run(
          mergedCvss ?? null,
          mergedSeverity ?? null,
          mergedDescription ?? null,
          mergedSourceUrl ?? null,
          existingCve.id
        );
        cveRecordId = existingCve.id;
      }

      // Link CVE to host, tracking first/last seen timestamps.
      const existingHostCve = selectHostCve.get(
        svc.hostId,
        cveRecordId
      ) as
        | {
            id: number;
            first_seen: string;
            last_seen: string;
          }
        | undefined;

      if (!existingHostCve) {
        insertHostCve.run(svc.hostId, cveRecordId, nowIso, nowIso);
      } else {
        updateHostCveLastSeen.run(nowIso, existingHostCve.id);
      }

      const summaryParts = [
        cve.cveId,
        cve.description || "CVE matched for detected service.",
      ];
      const summary = summaryParts.filter(Boolean).join(" - ");

      const existingFinding = selectExistingVulnFinding.get(
        svc.portId,
        summary,
        "cve_lookup"
      ) as { id: number } | undefined;

      if (!existingFinding) {
        insertVulnFinding.run(
          svc.portId,
          summary,
          cve.severity ?? null,
          "cve_lookup"
        );
      }
    }
  }

  return { hostsCount: hosts.length };
}

