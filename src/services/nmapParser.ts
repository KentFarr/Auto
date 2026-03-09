import fs from "fs";
import { parseStringPromise } from "xml2js";

export interface ParsedPort {
  port: number;
  protocol: string;
  state: string;
  serviceName?: string;
  serviceVersion?: string;
}

export interface ParsedHost {
  address: string;
  hostname?: string;
  osGuess?: string;
  isUp: boolean;
  ports: ParsedPort[];
}

export async function parseNmapXml(filePath: string): Promise<ParsedHost[]> {
  const xml = await fs.promises.readFile(filePath, "utf-8");
  const doc = await parseStringPromise(xml);

  const hosts: ParsedHost[] = [];
  const hostNodes = doc.nmaprun && doc.nmaprun.host ? doc.nmaprun.host : [];

  for (const h of hostNodes) {
    const status = h.status?.[0]?.$.state ?? "down";
    const isUp = status === "up";

    const address = h.address?.[0]?.$.addr ?? "unknown";
    const hostname = h.hostnames?.[0]?.hostname?.[0]?.$.name;

    const osGuess =
      h.os?.[0]?.osmatch && h.os[0].osmatch[0]?.$.name
        ? h.os[0].osmatch[0].$.name
        : undefined;

    const ports: ParsedPort[] = [];
    const portNodes = h.ports?.[0]?.port ?? [];
    for (const p of portNodes) {
      const portid = Number(p.$.portid);
      const protocol = p.$.protocol;
      const state = p.state?.[0]?.$.state ?? "unknown";
      const serviceAttrs = p.service?.[0]?.$ ?? {};
      const serviceName = serviceAttrs.name;
      const serviceVersion =
        serviceAttrs.version || serviceAttrs.product || serviceAttrs.extrainfo;

      ports.push({
        port: portid,
        protocol,
        state,
        serviceName,
        serviceVersion,
      });
    }

    hosts.push({
      address,
      hostname,
      osGuess,
      isUp,
      ports,
    });
  }

  return hosts;
}

