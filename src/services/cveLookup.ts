export interface PortServiceDescriptor {
  hostId: number;
  hostIp: string;
  portId: number;
  port: number;
  protocol: string;
  serviceName?: string;
  serviceVersion?: string;
}

export interface CveCandidate {
  cveId: string;
  cvssScore?: number;
  severity?: string;
  description?: string;
  sourceUrl?: string;
}

/**
 * Look up CVE candidates for a given network service.
 *
 * This v1 implementation is intentionally conservative and returns an empty
 * list. It is wired into the processing pipeline so that a real lookup
 * implementation (e.g. NVD, Vulners, etc.) can be dropped in later without
 * changing callers.
 *
 * To implement a real lookup, replace the body of this function with an
 * adapter that calls your chosen CVE source and maps results into CveCandidate
 * objects.
 */
export async function lookupCvesForService(
  _svc: PortServiceDescriptor
): Promise<CveCandidate[]> {
  return [];
}

