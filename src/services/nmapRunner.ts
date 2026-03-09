import { exec } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import { config } from "../config";

const execAsync = promisify(exec);

export interface NmapRunOptions {
  target: string;
  flags: string;
}

export interface NmapRunResult {
  command: string;
  stdoutPath: string;
  stderr: string;
}

function ensureScanDir() {
  if (!fs.existsSync(config.scanOutputDir)) {
    fs.mkdirSync(config.scanOutputDir, { recursive: true });
  }
}

export async function runNmapScan(options: NmapRunOptions): Promise<NmapRunResult> {
  ensureScanDir();
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const fileBase = `scan-${timestamp}.xml`;
  const outPath = path.join(config.scanOutputDir, fileBase);

  const command = `nmap ${options.flags} -oX "${outPath}" ${options.target}`;

  const { stderr } = await execAsync(command);

  return {
    command,
    stdoutPath: outPath,
    stderr,
  };
}

