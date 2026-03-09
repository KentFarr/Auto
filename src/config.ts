import dotenv from "dotenv";

dotenv.config();

export const config = {
  port: Number(process.env.PORT) || 3000,
  logLevel: process.env.LOG_LEVEL || "info",
  dbPath: process.env.DB_PATH || "data/db.sqlite",
  scanOutputDir: process.env.SCAN_OUTPUT_DIR || "data/scans",
  defaultCidr: process.env.SCAN_DEFAULT_CIDR || "192.168.1.0/24",
  openAiApiKey: process.env.OPENAI_API_KEY || "",
};
