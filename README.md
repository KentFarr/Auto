## Network Security Auto Scanner

Automated network security scanner using Nmap, CVE lookup, and LLM‑generated reports.

The service runs scheduled and on‑demand scans, stores results in SQLite, and exposes a simple HTTP API (Express + TypeScript).

---

### Tech stack

- **Language**: TypeScript (compiled to Node.js)
- **Framework**: Express
- **DB**: SQLite via `better-sqlite3`
- **Scheduling**: `node-cron`
- **Scanning**: `nmap` CLI
- **LLM**: `openai` SDK
- **Container**: Docker + `docker-compose`

---

### Prerequisites

- Node.js **20.x** (to match the Docker base image)
- npm
- (Optional) Docker and Docker Compose, if you want to run it in containers
- Nmap installed **only if** you plan to run directly on the host (Docker image already includes Nmap)

---

### Local development (no Docker)

1. **Install dependencies**

   ```bash
   npm install
   ```

2. **Configure environment**

   Create a `.env` file in the project root:

   ```bash
   # Claude / Anthropic API key (preferred)
   CLAUDE_API_KEY=your_claude_api_key_here

   # Optional: legacy OpenAI key if you wire it in elsewhere
   OPENAI_API_KEY=your_openai_api_key_here

   PORT=3000
   LOG_LEVEL=info
   DB_PATH=./data/db.sqlite
   SCAN_OUTPUT_DIR=./data/scans
   ```

   - `DB_PATH` and `SCAN_OUTPUT_DIR` can be any writable paths on your machine.

3. **Build the TypeScript code**

   ```bash
   npm run build
   ```

4. **Start the server**

   ```bash
   npm start
   ```

   The API will listen on `http://localhost:3000`.

5. **Health check**

   ```bash
   curl http://localhost:3000/health
   ```

   You should get:

   ```json
   { "status": "ok" }
   ```

---

### Development mode (auto‑reload)

For faster iteration you can run the TypeScript source directly:

```bash
npm run dev
```

This uses `ts-node-dev` to watch and restart the server on changes.

---

### Running with Docker

1. **Set environment variable for Docker**

   On your host, export your OpenAI key (Docker Compose will pass it through):

   ```bash
   export OPENAI_API_KEY=your_openai_api_key_here
   ```

   On Windows PowerShell:

   ```powershell
   $env:OPENAI_API_KEY="your_openai_api_key_here"
   ```

2. **Build and run via Docker Compose**

   ```bash
   docker-compose up --build
   ```

   - The app will run in a container named `network-security-autoscanner`.
   - SQLite DB and scan output are stored in the `app-data` Docker volume, mounted at `/data` in the container.

3. **Access the API**

   With `network_mode: host` in `docker-compose.yml`, the API is available on your host at:

   - `http://localhost:3000/health`
   - `http://localhost:3000/api/scans`
   - `http://localhost:3000/api/hosts`

4. **Stop the container**

   ```bash
   docker-compose down
   ```

---

### Project scripts

From `package.json`:

- `npm run build` – compile TypeScript from `src` to `dist`
- `npm start` – run the compiled server (`dist/server.js`)
- `npm run dev` – run the server in watch mode with `ts-node-dev`

---

### API overview (high level)

- `GET /health` – health check
- `GET /api/scans` – list scans and/or get scan status/results
- `POST /api/scans` – trigger a new scan (exact body depends on your `src/routes/scans.ts` implementation)
- `GET /api/hosts` – list discovered hosts / vulnerabilities

See the `src/routes` and `src/services` files for more details on parameters and behavior.

---

### Repository

This project is hosted at: `https://github.com/KentFarr/Auto`

