## Network Security Auto Scanner

**Tech choices for v1**

- **Backend**: Express.js with TypeScript, running as a single service.
- **Database**: SQLite using `better-sqlite3` for a lightweight, file-based store that works well in a single-container deployment.
- **Scheduling**: `node-cron` inside the backend process for recurring scans.
- **Scanning**: `nmap` executed from within the container (installed by the Docker image).
- **LLM**: Cloud API (e.g. OpenAI) accessed via the `openai` SDK.

This setup favors simplicity and a small footprint for a single-server deployment, while still keeping the architecture modular enough to swap components (e.g. a different DB or scanner implementation) later.

