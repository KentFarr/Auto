import { Router } from "express";
import { getDb } from "../db";

const router = Router();

router.get("/", (_req, res) => {
  try {
    const db = getDb();
    const hosts = db
      .prepare(
        `SELECT h.id, h.ip, h.hostname, h.os_guess, h.is_up,
                COUNT(p.id) AS open_ports
         FROM hosts h
         LEFT JOIN ports p ON p.host_id = h.id AND p.state = 'open'
         GROUP BY h.id
         ORDER BY h.id DESC
         LIMIT 200`
      )
      .all();
    res.json(hosts);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ error: "Failed to list hosts" });
  }
});

export default router;

