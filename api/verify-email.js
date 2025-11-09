// /api/verify-email.js — PING mínimo (Node 18, ESM)
export default async function handler(req, res) {
  try {
    res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed", stage: "ping" });

    return res.status(200).json({ ok: true, stage: "ping" });
  } catch (e) {
    console.error("ping error:", e);
    return res.status(500).json({ error: e.message || String(e), stage: "ping-catch" });
  }
}
