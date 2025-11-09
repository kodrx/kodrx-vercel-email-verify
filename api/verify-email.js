import admin from "firebase-admin";

// Init Admin con Service Account de env
const saJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
if (!admin.apps.length) {
  if (!saJson) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON no definido");
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(saJson)) });
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// Lee body crudo y parsea JSON
async function readJsonBody(req) {
  const chunks = [];
  for await (const ch of req) chunks.push(ch);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  try { return JSON.parse(raw); }
  catch { throw new Error("Invalid JSON body"); }
}

export default async function handler(req, res) {
  cors(res);

  // Modo diagnóstico rápido por GET: no debe crashear
  if (req.method === "GET") {
    return res.status(405).json({ error: "Method not allowed", diag: true });
  }
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    // 1) Token del admin
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });

    const decoded = await admin.auth().verifyIdToken(token);

    // 2) Política admin (claim o email en env)
    const allowedAdminEmail = (process.env.ADMIN_EMAIL || "").toLowerCase();
    const isAdminClaim = decoded.role === "admin";
    const isAdminEmail = !!allowedAdminEmail && (decoded.email || "").toLowerCase() === allowedAdminEmail;
    if (!isAdminClaim && !isAdminEmail) return res.status(403).json({ error: "Forbidden" });

    // 3) Body
    const { uid } = await readJsonBody(req);
    if (!uid) return res.status(400).json({ error: "uid required" });

    // 4) Marca email verificado en Auth (sin Firestore)
    await admin.auth().updateUser(uid, { emailVerified: true });
    const u = await admin.auth().getUser(uid);

    // 5) Éxito
    return res.status(200).json({ ok: true, emailVerified: u.emailVerified });
  } catch (e) {
    console.error("verify-email error:", e);
    return res.status(500).json({ error: e.message || String(e) });
  }
}
