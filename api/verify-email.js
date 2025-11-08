// /api/verify-email.js — Vercel Serverless (Node 18, ESM)
import admin from "firebase-admin";

// Carga Service Account desde env (JSON string)
const saJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
if (!admin.apps.length) {
  if (!saJson) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON no definido");
  }
  const cred = JSON.parse(saJson);
  admin.initializeApp({ credential: admin.credential.cert(cred) });
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });

    // Verifica ID token del usuario que llama (debe ser admin)
    const decoded = await admin.auth().verifyIdToken(token);

    // Política de admin: claim o email permitido por env
    const allowedAdminEmail = (process.env.ADMIN_EMAIL || "").toLowerCase();
    const isAdminClaim = decoded.role === "admin";
    const isAdminEmail =
      !!allowedAdminEmail &&
      (decoded.email || "").toLowerCase() === allowedAdminEmail;

    if (!isAdminClaim && !isAdminEmail) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { uid } = req.body || {};
    if (!uid) return res.status(400).json({ error: "uid required" });

    await admin.auth().updateUser(uid, { emailVerified: true });
    const u = await admin.auth().getUser(uid);

    // (Opcional) espejar a Firestore
    await admin.firestore().doc(`medicos/${uid}`).set(
      {
        correoVerificado: true,
        verificadoPor: decoded.email || "admin",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    return res.status(200).json({ ok: true, emailVerified: u.emailVerified });
  } catch (e) {
    console.error("verify-email error:", e);
    return res.status(500).json({ error: e.message || String(e) });
  }
}

