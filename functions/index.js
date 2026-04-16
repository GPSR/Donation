const crypto = require("node:crypto");
const admin = require("firebase-admin");
const { onRequest } = require("firebase-functions/v2/https");

if (!admin.apps.length) {
  admin.initializeApp();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password || ""), "utf8").digest("hex");
}

function hashValue(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");
}

function sendJson(res, status, body) {
  res.status(status).set("Content-Type", "application/json").send(JSON.stringify(body));
}

function setCors(req, res, methods) {
  const origin = req.headers.origin || "";
  const allowedOrigins = new Set([
    "https://gpsr.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173"
  ]);
  if (allowedOrigins.has(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
  }
  res.set("Vary", "Origin");
  res.set("Access-Control-Allow-Methods", methods);
  res.set("Access-Control-Allow-Headers", "Content-Type");
}

function getPublicConfig() {
  const projectId = String(process.env.FIREBASE_PROJECT_ID || "").trim();
  return {
    firebase: {
      apiKey: String(process.env.FIREBASE_API_KEY || "").trim(),
      authDomain: String(process.env.FIREBASE_AUTH_DOMAIN || "").trim(),
      projectId,
      storageBucket: String(process.env.FIREBASE_STORAGE_BUCKET || "").trim(),
      messagingSenderId: String(process.env.FIREBASE_MESSAGING_SENDER_ID || "").trim(),
      appId: String(process.env.FIREBASE_APP_ID || "").trim(),
      measurementId: String(process.env.FIREBASE_MEASUREMENT_ID || "").trim()
    },
    adminApiUrl: `https://us-central1-${projectId}.cloudfunctions.net/adminLogin`
  };
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.ip || "unknown";
}

async function enforceAdminRateLimit(firestore, email, ip) {
  const key = hashValue(`${normalizeEmail(email)}|${ip}`);
  const ref = firestore.collection("adminLoginAttempts").doc(key);
  const snap = await ref.get();
  const now = Date.now();
  if (!snap.exists) return { allowed: true, ref };

  const data = snap.data() || {};
  const blockedUntil = data.blockedUntil ? new Date(data.blockedUntil).getTime() : 0;
  if (blockedUntil > now) {
    return { allowed: false, ref, retryAt: blockedUntil };
  }
  return { allowed: true, ref };
}

async function recordAdminFailure(ref) {
  const snap = await ref.get();
  const now = new Date();
  const nowMs = now.getTime();
  const windowMs = 15 * 60 * 1000;
  const existing = snap.exists ? snap.data() || {} : {};
  const firstFailedAtMs = existing.firstFailedAt ? new Date(existing.firstFailedAt).getTime() : nowMs;
  const inWindow = nowMs - firstFailedAtMs < windowMs;
  const failedCount = inWindow ? (Number(existing.failedCount || 0) + 1) : 1;
  const blockedUntil = failedCount >= 5 ? new Date(nowMs + windowMs).toISOString() : null;

  await ref.set(
    {
      failedCount,
      firstFailedAt: inWindow ? existing.firstFailedAt || now.toISOString() : now.toISOString(),
      lastFailedAt: now.toISOString(),
      blockedUntil
    },
    { merge: true }
  );
}

async function clearAdminFailures(ref) {
  await ref.delete().catch(() => {});
}

exports.appConfig = onRequest({ region: "us-central1" }, async (req, res) => {
  setCors(req, res, "GET, OPTIONS");
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "GET") {
    sendJson(res, 405, { error: "method-not-allowed" });
    return;
  }

  const payload = getPublicConfig();
  if (!payload.firebase.projectId || !payload.firebase.apiKey) {
    sendJson(res, 500, { error: "app-config-missing" });
    return;
  }

  res.set("Cache-Control", "public, max-age=300, s-maxage=300");
  sendJson(res, 200, payload);
});

exports.adminLogin = onRequest({ region: "us-central1" }, async (req, res) => {
  setCors(req, res, "POST, OPTIONS");
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method-not-allowed" });
    return;
  }

  const configuredEmail = normalizeEmail(process.env.ADMIN_EMAIL);
  const configuredHash = String(process.env.ADMIN_PASS_HASH || "").trim();
  if (!configuredEmail || !configuredHash) {
    sendJson(res, 500, { error: "admin-config-missing" });
    return;
  }

  const body = req.body || {};
  const email = normalizeEmail(body.email);
  const passwordHash = hashPassword(body.password);

  const emailMatches = email === configuredEmail;
  const hashMatches =
    configuredHash.length === passwordHash.length &&
    crypto.timingSafeEqual(Buffer.from(configuredHash), Buffer.from(passwordHash));

  const auth = admin.auth();
  const firestore = admin.firestore();
  const adminUid = "admin-root";
  const adminName = "Admin";
  const ip = getClientIp(req);
  let rate = null;

  try {
    res.set("Cache-Control", "private, no-store");
    rate = await enforceAdminRateLimit(firestore, email, ip);
    if (!rate.allowed) {
      sendJson(res, 429, { error: "too-many-attempts" });
      return;
    }

    if (!emailMatches || !hashMatches) {
      await recordAdminFailure(rate.ref);
      sendJson(res, 401, { error: "invalid-credentials" });
      return;
    }

    try {
      await auth.getUser(adminUid);
    } catch {
      await auth.createUser({ uid: adminUid, email: configuredEmail, displayName: adminName });
    }

    await auth.setCustomUserClaims(adminUid, { role: "admin" });

    const userQuery = await firestore.collection("users").where("email", "==", configuredEmail).limit(1).get();
    let userDocRef;
    if (userQuery.empty) {
      userDocRef = await firestore.collection("users").add({
        email: configuredEmail,
        name: adminName,
        role: "admin",
        createdAt: new Date().toISOString()
      });
    } else {
      userDocRef = userQuery.docs[0].ref;
      await userDocRef.set(
        {
          email: configuredEmail,
          name: adminName,
          role: "admin",
          updatedAt: new Date().toISOString()
        },
        { merge: true }
      );
    }

    const customToken = await auth.createCustomToken(adminUid, { role: "admin" });
    await clearAdminFailures(rate.ref);
    sendJson(res, 200, {
      customToken,
      user: {
        id: userDocRef.id,
        email: configuredEmail,
        name: adminName,
        role: "admin"
      }
    });
  } catch (error) {
    console.error("adminLogin failed", error);
    try {
      if (rate && rate.ref) await recordAdminFailure(rate.ref);
    } catch (rateError) {
      console.error("adminLogin rate-limit update failed", rateError);
    }
    sendJson(res, 500, { error: "admin-login-failed" });
  }
});
