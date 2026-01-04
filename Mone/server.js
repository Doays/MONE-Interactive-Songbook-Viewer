import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import { promisify } from "util";
import { ChzzkClient } from "chzzk";
import dns from "dns";
import fs from "fs";
import fsp from "fs/promises";

dns.setDefaultResultOrder("ipv4first");
const fetchFn = globalThis.fetch;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.disable("x-powered-by");

app.set("trust proxy", Number(process.env.TRUST_PROXY ?? 1));
const PORT = Number(process.env.PORT ?? 8080);

// ✅ 데이터 저장 위치(서버에서는 /var/lib/... 권장)
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, "data");

const AUTH_FILE = path.join(DATA_DIR, "auth.json");
const SESS_FILE = path.join(DATA_DIR, "sessions.json");
const QUEUE_FILE = path.join(DATA_DIR, "queue.json");

const APPS_SCRIPT_URL =
  process.env.APPS_SCRIPT_URL ??
  "X";

const REFRESH_INTERVAL = Number(process.env.REFRESH_INTERVAL_MS ?? 60_000);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS ?? 12_000);

// CORS 필요 없으면 비움(동일 오리진만 사용)
const CORS_ORIGIN = process.env.CORS_ORIGIN ?? "";

// ✅ AUTH
const MASTER_PASSWORD = process.env.MASTER_PASSWORD ?? "O";
const DEFAULT_PASSWORD = process.env.DEFAULT_PASSWORD ?? "O";

const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS ?? 30);
const SESSION_TTL_MS = Math.max(1, SESSION_TTL_DAYS) * 24 * 60 * 60 * 1000;

const AUTH_COOKIE = "mone_sid";
const CSRF_COOKIE = "mone_csrf";

const COOKIE_SECURE =
  process.env.COOKIE_SECURE === "1" ||
  (process.env.NODE_ENV === "production" && process.env.COOKIE_SECURE !== "0");

// ✅ sessions 최적화 파라미터
const SESSION_LAST_SEEN_PERSIST_MS = Number(process.env.SESSION_LAST_SEEN_PERSIST_MS ?? 60_000); // lastSeenAt 디스크 반영 최소 간격
const SESS_WRITE_DEBOUNCE_MS = Number(process.env.SESS_WRITE_DEBOUNCE_MS ?? 5000);              // 300ms → 5s
const SESS_CLEANUP_INTERVAL_MS = Number(process.env.SESS_CLEANUP_INTERVAL_MS ?? 30 * 60 * 1000);

// ✅ login limiter OOM 방지
const LOGIN_LIMITER_TTL_MS = Number(process.env.LOGIN_LIMITER_TTL_MS ?? 30 * 60 * 1000);
const LOGIN_LIMITER_MAX = Number(process.env.LOGIN_LIMITER_MAX ?? 5000);

// ===== util =====
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
async function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) await fsp.mkdir(DATA_DIR, { recursive: true });
}
function sha256Hex(s) { return crypto.createHash("sha256").update(String(s)).digest("hex"); }
function randomTokenB64Url(bytes = 32) { return crypto.randomBytes(bytes).toString("base64url"); }
function timingSafeEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function parseCookies(req) {
  const raw = req.headers.cookie || "";
  const out = Object.create(null);
  raw.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!k) return;
    out[k] = decodeURIComponent(v);
  });
  return out;
}
function setCookie(res, name, value, opts = {}) {
  const parts = [];
  parts.push(`${name}=${encodeURIComponent(value ?? "")}`);
  parts.push(`Path=${opts.path ?? "/"}`);
  if (opts.maxAge != null) parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite ?? "Lax"}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  const prev = res.getHeader("Set-Cookie");
  const next = Array.isArray(prev) ? prev.concat(parts.join("; ")) : prev ? [prev, parts.join("; ")] : [parts.join("; ")];
  res.setHeader("Set-Cookie", next);
}
function clearCookie(res, name) {
  setCookie(res, name, "", { maxAge: 0, httpOnly: true, secure: COOKIE_SECURE, sameSite: "Lax" });
}
function getClientIp(req) { return (req.ip || "").replace("::ffff:", "") || "0.0.0.0"; }

async function writeFileAtomic(filePath, dataUtf8) {
  await ensureDataDir();
  const tmp = `${filePath}.tmp`;
  try {
    await fsp.writeFile(tmp, dataUtf8, "utf8");
    await fsp.rename(tmp, filePath);
  } catch {
    try { await fsp.writeFile(filePath, dataUtf8, "utf8"); } catch {}
    try { await fsp.unlink(tmp); } catch {}
  }
}

// ===== scrypt (async) =====
const scryptAsync = promisify(crypto.scrypt);

async function scryptHashAsync(password, saltB64) {
  const salt = saltB64 ? Buffer.from(saltB64, "base64") : crypto.randomBytes(16);
  const dk = await scryptAsync(String(password), salt, 64, { N: 16384, r: 8, p: 1 });
  return { alg: "scrypt", salt: salt.toString("base64"), hash: Buffer.from(dk).toString("base64") };
}
async function verifyScryptAsync(password, rec) {
  if (!rec || rec.alg !== "scrypt" || !rec.salt || !rec.hash) return false;
  const out = await scryptHashAsync(password, rec.salt);
  return timingSafeEq(out.hash, rec.hash);
}

// ===== csrf =====
function makeCsrfToken() { return randomTokenB64Url(24); }
function ensureCsrfCookie(req, res) {
  const cookies = parseCookies(req);
  let csrf = cookies[CSRF_COOKIE];
  if (!csrf || String(csrf).length < 10) {
    csrf = makeCsrfToken();
    setCookie(res, CSRF_COOKIE, csrf, {
      httpOnly: false,
      secure: COOKIE_SECURE,
      sameSite: "Lax",
      maxAge: SESSION_TTL_MS / 1000,
    });
  }
  return csrf;
}
function requireCsrf(req) {
  const cookies = parseCookies(req);
  const c = cookies[CSRF_COOKIE] || "";
  const h = req.headers["x-csrf-token"] || "";
  if (!c || !h) return false;
  return timingSafeEq(String(c), String(h));
}

// ===== security headers =====
app.use((req, res, next) => {
  const corp = CORS_ORIGIN ? "cross-origin" : "same-origin";

  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self' data: blob: https: http:;",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http:;",
      "style-src 'self' 'unsafe-inline' https: http:;",
      "img-src 'self' data: blob: https: http:;",
      "connect-src 'self' https: http:;",
      "font-src 'self' data: https: http:;",
      "frame-src 'self' https: http:;",
    ].join(" ")
  );

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", corp);
  next();
});

// ===== api cors (optional) =====
if (CORS_ORIGIN) {
  app.use("/api", (req, res, next) => {
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    if (CORS_ORIGIN === "*") res.setHeader("Access-Control-Allow-Origin", "*");
    else res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });
}

app.use(express.json({ limit: "512kb" }));

app.use(
  express.static(path.join(__dirname, "public"), {
    etag: true,
    maxAge: "1h",
  })
);

// ===== songbook cache =====
function shouldOmitGrid(req) {
  return req.query?.noGrid === "1" || req.query?.noGrid === "true";
}

let cache = {
  updatedAt: null,
  fetchedAt: null,
  songs: [],
  manual: [],
  manualGrid: null,
  dataHash: null,
  lastError: null,
};

let refreshInFlight = null;

function stableHash(payload) {
  const core = { songs: payload.songs ?? [], manual: payload.manual ?? [], manualGrid: payload.manualGrid ?? null };
  return crypto.createHash("sha1").update(JSON.stringify(core)).digest("hex");
}

async function fetchJsonWithTimeout(url, opts = {}) {
  const timeoutMs = Number(opts.timeoutMs ?? FETCH_TIMEOUT_MS);
  const extraHeaders = opts.headers ?? {};
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchFn(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "cache-control": "no-store", accept: "application/json", ...extraHeaders },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function refreshSongbook() {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const data = await fetchJsonWithTimeout(APPS_SCRIPT_URL);
        const nextPayload = {
          songs: data?.songs ?? [],
          manual: data?.manual ?? [],
          manualGrid: data?.manualGrid ?? null,
        };

        const nextHash = stableHash(nextPayload);
        const nowIso = new Date().toISOString();
        const changed = nextHash !== cache.dataHash;

        cache = {
          ...cache,
          songs: nextPayload.songs,
          manual: nextPayload.manual,
          manualGrid: nextPayload.manualGrid,
          dataHash: nextHash,
          fetchedAt: nowIso,
          updatedAt: changed ? nowIso : cache.updatedAt ?? nowIso,
          lastError: null,
        };
        return;
      } catch (e) {
        const msg = e?.name === "AbortError" ? "timeout" : (e?.message ?? String(e));
        cache.lastError = msg;
        if (attempt < 3) await sleep(600 * attempt + Math.floor(Math.random() * 120));
      }
    }
  })().finally(() => { refreshInFlight = null; });

  return refreshInFlight;
}

// ===== CHZZK =====
function normalizeChzzkChannelId(v) {
  const s = String(v ?? "").trim();
  if (!s) return "";
  const m = s.match(/chzzk\.naver\.com\/([0-9a-f]{32})/i);
  return m ? m[1] : s;
}
const CHZZK_CHANNEL_ID = normalizeChzzkChannelId(process.env.CHZZK_CHANNEL_ID || "5c897b3e639045ca6e314bbaff991f73");
const NID_AUT = process.env.NID_AUT;
const NID_SES = process.env.NID_SES;

const CHZZK_LIVE_POLL_MS = Number(process.env.CHZZK_LIVE_POLL_MS ?? 5000);
const CHZZK_HTTP_TIMEOUT_MS = Number(process.env.CHZZK_HTTP_TIMEOUT_MS ?? 15000);
const CHZZK_MISSION_LIMIT = Number(process.env.CHZZK_MISSION_LIMIT ?? 50);

const chzzkState = {
  live: { channelId: CHZZK_CHANNEL_ID || null, openLive: null, checkedAt: null, changedAt: null, lastError: null },
  chat: { connected: false, lastConnectAt: null, lastError: null },
  missions: [],
};
function pushMission(item) {
  chzzkState.missions.unshift(item);
  if (chzzkState.missions.length > CHZZK_MISSION_LIMIT) chzzkState.missions.length = CHZZK_MISSION_LIMIT;
}
async function pollChzzkLiveOnce() {
  if (!CHZZK_CHANNEL_ID) return;
  const url = `https://api.chzzk.naver.com/service/v1/channels/${CHZZK_CHANNEL_ID}`;
  try {
    const json = await fetchJsonWithTimeout(url, {
      timeoutMs: CHZZK_HTTP_TIMEOUT_MS,
      headers: {
        connection: "close",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        referer: "https://chzzk.naver.com/",
        origin: "https://chzzk.naver.com",
        "accept-language": "ko-KR,ko;q=0.9,en;q=0.8",
        accept: "application/json",
      },
    });

    const nextOpenLive = !!json?.content?.openLive;
    const nowIso = new Date().toISOString();
    const prev = chzzkState.live.openLive;
    const changed = prev !== null && prev !== nextOpenLive;

    chzzkState.live.openLive = nextOpenLive;
    chzzkState.live.checkedAt = nowIso;
    if (changed) chzzkState.live.changedAt = nowIso;
    chzzkState.live.lastError = null;
  } catch (e) {
    const msg = e?.name === "AbortError" ? "timeout" : (e?.message ?? String(e));
    chzzkState.live.lastError = msg;
    chzzkState.live.checkedAt = new Date().toISOString();
  }
}
async function startChzzkWatchers() {
  if (!CHZZK_CHANNEL_ID) return;

  await pollChzzkLiveOnce().catch(() => {});
  setInterval(() => pollChzzkLiveOnce().catch(() => {}), CHZZK_LIVE_POLL_MS);

  if (!NID_AUT || !NID_SES) return;

  try {
    const client = new ChzzkClient({ nidAuth: NID_AUT, nidSession: NID_SES });
    const chat = client.chat({ channelId: CHZZK_CHANNEL_ID, pollInterval: 30 * 1000 });

    chat.on("donation", (donation) => {
      const donationType = donation?.extras?.donationType ?? donation?.donationType ?? donation?.type ?? null;
      if (donationType !== "MISSION" && donationType !== "MISSION_PARTICIPATION") return;

      pushMission({
        at: new Date().toISOString(),
        donationType,
        from: donation?.profile?.nickname ?? donation?.extras?.nickname ?? donation?.nickname ?? "익명",
        amount: donation?.extras?.payAmount ?? donation?.payAmount ?? null,
        text: donation?.message ?? donation?.extras?.message ?? donation?.extras?.missionText ?? "",
        raw: donation,
      });
    });

    chat.on("connect", () => {
      chzzkState.chat.connected = true;
      chzzkState.chat.lastConnectAt = new Date().toISOString();
      chzzkState.chat.lastError = null;
    });
    chat.on("disconnect", () => { chzzkState.chat.connected = false; });
    chat.on("reconnect", () => {
      chzzkState.chat.connected = true;
      chzzkState.chat.lastConnectAt = new Date().toISOString();
    });

    await chat.connect();
  } catch (e) {
    chzzkState.chat.connected = false;
    chzzkState.chat.lastError = e?.message ?? String(e);
  }
}

// ===== AUTH state =====
let authRecord = null; // { alg, salt, hash, updatedAt }
let sessions = new Map(); // key: sessionHashHex -> { createdAt,lastSeenAt,expiresAt,ipHash,uaHash }

let sessionsDirty = false;
let sessionsWriteTimer = null;
let sessionsWriting = false;

const sessionLastPersistedAt = new Map(); // key -> lastSeenAt(마지막 디스크 반영 시각)

function scheduleSessionsWrite() {
  sessionsDirty = true;
  if (sessionsWriteTimer) return;

  sessionsWriteTimer = setTimeout(async () => {
    sessionsWriteTimer = null;
    if (sessionsWriting) return;
    sessionsWriting = true;

    try {
      while (sessionsDirty) {
        sessionsDirty = false;

        const obj = {};
        for (const [k, v] of sessions.entries()) obj[k] = v;

        const payload = JSON.stringify({ v: 1, items: obj });
        await writeFileAtomic(SESS_FILE, payload);
      }
    } catch {
      // ignore
    } finally {
      sessionsWriting = false;
    }
  }, SESS_WRITE_DEBOUNCE_MS);
}

async function loadSessions() {
  await ensureDataDir();
  try {
    const raw = await fsp.readFile(SESS_FILE, "utf8");
    const j = JSON.parse(raw);
    const items = j?.items && typeof j.items === "object" ? j.items : {};
    sessions = new Map(Object.entries(items));

    sessionLastPersistedAt.clear();
    for (const [k, v] of sessions.entries()) {
      sessionLastPersistedAt.set(k, Number(v?.lastSeenAt ?? 0) || 0);
    }
  } catch {
    sessions = new Map();
    sessionLastPersistedAt.clear();
  }
}

function cleanupSessions() {
  const t = Date.now();
  let changed = false;

  for (const [k, v] of sessions.entries()) {
    if (!v || typeof v !== "object") {
      sessions.delete(k);
      sessionLastPersistedAt.delete(k);
      changed = true;
      continue;
    }
    if (Number(v.expiresAt ?? 0) <= t) {
      sessions.delete(k);
      sessionLastPersistedAt.delete(k);
      changed = true;
    }
  }

  if (changed) scheduleSessionsWrite();
}

async function loadOrInitAuth() {
  await ensureDataDir();
  try {
    const raw = await fsp.readFile(AUTH_FILE, "utf8");
    const j = JSON.parse(raw);
    if (j?.alg && j?.salt && j?.hash) {
      authRecord = { alg: j.alg, salt: j.salt, hash: j.hash, updatedAt: j.updatedAt ?? null };
      return;
    }
  } catch {}

  const rec = await scryptHashAsync(DEFAULT_PASSWORD);
  authRecord = { ...rec, updatedAt: new Date().toISOString() };
  await writeFileAtomic(AUTH_FILE, JSON.stringify(authRecord));
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req);
  const token = cookies[AUTH_COOKIE];
  if (!token || String(token).length < 16) return null;

  const key = sha256Hex(token);
  const rec = sessions.get(key);
  if (!rec) return null;

  const t = Date.now();
  if (Number(rec.expiresAt ?? 0) <= t) {
    sessions.delete(key);
    sessionLastPersistedAt.delete(key);
    scheduleSessionsWrite();
    return null;
  }

  rec.lastSeenAt = t;
  sessions.set(key, rec);

  const lastP = sessionLastPersistedAt.get(key) || 0;
  if (t - lastP >= SESSION_LAST_SEEN_PERSIST_MS) {
    sessionLastPersistedAt.set(key, t);
    scheduleSessionsWrite();
  }

  return { token, key, rec };
}

function setAuthSession(res, token, ttlMs) {
  setCookie(res, AUTH_COOKIE, token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "Lax",
    maxAge: Math.floor(ttlMs / 1000),
  });
}

// login limiter
const loginLimiter = new Map(); // ip -> { fail, resetAt, blockUntil, lastAt }

function gcLoginLimiter() {
  const t = Date.now();

  for (const [ip, rec] of loginLimiter.entries()) {
    const lastAt = Number(rec?.lastAt ?? 0) || 0;
    const resetAt = Number(rec?.resetAt ?? 0) || 0;
    const blockUntil = Number(rec?.blockUntil ?? 0) || 0;

    if (t - lastAt > LOGIN_LIMITER_TTL_MS && t > resetAt && t > blockUntil) {
      loginLimiter.delete(ip);
    }
  }

  if (loginLimiter.size > LOGIN_LIMITER_MAX) {
    const arr = [];
    for (const [ip, rec] of loginLimiter.entries()) arr.push([ip, Number(rec?.lastAt ?? 0) || 0]);
    arr.sort((a, b) => a[1] - b[1]);
    const over = loginLimiter.size - LOGIN_LIMITER_MAX;
    for (let i = 0; i < over; i++) loginLimiter.delete(arr[i][0]);
  }
}

function checkLoginRateLimit(ip) {
  const t = Date.now();
  const rec = loginLimiter.get(ip) || { fail: 0, resetAt: t + 10 * 60 * 1000, blockUntil: 0, lastAt: t };
  if (rec.blockUntil && t < rec.blockUntil) return { ok: false };
  if (t > rec.resetAt) { rec.fail = 0; rec.resetAt = t + 10 * 60 * 1000; rec.blockUntil = 0; }
  rec.lastAt = t;
  loginLimiter.set(ip, rec);
  return { ok: true };
}
function markLoginFail(ip) {
  const t = Date.now();
  const rec = loginLimiter.get(ip) || { fail: 0, resetAt: t + 10 * 60 * 1000, blockUntil: 0, lastAt: t };
  if (t > rec.resetAt) { rec.fail = 0; rec.resetAt = t + 10 * 60 * 1000; }
  rec.fail += 1;
  if (rec.fail >= 10) rec.blockUntil = t + 15 * 60 * 1000;
  rec.lastAt = t;
  loginLimiter.set(ip, rec);
}
function markLoginSuccess(ip) { loginLimiter.delete(ip); }

// ===== QUEUE =====
let queueState = { v: 1, updatedAt: null, nextOrder: 1, nowPlayingKey: null, items: {} };
let queueDirty = false;
let queueWriteTimer = null;
let queueWriting = false;

function scheduleQueueWrite() {
  queueDirty = true;
  if (queueWriteTimer) return;

  queueWriteTimer = setTimeout(async () => {
    queueWriteTimer = null;
    if (queueWriting) return;
    queueWriting = true;

    try {
      while (queueDirty) {
        queueDirty = false;
        const payload = JSON.stringify(queueState);
        await writeFileAtomic(QUEUE_FILE, payload);
      }
    } catch {
      // ignore
    } finally {
      queueWriting = false;
    }
  }, 500);
}
function touchQueue() {
  queueState.updatedAt = new Date().toISOString();
  scheduleQueueWrite();
}
async function loadQueue() {
  await ensureDataDir();
  try {
    const raw = await fsp.readFile(QUEUE_FILE, "utf8");
    const j = JSON.parse(raw);
    if (j && typeof j === "object") {
      queueState = {
        v: 1,
        updatedAt: j.updatedAt ?? null,
        nextOrder: Number(j.nextOrder ?? 1) || 1,
        nowPlayingKey: j.nowPlayingKey ?? null,
        items: (j.items && typeof j.items === "object") ? j.items : {},
      };
      return;
    }
  } catch {}
  queueState.updatedAt = new Date().toISOString();
  scheduleQueueWrite();
}

// ===== APIs =====
app.post("/api/auth/login", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  const ip = getClientIp(req);
  if (!checkLoginRateLimit(ip).ok) return res.status(429).json({ ok: false, error: "too_many_requests" });

  const password = String(req.body?.password ?? "");
  const csrf = ensureCsrfCookie(req, res);

  const isMaster = password && timingSafeEq(password, MASTER_PASSWORD);
  const isOk = isMaster || await verifyScryptAsync(password, authRecord);

  if (!isOk) {
    markLoginFail(ip);
    return res.status(401).json({ ok: false, authenticated: false, error: "invalid" });
  }

  markLoginSuccess(ip);

  const token = randomTokenB64Url(32);
  const key = sha256Hex(token);
  const t = Date.now();
  const rec = {
    createdAt: t,
    lastSeenAt: t,
    expiresAt: t + SESSION_TTL_MS,
    ipHash: sha256Hex(ip),
    uaHash: sha256Hex(String(req.headers["user-agent"] ?? "")),
  };
  sessions.set(key, rec);
  sessionLastPersistedAt.set(key, t);
  scheduleSessionsWrite();

  setAuthSession(res, token, SESSION_TTL_MS);
  return res.json({ ok: true, authenticated: true, csrf, expiresAt: rec.expiresAt });
});

app.get("/api/auth/me", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  ensureCsrfCookie(req, res);
  const s = getSessionFromReq(req);
  if (!s) return res.json({ ok: true, authenticated: false });
  return res.json({ ok: true, authenticated: true, expiresAt: s.rec.expiresAt, lastSeenAt: s.rec.lastSeenAt });
});

app.post("/api/auth/logout", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!requireCsrf(req)) return res.status(403).json({ ok: false, error: "csrf" });

  const s = getSessionFromReq(req);
  if (s) {
    sessions.delete(s.key);
    sessionLastPersistedAt.delete(s.key);
    scheduleSessionsWrite();
  }
  clearCookie(res, AUTH_COOKIE);
  return res.json({ ok: true });
});

app.post("/api/auth/change-password", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!requireCsrf(req)) return res.status(403).json({ ok: false, error: "csrf" });

  const s = getSessionFromReq(req);
  if (!s) return res.status(401).json({ ok: false, error: "unauthorized" });

  const currentPassword = String(req.body?.currentPassword ?? "");
  const newPassword = String(req.body?.newPassword ?? "");

  if (!newPassword || newPassword.length < 4 || newPassword.length > 64)
    return res.status(400).json({ ok: false, error: "bad_new_password" });
  if (timingSafeEq(newPassword, MASTER_PASSWORD))
    return res.status(400).json({ ok: false, error: "reserved" });

  const isMaster = currentPassword && timingSafeEq(currentPassword, MASTER_PASSWORD);
  const isOk = isMaster || await verifyScryptAsync(currentPassword, authRecord);
  if (!isOk) return res.status(401).json({ ok: false, error: "invalid" });

  const rec = await scryptHashAsync(newPassword);
  authRecord = { ...rec, updatedAt: new Date().toISOString() };
  await writeFileAtomic(AUTH_FILE, JSON.stringify(authRecord));
  return res.json({ ok: true });
});

// queue (ETag 지원)
app.get("/api/queue", (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  const etag = `W/"queue-${queueState.updatedAt ?? "0"}"`;
  if (req.headers["if-none-match"] === etag) return res.status(304).end();

  res.setHeader("ETag", etag);
  res.json({ ok: true, queue: queueState });
});

app.post("/api/queue/action", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!requireCsrf(req)) return res.status(403).json({ ok: false, error: "csrf" });
  const s = getSessionFromReq(req);
  if (!s) return res.status(401).json({ ok: false, error: "unauthorized" });

  const type = String(req.body?.type ?? "");
  const key = String(req.body?.key ?? "").trim();
  if (!type) return res.status(400).json({ ok: false, error: "bad_type" });

  const ensurePending = (k) => {
    const it = queueState.items[k];
    if (!it) queueState.items[k] = { status: "pending", order: queueState.nextOrder++ };
    else {
      if (it.status !== "pending") it.status = "pending";
      if (!it.order) it.order = queueState.nextOrder++;
    }
  };

  if (type === "toggle") {
    if (!key) return res.status(400).json({ ok: false, error: "bad_key" });
    const it = queueState.items[key];
    if (!it) queueState.items[key] = { status: "pending", order: queueState.nextOrder++ };
    else if (it.status === "pending") {
      delete queueState.items[key];
      if (queueState.nowPlayingKey === key) queueState.nowPlayingKey = null;
    } else {
      queueState.items[key] = { status: "pending", order: queueState.nextOrder++ };
    }
    touchQueue();
    return res.json({ ok: true, queue: queueState });
  }

  if (type === "nowPlaying") {
    if (!key) return res.status(400).json({ ok: false, error: "bad_key" });
    ensurePending(key);
    queueState.nowPlayingKey = key;
    touchQueue();
    return res.json({ ok: true, queue: queueState });
  }

  if (type === "done") {
    const np = queueState.nowPlayingKey;
    if (!np) return res.json({ ok: true, queue: queueState });
    queueState.items[np] = queueState.items[np] || { status: "pending", order: queueState.nextOrder++ };
    queueState.items[np].status = "done";
    queueState.nowPlayingKey = null;
    touchQueue();
    return res.json({ ok: true, queue: queueState });
  }

  if (type === "clear") {
    queueState.items = {};
    queueState.nowPlayingKey = null;
    queueState.nextOrder = 1;
    touchQueue();
    return res.json({ ok: true, queue: queueState });
  }

  return res.status(400).json({ ok: false, error: "unknown_type" });
});

// songbook
app.get("/api/songbook", (req, res) => {
  const omitGrid = shouldOmitGrid(req);

  const body = {
    ok: true,
    updatedAt: cache.updatedAt,
    fetchedAt: cache.fetchedAt,
    songs: cache.songs,
    manual: cache.manual,
    manualGrid: omitGrid ? null : cache.manualGrid,
    lastError: cache.lastError,
  };

  const etag = `W/"songbook-${cache.dataHash ?? "0"}-${omitGrid ? "nogrid" : "grid"}"`;
  if (req.headers["if-none-match"] === etag) return res.status(304).end();

  res.setHeader("ETag", etag);
  res.setHeader("Cache-Control", "public, max-age=5, stale-while-revalidate=60");
  res.type("json").send(JSON.stringify(body));
});

app.post("/api/refresh", async (req, res) => {
  if (!requireCsrf(req)) return res.status(403).json({ ok: false, error: "csrf" });
  const s = getSessionFromReq(req);
  if (!s) return res.status(401).json({ ok: false, error: "unauthorized" });
  await refreshSongbook();
  res.json({ ok: true, updatedAt: cache.updatedAt, fetchedAt: cache.fetchedAt, lastError: cache.lastError });
});

// chzzk
app.get("/api/chzzk/live", (req, res) => res.json({ ok: true, ...chzzkState.live }));
app.get("/api/chzzk/missions", (req, res) => {
  const limit = Math.max(1, Math.min(CHZZK_MISSION_LIMIT, Number(req.query.limit ?? 10)));
  res.json({ ok: true, items: chzzkState.missions.slice(0, limit) });
});

app.get("/healthz", (req, res) => {
  res.json({
    ok: true,
    updatedAt: cache.updatedAt,
    fetchedAt: cache.fetchedAt,
    lastError: cache.lastError,
    chzzk: { live: chzzkState.live, chat: chzzkState.chat, missionsCount: chzzkState.missions.length },
  });
});

app.get("/.well-known/appspecific/com.chrome.devtools.json", (_, res) => res.status(204).end());
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ===== boot =====
async function boot() {
  await ensureDataDir();
  await loadOrInitAuth();
  await loadSessions();
  cleanupSessions();
  scheduleSessionsWrite();

  await loadQueue();

  await refreshSongbook();
  setInterval(() => refreshSongbook().catch(() => {}), REFRESH_INTERVAL);

  // ✅ 주기 관리(누수/만료 정리)
  setInterval(() => cleanupSessions(), SESS_CLEANUP_INTERVAL_MS);
  setInterval(() => gcLoginLimiter(), 5 * 60 * 1000);

  startChzzkWatchers().catch(() => {});
  app.listen(PORT, () => console.log(`🚀 http://127.0.0.1:${PORT}`));
}
boot().catch((e) => {
  console.error("❌ boot fail:", e?.message ?? String(e));
  process.exit(1);
});
