// ============================================================
// Shadow AI Detector - Backend Server
// Pure Node.js, ZERO external packages. Run:  node server.js
// ------------------------------------------------------------
// - Receives behaviour events from the Chrome extension
// - Classifies them with 6 detection rules
// - Serves the admin dashboard
// - Admin login + tamper-resistant audit trail
// ============================================================

const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const crypto = require("crypto");
const { detectSensitivePatterns } = require("./sensitive-patterns");
const PORT = 3000;
const DB_FILE = path.join(__dirname, "events.json");
const AUDIT_FILE = path.join(__dirname, "audit.json");
const DASHBOARD_FILE = path.join(__dirname, "../dashboard/dashboard.html");

// ── Admin credentials ────────────────────────────────────────
// Overridable via environment variables (SAI_ADMIN_USER / SAI_ADMIN_PASS)
// so real credentials are never hardcoded or committed. Falls back to the
// original demo defaults ONLY so local/offline testing keeps working out
// of the box — a clear warning prints at startup whenever that fallback
// is in use (see server.listen below).
const ADMIN_USER = process.env.SAI_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.SAI_ADMIN_PASS || "12341234";
const USING_DEFAULT_CREDS = !process.env.SAI_ADMIN_USER || !process.env.SAI_ADMIN_PASS;

// In-memory login tokens { token: expiryTimestamp }. 2-hour sessions.
const sessions = {};
const SESSION_MS = 2 * 60 * 60 * 1000;

// ── Tiny JSON "database" ────────────────────────────────────
function loadJson(file) {
  if (!fs.existsSync(file)) return [];
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return []; }
}
function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
const loadEvents = () => loadJson(DB_FILE);
const saveEvents = (e) => saveJson(DB_FILE, e);

// Audit log is append-only: we never overwrite past entries.
function appendAudit(entry) {
  const log = loadJson(AUDIT_FILE);
  log.push({ ...entry, time: new Date().toISOString() });
  saveJson(AUDIT_FILE, log);
}

// ── Rank helper so we can keep the HIGHEST risk found ───────
const RANK = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
const higher = (a, b) => (RANK[a] >= RANK[b] ? a : b);

// ── Risk Classification Engine (6 rules) ────────────────────
function classifyEvent(event) {
  const { type, pasteLength, keywords, promptCount, text, pasteCount, bulk } = event;
  let risk = "LOW";
  const flags = [];

  // Rule 1 — File upload to an AI tool or social platform
  if (type === "file_upload") {
    risk = higher(risk, "HIGH");
    flags.push(bulk ? "Bulk file upload (multiple files at once)" : "File upload to AI tool");
  }
  // Rule 2 — Sensitive keyword match
  if (type === "sensitive_keyword" && keywords && keywords.length > 0) {
    risk = higher(risk, "HIGH");
    flags.push("Sensitive keywords: " + keywords.join(", "));
  }
  // Rule 3 — Large clipboard paste (SIZE of one paste)
  if (type === "large_paste") {
    if (pasteLength > 2000) { risk = higher(risk, "HIGH"); flags.push("Very large paste: " + pasteLength + " chars"); }
    else { risk = higher(risk, "MEDIUM"); flags.push("Large paste: " + pasteLength + " chars"); }
  }
  // Rule 4 — Rapid prompt submissions
  if (type === "rapid_prompts") {
    risk = higher(risk, "MEDIUM");
    flags.push("Rapid prompts: " + promptCount + " in 60s");
  }
  // Rule 5 — Sensitive data PATTERN detection (runs on any text we receive)
  if (text) {
    const pat = detectSensitivePatterns(text);
    if (pat.matches.length > 0) {
      risk = higher(risk, pat.risk);
      flags.push("Pattern match: " + pat.matches.join(", "));
    }
  }
  // Rule 6 — Bulk/rapid paste activity (FREQUENCY of many separate pastes,
  // as opposed to Rule 3's SIZE of one paste — catches piecemeal exfiltration)
  if (type === "bulk_paste") {
    risk = higher(risk, "MEDIUM");
    flags.push("Bulk paste activity: " + (pasteCount || "multiple") + " pastes in 60s");
  }

  return { risk, flags };
}

// ── HTTP helpers ────────────────────────────────────────────
function sendJSON(res, obj, code = 200) {
  res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(obj));
}
function readBody(req, cb) {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => { try { cb(body ? JSON.parse(body) : {}); } catch { cb({}); } });
}
function isAuthed(req) {
  const token = req.headers["x-admin-token"];
  if (!token || !sessions[token]) return false;
  if (Date.now() > sessions[token]) { delete sessions[token]; return false; }
  return true;
}

// ── Server ──────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const { pathname, query } = url.parse(req.url, true);
  const method = req.method;

  // CORS preflight (extension talks to us cross-origin)
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,x-admin-token"
    });
    return res.end();
  }

  // POST /api/events — extension reports a new behaviour event
  if (method === "POST" && pathname === "/api/events") {
    return readBody(req, (data) => {
      const { risk, flags } = classifyEvent(data);
      const record = {
        id: crypto.randomBytes(6).toString("hex"),
        type: data.type || "unknown",
        source: data.source || "unknown",
        url: data.url || "",
        risk,
        flags,
        detail: data.detail || "",
        timestamp: data.timestamp || new Date().toISOString(),
        simulated: data.simulated === true // true only for Demo Simulator events, never for real extension captures
      };
      const events = loadEvents();
      events.unshift(record);
      if (events.length > 1000) events.length = 1000; // retention cap
      saveEvents(events);
      sendJSON(res, { status: "logged", record });
    });
  }

  // GET /api/events?risk=HIGH&limit=50
  if (method === "GET" && pathname === "/api/events") {
    let events = loadEvents();
    if (query.risk) events = events.filter((e) => e.risk === String(query.risk).toUpperCase());
    const limit = parseInt(query.limit, 10) || 100;
    return sendJSON(res, events.slice(0, limit));
  }

  // GET /api/stats — dashboard summary
  if (method === "GET" && pathname === "/api/stats") {
    const events = loadEvents();
    const byRisk = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    const bySource = {};
    events.forEach((e) => {
      byRisk[e.risk] = (byRisk[e.risk] || 0) + 1;
      bySource[e.source] = (bySource[e.source] || 0) + 1;
    });
    return sendJSON(res, { total: events.length, byRisk, bySource });
  }

  // POST /api/login — admin authentication
  if (method === "POST" && pathname === "/api/login") {
    return readBody(req, (data) => {
      if (data.username === ADMIN_USER && data.password === ADMIN_PASS) {
        const token = crypto.randomBytes(24).toString("hex");
        sessions[token] = Date.now() + SESSION_MS;
        appendAudit({ action: "ADMIN_LOGIN", by: ADMIN_USER });
        return sendJSON(res, { status: "ok", token });
      }
      sendJSON(res, { status: "denied" }, 401);
    });
  }

  // DELETE /api/events — protected: needs admin token + password + reason
  if (method === "DELETE" && pathname === "/api/events") {
    if (!isAuthed(req)) return sendJSON(res, { status: "unauthorized" }, 401);
    return readBody(req, (data) => {
      if (data.password !== ADMIN_PASS) return sendJSON(res, { status: "bad_password" }, 401);
      if (!data.reason || data.reason.trim().length < 3)
        return sendJSON(res, { status: "reason_required" }, 400);
      const count = loadEvents().length;
      saveEvents([]);
      appendAudit({ action: "CLEAR_EVENTS", by: ADMIN_USER, reason: data.reason, clearedCount: count });
      sendJSON(res, { status: "cleared", clearedCount: count });
    });
  }

  // GET /api/audit — protected: view the immutable audit trail
  if (method === "GET" && pathname === "/api/audit") {
    if (!isAuthed(req)) return sendJSON(res, { status: "unauthorized" }, 401);
    return sendJSON(res, loadJson(AUDIT_FILE).slice().reverse());
  }

  // Serve the dashboard
  if (method === "GET" && (pathname === "/" || pathname === "/dashboard.html")) {
    if (fs.existsSync(DASHBOARD_FILE)) {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(fs.readFileSync(DASHBOARD_FILE));
    }
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log("\n  Shadow AI Detector Backend (zero dependencies)");
  console.log("   Server:    http://localhost:" + PORT);
  console.log("   Dashboard: http://localhost:" + PORT + "/dashboard.html\n");
  if (USING_DEFAULT_CREDS) {
    console.warn("  ⚠  Using default admin credentials (admin/12341234).");
    console.warn("     Set SAI_ADMIN_USER and SAI_ADMIN_PASS env vars before any real deployment.\n");
  }
});
