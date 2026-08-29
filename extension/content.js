// ============================================================
// Shadow AI Detector - Content Script
// Runs inside AI tool pages (ChatGPT, Claude, Gemini, etc.) and
// social media platforms (Facebook, X, Instagram, etc.) — Shadow
// AI risk isn't limited to AI-chat tools narrowly, so coverage was
// broadened to any external platform sensitive data could leak
// through. Monitors behaviour and reports events to the local
// backend.
// ============================================================

const BACKEND = "http://localhost:3000/api/events";
const SOURCE = window.location.hostname;

// Keywords that always raise a flag (Rule 2).
// Full list is in sensitive-keywords.js (loaded first). Fallback below.
const SENSITIVE_KEYWORDS = globalThis.SENSITIVE_KEYWORDS || [
  "password", "api_key", "secret", "confidential", "credit card"
];

// Quick client-side pattern pre-check (Rule 5) so typed secrets with NO
// keyword still get sent to the server for full pattern analysis.
// Uses the SAME canonical pattern set + weights as the backend
// (sensitive-patterns.js, loaded just before this file — see
// manifest.json) so the client-side gate and the server's authoritative
// scoring can never disagree about what "looks sensitive" means.
const SharedDetector = globalThis.SharedPatterns ||
  { detectSensitivePatterns: () => ({ matches: [], score: 0, risk: "NONE" }) };
function looksSensitive(t) { return SharedDetector.detectSensitivePatterns(t).risk !== "NONE"; }

// -- Send any event to the backend --
function sendEvent(payload) {
  payload.source = SOURCE;
  payload.url = window.location.href;
  payload.timestamp = new Date().toISOString();
  fetch(BACKEND, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).catch(() => {});
  try { chrome.runtime.sendMessage({ kind: "bump" }); } catch (e) {}
}

// -- Lightweight, non-blocking "heads up" toast for bulk paste/upload activity --
// (Distinct from the Yes/No upload confirmation below, which BLOCKS the
// action; this just informs the user, auto-dismisses after 4s, and never
// interrupts typing or pasting.)
function showQuickAlert(message) {
  const toast = document.createElement("div");
  toast.style.cssText =
    "position:fixed;top:16px;right:16px;z-index:2147483647;background:#1A1A2E;color:#fff;" +
    "font-family:Arial,sans-serif;font-size:13px;line-height:1.4;padding:12px 16px;border-radius:10px;" +
    "box-shadow:0 10px 30px rgba(0,0,0,.35);max-width:320px;border-left:4px solid #DC2626;" +
    "opacity:0;transition:opacity .25s ease;";
  toast.innerHTML =
    '<div style="font-weight:bold;margin-bottom:4px;">⚠ Shadow AI Detector</div><div>' + message + "</div>";
  document.body.appendChild(toast);
  requestAnimationFrame(() => { toast.style.opacity = "1"; });
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Word-boundary keyword matching lives in keyword-matcher.js (loaded
// before this file — see manifest.json), shared with the evaluation
// harness so tests exercise the exact same matching logic as production.
function findKeywords(text) {
  const KM = globalThis.KeywordMatcher || { matchKeywords: () => [] };
  return KM.matchKeywords(SENSITIVE_KEYWORDS, text);
}

// -- Shared text inspection (used by BOTH paste and prompt submit) --
function inspectText(text, origin) {
  if (!text || !text.trim()) return;

  const kw = findKeywords(text);
  if (kw.length > 0) {
    sendEvent({ type: "sensitive_keyword", keywords: kw, text: text.slice(0, 500) });
    return;
  }
  if (text.length > 500) {
    sendEvent({ type: "large_paste", pasteLength: text.length, text: text.slice(0, 500) });
    return;
  }
  if (looksSensitive(text)) {
    sendEvent({ type: origin, pasteLength: text.length, text: text.slice(0, 500) });
  }
}

// -- Rule 2 + 3 + 5 on PASTE, plus Rule 6 (bulk/rapid paste) --
// Rule 6 is FREQUENCY-based (many separate paste actions in a short
// window) — distinct from Rule 3, which is SIZE-based (one big paste).
// It catches someone moving data out piecemeal, a few hundred chars at
// a time, which Rule 3 alone would miss.
let pasteTimes = [];
const BULK_PASTE_THRESHOLD = 5;     // this many pastes...
const BULK_PASTE_WINDOW_MS = 60000; // ...within this window = bulk
document.addEventListener("paste", function (e) {
  const pasted = (e.clipboardData || window.clipboardData).getData("text") || "";
  inspectText(pasted, "paste");

  const now = Date.now();
  pasteTimes = pasteTimes.filter((t) => now - t < BULK_PASTE_WINDOW_MS);
  pasteTimes.push(now);
  if (pasteTimes.length >= BULK_PASTE_THRESHOLD) {
    sendEvent({ type: "bulk_paste", pasteCount: pasteTimes.length });
    showQuickAlert("Bulk paste detected — " + pasteTimes.length + " separate pastes in the last minute.");
    pasteTimes = [];
  }
}, true);

// -- Rule 2 + 3 + 5 on TYPED PROMPT SUBMIT + Rule 4 --
let promptTimes = [];
document.addEventListener("keydown", function (e) {
  if (e.key !== "Enter" || e.shiftKey) return;

  let text = "";
  const f = e.target;
  if (f) {
    if (typeof f.value === "string") text = f.value;
    else if (f.isContentEditable) text = f.innerText || "";
  }
  if (!text) {
    const a = document.activeElement;
    if (a) text = (typeof a.value === "string" ? a.value : a.innerText) || "";
  }
  inspectText(text, "prompt");

  const now = Date.now();
  promptTimes = promptTimes.filter((t) => now - t < 60000);
  promptTimes.push(now);
  if (promptTimes.length >= 10) {
    sendEvent({ type: "rapid_prompts", promptCount: promptTimes.length });
    promptTimes = [];
  }
}, true);

// ============================================================
// UPLOAD GUARD — Rule 1 with a Yes/No confirmation, plus a bulk-
// upload quick alert (many files at once, or repeated uploads)
// ============================================================
(function () {
  const approvedInputs = new WeakSet();
  let uploadTimes = [];
  const BULK_UPLOAD_THRESHOLD = 3;      // this many separate upload actions...
  const BULK_UPLOAD_WINDOW_MS = 300000; // ...within 5 minutes = a bulk pattern

  document.addEventListener("change", function (e) {
    const input = e.target;
    if (!input || input.tagName !== "INPUT" || input.type !== "file") return;
    if (!input.files || input.files.length === 0) return;
    if (approvedInputs.has(input)) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    const heldFiles = input.files;
    const fileNames = Array.from(heldFiles).map((f) => f.name);
    input.value = "";

    showUploadConfirm(fileNames, function (approved) {
      const isBulk = heldFiles.length >= 2;
      if (approved) {
        const dt = new DataTransfer();
        for (const f of heldFiles) dt.items.add(f);
        input.files = dt.files;
        approvedInputs.add(input);
        input.dispatchEvent(new Event("change", { bubbles: true }));
        sendEvent({ type: "file_upload", detail: "Approved by user: " + fileNames.join(", "), bulk: isBulk });

        const now = Date.now();
        uploadTimes = uploadTimes.filter((t) => now - t < BULK_UPLOAD_WINDOW_MS);
        uploadTimes.push(now);
        if (isBulk || uploadTimes.length >= BULK_UPLOAD_THRESHOLD) {
          showQuickAlert(isBulk
            ? "Bulk upload detected — " + heldFiles.length + " files uploaded at once."
            : "Bulk upload pattern detected — " + uploadTimes.length + " uploads in the last few minutes.");
        }
      } else {
        sendEvent({ type: "file_upload", detail: "BLOCKED by user: " + fileNames.join(", "), bulk: isBulk });
      }
    });
  }, true);

  function showUploadConfirm(fileNames, callback) {
    const overlay = document.createElement("div");
    overlay.style.cssText =
      "position:fixed;inset:0;background:rgba(15,23,42,.6);z-index:2147483647;" +
      "display:flex;align-items:center;justify-content:center;font-family:Arial,sans-serif;";
    const box = document.createElement("div");
    box.style.cssText =
      "background:#fff;max-width:420px;width:90%;border-radius:14px;padding:24px;" +
      "box-shadow:0 20px 50px rgba(0,0,0,.35);text-align:left;";
    const list = fileNames.map((n) => "&bull; " + n).join("<br>");
    box.innerHTML =
      '<div style="font-size:18px;font-weight:bold;color:#1A1A2E;margin-bottom:6px;">Shadow AI Detector</div>' +
      '<div style="font-size:14px;color:#475569;margin-bottom:14px;">You are about to upload a file to an AI tool or social platform. ' +
      'This may share sensitive data outside the organization.</div>' +
      '<div style="font-size:13px;color:#1A202C;background:#F0F4F8;border-radius:8px;padding:10px;' +
      'margin-bottom:18px;word-break:break-all;">' + list + "</div>" +
      '<div style="display:flex;gap:10px;justify-content:flex-end;">' +
      '<button id="sai-no" style="padding:9px 18px;border:none;border-radius:8px;background:#E2E8F0;' +
      'color:#1A202C;font-size:14px;font-weight:bold;cursor:pointer;">No, cancel</button>' +
      '<button id="sai-yes" style="padding:9px 18px;border:none;border-radius:8px;background:#DC2626;' +
      'color:#fff;font-size:14px;font-weight:bold;cursor:pointer;">Yes, upload</button></div>';
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    function close(result) { overlay.remove(); callback(result); }
    box.querySelector("#sai-yes").addEventListener("click", () => close(true));
    box.querySelector("#sai-no").addEventListener("click", () => close(false));
  }
})();

console.log("[Shadow AI Detector] monitoring active on " + SOURCE);
