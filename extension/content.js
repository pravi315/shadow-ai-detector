// ============================================================
// Shadow AI Detector - Content Script
// Runs inside AI tool pages (ChatGPT, Claude, Gemini, etc.)
// Monitors behaviour and reports events to the local backend.
// ============================================================

const BACKEND = "http://localhost:3000/api/events";
const SOURCE = window.location.hostname;

// Keywords that always raise a flag (Rule 2).
// Full list is in sensitive-keywords.js (loaded first). Fallback below.
const SENSITIVE_KEYWORDS = globalThis.SENSITIVE_KEYWORDS || [
  "password", "api_key", "secret", "confidential", "credit card"
];

// Quick client-side shapes (Rule 5 pre-check) so typed secrets with NO
// keyword still get sent to the server for full pattern analysis.
const QUICK_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /sk-[A-Za-z0-9]{20,}/,
  /-----BEGIN/,
  /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\./,
  /(?:\d[ -]?){13,16}/,
  /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/
];
function looksSensitive(t) { return QUICK_PATTERNS.some((re) => re.test(t)); }

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

function findKeywords(text) {
  const low = (text || "").toLowerCase();
  return SENSITIVE_KEYWORDS.filter((k) => low.includes(k));
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

// -- Rule 2 + 3 + 5 on PASTE --
document.addEventListener("paste", function (e) {
  const pasted = (e.clipboardData || window.clipboardData).getData("text") || "";
  inspectText(pasted, "paste");
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
// UPLOAD GUARD — Rule 1 with a Yes/No confirmation
// ============================================================
(function () {
  const approvedInputs = new WeakSet();

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
      if (approved) {
        const dt = new DataTransfer();
        for (const f of heldFiles) dt.items.add(f);
        input.files = dt.files;
        approvedInputs.add(input);
        input.dispatchEvent(new Event("change", { bubbles: true }));
        sendEvent({ type: "file_upload", detail: "Approved by user: " + fileNames.join(", ") });
      } else {
        sendEvent({ type: "file_upload", detail: "BLOCKED by user: " + fileNames.join(", ") });
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
      '<div style="font-size:14px;color:#475569;margin-bottom:14px;">You are about to upload a file to an AI tool. ' +
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
