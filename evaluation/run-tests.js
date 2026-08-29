// ============================================================
// Shadow AI Detector — Structured Evaluation Harness (v2)
// ------------------------------------------------------------
// Generates real, reproducible evaluation data for the research
// paper by exercising the ACTUAL backend risk engine (server.js +
// the shared pattern detector) through its real HTTP API, plus a
// standalone check of the REAL shared keyword matcher
// (extension/keyword-matcher.js, required directly — not a
// hand-copied reimplementation) against both benign control
// sentences (false-positive check) and genuine uses of the same
// short keywords (true-positive check).
//
// Self-contained: this script spawns `node backend/server.js`
// itself, waits for it to be ready, runs the corpus, then kills it.
// Test traffic is NOT left in backend/events.json or audit.json —
// both are snapshotted before the run and restored after, so the
// real historical/live log stays untouched.
//
// Run from the repo root:   node evaluation/run-tests.js
// Pure Node 18+, zero dependencies (uses global fetch).
// ============================================================

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const vm = require("vm");
const { matchKeywords } = require("../extension/keyword-matcher.js");

const ROOT = path.join(__dirname, "..");
const EVENTS_FILE = path.join(ROOT, "backend", "events.json");
const AUDIT_FILE = path.join(ROOT, "backend", "audit.json");
const API = "http://localhost:3000/api/events";

const GOOGLE_KEY_BODY = "Ab3D_".repeat(7); // exactly 35 chars, built not hand-counted
const SK_KEY_BODY = "ab12".repeat(6);      // 24 chars, well over the >=20 requirement

const cases = [
  // --- Rule 1: file upload -> always HIGH ---
  { id: "R1-01", rule: "Rule 1: file upload", expect: "HIGH",
    event: { type: "file_upload", source: "claude.ai", detail: "Approved by user: payroll_2026.xlsx" } },
  { id: "R1-02", rule: "Rule 1: bulk file upload (2+ files)", expect: "HIGH",
    event: { type: "file_upload", source: "claude.ai", detail: "Approved by user: a.xlsx, b.xlsx", bulk: true } },

  // --- Rule 2: sensitive keyword -> always HIGH ---
  { id: "R2-01", rule: "Rule 2: keyword (credentials)", expect: "HIGH",
    event: { type: "sensitive_keyword", source: "chatgpt.com", keywords: ["password"], text: "my password is hunter2" } },
  { id: "R2-02", rule: "Rule 2: keyword (PII)", expect: "HIGH",
    event: { type: "sensitive_keyword", source: "chatgpt.com", keywords: ["ssn"], text: "here is my ssn 123-45-6789" } },
  { id: "R2-03", rule: "Rule 2: keyword (health)", expect: "HIGH",
    event: { type: "sensitive_keyword", source: "gemini.google.com", keywords: ["medical record"], text: "attaching my medical record" } },

  // --- Rule 3: large paste, boundary values ---
  { id: "R3-01", rule: "Rule 3: large paste (501 chars)", expect: "MEDIUM",
    event: { type: "large_paste", source: "chatgpt.com", pasteLength: 501, text: "x".repeat(200) } },
  { id: "R3-02", rule: "Rule 3: large paste (2000 chars, boundary)", expect: "MEDIUM",
    event: { type: "large_paste", source: "chatgpt.com", pasteLength: 2000, text: "x".repeat(200) } },
  { id: "R3-03", rule: "Rule 3: large paste (2001 chars)", expect: "HIGH",
    event: { type: "large_paste", source: "chatgpt.com", pasteLength: 2001, text: "x".repeat(200) } },

  // --- Rule 4: rapid prompts (fixed MEDIUM regardless of count, by design) ---
  { id: "R4-01", rule: "Rule 4: rapid prompts (10)", expect: "MEDIUM",
    event: { type: "rapid_prompts", source: "perplexity.ai", promptCount: 10 } },
  { id: "R4-02", rule: "Rule 4: rapid prompts (50)", expect: "MEDIUM",
    event: { type: "rapid_prompts", source: "perplexity.ai", promptCount: 50 } },

  // --- Rule 5: pattern detection ---
  { id: "R5-01", rule: "Rule 5: private key block (w=50)", expect: "HIGH",
    event: { type: "paste", source: "claude.ai", text: "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----" } },
  { id: "R5-02", rule: "Rule 5: AWS key alone (w=45)", expect: "HIGH",
    event: { type: "paste", source: "claude.ai", text: "export AWS_KEY=AKIAIOSFODNN7EXAMPLE" } },
  { id: "R5-03", rule: "Rule 5: sk- key alone (w=40)", expect: "HIGH",
    event: { type: "paste", source: "claude.ai", text: "use sk-" + SK_KEY_BODY + " as the key" } },
  { id: "R5-04", rule: "Rule 5: Google key alone (w=40)", expect: "HIGH",
    event: { type: "paste", source: "claude.ai", text: "key: AIza" + GOOGLE_KEY_BODY } },
  { id: "R5-05", rule: "Rule 5: JWT alone (w=35)", expect: "MEDIUM",
    event: { type: "paste", source: "claude.ai", text: "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" } },
  { id: "R5-06", rule: "Rule 5: valid credit card, Luhn passes (w=35)", expect: "MEDIUM",
    event: { type: "paste", source: "gemini.google.com", text: "charge the card 4539 1488 0343 6467 today" } },
  { id: "R5-07", rule: "Rule 5: card-shaped digits, Luhn FAILS (negative control)", expect: "LOW",
    event: { type: "paste", source: "gemini.google.com", text: "reference number 1234 5678 9012 3456" } },
  { id: "R5-08", rule: "Rule 5: password assignment (w=30)", expect: "MEDIUM",
    event: { type: "paste", source: "claude.ai", text: "db_password = Sup3rSecret!" } },
  { id: "R5-09", rule: "Rule 5: email only (w=15)", expect: "LOW",
    event: { type: "paste", source: "claude.ai", text: "contact me at chan@example.com" } },
  { id: "R5-10", rule: "Rule 5: IP only (w=10)", expect: "LOW",
    event: { type: "paste", source: "claude.ai", text: "the server lives at 192.168.1.42" } },
  { id: "R5-11", rule: "Rule 5: compounding, key+card (w=40+35=75)", expect: "HIGH",
    event: { type: "paste", source: "claude.ai", text: "use sk-" + SK_KEY_BODY + " and charge card 4539 1488 0343 6467" } },
  { id: "R5-12", rule: "Rule 5: benign prose (true negative)", expect: "LOW",
    event: { type: "paste", source: "claude.ai", text: "can you help me summarize this article about renewable energy" } },
  { id: "R5-13", rule: "Rule 5: benign code, no secrets (true negative)", expect: "LOW",
    event: { type: "paste", source: "claude.ai", text: "function add(a, b) { return a + b; }" } },

  // --- Rule 6 (NEW): bulk/rapid paste ---
  { id: "R6-01", rule: "Rule 6: bulk paste (5 in 60s)", expect: "MEDIUM",
    event: { type: "bulk_paste", source: "facebook.com", pasteCount: 5 } },
  { id: "R6-02", rule: "Rule 6: bulk paste on social media source", expect: "MEDIUM",
    event: { type: "bulk_paste", source: "www.linkedin.com", pasteCount: 8 } },
];

function post(event) {
  return fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event)
  }).then((r) => r.json());
}

// Loads the REAL sensitive-keywords.js (not a hand-copied list).
function loadRealKeywordList() {
  const file = path.join(ROOT, "extension", "sensitive-keywords.js");
  const src = fs.readFileSync(file, "utf8");
  const sandbox = {};
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return sandbox.SENSITIVE_KEYWORDS;
}

// Ordinary, unrelated sentences — none of these should be flagged.
// Several deliberately contain short keyword substrings ("nic", "nda")
// inside completely unrelated words. This is the SAME set used in the
// v1 run (which found an 8/8 false-positive rate under naive substring
// matching) — kept identical so this run is a valid before/after.
const benignControls = [
  "Let's go on a picnic this weekend if the weather holds.",
  "Can you send me the meeting agenda before Friday?",
  "I love going to the clinic for my annual checkup.",
  "That mechanic fixed my car in under an hour.",
  "She's a really cynical person about most things.",
  "We watched a documentary about pandas at the zoo.",
  "My aunt Amanda is visiting next week.",
  "Please review the technical design doc when you can."
];

// Genuine uses of the SAME short keywords, as whole words — these SHOULD
// be flagged. Proves the word-boundary fix didn't trade false positives
// for false negatives.
const truePositiveControls = [
  { text: "please don't share your nic number with anyone", expect: "nic" },
  { text: "make sure everyone has signed the nda before the meeting", expect: "nda" },
  { text: "here is my password: hunter2", expect: "password" },
  { text: "this document is strictly confidential", expect: "confidential" }
];

function waitForServer(testUrl, tries) {
  return new Promise((resolve, reject) => {
    const attempt = (n) => {
      fetch(testUrl).then(() => resolve()).catch(() => {
        if (n <= 0) return reject(new Error("backend did not come up in time"));
        setTimeout(() => attempt(n - 1), 200);
      });
    };
    attempt(tries);
  });
}

(async () => {
  const eventsBackup = fs.readFileSync(EVENTS_FILE, "utf8");
  const auditBackup = fs.readFileSync(AUDIT_FILE, "utf8");

  console.log("Starting backend for evaluation (node backend/server.js)...");
  const child = spawn("node", ["backend/server.js"], { cwd: ROOT, env: process.env });
  let serverOut = "";
  child.stdout.on("data", (d) => (serverOut += d));
  child.stderr.on("data", (d) => (serverOut += d));

  try {
    await waitForServer("http://localhost:3000/api/stats", 30);
    console.log("Backend is up.\n");
    console.log("-- Part A: backend risk-engine test corpus (" + cases.length + " cases) --\n");

    const results = [];
    let pass = 0;
    for (const c of cases) {
      const res = await post(c.event);
      const got = res.record ? res.record.risk : "ERROR";
      const ok = got === c.expect;
      if (ok) pass++;
      results.push({ id: c.id, rule: c.rule, expect: c.expect, got, flags: res.record ? res.record.flags : [], match: ok });
      console.log((ok ? "MATCH " : "DIFF  ") + c.id.padEnd(7) + c.rule.padEnd(48) + " expected=" + c.expect.padEnd(7) + " got=" + got);
    }
    console.log("\nBackend corpus: " + pass + "/" + cases.length + " matched the pre-registered expectation.\n");

    console.log("-- Part B1: REAL keyword matcher vs benign controls (false-positive check) --\n");
    const list = loadRealKeywordList();
    console.log("Loaded " + list.length + " keywords from extension/sensitive-keywords.js (via extension/keyword-matcher.js)\n");
    const falsePositives = [];
    for (const text of benignControls) {
      const hits = matchKeywords(list, text);
      const flagged = hits.length > 0;
      console.log((flagged ? "FALSE POSITIVE " : "clean          ") + JSON.stringify(text) + (flagged ? "  -> matched: " + hits.join(", ") : ""));
      if (flagged) falsePositives.push({ text, matched: hits });
    }
    console.log("\n" + falsePositives.length + " / " + benignControls.length + " benign control sentences incorrectly flagged (v1 baseline was 8/8).\n");

    console.log("-- Part B2: REAL keyword matcher vs true-positive controls (recall check) --\n");
    let truePositives = 0;
    const tpResults = [];
    for (const tc of truePositiveControls) {
      const hits = matchKeywords(list, tc.text);
      const ok = hits.includes(tc.expect);
      if (ok) truePositives++;
      console.log((ok ? "CAUGHT " : "MISSED ") + JSON.stringify(tc.text) + "  (expected \"" + tc.expect + "\")" + (hits.length ? "  -> matched: " + hits.join(", ") : ""));
      tpResults.push({ text: tc.text, expect: tc.expect, matched: hits, ok });
    }
    console.log("\n" + truePositives + " / " + truePositiveControls.length + " genuine keyword uses still correctly caught.\n");

    const summary = {
      generatedAt: new Date().toISOString(),
      note: "Test traffic from this run was NOT persisted into backend/events.json/audit.json — both are restored to their pre-test state immediately after this script finishes. Part B uses extension/keyword-matcher.js directly via require(), the same module the real extension loads, so this is a test of production code, not a reimplementation.",
      backendCorpus: { total: cases.length, passed: pass, results },
      keywordFalsePositives: { totalControls: benignControls.length, flagged: falsePositives.length, details: falsePositives },
      keywordTruePositives: { totalControls: truePositiveControls.length, caught: truePositives, details: tpResults }
    };
    fs.writeFileSync(path.join(__dirname, "results.json"), JSON.stringify(summary, null, 2));
    console.log("Full results written to evaluation/results.json");
  } catch (e) {
    console.error("EVALUATION ERROR:", e);
    console.error("Server output so far:\n" + serverOut);
    process.exitCode = 1;
  } finally {
    child.kill();
    fs.writeFileSync(EVENTS_FILE, eventsBackup);
    fs.writeFileSync(AUDIT_FILE, auditBackup);
    console.log("\nRestored backend/events.json and backend/audit.json to their pre-test state.");
  }
})();
