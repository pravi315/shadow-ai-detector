// ============================================================
// Shadow AI Detector - Rule 5: Sensitive Data Pattern Detection
// ------------------------------------------------------------
// Detects secrets and personal data by their FORMAT (regex),
// not by a fixed keyword list. Catches leaks that were never
// predicted in advance (API keys, cards, private keys, etc).
// Pure JavaScript, zero dependencies.
// ============================================================

const PATTERNS = [
  { name: "Private Key Block", weight: 50,
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "AWS Access Key", weight: 45, regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "API Secret Key", weight: 40, regex: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: "Google API Key", weight: 40, regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { name: "JWT Token", weight: 35,
    regex: /\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/ },
  { name: "Credit Card Number", weight: 35, luhn: true,
    regex: /\b(?:\d[ -]*?){13,16}\b/ },
  { name: "Password Assignment", weight: 30,
    regex: /(?:password|passwd|pwd)\s*[:=]\s*\S{4,}/i },
  { name: "Email Address", weight: 15,
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  { name: "IP Address", weight: 10,
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/ }
];

// Luhn check: confirms a real card number so random long digits don't false-alarm
function passesLuhn(raw) {
  const d = raw.replace(/[^0-9]/g, "");
  if (d.length < 13 || d.length > 16) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = parseInt(d[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

// Returns: { matches: [names], score, risk: "HIGH"|"MEDIUM"|"LOW"|"NONE" }
function detectSensitivePatterns(text) {
  if (!text || typeof text !== "string") return { matches: [], score: 0, risk: "NONE" };
  const matches = [];
  let score = 0;
  for (const p of PATTERNS) {
    const found = text.match(p.regex);
    if (!found) continue;
    if (p.luhn && !passesLuhn(found[0])) continue;
    matches.push(p.name);
    score += p.weight;
  }
  let risk = "NONE";
  if (score >= 40) risk = "HIGH";
  else if (score >= 20) risk = "MEDIUM";
  else if (score > 0) risk = "LOW";
  return { matches, score, risk };
}

module.exports = { detectSensitivePatterns };
