// ============================================================
// Shadow AI Detector - Rule 5: Sensitive Data Pattern Detection
// ------------------------------------------------------------
// This file used to hold its own copy of the pattern list, kept
// separately from the extension's client-side quick-check list.
// It's now a thin re-export: the single canonical implementation
// lives in extension/sensitive-patterns.js, so the browser content
// script and this backend score text with EXACTLY the same rules
// and weights and can never drift out of sync. See that file for
// the pattern list, the Luhn check, and detectSensitivePatterns().
// ============================================================

module.exports = require("../extension/sensitive-patterns.js");
