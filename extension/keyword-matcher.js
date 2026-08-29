// ============================================================
// Shared Keyword Matcher
// ------------------------------------------------------------
// SINGLE SOURCE OF TRUTH for keyword matching (Rule 2). Loaded two
// ways, same reasoning as extension/sensitive-patterns.js:
//   1) As a browser content script (see manifest.json, loaded
//      before content.js) — attaches to `globalThis.KeywordMatcher`.
//   2) As a Node module (required directly by the evaluation
//      harness) — so a test of "does the real matcher avoid false
//      positives" is actually testing the real production code,
//      not a hand-copied reimplementation that could drift.
//
// Uses WORD-BOUNDARY matching, not naive substring search, so a
// short keyword like "nic" (National ID) or "nda" (NDA) doesn't
// false-positive inside unrelated words like "picnic" or "agenda" —
// this was a real bug found during evaluation (see evaluation/).
// Pure JavaScript, zero dependencies.
// ============================================================
(function (root) {
  function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  function compile(list) {
    return list.map((k) => ({ keyword: k, regex: new RegExp("\\b" + escapeRegex(k) + "\\b", "i") }));
  }

  // Cache compiled regexes per list instance so repeated calls (every
  // paste/prompt-submit) don't recompile 360+ regexes each time.
  const _cache = new Map();
  function matchKeywords(list, text) {
    let compiled = _cache.get(list);
    if (!compiled) { compiled = compile(list); _cache.set(list, compiled); }
    const t = text || "";
    return compiled.filter((entry) => entry.regex.test(t)).map((entry) => entry.keyword);
  }

  const api = { matchKeywords };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.KeywordMatcher = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
