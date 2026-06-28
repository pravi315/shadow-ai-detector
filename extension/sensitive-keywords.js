// ============================================================
// Shadow AI Detector - Sensitive Keyword List
// ------------------------------------------------------------
// Words/phrases that suggest sensitive data is being shared with
// an AI tool. Grouped by category for clarity. All lowercase —
// matching is case-insensitive in content.js.
//
// Loaded BEFORE content.js (see manifest.json) so the list is
// available to the keyword rule. Add or remove terms freely.
// ============================================================

globalThis.SENSITIVE_KEYWORDS = [

  // --- Credentials & secrets ---
  "password", "passwd", "pwd", "api key", "api_key", "apikey",
  "secret key", "secret_key", "access token", "auth token",
  "bearer token", "client secret", "private key", "ssh key",
  "encryption key", "credentials", "login details",
  "connection string", "database password", "db password", "root password",

  // --- Confidentiality markers ---
  "confidential", "strictly confidential", "internal only",
  "internal use only", "for internal use", "proprietary",
  "classified", "restricted", "do not distribute", "do not share",
  "not for distribution", "trade secret", "company confidential",
  "nda", "non-disclosure",

  // --- Personal data (PII) ---
  "social security", "ssn", "passport number", "national id",
  "nic", "national identity", "driving licence", "driver license",
  "driver's license", "date of birth", "home address", "personal data",

  // --- Financial ---
  "credit card", "debit card", "card number", "cvv", "cvc",
  "expiry date", "bank account", "account number", "routing number",
  "sort code", "iban", "swift code", "salary", "payroll",
  "invoice", "tax id",

  // --- Health (PHI) ---
  "medical record", "patient record", "patient id", "diagnosis",
  "prescription", "health record", "insurance number",

  // --- Corporate & intellectual property ---
  "source code", "api endpoint", "production server",
  "staging credentials", "internal document", "merger",
  "acquisition", "litigation", "lawsuit", "financial statement",
  "unreleased"

];
