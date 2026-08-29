// ============================================================
// Shadow AI Detector - Sensitive Keyword List (360+ terms)
// ------------------------------------------------------------

globalThis.SENSITIVE_KEYWORDS = [

  // --- Credentials & secrets ---
  "password", "passwd", "pwd", "api key", "api_key", "apikey",
  "secret key", "secret_key", "access token", "auth token",
  "bearer token", "client secret", "private key", "ssh key",
  "encryption key", "credentials", "login details",
  "connection string", "database password", "db password", "root password",
  "oauth token", "refresh token", "session token", "security token",
  "master key", "encryption secret", "signing key", "certificate key",
  "keystore password", "admin password", "service account key",
  "aws secret", "aws secret key", "gcp key", "azure key",
  "github token", "gitlab token", "npm token", "slack webhook",
  "stripe secret key", "twilio auth token", "sendgrid api key",
  "openai api key", "firebase api key", "digitalocean token",
  "cloudflare api token", "vault token", "wifi password", "router password",
  "webhook secret", "recovery code", "backup codes", "authenticator code",
  "one time password", "security question answer", "activation key",
  "license key", "product key",

  // --- Confidentiality markers ---
  "confidential", "strictly confidential", "internal only",
  "internal use only", "for internal use", "proprietary",
  "classified", "restricted", "do not distribute", "do not share",
  "not for distribution", "trade secret", "company confidential",
  "nda", "non-disclosure", "top secret", "eyes only",
  "need to know basis", "sensitive information",
  "privileged and confidential", "attorney client privilege",
  "embargoed", "under embargo", "do not forward", "private and confidential",
  "commercial in confidence", "market sensitive", "insider information",
  "price sensitive information", "do not copy", "controlled document",
  "export controlled", "itar controlled",

  // --- Personal data (PII) ---
  "social security", "ssn", "passport number", "national id",
  "nic", "national identity", "driving licence", "driver license",
  "driver's license", "date of birth", "home address", "personal data",
  "mother's maiden name", "place of birth", "biometric data",
  "fingerprint data", "facial recognition data", "immigration status",
  "visa number", "voter id", "employee id number", "student id number",
  "next of kin", "emergency contact", "personal identification number",
  "full name and address", "marital status", "religious affiliation",
  "ethnic origin", "sexual orientation",
  "maiden name", "blood type", "vehicle registration number",
  "license plate number", "resident permit number", "citizenship status",
  "custody arrangement", "adoption record", "criminal record",
  "background check report", "court record", "divorce record",
  "gender identity", "pregnancy status", "household income",
  "life insurance policy number",

  // --- Financial ---
  "credit card", "debit card", "card number", "cvv", "cvc",
  "expiry date", "bank account", "account number", "routing number",
  "sort code", "iban", "swift code", "salary", "payroll",
  "invoice", "tax id", "bank statement", "wire transfer", "ach number",
  "pin number", "billing address", "cardholder name", "credit score",
  "loan number", "mortgage account", "investment account",
  "brokerage account", "cryptocurrency wallet", "wallet address",
  "seed phrase", "private wallet key", "net worth",
  "bic code", "paypal account", "venmo account", "metamask seed phrase",
  "trading account number", "stock portfolio", "401k account",
  "pension account number", "insurance policy number", "claim number",
  "escrow account", "letter of credit", "line of credit",
  "overdraft limit", "chargeback dispute", "offshore account",

  // --- Health (PHI) ---
  "medical record", "patient record", "patient id", "diagnosis",
  "prescription", "health record", "insurance number",
  "medical history", "treatment plan", "mental health record",
  "therapy notes", "lab results", "genetic data", "hiv status",
  "disability status",
  "std test result", "pregnancy test result", "psychiatric evaluation",
  "substance abuse record", "rehab record", "surgery record",
  "vaccination record", "allergy information", "blood test results",
  "mri scan", "biopsy result", "health insurance claim", "disability claim",

  // --- Corporate & intellectual property ---
  "source code", "api endpoint", "production server",
  "staging credentials", "internal document", "merger",
  "acquisition", "litigation", "lawsuit", "financial statement",
  "unreleased", "unpublished results", "unpatented", "patent pending",
  "trademark application", "board meeting minutes",
  "executive compensation", "layoff plan", "restructuring plan",
  "product roadmap", "go to market strategy", "pricing strategy",
  "vendor contract", "supplier agreement", "performance review",
  "termination notice",
  "term sheet", "cap table", "investor deck", "due diligence report",
  "non-compete agreement", "severance agreement", "settlement agreement",
  "arbitration case", "internal memo", "insider trading",
  "material nonpublic information", "earnings call script",
  "press release draft", "product launch date", "beta access code",
  "salary band", "stock option grant", "equity grant", "vesting schedule",
  "shareholder agreement",

  // --- Legal & compliance ---
  "gdpr", "hipaa", "pci dss", "sox compliance", "regulatory filing",
  "compliance violation", "audit finding", "data breach",
  "security incident", "whistleblower report",
  "ccpa", "ferpa", "glba", "coppa", "iso 27001", "soc 2 report",
  "penetration test report", "vulnerability report",
  "incident response plan", "data processing agreement", "subpoena",
  "cease and desist", "legal hold notice", "discovery request",
  "regulatory inquiry",

  // --- Technical & infrastructure ---
  "production database", "prod environment", "kubernetes secret",
  "docker secret", "environment variable", "config file",
  "firewall rule", "vpn credentials", "admin console", "root access",
  "sudo password", "server ip", "internal ip address",
  "network diagram", "infrastructure diagram",
  "kubeconfig", "terraform state", "ansible vault",
  "aws credentials file", "gcp service account json",
  "azure connection string", "internal api documentation",
  "private repository", "cve details", "zero day exploit", "exploit code",

  // --- Government & regional ID formats ---
  "passport photo", "visa application", "work permit", "tax return",
  "national insurance number", "medicare number", "pan card",
  "aadhaar number", "voter registration", "birth certificate",
  "green card number", "itin number", "ein number", "tax file number",
  "medicaid number", "social insurance number", "health card number",
  "residence permit number", "asylum application",
  "immigration case number", "police report number",

  // --- Academic & institutional (relevant given this tool's own use case) ---
  "exam paper", "exam questions", "answer key", "grading rubric",
  "student transcript", "academic record", "thesis draft",
  "unpublished research",
  "dissertation draft", "plagiarism report", "exam answer sheet",
  "peer review comments", "grant proposal", "research proposal",
  "ethics approval number", "unpublished manuscript", "lab notebook",
  "raw research data", "participant data", "survey response data",
  "irb approval",

  // --- Communications & social media (new) ---
  "private conversation screenshot", "group chat log",
  "direct message history", "leaked messages", "private photos",
  "location history", "travel itinerary", "flight confirmation number",
  "hotel reservation number", "home address and schedule"

];
