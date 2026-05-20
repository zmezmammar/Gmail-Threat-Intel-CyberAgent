/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║         CyberAgent v25.0 — Unified Cyber Defense System         ║
 * ║                                                                  ║
 * ║  Combines: Smart Phishing Reporter + Threat Intelligence Engine  ║
 * ║                                                                  ║
 * ║  Safe Mode — the system NEVER:                                   ║
 * ║    • Sends emails automatically                                  ║
 * ║    • Deletes any email                                           ║
 * ║    • Opens any link                                              ║
 * ║                                                                  ║
 * ║  The system DOES:                                                ║
 * ║    • Scan Inbox + Spam (last 24 hours)                          ║
 * ║    • Extract real sender IP via header forensics                 ║
 * ║    • Check IP reputation via AbuseIPDB                          ║
 * ║    • Check URLs via VirusTotal (MEDIUM/HIGH only)               ║
 * ║    • Detect phishing, spoofing, brand impersonation             ║
 * ║    • Detect newsletter / marketing email patterns               ║
 * ║    • Create draft report for suspicious emails                  ║
 * ║    • Log everything to Google Sheet                             ║
 * ║                                                                  ║
 * ║  SETUP (one-time):                                               ║
 * ║    1. Apps Script → Services → Enable "Gmail API"               ║
 * ║    2. Script Properties → Add:                                   ║
 * ║         VT_KEY    = your VirusTotal API key                     ║
 * ║         ABUSE_KEY = your AbuseIPDB API key                      ║
 * ║    3. Set your LOG_SHEET_ID below                               ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

// ══════════════════════════════════════════════════════════════════
// SECTION 1 — CONFIGURATION
// ══════════════════════════════════════════════════════════════════

// API keys stored securely in Script Properties (never hardcoded)
const KEYS = {
  VT_KEY    : PropertiesService.getScriptProperties().getProperty("VT_KEY"),
  ABUSE_KEY : PropertiesService.getScriptProperties().getProperty("ABUSE_KEY")
};

// Phishing report recipients
const REPORT_TO = [
  "report@phishing.gov.uk",      // 🇬🇧 NCSC — UK National Cyber Security Centre
  "reportphishing@apwg.org",     // 🌍 APWG — Anti-Phishing Working Group
  "scam@mcafee.com",
  "spam@avast.com",
  "abuse@yahoo.com",
  "security@yahoo.com",
  "abuse@outlook.com"
].join(",");

// Google Sheet ID for logging
const LOG_SHEET_ID = "PUT_YOUR_GOOGLE_SHEET_ID_HERE";

// Gmail labels
const LABEL_PROCESSED = "CyberAgent-Processed";
const LABEL_REVIEW    = "CyberAgent-Review";
const LABEL_TRUSTED   = "CyberAgent-Trusted-Logged";

// Limits
const MAX_THREADS          = 10;   // emails per run
const MAX_DRAFT_BODY_CHARS = 12000; // truncate long bodies
const MAX_VT_URLS          = 5;    // VirusTotal calls per email (rate limit)
const SKIP_OWN_EMAIL       = true;

// Risk thresholds
const THRESHOLD_HIGH   = 85;
const THRESHOLD_MEDIUM = 45;

// ── TRUSTED SENDER DOMAINS ────────────────────────────────────────
// Only institutional domains a random person CANNOT freely register.
// DO NOT add gmail.com / outlook.com / live.com here —
// any scammer can create a @gmail.com address for free.
const TRUSTED_SENDER_DOMAINS = [
  // Cloud / Infrastructure
  "cloudflare.com", "notify.cloudflare.com",
  // Google corporate only
  "google.com", "accounts.google.com",
  "myaccount.google.com", "securityalerts.google.com",
  // Microsoft corporate only
  "microsoft.com", "account.microsoft.com",
  // Other big tech
  "apple.com", "amazon.com", "paypal.com",
  "github.com", "dropbox.com", "atlassian.com",
  "zoom.us", "slack.com", "openai.com",
  // Domain registrars
  "godaddy.com", "namecheap.com", "name.com",
  "hover.com", "123-reg.co.uk", "fasthosts.co.uk",
  "ionos.co.uk", "ionos.com",
  "registrar-servers.com", "domaincontrol.com",
  // Email / marketing platforms
  "klaviyo.com", "kmail-lists.com", "klclick.com",
  "mailchimp.com", "sendgrid.net",
  "amazonses.com", "mandrillapp.com",
  // UK Government
  "gov.uk", "hmrc.gov.uk",
  // Banks
  "barclays.co.uk", "hsbc.co.uk", "lloyds.com", "natwest.com"
];

// ── TRUSTED URL DOMAINS ───────────────────────────────────────────
// Used when evaluating links inside emails.
// Includes free platforms (gmail.com etc.) — a LINK to gmail.com is safe.
const TRUSTED_URL_DOMAINS = [
  ...TRUSTED_SENDER_DOMAINS,
  // Free email platforms — safe as links, NOT as senders
  "gmail.com", "outlook.com", "live.com",
  "yahoo.com", "icloud.com",
  // Social / Public
  "linkedin.com", "facebook.com", "instagram.com",
  "x.com", "twitter.com", "t.me", "telegram.org",
  "youtube.com", "kickstarter.com",
  // CDN / Infrastructure
  "cloudfront.net", "w3.org", "googleapis.com",
  "gstatic.com", "licdn.com", "yelpcdn.com",
  "klaviyo-cdn.com", "static-forms.klaviyo.com"
];

// ── MARKETING PLATFORMS ───────────────────────────────────────────
const MARKETING_PLATFORMS = [
  "kmail-lists.com", "klclick.com", "klaviyo.com",
  "mailchimp.com", "sendgrid.net",
  "mandrillapp.com", "amazonses.com"
];

// ── GOOGLE SERVER IP RANGES (filtered from sender IP) ────────────
const GOOGLE_IP_RANGES = [
  "209.85.", "66.102.", "74.125.", "64.233.",
  "66.249.", "72.14.",  "216.58.", "216.239.",
  "108.177.","142.250.","172.217.","173.194."
];


// ══════════════════════════════════════════════════════════════════
// SECTION 2 — MAIN FUNCTION (RUN THIS ONLY)
// ══════════════════════════════════════════════════════════════════

function scanAndDefend() {
  const labelProcessed = getOrCreateLabel(LABEL_PROCESSED);
  const labelReview    = getOrCreateLabel(LABEL_REVIEW);
  const labelTrusted   = getOrCreateLabel(LABEL_TRUSTED);

  const query   = `newer_than:1d (in:inbox OR in:spam) -label:${LABEL_PROCESSED}`;
  const threads = GmailApp.search(query, 0, MAX_THREADS);

  if (!threads || threads.length === 0) {
    Logger.log("✅ No new emails to scan.");
    return;
  }

  Logger.log(`🔍 Found ${threads.length} thread(s) to scan.`);

  threads.forEach(thread => {
    thread.getMessages().forEach(message => {
      try {
        // Skip already processed
        if (alreadyProcessed(message)) {
          Logger.log("⏭ Skipped (already processed).");
          return;
        }

        // Skip own emails
        if (isOwnEmail(message)) {
          markProcessed(message, labelProcessed);
          Logger.log("⏭ Skipped (own email).");
          return;
        }

        // ── Phase 1: Analyse email ──────────────────────────────
        const report = analyseEmail(message);

        // ── Phase 2: Threat Intelligence (MEDIUM/HIGH only) ────
        if (report.risk !== "LOW") {
          const intel = runThreatIntelligence(message, report.urls);
          report.senderIp       = intel.senderIp;
          report.ipReputation   = intel.ipReputation;
          report.vtResults      = intel.vtResults;
        } else {
          report.senderIp     = "Skipped (LOW risk)";
          report.ipReputation = "Skipped (LOW risk)";
          report.vtResults    = [];
        }

        // ── Phase 3: Log to Google Sheet ────────────────────────
        logToSheet(report);

        // ── Phase 4: Route the email ────────────────────────────
        if (report.trustedSender && report.score < THRESHOLD_HIGH) {
          thread.addLabel(labelTrusted);
          markProcessed(message, labelProcessed);
          Logger.log(`🟢 Trusted sender logged: ${report.originalSubject}`);
          return;
        }

        if (report.newsletterPattern && report.score < THRESHOLD_HIGH) {
          thread.addLabel(labelTrusted);
          markProcessed(message, labelProcessed);
          Logger.log(`📧 Newsletter logged: ${report.originalSubject}`);
          return;
        }

        if (report.risk !== "LOW") {
          createDraftReport(report);
          thread.addLabel(labelReview);
          Logger.log(`🚨 Draft created [${report.risk}]: ${report.originalSubject}`);
        }

        markProcessed(message, labelProcessed);

      } catch (err) {
        Logger.log(`❌ ERROR: ${err.message}`);
      }
    });
  });

  Logger.log("✅ Scan completed.");
}


// ══════════════════════════════════════════════════════════════════
// SECTION 3 — EMAIL ANALYSIS
// ══════════════════════════════════════════════════════════════════

function analyseEmail(message) {
  const gmailFrom  = safeText(message.getFrom());
  const subject    = safeText(message.getSubject());
  const date       = message.getDate();
  const messageId  = message.getId();

  const plainBody  = safeText(message.getPlainBody());
  const htmlBody   = safeText(message.getBody());
  const body       = plainBody || stripHtml(htmlBody);
  const fullText   = plainBody + "\n\n" + htmlBody;

  const urls        = extractUrls(fullText);
  const attachments = message.getAttachments();
  const forwarded   = extractForwardedDetails(body);
  const riskData    = calculateRisk(subject, fullText, urls, attachments, gmailFrom);

  return {
    messageId:        messageId,
    gmailFrom:        gmailFrom,
    senderDomain:     riskData.senderDomain,
    trustedSender:    riskData.trustedSender,
    newsletterPattern:riskData.newsletterPattern,
    originalFrom:     forwarded.from    || "Not detected",
    originalSubject:  forwarded.subject || subject,
    subject:          subject,
    date:             date,
    urls:             urls,
    attachments:      attachments.map(a => a.getName()),
    risk:             riskData.level,
    score:            riskData.score,
    reasons:          riskData.reasons,
    body:             body,
    // filled by ThreatIntel later
    senderIp:         "",
    ipReputation:     "",
    vtResults:        []
  };
}


// ══════════════════════════════════════════════════════════════════
// SECTION 4 — RISK ENGINE
// ══════════════════════════════════════════════════════════════════

function calculateRisk(subject, body, urls, attachments, from) {
  let score   = 0;
  let reasons = [];

  const text         = (subject + " " + body + " " + from).toLowerCase();
  const senderDomain = extractDomainFromSender(from);
  const trustedSender= isTrustedSenderDomain(senderDomain);

  // ── Urgent / fear language ───────────────────────────────────
  const urgentWords = [
    "urgent", "warning", "immediate action", "final notice",
    "expires today", "account suspended", "account locked",
    "verify now", "confirm your account", "update your details",
    "your data will be lost", "your photos will be lost",
    "storage is full", "mail stopped", "drive stopped"
  ];

  urgentWords.forEach(word => {
    if (text.includes(word)) {
      score += trustedSender ? 3 : 10;
      reasons.push("Suspicious wording: " + word);
    }
  });

  // ── Advanced analysis ────────────────────────────────────────
  const advanced = advancedAnalysis(text, urls, senderDomain, trustedSender);
  score  += advanced.score;
  reasons = reasons.concat(advanced.reasons);
  const newsletterPattern = advanced.newsletterPattern;

  // ── URL analysis ─────────────────────────────────────────────
  urls.forEach(url => {
    const u          = url.toLowerCase();
    const urlDomain  = extractDomainFromUrl(u);
    const trustedUrl = isTrustedUrlDomain(urlDomain);

    if (u.includes("storage.googleapis.com")) {
      score += trustedSender ? 10 : 40;
      reasons.push("Google Cloud Storage phishing-style URL");
    }

    if (u.startsWith("http://")) {
      score += trustedUrl ? 3 : 15;
      reasons.push("Non-HTTPS link");
    }

    if (u.includes("@")) {
      score += 25;
      reasons.push("URL contains @ symbol");
    }

    if (isShortUrl(u)) {
      score += trustedSender ? 10 : 30;
      reasons.push("Shortened URL detected");
    }

    if (hasSuspiciousTld(u)) {
      score += trustedSender ? 5 : 25;
      reasons.push("Suspicious TLD in URL");
    }

    if (isCredentialPhishingUrl(u)) {
      score += trustedSender ? 10 : 35;
      reasons.push("Credential phishing URL pattern");
    }
  });

  if (urls.length > 0) {
    score += trustedSender ? 2 : 10;
    reasons.push("Email contains external links");
  }

  // ── Trusted sender discount ──────────────────────────────────
  if (trustedSender) {
    score -= 45;
    reasons.push("Trusted sender domain: " + senderDomain);
  }

  // ── Newsletter discount ──────────────────────────────────────
  if (newsletterPattern) {
    score -= 40;
    reasons.push("Newsletter / marketing pattern detected");
  }

  // ── Dangerous attachments ────────────────────────────────────
  attachments.forEach(att => {
    if (/\.(exe|js|vbs|scr|bat|cmd|zip|rar|iso|html|htm|lnk|ps1)$/i
        .test(att.getName())) {
      score += 45;
      reasons.push("Dangerous attachment: " + att.getName());
    }
  });

  score   = Math.max(0, score);
  reasons = uniqueArray(reasons);

  const level = score >= THRESHOLD_HIGH   ? "HIGH"
              : score >= THRESHOLD_MEDIUM  ? "MEDIUM"
              : "LOW";

  return { level, score, reasons, senderDomain, trustedSender, newsletterPattern };
}


// ══════════════════════════════════════════════════════════════════
// SECTION 5 — ADVANCED ANALYSIS
// ══════════════════════════════════════════════════════════════════

function advancedAnalysis(text, urls, senderDomain, trustedSender) {
  let score   = 0;
  let reasons = [];

  // ── Brand impersonation (intent-based, not word-based) ───────
  const brands = [
    { brand: "microsoft",  domain: "microsoft.com"  },
    { brand: "outlook",    domain: "microsoft.com"  },
    { brand: "office 365", domain: "microsoft.com"  },
    { brand: "google",     domain: "google.com"     },
    { brand: "gmail",      domain: "google.com"     },
    { brand: "icloud",     domain: "apple.com"      },
    { brand: "apple",      domain: "apple.com"      },
    { brand: "paypal",     domain: "paypal.com"     },
    { brand: "amazon",     domain: "amazon.com"     },
    { brand: "dhl",        domain: "dhl.com"        },
    { brand: "royal mail", domain: "royalmail.com"  },
    { brand: "hmrc",       domain: "hmrc.gov.uk"    },
    { brand: "barclays",   domain: "barclays.co.uk" },
    { brand: "hsbc",       domain: "hsbc.co.uk"     },
    { brand: "lloyds",     domain: "lloyds.com"     },
    { brand: "natwest",    domain: "natwest.com"    },
    { brand: "cloudflare", domain: "cloudflare.com" },
    { brand: "godaddy",    domain: "godaddy.com"    },
    { brand: "namecheap",  domain: "namecheap.com"  }
  ];

  brands.forEach(({ brand, domain }) => {
    // Only flag if the email CLAIMS to be that brand (not just mentions it)
    const impersonationPhrases = [
      `your ${brand} account`,
      `${brand} security alert`,
      `${brand} support`,
      `sign in to ${brand}`,
      `verify your ${brand}`,
      `from ${brand} team`,
      `${brand} account locked`,
      `${brand} password reset`,
      `${brand} billing problem`,
      `${brand} payment failed`,
      `${brand} account verification`
    ];

    const claimsToBeThisBrand = impersonationPhrases.some(p => text.includes(p));

    if (claimsToBeThisBrand && senderDomain && !senderDomain.endsWith(domain)) {
      score += trustedSender ? 5 : 25;
      reasons.push("Brand impersonation detected: " + brand);
    }
  });

  // ── Spam / AI filter poisoning ───────────────────────────────
  const poisonPatterns = [
    "--sd1v4w6w", "your seller id", "company: company",
    "street: street", "city: city", "last name: last name",
    "this is an archived section", "trusted sender",
    "xfinity forum archive", "ordered publications",
    "personal data note", "dear customer name"
  ];

  const poisonHits = poisonPatterns.filter(p => text.includes(p)).length;
  if (poisonHits >= 3) {
    score += 45;
    reasons.push("Spam filter text poisoning detected");
  }

  // ── Volume signals ───────────────────────────────────────────
  if (text.length > 5000 && urls.length > 0) {
    score += trustedSender ? 5 : 20;
    reasons.push("Very long body with external links");
  }

  if (urls.length >= 5) {
    score += trustedSender ? 3 : 15;
    reasons.push("High link count in email");
  }

  // ── Newsletter detection ─────────────────────────────────────
  const hasNewsletterText =
    text.includes("unsubscribe")       ||
    text.includes("manage preferences")||
    text.includes("view in your browser")||
    text.includes("email preferences");

  const usesMarketingPlatform = urls.some(url =>
    MARKETING_PLATFORMS.some(d => url.toLowerCase().includes(d))
  );

  const newsletterPattern = hasNewsletterText && usesMarketingPlatform;

  return { score, reasons, newsletterPattern };
}


// ══════════════════════════════════════════════════════════════════
// SECTION 6 — THREAT INTELLIGENCE ENGINE
// ══════════════════════════════════════════════════════════════════

function runThreatIntelligence(message, urls) {
  const result = {
    senderIp:     "Not available",
    ipReputation: "Not checked",
    vtResults:    []
  };

  // ── IP Forensics ─────────────────────────────────────────────
  result.senderIp = extractRealSenderIp(message);

  if (result.senderIp !== "Not available") {
    result.ipReputation = checkAbuseIPDB(result.senderIp);
  }

  // ── VirusTotal URL checks (suspicious URLs only) ─────────────
  if (KEYS.VT_KEY) {
    const urlsToCheck = urls
      .filter(u => !isTrustedUrlDomain(extractDomainFromUrl(u)))
      .slice(0, MAX_VT_URLS);

    urlsToCheck.forEach((url, index) => {
      if (index > 0) Utilities.sleep(16000); // 4 req/min for free tier
      const vtResult = checkVirusTotal(url);
      result.vtResults.push({ url, result: vtResult });
    });
  }

  return result;
}

// ── Real Sender IP — 3-method forensics ──────────────────────────
function extractRealSenderIp(message) {
  // Method 1: X-Originating-IP header
  const xOrigin = safeGetHeader(message, "X-Originating-IP");
  if (xOrigin) {
    const ip = parseFirstIp(xOrigin);
    if (ip && !isInternalIp(ip)) return ip;
  }

  // Method 2: X-Sender-IP header
  const xSender = safeGetHeader(message, "X-Sender-IP");
  if (xSender) {
    const ip = parseFirstIp(xSender);
    if (ip && !isInternalIp(ip)) return ip;
  }

  // Method 3: Last external Received header via Gmail Advanced Service
  try {
    const gmailData = Gmail.Users.Messages.get("me", message.getId(), {
      format: "metadata",
      metadataHeaders: ["Received"]
    });

    const receivedLines = (gmailData.payload.headers || [])
      .filter(h => h.name === "Received")
      .map(h => h.value);

    // Start from last (oldest = original sender) going to first (Google)
    for (let i = receivedLines.length - 1; i >= 0; i--) {
      const ip = parseFirstIp(receivedLines[i]);
      if (ip && !isInternalIp(ip) && !isGoogleIp(ip)) return ip;
    }
  } catch (e) {
    // Gmail Advanced Service not enabled — fallback
    Logger.log("⚠️ Enable Gmail Advanced Service for IP forensics: " + e.message);
    const basicReceived = safeGetHeader(message, "Received");
    if (basicReceived) {
      const ip = parseFirstIp(basicReceived);
      if (ip && !isInternalIp(ip) && !isGoogleIp(ip)) return ip;
    }
  }

  return "Not available";
}

// ── AbuseIPDB ─────────────────────────────────────────────────────
function checkAbuseIPDB(ip) {
  if (!KEYS.ABUSE_KEY) return "⚠️ ABUSE_KEY not set in Script Properties";

  try {
    const res = UrlFetchApp.fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      {
        headers: { "Key": KEYS.ABUSE_KEY, "Accept": "application/json" },
        muteHttpExceptions: true
      }
    );

    if (res.getResponseCode() === 200) {
      const d      = JSON.parse(res.getContentText()).data;
      const icon   = d.abuseConfidenceScore >= 50 ? "🔴 DANGEROUS"
                   : d.abuseConfidenceScore >= 20 ? "🟡 SUSPICIOUS"
                   : "🟢 CLEAN";
      return `${icon} | Score: ${d.abuseConfidenceScore}% | Country: ${d.countryCode} | Reports: ${d.totalReports} | ISP: ${d.isp || "Unknown"}`;
    }

    return `AbuseIPDB returned: ${res.getResponseCode()}`;
  } catch (e) {
    return "Error connecting to AbuseIPDB";
  }
}

// ── VirusTotal ────────────────────────────────────────────────────
function checkVirusTotal(url) {
  if (!KEYS.VT_KEY) return "⚠️ VT_KEY not set in Script Properties";

  try {
    const base64Url = Utilities.base64EncodeWebSafe(url).replace(/=+$/, "");
    const res = UrlFetchApp.fetch(
      `https://www.virustotal.com/api/v3/urls/${base64Url}`,
      {
        headers: { "x-apikey": KEYS.VT_KEY },
        muteHttpExceptions: true
      }
    );

    if (res.getResponseCode() === 200) {
      const stats = JSON.parse(res.getContentText())
                      .data.attributes.last_analysis_stats;
      const icon  = stats.malicious  > 0 ? "🔴 MALICIOUS"
                  : stats.suspicious > 0 ? "🟡 SUSPICIOUS"
                  : "🟢 CLEAN";
      return `${icon} | Malicious: ${stats.malicious} | Suspicious: ${stats.suspicious} | Clean: ${stats.harmless}`;
    }

    if (res.getResponseCode() === 404) return "🟢 Not in VT database";
    if (res.getResponseCode() === 429) return "⏳ Rate limit — retry later";

    return `VT returned: ${res.getResponseCode()}`;
  } catch (e) {
    return "Error connecting to VirusTotal";
  }
}

// ── IP Helper Functions ───────────────────────────────────────────
function parseFirstIp(text) {
  if (!text) return null;
  const match = text.match(/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/);
  if (!match) return null;
  return isValidIpFormat(match[1]) ? match[1] : null;
}

function isValidIpFormat(ip) {
  return ip.split(".").every(p => { const n = parseInt(p); return n >= 0 && n <= 255; });
}

function isPrivateIp(ip) {
  return ip.startsWith("127.")     ||
         ip.startsWith("10.")      ||
         ip.startsWith("192.168.") ||
         ip === "0.0.0.0"          ||
         /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

function isGoogleIp(ip) {
  return GOOGLE_IP_RANGES.some(r => ip.startsWith(r));
}

function isInternalIp(ip) {
  return !ip || isPrivateIp(ip) || isGoogleIp(ip);
}


// ══════════════════════════════════════════════════════════════════
// SECTION 7 — DRAFT REPORT
// ══════════════════════════════════════════════════════════════════

function createDraftReport(data) {
  const subject  = `[CyberAgent v25] ${data.risk} RISK — ${data.originalSubject}`;
  const safeBody = limitText(data.body, MAX_DRAFT_BODY_CHARS);

  // ── Threat Intelligence block ─────────────────────────────────
  const intelBlock = `
==============================
THREAT INTELLIGENCE FORENSICS
==============================

Sender IP (Real):
${data.senderIp}

AbuseIPDB Analysis:
${data.ipReputation}

VirusTotal URL Results:
${data.vtResults.length
  ? data.vtResults.map(v => `  ${v.url}\n  → ${v.result}`).join("\n\n")
  : "  Not checked (LOW risk or no suspicious URLs)"}
`;

  // ── Google Storage block ──────────────────────────────────────
  const googleStorageUrls = data.urls.filter(u =>
    u.toLowerCase().includes("storage.googleapis.com")
  );

  const googleBlock = googleStorageUrls.length ? `
==============================
GOOGLE SAFE BROWSING — ACTION REQUIRED
==============================

These URLs abuse Google Cloud Storage hosting:
${googleStorageUrls.join("\n")}

Report here:
https://safebrowsing.google.com/safebrowsing/report_phish/
` : "";

  const body = `Hello,

I would like to report a suspicious / phishing email for investigation.

==============================
THREAT ASSESSMENT
==============================

Risk Level:     ${data.risk}
Risk Score:     ${data.score}
Trusted Sender: ${data.trustedSender ? "YES — " + data.senderDomain : "NO"}
Newsletter:     ${data.newsletterPattern ? "YES" : "NO"}

Detection Reasons:
${data.reasons.length ? data.reasons.map(r => "  • " + r).join("\n") : "  None detected"}

==============================
EMAIL DETAILS
==============================

Gmail Sender:          ${data.gmailFrom}
Sender Domain:         ${data.senderDomain}
Possible Original From:${data.originalFrom}
Subject:               ${data.originalSubject}
Date:                  ${data.date}
Message ID:            ${data.messageId}

==============================
DETECTED URLS
==============================

${data.urls.length ? data.urls.map(u => "  " + u).join("\n") : "  None"}

==============================
ATTACHMENTS
==============================

${data.attachments.length ? data.attachments.map(a => "  " + a).join("\n") : "  None"}
${intelBlock}${googleBlock}
==============================
MANUAL REVIEW REFERENCES
==============================

  Google Safe Browsing : https://safebrowsing.google.com/safebrowsing/report_phish/
  VirusTotal           : https://www.virustotal.com/gui/home/url
  Kaspersky OpenTip    : https://opentip.kaspersky.com/
  AbuseIPDB            : https://www.abuseipdb.com/check/${data.senderIp}

==============================
FULL EMAIL CONTENT
==============================

${safeBody}

==============================
ANALYSIS SUMMARY
==============================

This email was automatically analysed by CyberAgent v25.0.
Indicators may suggest: phishing, brand impersonation,
credential harvesting, malicious links, or social engineering.

Please review and investigate accordingly.

Regards,
CyberAgent v25.0 — Automated Cyber Defense System
`;

  GmailApp.createDraft(REPORT_TO, subject, body);
}


// ══════════════════════════════════════════════════════════════════
// SECTION 8 — GOOGLE SHEET LOGGING
// ══════════════════════════════════════════════════════════════════

function logToSheet(data) {
  if (!LOG_SHEET_ID || LOG_SHEET_ID === "PUT_YOUR_GOOGLE_SHEET_ID_HERE") {
    throw new Error("Set your Google Sheet ID in LOG_SHEET_ID.");
  }

  const ss    = SpreadsheetApp.openById(LOG_SHEET_ID);
  let sheet   = ss.getSheetByName("CyberAgent Log");

  if (!sheet) {
    sheet = ss.insertSheet("CyberAgent Log");
    const headers = [
      "Date", "Gmail From", "Sender Domain", "Trusted Sender",
      "Newsletter", "Original From", "Subject", "Risk", "Score",
      "Sender IP", "IP Reputation", "VT Results",
      "Reasons", "URLs", "Attachments", "Message ID"
    ];
    sheet.appendRow(headers);
    sheet.getRange(1, 1, 1, headers.length)
         .setFontWeight("bold")
         .setBackground("#1a73e8")
         .setFontColor("#FFFFFF");
  }

  const vtSummary = data.vtResults && data.vtResults.length
    ? data.vtResults.map(v => `${v.url} → ${v.result}`).join("\n")
    : "Not checked";

  sheet.appendRow([
    data.date,
    data.gmailFrom,
    data.senderDomain,
    data.trustedSender    ? "YES" : "NO",
    data.newsletterPattern? "YES" : "NO",
    data.originalFrom,
    data.originalSubject,
    data.risk,
    data.score,
    data.senderIp     || "",
    data.ipReputation || "",
    vtSummary,
    data.reasons.join("\n"),
    data.urls.join("\n"),
    data.attachments.join("\n"),
    data.messageId
  ]);
}


// ══════════════════════════════════════════════════════════════════
// SECTION 9 — DUPLICATE PREVENTION
// ══════════════════════════════════════════════════════════════════

function alreadyProcessed(message) {
  return PropertiesService.getScriptProperties()
    .getProperty("MSG_" + message.getId()) === "DONE";
}

function markProcessed(message, label) {
  cleanupOldProperties();
  PropertiesService.getScriptProperties()
    .setProperty("MSG_" + message.getId(), "DONE");
  message.getThread().addLabel(label);
}

function cleanupOldProperties() {
  const props = PropertiesService.getScriptProperties();
  const keys  = Object.keys(props.getProperties())
                      .filter(k => k.startsWith("MSG_"));
  if (keys.length > 400) {
    keys.slice(0, keys.length - 300)
        .forEach(k => props.deleteProperty(k));
    Logger.log(`🧹 Cleaned ${keys.length - 300} old entries.`);
  }
}


// ══════════════════════════════════════════════════════════════════
// SECTION 10 — HELPER FUNCTIONS
// ══════════════════════════════════════════════════════════════════

function isOwnEmail(message) {
  if (!SKIP_OWN_EMAIL) return false;
  const myEmail = Session.getActiveUser().getEmail().toLowerCase();
  if (!myEmail) return false;
  return safeText(message.getFrom()).toLowerCase().includes(myEmail);
}

function limitText(text, max) {
  text = safeText(text);
  if (text.length <= max) return text;
  return text.substring(0, max) +
    `\n\n[TRUNCATED — body exceeded ${max} chars. Full email in Gmail.]`;
}

function extractForwardedDetails(text) {
  const section = text.split(
    /[-]{3,}\s*(forwarded message|original message)\s*[-]{3,}/i
  )[1] || "";
  const fromMatch    = section.match(/^From:\s*(.+)/im);
  const subjectMatch = section.match(/^Subject:\s*(.+)/im);
  return {
    from:    fromMatch    ? fromMatch[1].trim()    : "",
    subject: subjectMatch ? subjectMatch[1].trim() : ""
  };
}

function extractUrls(text) {
  if (!text) return [];
  const matches = text.match(/https?:\/\/[^\s"'<>]+/gi);
  if (!matches) return [];
  return uniqueArray(matches.map(u =>
    u.replace(/&amp;/g, "&").replace(/[),.;"]+$/g, "").trim()
  ));
}

function extractDomainFromSender(sender) {
  const m = sender.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return m ? m[1].toLowerCase() : "";
}

function extractDomainFromUrl(url) {
  try {
    const parsed = new URL(url.replace(/[""]/g, ""));
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch { return ""; }
}

function isTrustedSenderDomain(domain) {
  if (!domain) return false;
  domain = domain.toLowerCase().replace(/^www\./, "");
  return TRUSTED_SENDER_DOMAINS.some(t =>
    domain === t || domain.endsWith("." + t)
  );
}

function isTrustedUrlDomain(domain) {
  if (!domain) return false;
  domain = domain.toLowerCase().replace(/^www\./, "");
  return TRUSTED_URL_DOMAINS.some(t =>
    domain === t || domain.endsWith("." + t)
  );
}

function isShortUrl(url) {
  return ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly"]
    .some(d => url.includes(d));
}

function hasSuspiciousTld(url) {
  return [".biz",".ru",".cn",".top",".xyz",".click",
          ".zip",".ua",".biz.ua",".monster",".work"]
    .some(tld => url.includes(tld));
}

function isCredentialPhishingUrl(url) {
  return ["verify-account","secure-login","signin-confirm",
          "update-password","wallet-verify","account-recovery",
          "reset-password","confirm-identity","billing-update",
          "login-verify","security-check"]
    .some(w => url.toLowerCase().includes(w));
}

function safeGetHeader(message, name) {
  try { return message.getHeader(name) || null; }
  catch { return null; }
}

function getOrCreateLabel(name) {
  return GmailApp.getUserLabelByName(name) || GmailApp.createLabel(name);
}

function uniqueArray(arr) { return [...new Set(arr)]; }

function safeText(v) {
  return (v === null || v === undefined) ? "" : String(v);
}

function stripHtml(html) {
  return html ? html.replace(/<[^>]*>/g, " ") : "";
}
