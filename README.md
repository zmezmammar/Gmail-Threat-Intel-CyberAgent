# Gmail-Threat-Intel-CyberAgent 🛡️✈️

An enterprise-grade, automated **Threat Intelligence & Incident Response System** designed for Gmail using **Google Apps Script**. This cloud-native system runs on time-based triggers to parse incoming emails, conduct deep digital forensics, cross-reference global threat feeds, and automatically stage comprehensive incident reports—all without exposing sensitive API credentials.

---

## 📊 Key Architecture & Features

### 1. Advanced Email Header Forensics
- **Identity Spoofing & Masking Detection:** Inspects `Authentication-Results` (SPF, DKIM, DMARC), `Reply-To`, and `Return-Path` mismatches. Detects Unicode/IDN Homograph attacks and display-name wrapping tricks.
- **Geographical & ISP Intelligence:** Extracts the true originating IP address from the `Received` metadata headers and queries a secure GeoIP endpoint to log the attacker's Country, ISP, ASN, and network location.

### 2. Multi-Engine Threat Assessment
- **VirusTotal Integration:** Automated, rate-limited URL scanning via base64 web-safe encoding against 70+ antivirus engines.
- **AbuseIPDB Reputation Checks:** Live analytics on the sender's IP confidence score to weigh network maliciousness.
- **Dynamic Threat Databases:** Auto-syncs twice daily with active phishing/malware repository lists (e.g., OpenPhish, URLhaus).

### 3. Automated Incident Staging (100% Safe Mode)
- **Zero-Interaction Policy:** The script **NEVER** sends direct replies, deletes emails, or opens active links.
- **Dynamic Report Drafting:** Constructs contextual, professional incident reports customized by threat type (Phishing vs. Malware vs. Ad-Injection Flood) and saves them straight into your **Gmail Drafts** or logs them to an immutable **Google Sheets Audit Log**.

---

## 🛠️ Security Architecture: Secrets Management

To adhere to industry-standard security frameworks, this repository utilizes **Zero Hardcoded Credentials**. All sensitive API keys are abstractly mapped using Google's native environment variables container.

```javascript
// Production-ready secure configuration mapping
const INTEL_CONFIG = {
  VT_API_KEY     : PropertiesService.getScriptProperties().getProperty('VT_KEY'), 
  ABUSE_API_KEY  : PropertiesService.getScriptProperties().getProperty('ABUSE_KEY'),
  GEMINI_API_KEY : PropertiesService.getScriptProperties().getProperty('GEMINI_KEY'), 
  SHEET_NAME     : "Threat_Intelligence_DB"
};
