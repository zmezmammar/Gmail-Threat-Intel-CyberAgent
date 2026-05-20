# CyberAgent v25.0 — Unified Cyber Defense System 🛡️✈️

An enterprise-grade, cloud-native **Email Forensics, Threat Intelligence, and Automated Incident Response System** built for Gmail using Google Apps Script. CyberAgent v25.0 acts as an automated **SOAR** (Security Orchestration, Automation, and Response) platform—scanning incoming traffic, analyzing risk telemetry, extracting true infrastructure origins, and preparing compliance-ready incident response drafts.

---

## 📊 1. كيف يعمل النظام؟ | How the System Works?

### باللغة العربية:
يعمل النظام كحارس أمني ذكي ومؤتمت بالكامل لحماية بريدك الإلكتروني خلال الـ 24 ساعة الماضية عبر 4 مراحل أساسية:
1. **قراءة وتحليل الرسائل (Ingestion & Parsing):** يفحص صندوق الوارد ومجلد الرسائل غير المرغوب فيها (Spam)، ويستخرج الروابط، المرفقات، والنصوص.
2. **محرك تقييم المخاطر (Advanced Risk Engine):** يحلل محتوى الرسالة برمجياً، ويكتشف انتحال العلامات التجارية (Brand Impersonation)، والكلمات العاجلة، مع استبعاد النشرات الإخبارية الموثوقة ذكياً لمنع التنبيهات الكاذبة.
3. **التحليل الجنائي الرقمي (Threat Intelligence):** إذا كانت الرسالة مشبوهة (MEDIUM/HIGH)، يتم استخراج الـ IP الحقيقي للمرسل من الـ Headers وعزله عن خوادم جوجل، ثم فحصه عبر AbuseIPDB، وفحص الروابط عبر VirusTotal.
4. **الاستجابة المؤتمتة (Automated Response):** يسجل التفاصيل في Google Sheet، ويقوم بإنشاء **مسودة تقرير أمني احترافي جاهز** في بريدك لإرساله فوراً للجهات الأمنية العالمية (مثل NCSC و APWG).

### In English:
CyberAgent v25.0 operates as an automated, non-destructive tactical gateway processing emails from the last 24 hours through a 4-stage pipeline:
1. **Ingestion & Parsing:** Monitors both Inbox and Spam folders, extracting metadata, localized raw bodies, attachments, and URLs.
2. **Heuristic Risk Engine:** Programmatically evaluates metrics such as urgent call-to-actions, credential harvesting patterns, and Brand Impersonation, while dynamically whitelisting trusted infrastructure and marketing platforms (Newsletters).
3. **Forensic Threat Intelligence:** For non-LOW risk profiles, it extracts the true originating sender IP (bypassing Google's proxies), queries AbuseIPDB for multi-report historical confidence, and cross-references external links via VirusTotal.
4. **Orchestrated Incident Response:** Appends full metrics to a secure decentralized SIEM Google Sheet and **automatically builds an actionable, rich cyber incident report draft** addressed to global authorities (NCSC, APWG).

#### 🗺️ Unified Operational Pipeline / مخطط سير العمليات الموحد


---

## 🛠️ 2. إعداد البيئة الرقمية | Setting Up the Environment

### باللغة العربية:
1. انتقل إلى [Google Sheets](https://sheets.google.com) وأنشئ جدولاً جديداً.
2. انسخ **رابط معرف الجدول (Spreadsheet ID)** من شريط العنوان (الرمز الطويل المتواجد بين `/d/` و `/edit`).
3. من القائمة العلوية، اختر **Extensions** ثم **Apps Script**.
4. استبدل الكود الافتراضي بكود **`Code.gs` (الإصدار v25.0)**.
5. ابحث عن المتغير `LOG_SHEET_ID` في السطر 45 وضَع معرف الجدول الخاص بك مكانه. اضغط على زر **الحفظ (💾)**.

### In English:
1. Navigate to [Google Sheets](https://sheets.google.com) and create a new blank spreadsheet.
2. Copy the unique **Spreadsheet ID** from your browser's URL bar (the long alphanumeric string between `/d/` and `/edit`).
3. From the top menu, click **Extensions** ➔ **Apps Script**.
4. Delete all default placeholders and paste the **`Code.gs` (v25.0)** production code.
5. Locate the `LOG_SHEET_ID` constant (Line 45) and paste your copied Spreadsheet ID inside the quotes. Click the **Save (💾)** icon.

---

## 🔑 3. تفعيل الخدمات والمفاتيح | Enabling Services & APIs

### ⚙️ أ. تفعيل خدمة Gmail API (Advanced Service)
* **العربية:** داخل واجهة Apps Script، انظر للقائمة الجانبية اليسرى، اضغط على زر **(+)** بجانب كلمة **Services**، اختر **Gmail API** واضغط **Add**. (هذا ضروري جداً لتمكين الفحص الجنائي للـ Headers).
* **English:** Inside the Apps Script editor sidebar, click the **(+) icon next to Services**, select **Gmail API** from the list, and click **Add**. (Crucial for accessing Advanced Metadata and Header Forensic properties).

### 🔑 ب. ضبط مفاتيح الأسرار (Script Properties)
* **العربية:** اذهب إلى إعدادات المشروع ⚙️ (أيقونة الترس الجانبية)، انزل لأسفل إلى **Script Properties**، وأضف المفاتيح التالية:
  * `VT_KEY` ➔ (مفتاحك الخاص من VirusTotal)
  * `ABUSE_KEY` ➔ (مفتاحك الخاص من AbuseIPDB)
* **English:** Go to **Project Settings ⚙️** (the gear icon on the left), scroll down to **Script Properties**, click **Add script property**, and map your environment credentials:
  * `VT_KEY` ➔ [Your VirusTotal API Token]
  * `ABUSE_KEY` ➔ [Your AbuseIPDB API Token]

---

## 🛡️ 4. وضع الأمان والمخرجات المتوقعة | Safe Mode & Triage Matrix

### باللغة العربية:
يتميز النظام بـ **وضع الأمان المطلق (Safe Mode)**: فهو لا يقوم بحذف أي رسائل، ولا يفتح الروابط برمجياً، ولا يرسل إيميلات تلقائية بدون إذنك. يقتصر عمله على فرز وتصنيف الرسائل كالتالي:

| فئة المخاطر | الإجراء المتخذ برمجياً | الملصق المضاف (Label) |
| :--- | :--- | :--- |
| **مخاطر منخفضة / موثوق** | يتم تسجيل البيانات في الجدول فقط لتوثيقها بأمان. | `CyberAgent-Trusted-Logged` |
| **مخاطر متوسطة / عالية** | فحص عميق عبر الـ APIs + إنشاء مسودة بلاغ أمني جاهزة للإرسال. | `CyberAgent-Review` |

### In English:
The system strictly enforces **Safe Mode execution guidelines**: it never automatically sends outbound mail, never deletes records, and never triggers embedded links. It gracefully sorts traffic based on the following automated telemetry:

| Risk Profile | Automation Trigger | Applied Retention Label |
| :--- | :--- | :--- |
| **LOW / Trusted Platform** | Passive telemetry logging inside the spreadsheet for security auditing. | `CyberAgent-Trusted-Logged` |
| **MEDIUM / HIGH Risk** | API lookup enrichment + **Generates a full-text threat report draft** in your mailbox. | `CyberAgent-Review` |

```text
+-----------------------------------------------------------------------------------+
|               [CyberAgent v25.0 Threat Intelligence Draft Report]                 |
| To: report@phishing.gov.uk, reportphishing@apwg.org                              |
| Subject: [CyberAgent v25] HIGH RISK — Urgent Action Required: Account Suspended   |
| --------------------------------------------------------------------------------- |
| Forensics: IP: 185.x.x.x | Abuse Score: 92% | Country: UA                          |
| VirusTotal: 🔴 MALICIOUS | Google Storage Phishing Link Detected                  |
+-----------------------------------------------------------------------------------+
