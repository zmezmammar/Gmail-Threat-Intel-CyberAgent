# Gmail-Threat-Intel-CyberAgent 🛡️✈️

An enterprise-grade, automated **Threat Intelligence & Incident Response System** designed for Gmail using **Google Apps Script**. This cloud-native system runs on time-based triggers to parse incoming emails, conduct deep digital forensics, cross-reference global threat feeds, and automatically stage comprehensive incident reports—all without exposing sensitive API credentials.

---

## 📊 1. كيف يعمل النظام؟ | How the System Works?

### باللغة العربية:
النظام عبارة عن بيئة دفاعية مؤتمتة تعمل بالكامل في السحاب (Cloud-Native). يقوم السكربت المجدول بجمع البيانات وفحصها كالتالي:
1. **المُحفّز المجدول (Cron Trigger):** يشتغل السكربت مرتين يومياً تلقائياً دون أي تدخل بشري.
2. **تغذية التهديدات (Threat Feed):** يسحب أحدث مؤشرات الاختراق (IoCs) النشطة عالمياً من منصة URLhaus.
3. **الفحص المزدوج (Dual Scanning):** يرسل المؤشرات بشكل آمن إلى VirusTotal و AbuseIPDB عبر الـ API للتأكد من سمعتها وخطورتها.
4. **قاعدة البيانات (SIEM Sheet):** يتم تنظيف البيانات وتسجيلها فوراً في جدول Google Sheets المخصص لتصبح قاعدة بيانات حية ومحدثة للتهديدات.

### In English:
The system is a fully automated, cloud-native defense environment. The scheduled script orchestrates threat hunting as follows:
1. **Cron Trigger:** The script executes automatically twice a day without human interaction.
2. **Threat Feed Harvesting:** Fetches active indicators of compromise (IoCs) from the global URLhaus database.
3. **Dual API Enrichment:** Queries VirusTotal and AbuseIPDB to assess maliciousness and confidence scores.
4. **Decentralized SIEM Logging:** Automatically structures, sanitizes, and appends the intelligence telemetry into Google Sheets.

---

## 🛠️ 2. إعداد البيئة الرقمية | Setting Up the Environment

### باللغة العربية:
1. افتح حسابك الشخصي في جوجل، ثم انتقل إلى [Google Sheets](https://sheets.google.com).
2. أنشئ جدولاً فارغاً جديداً، وقم بتغيير اسم الصفحة بالأسفل بدقة من `Sheet1` إلى: **`Threat_Intelligence_DB`**.
3. من شريط الأدوات العلوي، اضغط على **Extensions** (الإضافات) ثم اختر **Apps Script**.
4. امسح الكود الافتراضي، وضَع كود السكربت المطور الخاص بنا (`Code.gs`)، ثم اضغط على زر **💾 (الحفظ)** المتواجد بالشريط العلوي.

### In English:
1. Log into your Google account and navigate to [Google Sheets](https://sheets.google.com).
2. Create a new blank spreadsheet, and rename the active tab at the bottom from `Sheet1` to exactly: **`Threat_Intelligence_DB`**.
3. From the top menu, click on **Extensions**, then select **Apps Script**.
4. Delete any default placeholder code, paste the secure automation code (`Code.gs`) from this repository, and click the **💾 (Save)** icon.

---

## 🔑 3. استخراج المفاتيح الأمنية | Extracting the Security API Keys

### 📑 أ. منصة VirusTotal Platform
* **العربية:** ادخل إلى `https://www.virustotal.com` وأنشئ حساباً مجانياً. فعّل الحساب من بريدك، ثم اضغط على **صورة ملفك الشخصي** في أعلى اليمين واختر **API key** وانسخ الرمز الطويل.
* **English:** Go to `https://www.virustotal.com` and register a free account. Verify your email, click your **User Profile icon** in the top-right corner, select **API key**, and copy the active key string.

### 📑 ب. منصة AbuseIPDB Platform
* **العربية:** سجل في `https://www.abuseipdb.com/register` بحساب **Developer** مجاني. بعد التفعيل، ادخل للوحة التحكم، واضغط على تبويب **API**، ثم زر **Create Key** الأزرق وانسخ المفتاح.
* **English:** Register at `https://www.abuseipdb.com/register` for a free **Developer** account. Once verified, go to the dashboard, click the **API** tab, hit the blue **Create Key** button, and copy your token.

### 📑 ج. منصة Gemini API (Google AI Studio)
* **العربية:** توجه إلى `https://aistudio.google.com/` واضغط على **Get API key** من القائمة الجانبية، ثم اختر **Create API key** وانسخ الرمز المتولد للتحليل الذكي الافتراضي للتهديدات.
* **English:** Navigate to `https://aistudio.google.com/`, click **Get API key** from the sidebar menu, select **Create API key**, and copy the generated AI token.

---

## 🔒 4. إدارة الأسرار وإخفاء المفاتيح | Secrets Management

### باللغة العربية:
لحماية المفاتيح من السرقة وعدم تركها مكشوفة في الكود (وهو معيار أمني عالمي لحماية البيانات الحساسة):
1. داخل صفحة **Google Apps Script**، اضغط على أيقونة **الترس ⚙️ (Project Settings)** من القائمة الجانبية اليسرى.
2. انزل لأسفل الصفحة حتى تصل إلى قسم **Script Properties**.
3. اضغط على زر **Add script property** وأضف الرموز كالتالي:
   * اسم الخاصية (Property): `VT_KEY` -> القيمة (Value): [ضع مفتاح VirusTotal هنا]
   * اسم الخاصية (Property): `ABUSE_KEY` -> القيمة (Value): [ضع مفتاح AbuseIPDB هنا]
   * اسم الخاصية (Property): `GEMINI_KEY` -> القيمة (Value): [ضع مفتاح Gemini هنا]
4. اضغط على الزر الأزرق **Save script properties**.

### In English:
To adhere to industrial frameworks and avoid hardcoding credentials inside open-source code:
1. Within your **Google Apps Script** dashboard, click the **Gear Icon ⚙️ (Project Settings)** on the left sidebar.
2. Scroll down to the **Script Properties** deployment window.
3. Click **Add script property** and securely map the environment variables:
   * Property: `VT_KEY` -> Value: [Your VirusTotal API Key]
   * Property: `ABUSE_KEY` -> Value: [Your AbuseIPDB API Key]
   * Property: `GEMINI_KEY` -> Value: [Your Gemini API Key]
4. Click the blue **Save script properties** button to lock the secrets in the environment variable container.

```javascript
// Production-ready secure configuration mapping (Zero Hardcoded Credentials)
const INTEL_CONFIG = {
  VT_API_KEY     : PropertiesService.getScriptProperties().getProperty('VT_KEY'), 
  ABUSE_API_KEY  : PropertiesService.getScriptProperties().getProperty('ABUSE_KEY'),
  GEMINI_API_KEY : PropertiesService.getScriptProperties().getProperty('GEMINI_KEY'), 
  SHEET_NAME     : "Threat_Intelligence_DB"
};
