/**
 * ==============================================================================
 * Project: Gmail Threat Intelligence & Cyber Defense System (CyberAgent v1.0)
 * Description: Automated cloud-native system for threat hunting and logging.
 * Security Standard: Zero Hardcoded Credentials (Uses Script Properties).
 * ==============================================================================
 */

// 1. الإعدادات الأمنية: استدعاء المفاتيح من بيئة جوجل المخفية لحمايتها من السرقة
const INTEL_CONFIG = {
  VT_API_KEY     : PropertiesService.getScriptProperties().getProperty('VT_KEY'), 
  ABUSE_API_KEY  : PropertiesService.getScriptProperties().getProperty('ABUSE_KEY'),
  GEMINI_API_KEY : PropertiesService.getScriptProperties().getProperty('GEMINI_KEY'), 
  SHEET_NAME     : "Threat_Intelligence_DB"
};

/**
 * دالة التشغيل الرئيسية - يتم جدexternalها لتعمل تلقائياً
 */
function runDailyThreatIntel() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(INTEL_CONFIG.SHEET_NAME);
  
  // إذا لم تكن الصفحة موجودة في الـ Sheet، يتم إنشاؤها وضبط العناوين فوراً
  if (!sheet) {
    sheet = ss.insertSheet(INTEL_CONFIG.SHEET_NAME);
    sheet.appendRow(["التاريخ", "نوع المؤشر", "مؤشر الاختراق (Indicator)", "تقييم AbuseIPDB", "تقييم VirusTotal", "الحالة"]);
    sheet.getRange("A1:F1").setFontWeight("bold").setBackground("#1a73e8").setFontColor("#FFFFFF");
  }

  // سحب عينة تهديدات حقيقية ونشطة من الإنترنت
  const targets = fetchLatestGlobalThreats();

  for (let item of targets) {
    let vtReport = "غير مفحوص (مفتاح الـ API مفقود)";
    let abuseReport = "غير مفحوص (مفتاح الـ API مفقود)";

    // الفحص عبر AbuseIPDB إذا كان المؤشر عنوان IP والمفتاح موجود
    if (item.type === "ip" && INTEL_CONFIG.ABUSE_API_KEY) {
      abuseReport = checkIpAbuseScore(item.value);
    } else if (item.type === "ip") {
      abuseReport = "يرجى إضافة مفتاح ABUSE_KEY في الإعدادات";
    }

    // الفحص عبر VirusTotal إذا كان المفتاح موجود
    if (INTEL_CONFIG.VT_API_KEY) {
      vtReport = checkWithVirusTotal(item.value, item.type);
    } else {
      vtReport = "يرجى إضافة مفتاح VT_KEY في الإعدادات";
    }

    // تسجيل البيانات في جدول Google Sheets كقاعدة بيانات أمنية للمشروع
    sheet.appendRow([
      new Date(),
      item.type.toUpperCase(),
      item.value,
      abuseReport,
      vtReport,
      "مؤرشف ومراقب 👁️"
    ]);
    
    // انتظار 15 ثانية بين الطلبات لتجنب حظر الحساب المجاني (Rate Limit)
    Utilities.sleep(15000); 
  }
}

/**
 * جلب أحدث التهديدات النشطة عالمياً من قاعدة بيانات URLhaus المفتوحة
 */
function fetchLatestGlobalThreats() {
  try {
    const response = UrlFetchApp.fetch("https://urlhaus.abuse.ch/api/v1/urls/recent/", {muteHttpExceptions: true});
    if (response.getResponseCode() === 200) {
      const json = JSON.parse(response.getContentText());
      const urls = json.urls || [];
      // نأخذ عنصرين فقط لتوظيف الحساب المجاني باقتصاد
      return urls.slice(0, 2).map(u => ({ type: "url", value: u.url }));
    }
  } catch(e) {
    Logger.log("فشل الاتصال بالتغذية الخارجية، استخدام العينة الاحتياطية");
  }
  
  // عينة احتياطية حقيقية لضمان عمل السكربت بنجاح أثناء التجرية
  return [
    { type: "ip", value: "118.107.44.130" },
    { type: "url", value: "http://bad-phishing-login-example.com" }
  ];
}

/**
 * فحص سمعة الـ IP عبر AbuseIPDB API
 */
function checkIpAbuseScore(ip) {
  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`;
    const res = UrlFetchApp.fetch(url, {
      headers: { "Key": INTEL_CONFIG.ABUSE_API_KEY, "Accept": "application/json" },
      muteHttpExceptions: true
    });
    if (res.getResponseCode() === 200) {
      const data = JSON.parse(res.getContentText());
      return "نسبة خطورة العنوان: " + data.data.abuseConfidenceScore + "%";
    }
  } catch(e) {
    return "خطأ في الاتصال بـ AbuseIPDB";
  }
  return "لا توجد بيانات متوفرة";
}

/**
 * فحص الروابط والمؤشرات عبر VirusTotal API
 */
function checkWithVirusTotal(indicator, type) {
  try {
    // تشفير الرابط بصيغة Base64 بدون علامات مساوية حسب توثيق VirusTotal API v3
    const base64Url = Utilities.base64EncodeWebSafe(indicator).replace(/=+$/, "");
    const url = `https://www.virustotal.com/api/v3/urls/${base64Url}`;
    
    const res = UrlFetchApp.fetch(url, {
      headers: { "x-apikey": INTEL_CONFIG.VT_API_KEY },
      muteHttpExceptions: true
    });
    
    if (res.getResponseCode() === 200) {
      const data = JSON.parse(res.getContentText());
      const stats = data.data.attributes.last_analysis_stats;
      return `النتيجة: الخبيثة (${stats.malicious}) | المشبوهة (${stats.suspicious})`;
    } else if (res.getResponseCode() === 404) {
      return "الرابط نظيف أو لم يتم رصده مسبقاً في قاعدة البيانات";
    }
  } catch(e) {
    return "خطأ في الاتصال بـ VirusTotal";
  }
  return "استجابة غير معروفة من الخادم";
}
