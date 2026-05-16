# Mini EDR Pro V1.0 - Update Run Guide

هذا الملف يشرح بالضبط ماذا تعمل بعد التحديث الأخير حتى يعمل النظام بشكل صحيح.

## 1) المتطلبات

- Python موجود على السيرفر والـ agent.
- الـ virtual environment موجود داخل المشروع في `venv`.
- مكتبات المشروع مثبتة.

## 2) تثبيت المكتبات (على جهاز السيرفر)

من داخل مسار المشروع:

```powershell
cd "c:\Users\ahmad\Desktop\mini_edr_pro V1.0"
.\venv\Scripts\pip.exe install -r requirements.txt
```

إذا الـ agent عندك Linux منفصل، ثبّت نفس المتطلبات هناك حسب نسخة المشروع الموجودة عندك.

## 3) ضبط IP السيرفر للـ Agent

افتح الملف:

`agent/config.py`

وتأكد أن:

- `SERVER_IP` = IP جهاز السيرفر الحقيقي (وليس `127.0.0.1` إذا الـ agent على جهاز ثاني).
- `PORT` = `9999` (نفس السيرفر).

## 4) تشغيل السيرفر (Backend Socket)

على جهاز السيرفر (Windows):

```powershell
cd "c:\Users\ahmad\Desktop\mini_edr_pro V1.0"
.\venv\Scripts\python.exe .\server\core\server.py
```

يجب أن ترى:

`[+] Server running...`

## 5) تشغيل الداشبورد (Flask)

في Terminal ثاني على نفس السيرفر:

```powershell
cd "c:\Users\ahmad\Desktop\mini_edr_pro V1.0"
.\venv\Scripts\python.exe .\server\dashboard\app.py
```

افتح المتصفح:

`http://127.0.0.1:5000`

## 6) تشغيل Agent

على جهاز الـ agent:

```bash
python agent/core/agent.py
```

بعدها المفروض endpoint يظهر في واجهة الداشبورد خلال ثواني.

## 7) ما الذي تغيّر في هذا التحديث

- Telemetry أعمق للعمليات:
  - `pid`, `ppid`, `username`, `cmdline`, `exe`, `sha256`, `start_time`, `cpu`, `memory`.
- Network enrichment:
  - `remote_connections` مع المنافذ البعيدة.
- Detection engine جديد مبني على policies:
  - الملف: `server/policies/detection_rules.json`
- تنبيهات مع حقول MITRE:
  - `technique_id`, `tactic`, `source`.
- Process snapshots للتحقيق:
  - جدول جديد: `process_snapshots`.

## 8) API endpoints الجديدة (اختياري للفحص)

أثناء تشغيل Flask:

- `GET /api/processes/recent`
- `GET /api/processes/recent?ip=YOUR_AGENT_IP&limit=100`
- `GET /api/indicators/summary`

مثال سريع من PowerShell:

```powershell
Invoke-RestMethod "http://127.0.0.1:5000/api/indicators/summary"
```

## 9) تعديل قواعد الكشف

الملف:

`server/policies/detection_rules.json`

تقدر تعدل:

- أدوات high risk
- أدوات scripting
- المنافذ المشبوهة
- عتبة `port_spike_threshold`
- عتبة `network_exfiltration_threshold`

بعد التعديل، فقط أعد تشغيل:

1. `server/core/server.py`
2. `server/dashboard/app.py`

## 10) فحص سريع إذا في مشكلة

من جذر المشروع:

```powershell
.\venv\Scripts\python.exe -m compileall agent server
```

إذا نجحت بدون أخطاء، الـ syntax سليم.

## 11) مشاكل شائعة

- الـ endpoint لا يظهر:
  - تأكد `SERVER_IP` في `agent/config.py`.
  - تأكد firewall يسمح على `9999`.
- الداشبورد فاضي:
  - تأكد السيرفر شغال + agent يرسل.
- لا تظهر تنبيهات جديدة:
  - شغّل أوامر/عمليات مشمولة في القواعد داخل `detection_rules.json`.

## 12) ترتيب التشغيل الصحيح (مختصر)

1. شغّل `server/core/server.py`
2. شغّل `server/dashboard/app.py`
3. شغّل `agent/core/agent.py`
4. افتح `http://127.0.0.1:5000`

