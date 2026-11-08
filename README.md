# Saba Public Inter College - Website + School ERP

## Run on your laptop
1. Install Python 3.10+
2. pip install -r requirements.txt
3. python app.py
4. Open http://127.0.0.1:5000  (public website)
   Staff login: http://127.0.0.1:5000/erp/login

## Demo logins (CHANGE BEFORE GOING ONLINE)
- Super Admin: admin / admin123
- Teacher: teacher1 / teacher123

## Before deployment
- Set a long random SECRET_KEY environment variable.
- Change both demo passwords (Password page; Teachers page for teacher resets).
- Run behind HTTPS with a production server, e.g. gunicorn app:app
- Back up the file saba.db regularly (copy it). Set DB_PATH to change its location.

## Roles
- Super Admin: everything (students, attendance, fees, teachers, dashboard).
- Teacher: students + attendance only. Fees, teachers and dashboard return 403.
  Teachers can edit attendance for today only; past dates are view-only.

## Email alert for admission enquiries
Set these BEFORE running python app.py (Windows, same Command Prompt window):
  set SMTP_HOST=smtp.gmail.com
  set SMTP_PORT=587
  set SMTP_USER=yourschoolgmail@gmail.com
  set SMTP_PASS=your-16-letter-app-password
  set NOTIFY_EMAIL=sabapublicintercollege@gmail.com
Gmail needs 2-Step Verification ON, then create an "App password" in your Google account.
If NOTIFY_EMAIL is not set, the email from Settings is used. Never put the password inside app.py.
Admin login page: /admin (or /erp/login). After 5 wrong tries, login is paused for 10 minutes.
