import os, re, time, smtplib, threading, sqlite3, datetime, secrets, csv, io
from email.message import EmailMessage
from functools import wraps
from flask import (Flask, request, redirect, render_template_string, g,
                   session, abort, flash, Response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash 

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=5 * 1024 * 1024)
DB = os.environ.get("DB_PATH", "saba.db")
STATUSES = ("Present", "Absent", "Leave")
SFIELDS = [("adm_no", "Admission No", "text"), ("name", "Student Name", "text"),
           ("father", "Father's Name", "text"), ("mother", "Mother's Name", "text"),
           ("dob", "Date of Birth", "date"), ("gender", "Gender", "text"),
           ("cls", "Class", "text"), ("section", "Section", "text"),
           ("phone", "Contact", "text"), ("address", "Address", "text"),
           ("adm_date", "Admission Date", "date"), ("session", "Session", "text")]


def today():
    return datetime.date.today().isoformat()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


def q(sql, a=(), one=False):
    r = db().execute(sql, a).fetchall()
    return (r[0] if r else None) if one else r


def ex(sql, a=()):
    c = db().execute(sql, a)
    db().commit()
    return c


@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
      name TEXT, pw TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('admin','teacher')),
      active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, adm_no TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL, father TEXT, mother TEXT, dob TEXT, gender TEXT, cls TEXT,
      section TEXT, phone TEXT, address TEXT, adm_date TEXT, session TEXT,
      fee_total REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS attendance(student_id INTEGER, day TEXT,
      status TEXT CHECK(status IN('Present','Absent','Leave')), marked_by INTEGER,
      PRIMARY KEY(student_id, day));
    CREATE TABLE IF NOT EXISTS fees(id INTEGER PRIMARY KEY, student_id INTEGER,
      category TEXT, amount REAL, paid_on TEXT);
    CREATE TABLE IF NOT EXISTS enquiries(id INTEGER PRIMARY KEY, name TEXT, phone TEXT,
      cls TEXT, message TEXT, created TEXT);
    """)
    if not c.execute("SELECT 1 FROM users").fetchone():
        c.executemany("INSERT INTO users(username,name,pw,role) VALUES(?,?,?,?)", [
            ("admin", "Super Admin", generate_password_hash("admin123"), "admin"),
            ("teacher1", "Demo Teacher", generate_password_hash("teacher123"), "teacher")])
        demo = [("1001", "Aman Khan", "Irfan Khan", "Shabana", "2009-05-12", "Male", "10", "A"),
                ("1002", "Sana Fatima", "Zaid Ali", "Nazia", "2009-08-03", "Female", "10", "A"),
                ("1003", "Rahul Yadav", "Ramesh Yadav", "Sunita", "2009-01-20", "Male", "10", "A"),
                ("1101", "Zoya Ansari", "Imran Ansari", "Rubina", "2008-02-14", "Female", "11", "Science"),
                ("1102", "Arjun Singh", "Vijay Singh", "Meena", "2008-11-09", "Male", "11", "Science")]
        c.executemany("INSERT INTO students(adm_no,name,father,mother,dob,gender,cls,section,"
                      "phone,address,adm_date,session,fee_total) VALUES(?,?,?,?,?,?,?,?,"
                      "'9000000000','Azamgarh','2025-04-01','2026-27',12000)", demo)
    c.commit()
    c.close()


# ---------- security ----------
def token():
    session.setdefault("csrf", secrets.token_hex(16))
    return session["csrf"]


app.jinja_env.globals["csrf"] = token


@app.before_request
def csrf_check():
    if request.method == "POST":
        if not session.get("csrf") or request.form.get("csrf") != session["csrf"]:
            abort(400)


def login_required(role=None):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            uid = session.get("uid")
            user = q("SELECT * FROM users WHERE id=? AND active=1", (uid,), True) if uid else None
            if not user:
                return redirect("/erp/login")
            if role and user["role"] != role:
                abort(403)  # enforced on the server, not just hidden in the menu
            g.user = user
            return f(*a, **k)
        return w
    return deco


# ---------- templates ----------
BASE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Saba Public Inter College</title>
<style>
:root{--n:{{th[0]}};--g:{{th[1]}};--bg:{{th[2]}};--n2:{{th[3]}};--text:#263B35;--ivory:#F7F5ED;--forest:#123B32;--gold:#D6B45C}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:system-ui,Segoe UI,sans-serif;color:var(--text);background:var(--bg);line-height:1.55;overflow-wrap:anywhere}
h1,h2,h3,h4{font-family:Georgia,serif;color:var(--n);line-height:1.25}
header{position:sticky;top:0;z-index:5;background:var(--n);color:var(--ivory);padding:12px clamp(12px,3vw,24px);display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;border-bottom:4px solid var(--g)}
header b{color:var(--g);font-size:clamp(16px,2vw,20px);font-family:Georgia,serif}
header small{display:block;max-width:100%;font-size:12px}
nav{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px;max-width:100%}
nav a{color:var(--ivory);text-decoration:none;font-size:14px;border-bottom:2px solid transparent;padding:5px 2px;white-space:nowrap}
nav a:hover,nav a:focus{border-color:var(--g);color:var(--g)}
main{width:100%;max-width:1100px;margin:0 auto;padding:clamp(10px,2.5vw,22px)}
.hero{background:linear-gradient(135deg,var(--n),var(--n2));color:var(--ivory);padding:clamp(24px,6vw,56px) 18px;text-align:center;border-radius:14px}
.hero h1{margin:6px 0;color:var(--g);font-size:clamp(26px,6vw,42px)}.hero p{margin:6px 0}
.tag{letter-spacing:clamp(1px,0.5vw,3px);text-transform:uppercase;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,210px),1fr));gap:12px;margin:14px 0}
.stat{background:#fff;border-top:4px solid var(--g);border-radius:8px;padding:14px;text-align:center;box-shadow:0 1px 4px #0002}.stat b{display:block;font-size:clamp(18px,3vw,22px);color:var(--n)}
.card{background:#fff;border-radius:10px;padding:clamp(12px,2.5vw,18px);margin:12px 0;box-shadow:0 1px 5px #0002;min-width:0}.grid .card{margin:0}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid #e1e4ec;padding:9px;text-align:left;vertical-align:top}th{color:var(--n)}
.tw{width:100%;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}.tw table{min-width:600px}
input,select,textarea,button{padding:10px;font-size:16px;margin:4px 0;max-width:100%;border:1px solid #c8ccd6;border-radius:6px}
input:not([type=radio]):not([type=checkbox]):not([type=color]):not([type=file]),select,textarea{width:min(100%,360px)}
textarea{resize:vertical}
button,.btn{background:var(--n);color:var(--ivory);border:0;cursor:pointer;padding:10px 14px;text-decoration:none;display:inline-block;border-radius:6px}
.btn.gold{background:var(--g);color:var(--n);font-weight:700}.btn.ghost{background:#ffffff33}
.msg{background:#fff6d6;padding:10px;border-left:4px solid var(--g);margin:8px 0}
.login{max-width:420px;width:100%;margin:clamp(16px,5vh,40px) auto;text-align:center}.login input,.login button{width:100%}
.sw{display:inline-block;width:46px;height:26px;border-radius:5px;margin:4px 3px 0 0}
footer{background:var(--n);color:var(--ivory);text-align:center;padding:18px;margin-top:26px;border-top:4px solid var(--g);font-size:14px}
img{max-width:100%;height:auto}
@media(max-width:700px){
 header{position:relative;align-items:flex-start;flex-direction:column}
 nav{width:100%;display:flex;flex-wrap:nowrap;overflow-x:auto;overflow-y:hidden;padding:4px 0 8px;gap:8px;-webkit-overflow-scrolling:touch}
 nav a{flex:0 0 auto;font-size:13px}
 main{padding:10px}
 .hero{border-radius:10px}
 .grid{grid-template-columns:repeat(auto-fit,minmax(min(100%,145px),1fr));gap:8px}
 .card{margin:9px 0}
 .tw table{min-width:560px}
 .tag{letter-spacing:1px}
}
@media(max-width:420px){
 .grid{grid-template-columns:1fr}
 .hero .btn{margin:4px 0}
}
@media print{header,footer,.np{display:none}}
</style></head><body>
<header><div><b>{{site.school}}</b><br><small>{{site.address}} &middot; Est. 2003</small></div>
<nav class=np>{% if erp %}{% if g.user.role=='admin' %}<a href=/erp>Admin Panel</a>{% else %}<a href=/erp/teacher>Teacher Panel</a>{% endif %}
<a href=/erp/students>Students</a><a href=/erp/attendance>Attendance</a><a href=/erp/report>Monthly</a>
{% if g.user.role=='admin' %}<a href=/erp/fees>Fees</a><a href=/erp/teachers>Teachers</a><a href=/erp/exams>Exams</a>{% for k in ['notices','faculty','events','gallery','homework','timetable','library','inventory','transport'] %}<a href=/erp/m/{{k}}>{{k|capitalize}}</a>{% endfor %}<a href=/erp/enquiries>Enquiries</a><a href=/erp/data>Data</a><a href=/erp/settings>Settings</a><a href=/erp/pages>Website</a>{% endif %}
<a href=/erp/password>Password</a><a href=/erp/logout>Logout</a>
{% else %}<a href=/>Home</a><a href=/about>About</a><a href=/founder>Founder</a><a href=/programmes>Programmes</a><a href=/faculty>Faculty</a><a href=/notices>Notices</a><a href=/events>Events</a><a href=/gallery>Gallery</a><a href=/contact>Contact</a><a href=/location>Location</a><a href=/admin>Admin Login</a>{% endif %}</nav></header>
<main>{% for m in get_flashed_messages() %}<div class=msg>{{m}}</div>{% endfor %}{{ body|safe }}</main><footer class=np>{{site.school}}, {{site.address}} &middot; Phone: {{site.phone}}<br>Email: {{site.email}}</footer></body></html>"""

CSRF = '<input type=hidden name=csrf value="{{csrf()}}">'
GSEL = ('<select name=grp>{% for c in groups %}<option value="{{c.cls}}|{{c.section}}" '
        '{{"selected" if grp==c.cls+"|"+c.section}}>Class {{c.cls}}-{{c.section}}</option>{% endfor %}</select>')

PUBLIC = {
    "": """<div class=hero><div style="font-size:44px">&#128214;</div><h1>{{site.school}}</h1><p class=tag>{{site.tagline}}</p>
<p>UP Board &middot; Nursery to Class 12 &middot; Arts &amp; Science &middot; Azamgarh, Uttar Pradesh</p>
<p><a class="btn gold" href=#enquiry>Admission Enquiry</a> <a class="btn ghost" href=/about>About Us</a></p></div>
<div class=grid><div class=stat><b>2003</b>Established</div><div class=stat><b>Nursery-12</b>Classes</div><div class=stat><b>UP Board</b>Board</div><div class=stat><b>Arts &amp; Science</b>Streams</div></div>
<div class=grid><div class=card><h3>Science Stream</h3><p>Science education for Classes 11 and 12.</p></div><div class=card><h3>Arts Stream</h3><p>Arts education for Classes 11 and 12.</p></div>
<div class=card><h3>Values &amp; Discipline</h3><p>Quality education that builds confident, responsible students.</p></div></div>
<div class=card style="display:flex;gap:16px;flex-wrap:wrap;align-items:center"><img src=/static/principal.jpg alt="Principal" style="width:120px;height:120px;object-fit:cover;object-position:top;border-radius:50%;border:3px solid var(--g)">
<div style="flex:1;min-width:220px"><h3 style="margin:0">Principal's Message</h3><p>It gives me immense pleasure to welcome you to Saba Public Inter College.</p>
<b>Dr. Syed Kaisar Husain</b>, Founder &amp; Principal<br><a href=/founder>Read full message</a></div></div>""",
    "about": """<div class=card><h2>About Saba Public Inter College</h2><p><b><i>Education Today, Leadership Tomorrow</i></b></p>
<p>Saba Public Inter College, established in 2003 under the visionary leadership of Dr. Syed Kaisar Husain, is dedicated to delivering quality education and shaping the future of young generations.</p>
<p>Since its establishment, the institution has focused on creating an educational environment where academic excellence, discipline, moral values, creativity, and personal development go hand in hand.</p>
<p>We believe that education is not simply about achieving good marks; it is about developing responsible citizens, independent thinkers, confident individuals, and future leaders.</p></div>
<div class=card><h3>Our Journey</h3><p>Founded in 2003, Saba Public Inter College began with a vision to make quality education accessible and meaningful for students. Over the years, the institution has continued its commitment to academic development and the holistic growth of students.</p>
<p>Our educational approach encourages students to explore their abilities, develop practical knowledge, participate in extracurricular activities, and build confidence for the challenges of tomorrow.</p></div>
<div class=card><h3>Our Mission</h3><p>Our mission is to provide a supportive, inclusive, and disciplined learning environment where every student receives opportunities to learn, grow, and achieve their potential.</p><p>We strive to:</p>
<ul><li>Deliver quality education through effective teaching.</li><li>Develop strong moral values and discipline.</li><li>Encourage creativity, curiosity, and critical thinking.</li><li>Promote physical, intellectual, and emotional development.</li><li>Prepare students for higher education and future careers.</li></ul></div>
<div class=card><h3>Our Vision</h3><p>To become a leading educational institution recognized for academic excellence, innovation, discipline, and character building.</p>
<p>We envision a future where every student becomes knowledgeable, confident, responsible, and capable of contributing positively to society.</p></div>
<div class=card><h3>Our Educational Philosophy</h3><p>At Saba Public Inter College, we believe every child has unique abilities and deserves the opportunity to succeed.</p><p>Our educational philosophy is based on five important pillars:</p>
<ol><li><b>Academic Excellence:</b> Building strong foundations and encouraging continuous learning.</li><li><b>Discipline:</b> Developing responsibility, respect, and good habits.</li>
<li><b>Character Building:</b> Promoting honesty, kindness, integrity, and moral values.</li><li><b>Creativity:</b> Encouraging students to think independently and explore new ideas.</li>
<li><b>Holistic Development:</b> Supporting academic, physical, social, and personal growth.</li></ol></div>
<div class=card><h3>A Commitment to Every Student</h3><p>We recognize that every student has different talents, interests, and learning abilities. Our aim is to encourage individual growth while maintaining a culture of respect, equality, and cooperation.</p>
<p>We want our students to leave the institution not only with academic knowledge but also with the confidence, skills, and values required to succeed in life.</p>
<p><b>Saba Public Inter College &mdash; Building Knowledge, Inspiring Excellence, Shaping Futures.</b></p></div>""",
    "programmes": """<div class=card><h2>Our Programmes</h2><p>Saba Public Inter College | Established 2003<br>Nursery to Class 12 &middot; UP Board School</p><h3>Education for Every Child, Opportunity for Every Future</h3>
<p>At Saba Public Inter College, we believe that education is the foundation of a better society. Our programmes are designed to provide quality, affordable and accessible education to children from our village and surrounding communities.</p></div>
<div class=grid>
<div class=card><h4>1. Pre-Primary (Nursery &ndash; UKG)</h4><p>Building strong foundations through:</p><ul><li>Basic English and Hindi</li><li>Number recognition</li><li>Reading and writing</li><li>Drawing and creative activities</li><li>Good habits and discipline</li></ul></div>
<div class=card><h4>2. Primary (Classes 1&ndash;5)</h4><p>Developing essential academic skills through:</p><ul><li>Hindi and English</li><li>Mathematics</li><li>Environmental Studies</li><li>General Knowledge</li><li>Basic computer awareness</li></ul></div>
<div class=card><h4>3. Upper Primary (Classes 6&ndash;8)</h4><p>Strengthening knowledge and understanding through:</p><ul><li>Hindi and English</li><li>Mathematics</li><li>Science</li><li>Social Science</li><li>Sanskrit</li><li>Computer Education</li></ul></div>
<div class=card><h4>4. Secondary (Classes 9&ndash;10)</h4><p>Preparing students for UP Board High School examinations through:</p><ul><li>Hindi and English</li><li>Mathematics</li><li>Science</li><li>Social Science</li><li>Other applicable board subjects</li></ul></div>
<div class=card><h4>5. Intermediate (Classes 11&ndash;12)</h4><p>Senior secondary education through applicable streams and subjects:</p><ul><li>Science Stream</li><li>Arts / Humanities Stream</li></ul></div>
<div class=card><h4>6. Computer Education</h4><ul><li>Basic computer operations</li><li>MS Word, Excel and PowerPoint</li><li>Internet and digital literacy</li><li>Practical computer knowledge</li></ul></div>
<div class=card><h4>7. Sports &amp; Physical Education</h4><ul><li>Indoor and outdoor games</li><li>Physical fitness activities</li><li>Annual sports competitions</li><li>Teamwork and leadership</li></ul></div>
<div class=card><h4>8. Cultural &amp; National Programmes</h4><ul><li>Independence Day</li><li>Republic Day</li><li>Annual functions</li><li>Speech and debate competitions</li><li>Drawing and essay competitions</li></ul></div>
<div class=card><h4>9. Student Support Programmes</h4><ul><li>Regular class tests</li><li>Examination preparation</li><li>Board examination guidance</li><li>Attendance monitoring</li><li>Parent-teacher meetings</li><li>Academic support for students</li></ul></div></div>
<div class=card><h3>Our Commitment</h3><p>We are committed to making education accessible to every child, especially those from rural communities. Our goal is to develop knowledgeable, disciplined, confident and responsible citizens.</p>
<h3>Our Motto: Learn Today, Lead Tomorrow.</h3><p>Saba Public Inter College &middot; Building a Brighter Future Since 2003</p></div>""",
    "founder": """<div class=card><h2>Founder &amp; Principal</h2>
<div style="display:flex;flex-wrap:wrap;gap:18px;align-items:flex-start">
<img src="/static/principal.jpg" alt="Dr. Syed Kaisar Husain" style="width:100%;max-width:300px;border-radius:8px;border:3px solid var(--g)">
<div style="flex:1;min-width:240px"><h3 style="margin-top:0">Dr. Syed Kaisar Husain</h3>
<p>Founder and Principal, Saba Public Inter College. He established the college in 2003.</p></div></div></div>
<div class=card><h3>Principal's Message</h3>
<p>Dear Students, Parents and Well-Wishers,</p>
<p>It gives me immense pleasure to welcome you to Saba Public Inter College.</p>
<p>Established in 2003 under the vision and leadership of our founder, Dr. Syed Kaisar Husain, our institution is committed to providing quality education and shaping responsible, confident and knowledgeable individuals.</p>
<p>We believe that education is not limited to textbooks and examinations. It is about developing strong values, discipline, creativity, critical thinking and a sense of responsibility towards society.</p>
<p>Our dedicated teachers strive to create a supportive and inspiring learning environment where every student gets the opportunity to discover their potential and achieve their goals. We encourage our students to work hard, respect others, embrace new ideas and face challenges with confidence.</p>
<p>We also believe that parents and teachers must work together to guide students towards a bright and successful future.</p>
<p>Let us continue this journey of learning, growth and excellence together.</p>
<p>With best wishes,<br><b>Dr. Syed Kaisar Husain</b><br>Principal<br>Saba Public Inter College<br>Azamgarh, Uttar Pradesh</p></div>""",
    "faculty": """<div class=card><h2>Faculty &amp; Staff</h2><p><i>[Faculty and staff list to be added by the school.]</i></p></div>""",
    "events": """<div class=card><h2>Events &amp; Activities</h2><p><i>[School events to be added.]</i></p></div>""",
    "gallery": """<div class=card><h2>School Gallery</h2><p><i>[Photos to be added.]</i></p></div>""",
    "location": """<div class=card><h2>School Location</h2><p>Saba Public Inter College, Azamgarh, Uttar Pradesh, India.</p>
<p><a href="https://www.google.com/maps/search/Saba+Public+Inter+College+Azamgarh">Open in Google Maps</a></p></div>""",
    "contact": """<div class=card><h2>Contact Us</h2><h3>Saba Public Inter College</h3><p>We welcome parents, students and visitors to connect with us.</p></div>
<div class=grid><div class=card><h4>Our Address</h4><p>Sihin, Paharpur, Sathiaon, Azamgarh, Uttar Pradesh &ndash; 276406</p></div>
<div class=card><h4>Phone Numbers</h4><p><a href=tel:9794333054>9794333054</a><br><a href=tel:9170133055>9170133055</a></p></div>
<div class=card><h4>Email Address</h4><p><a href=mailto:sabapublicintercollege@gmail.com>sabapublicintercollege@gmail.com</a></p></div>
<div class=card><h4>Facebook</h4><p>Saba Public Inter College</p></div></div>
<div class=card><h4>School Information</h4><ul><li>Founder: Dr. Syed Kaisar Husain</li><li>Established: 2003</li><li>Board: Uttar Pradesh Board (UP Board)</li></ul></div>
<div class=card><h4>Get in Touch</h4><p>For admissions, academic enquiries, or general information, please contact the school by phone, email, or Facebook.</p>
<p><b>Saba Public Inter College &ndash; Quality Education for a Brighter Future.</b></p></div>""",
}


def page(tpl, erp=False, **ctx):
    return render_template_string(BASE, erp=erp, body=render_template_string(tpl, **ctx))


def show_page(slug, default):
    row = q("SELECT html FROM pages WHERE slug=?", (slug,), True)
    if row:  # admin-edited text is shown as plain HTML, never run as a template
        return render_template_string(BASE, erp=False, body=row["html"])
    return page(default)


for _n, _t in PUBLIC.items():
    if _n and _n not in ("faculty", "events", "gallery"):  # these three are managed from the ERP menu
        app.add_url_rule("/" + _n, "pub_" + _n, (lambda n=_n, t=_t: show_page(n, t)))


def send_mail(to, subject, body):
    host, user, pw = os.environ.get("SMTP_HOST"), os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
    if not (host and user and pw and to):
        return  # email alerts are off until SMTP_* settings are provided

    def run():
        try:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = subject, user, to
            msg.set_content(body)
            port = int(os.environ.get("SMTP_PORT", "587"))
            if port == 465:
                srv = smtplib.SMTP_SSL(host, port, timeout=15)
            else:
                srv = smtplib.SMTP(host, port, timeout=15)
                srv.starttls()
            srv.login(user, pw)
            srv.send_message(msg)
            srv.quit()
        except Exception as e:
            print("Email failed:", e)
    threading.Thread(target=run, daemon=True).start()


@app.post("/enquiry")
def enquiry():
    f = request.form
    ex("INSERT INTO enquiries(name,phone,cls,message,created) VALUES(?,?,?,?,?)",
       (f["name"][:100], f["phone"][:20], f.get("cls", "")[:20], f.get("message", "")[:500], today()))
    send_mail(os.environ.get("NOTIFY_EMAIL") or all_settings().get("email") or SITE_DEFAULT["email"], "New admission enquiry",
              "Name: %s\nPhone: %s\nClass: %s\nMessage: %s\nDate: %s" % (f["name"][:100], f["phone"][:20], f.get("cls", "")[:20], f.get("message", "")[:500], today()))
    flash("Thank you. We will contact you soon.")
    return redirect("/")


# ---------- auth ----------
FAILS = {}


@app.route("/erp/login", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form["username"].strip()
        key, now = (request.remote_addr, name.lower()), time.time()
        FAILS[key] = [t for t in FAILS.get(key, []) if now - t < 600]
        if len(FAILS[key]) >= 5:
            flash("Too many wrong attempts. Please wait 10 minutes.")
        else:
            u = q("SELECT * FROM users WHERE username=? AND active=1", (name,), True)
            if u and check_password_hash(u["pw"], request.form["password"]):
                session.clear()
                session["uid"] = u["id"]
                FAILS.pop(key, None)
                return redirect("/erp" if u["role"] == "admin" else "/erp/teacher")
            FAILS[key].append(now)
            flash("Wrong username or password.")
    return page("<div class='card login'><div style='font-size:42px'>&#127979;</div><h2 style='margin:4px 0'>{{site.school}}</h2>"
                "<p style='color:#667;margin-top:0'>Admin &amp; Teacher Login</p><form method=post>" + CSRF +
                "<input name=username placeholder=Username required autocomplete=username>"
                "<input id=pw name=password type=password placeholder=Password required autocomplete=current-password>"
                "<label style='display:block;text-align:left;font-size:14px'><input type=checkbox style='width:auto' "
                "onclick=\"document.getElementById('pw').type=this.checked?'text':'password'\"> Show password</label><button>Login</button></form>"
                "<p style='font-size:13px;color:#667'>Forgot your password? Ask the Super Admin to reset it.</p><p><a href=/>&larr; Back to website</a></p></div>")


@app.route("/erp/logout")
def logout():
    session.clear()
    return redirect("/erp/login")


@app.route("/erp/password", methods=["GET", "POST"])
@login_required()
def password():
    if request.method == "POST":
        if not check_password_hash(g.user["pw"], request.form["old"]) or len(request.form["new"]) < 6:
            flash("Old password wrong, or new password shorter than 6 characters.")
        else:
            ex("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(request.form["new"]), g.user["id"]))
            flash("Password changed.")
    return page("<div class=card><h3>Change Password</h3><form method=post>" + CSRF +
                "<input name=old type=password placeholder='Current password' required><br>"
                "<input name=new type=password placeholder='New password' required><br><button>Change</button></form></div>", True)


# ---------- dashboard ----------
@app.route("/erp")
@login_required("admin")
def dashboard():
    n = lambda s, a=(): q(s, a, True)[0] or 0
    pending = n("SELECT SUM(fee_total) FROM students") - n("SELECT SUM(amount) FROM fees")
    return page("""<h2>Admin Dashboard</h2><div class=card>Students: <b>{{a}}</b> &middot; Teachers: <b>{{t}}</b> &middot;
Present today: <b>{{p}}</b> &middot; Pending fees: <b>{{pend}}</b></div>
<div class=card><h3>Recent admission enquiries <a href=/erp/enquiries style="font-size:14px">View all</a></h3><div class=tw><table>{% for e in enq %}<tr><td>{{e.created}}</td><td>{{e.name}}</td><td>{{e.phone}}</td><td>{{e.cls}}</td><td>{{e.message}}</td></tr>
{% else %}<tr><td>None yet.</td></tr>{% endfor %}</table></div></div>""", True,
                a=n("SELECT COUNT(*) FROM students"), t=n("SELECT COUNT(*) FROM users WHERE role='teacher'"),
                p=n("SELECT COUNT(*) FROM attendance WHERE day=? AND status='Present'", (today(),)),
                pend=pending, enq=q("SELECT * FROM enquiries ORDER BY id DESC LIMIT 5"))


# ---------- teacher panel (teacher-only workspace) ----------
@app.route("/erp/teacher")
@login_required("teacher")
def teacher_dashboard():
    total = q("SELECT COUNT(*) FROM students", one=True)[0] or 0
    marked = q("SELECT COUNT(*) FROM attendance WHERE day=? AND marked_by=?",
               (today(), g.user["id"]), one=True)[0] or 0
    present = q("SELECT COUNT(*) FROM attendance WHERE day=? AND marked_by=? AND status='Present'",
                (today(), g.user["id"]), one=True)[0] or 0
    return page("""<div class=hero><h1>Teacher Panel</h1>
    <p>Welcome, {{g.user.name or g.user.username}}. Manage daily classroom attendance and student records.</p>
    <p><a class="btn gold" href=/erp/attendance>Mark Attendance</a>
    <a class="btn ghost" href=/erp/report>Monthly Report</a></p></div>
    <div class=grid><div class=stat><b>{{total}}</b>Students in school</div>
    <div class=stat><b>{{marked}}</b>Attendance entries marked today</div>
    <div class=stat><b>{{present}}</b>Present entries marked today</div></div>
    <div class=grid><div class=card><h3>Attendance</h3><p>Mark attendance for your classroom. Teachers can edit today's attendance only.</p><a class=btn href=/erp/attendance>Open attendance</a></div>
    <div class=card><h3>Monthly Report</h3><p>Review class-wise monthly attendance summaries.</p><a class=btn href=/erp/report>View report</a></div>
    <div class=card><h3>Student Records</h3><p>Search students and open their attendance history.</p><a class=btn href=/erp/students>View students</a></div>
    <div class=card><h3>Account Security</h3><p>Update your password to keep your account secure.</p><a class=btn href=/erp/password>Change password</a></div></div>""",
    True, total=total, marked=marked, present=present)


# ---------- students ----------
@app.route("/erp/students")
@login_required()
def students():
    s = request.args.get("q", "")
    rows = q("SELECT * FROM students WHERE name LIKE ? OR adm_no LIKE ? ORDER BY cls,section,name",
             (f"%{s}%", f"%{s}%"))
    return page("""<h3>Students</h3><form method=get><input name=q value="{{s}}" placeholder="Search name or admission no"><button>Search</button>
<a class=btn href=/erp/students/new>Add student</a></form><div class=card><div class=tw><table>
<tr><th>Adm</th><th>Name</th><th>Father</th><th>Class</th><th>Phone</th><th></th></tr>
{% for r in rows %}<tr><td>{{r.adm_no}}</td><td>{{r.name}}</td><td>{{r.father}}</td><td>{{r.cls}}-{{r.section}}</td><td>{{r.phone}}</td>
<td><a href=/erp/students/{{r.id}}/edit>Edit</a> | <a href=/erp/students/{{r.id}}/attendance>Attendance</a>{% if g.user.role=='admin' %} <form method=post action=/erp/students/{{r.id}}/delete style=display:inline onsubmit="return confirm('Delete student?')"><input type=hidden name=csrf value="{{csrf()}}"><button>Delete</button></form>{% endif %}</td></tr>{% endfor %}</table></div></div>""",
                True, rows=rows, s=s)


def student_form(row):
    return page("""<h3>{{'Edit' if row else 'Add'}} student</h3><div class=card><form method=post>""" + CSRF + """
{% for k,label,t in fields %}<label>{{label}}<br><input type={{t}} name={{k}} value="{{row[k] if row else ''}}" {{'required' if k in ('adm_no','name')}}></label><br>{% endfor %}
<button>Save</button></form></div>""", True, row=row, fields=SFIELDS)


@app.route("/erp/students/new", methods=["GET", "POST"])
@login_required()
def student_new():
    if request.method == "POST":
        vals = [request.form.get(k, "").strip() for k, _, _ in SFIELDS]
        try:
            ex("INSERT INTO students(%s) VALUES(%s)" % (",".join(k for k, _, _ in SFIELDS),
                                                       ",".join("?" * len(SFIELDS))), vals)
            return redirect("/erp/students")
        except sqlite3.IntegrityError:
            flash("Admission number already exists.")
    return student_form(None)


@app.route("/erp/students/<int:sid>/edit", methods=["GET", "POST"])
@login_required()
def student_edit(sid):
    row = q("SELECT * FROM students WHERE id=?", (sid,), True) or abort(404)
    if request.method == "POST":
        vals = [request.form.get(k, "").strip() for k, _, _ in SFIELDS]
        try:
            ex("UPDATE students SET %s WHERE id=?" % ",".join(k + "=?" for k, _, _ in SFIELDS), vals + [sid])
            return redirect("/erp/students")
        except sqlite3.IntegrityError:
            flash("Admission number already exists.")
    return student_form(row)


@app.post("/erp/students/<int:sid>/delete")
@login_required("admin")
def student_delete(sid):
    ex("DELETE FROM attendance WHERE student_id=?", (sid,))
    ex("DELETE FROM students WHERE id=?", (sid,))
    return redirect("/erp/students")


# ---------- attendance ----------
@app.route("/erp/attendance", methods=["GET", "POST"])
@login_required()
def attendance():
    f = request.form if request.method == "POST" else request.args
    groups = q("SELECT DISTINCT cls,section FROM students ORDER BY cls,section")
    grp = f.get("grp") or (f"{groups[0]['cls']}|{groups[0]['section']}" if groups else "|")
    day = f.get("day") or today()
    cls, sec = grp.split("|", 1)
    studs = q("SELECT * FROM students WHERE cls=? AND section=? ORDER BY name", (cls, sec))
    editable = g.user["role"] == "admin" or day == today()
    if request.method == "POST":
        if not editable:
            abort(403)
        for s in studs:
            st = f.get(f"s{s['id']}")
            if st in STATUSES:
                db().execute("INSERT OR REPLACE INTO attendance(student_id,day,status,marked_by) VALUES(?,?,?,?)",
                             (s["id"], day, st, g.user["id"]))
        db().commit()
        flash("Attendance saved.")
        return redirect(f"/erp/attendance?grp={grp}&day={day}")
    marks = {r["student_id"]: r["status"] for r in
             q("SELECT student_id,status FROM attendance WHERE day=?", (day,))}
    return page("<h3>Attendance</h3><form method=get>" + GSEL + """<input type=date name=day value="{{day}}"><button>Show</button></form>
{% if studs %}<form method=post>""" + CSRF + """<input type=hidden name=grp value="{{grp}}"><input type=hidden name=day value="{{day}}">
<div class=card><div class=tw><table><tr><th>Adm</th><th>Name</th><th>Present</th><th>Absent</th><th>Leave</th></tr>
{% for s in studs %}<tr><td>{{s.adm_no}}</td><td><a href=/erp/students/{{s.id}}/attendance>{{s.name}}</a></td>
{% for o in statuses %}<td><input type=radio name="s{{s.id}}" value={{o}} {{'checked' if marks.get(s.id, 'Present' if editable else '')==o}} {{'' if editable else 'disabled'}}></td>{% endfor %}</tr>{% endfor %}
</table></div></div>{% if editable %}<button>Save attendance</button>{% else %}<div class=msg>Past dates are view-only for teachers.</div>{% endif %}</form>
{% else %}<p>No students in this class.</p>{% endif %}""", True,
                groups=groups, grp=grp, day=day, studs=studs, marks=marks, editable=editable, statuses=STATUSES)


@app.route("/erp/students/<int:sid>/attendance")
@login_required()
def student_history(sid):
    s = q("SELECT * FROM students WHERE id=?", (sid,), True) or abort(404)
    rows = q("SELECT day,status FROM attendance WHERE student_id=? ORDER BY day DESC LIMIT 90", (sid,))
    return page("<h3>{{s.name}} - attendance history</h3><div class=card><table>{% for r in rows %}<tr><td>{{r.day}}</td><td>{{r.status}}</td></tr>"
                "{% else %}<tr><td>No records yet.</td></tr>{% endfor %}</table></div>", True, s=s, rows=rows)


@app.route("/erp/report")
@login_required()
def report():
    groups = q("SELECT DISTINCT cls,section FROM students ORDER BY cls,section")
    grp = request.args.get("grp") or (f"{groups[0]['cls']}|{groups[0]['section']}" if groups else "|")
    month = request.args.get("month") or today()[:7]
    cls, sec = grp.split("|", 1)
    rows = q("SELECT s.adm_no,s.name,SUM(a.status='Present') p,SUM(a.status='Absent') ab,SUM(a.status='Leave') l "
             "FROM students s LEFT JOIN attendance a ON a.student_id=s.id AND substr(a.day,1,7)=? "
             "WHERE s.cls=? AND s.section=? GROUP BY s.id ORDER BY s.name", (month, cls, sec))
    return page("<h3>Monthly attendance report</h3><form method=get>" + GSEL + """<input type=month name=month value="{{month}}"><button>Show</button></form>
<div class=card><div class=tw><table><tr><th>Adm</th><th>Name</th><th>Present</th><th>Absent</th><th>Leave</th></tr>
{% for r in rows %}<tr><td>{{r.adm_no}}</td><td>{{r.name}}</td><td>{{r.p or 0}}</td><td>{{r.ab or 0}}</td><td>{{r.l or 0}}</td></tr>{% endfor %}</table></div></div>""",
                True, groups=groups, grp=grp, month=month, rows=rows)


# ---------- fees (admin only) ----------
@app.route("/erp/fees")
@login_required("admin")
def fees():
    s = request.args.get("q", "")
    rows = q("SELECT s.*, COALESCE((SELECT SUM(amount) FROM fees WHERE student_id=s.id),0) paid FROM students s "
             "WHERE s.name LIKE ? OR s.adm_no LIKE ? ORDER BY s.cls,s.name", (f"%{s}%", f"%{s}%"))
    if request.args.get("pending"):
        rows = [r for r in rows if r["fee_total"] - r["paid"] > 0]
    month = q("SELECT SUM(amount) FROM fees WHERE substr(paid_on,1,7)=?", (today()[:7],), True)[0] or 0
    year = q("SELECT SUM(amount) FROM fees WHERE substr(paid_on,1,4)=?", (today()[:4],), True)[0] or 0
    return page("""<h3>Fee Management</h3><div class=card>Collected this month: <b>{{month}}</b> &middot; this year: <b>{{year}}</b></div>
<form method=get><input name=q value="{{s}}" placeholder="Name or admission no"><label><input type=checkbox name=pending value=1> Pending only</label><button>Search</button></form>
<div class=card><div class=tw><table><tr><th>Adm</th><th>Name</th><th>Class</th><th>Total</th><th>Paid</th><th>Pending</th><th></th></tr>
{% for r in rows %}<tr><td>{{r.adm_no}}</td><td>{{r.name}}</td><td>{{r.cls}}-{{r.section}}</td><td>{{r.fee_total}}</td><td>{{r.paid}}</td><td>{{r.fee_total-r.paid}}</td>
<td><a href=/erp/fees/{{r.id}}>Open</a></td></tr>{% endfor %}</table></div></div>""", True, rows=rows, s=s, month=month, year=year)


@app.route("/erp/fees/<int:sid>", methods=["GET", "POST"])
@login_required("admin")
def fee_student(sid):
    s = q("SELECT * FROM students WHERE id=?", (sid,), True) or abort(404)
    if request.method == "POST":
        try:
            if request.form["action"] == "total":
                ex("UPDATE students SET fee_total=? WHERE id=?", (float(request.form["total"]), sid))
            else:
                amt = float(request.form["amount"])
                if amt <= 0:
                    raise ValueError
                c = ex("INSERT INTO fees(student_id,category,amount,paid_on) VALUES(?,?,?,?)",
                       (sid, request.form["category"][:40], amt, today()))
                return redirect(f"/erp/fees/receipt/{c.lastrowid}")
        except ValueError:
            flash("Enter a valid amount.")
        return redirect(f"/erp/fees/{sid}")
    pays = q("SELECT * FROM fees WHERE student_id=? ORDER BY id DESC", (sid,))
    paid = sum(p["amount"] for p in pays)
    return page("""<h3>{{s.name}} ({{s.adm_no}}) - Class {{s.cls}}-{{s.section}}</h3>
<div class=card>Total fee: <b>{{s.fee_total}}</b> &middot; Paid: <b>{{paid}}</b> &middot; Pending: <b>{{s.fee_total-paid}}</b>
<form method=post>""" + CSRF + """<input type=hidden name=action value=total><input name=total type=number step=0.01 value="{{s.fee_total}}"><button>Set total fee</button></form></div>
<div class=card><h4>Collect fee</h4><form method=post>""" + CSRF + """<input type=hidden name=action value=pay>
<input name=category placeholder="Category (Tuition, Exam...)" required><input name=amount type=number step=0.01 placeholder=Amount required><button>Collect &amp; receipt</button></form></div>
<div class=card><h4>Payment history</h4><table>{% for p in pays %}<tr><td>{{p.paid_on}}</td><td>{{p.category}}</td><td>{{p.amount}}</td><td><a href=/erp/fees/receipt/{{p.id}}>Receipt</a></td></tr>
{% else %}<tr><td>No payments yet.</td></tr>{% endfor %}</table></div>""", True, s=s, pays=pays, paid=paid)


@app.route("/erp/fees/receipt/<int:pid>")
@login_required("admin")
def receipt(pid):
    p = q("SELECT f.*, s.name, s.adm_no, s.cls, s.section FROM fees f JOIN students s ON s.id=f.student_id WHERE f.id=?",
          (pid,), True) or abort(404)
    return page("""<div class=card><h2>Fee Receipt R-{{'%05d'|format(p.id)}}</h2><p>Saba Public Inter College, Azamgarh</p>
<p>Date: {{p.paid_on}}<br>Student: {{p.name}} ({{p.adm_no}}), Class {{p.cls}}-{{p.section}}<br>Category: {{p.category}}<br>Amount received: <b>{{p.amount}}</b></p>
<button class=np onclick="window.print()">Print</button></div>""", True, p=p)


# ---------- teachers (admin only) ----------
@app.route("/erp/teachers", methods=["GET", "POST"])
@login_required("admin")
def teachers():
    if request.method == "POST":
        a, f = request.form["action"], request.form
        try:
            if a == "create" and len(f["password"]) >= 6:
                ex("INSERT INTO users(username,name,pw,role) VALUES(?,?,?,'teacher')",
                   (f["username"].strip(), f["name"].strip(), generate_password_hash(f["password"])))
            elif a == "toggle":
                ex("UPDATE users SET active=1-active WHERE id=? AND role='teacher'", (f["id"],))
            elif a == "reset" and len(f["password"]) >= 6:
                ex("UPDATE users SET pw=? WHERE id=? AND role='teacher'", (generate_password_hash(f["password"]), f["id"]))
            else:
                flash("Password must be at least 6 characters.")
        except sqlite3.IntegrityError:
            flash("Username already exists.")
        return redirect("/erp/teachers")
    return page("""<h3>Teacher Accounts</h3><div class=card><form method=post>""" + CSRF + """<input type=hidden name=action value=create>
<input name=name placeholder="Full name" required><input name=username placeholder=Username required><input name=password type=password placeholder="Password (6+)" required><button>Create teacher</button></form></div>
<div class=card><div class=tw><table>{% for t in rows %}<tr><td>{{t.name}}</td><td>{{t.username}}</td><td>{{'Active' if t.active else 'Disabled'}}</td>
<td><form method=post style=display:inline>""" + CSRF + """<input type=hidden name=action value=toggle><input type=hidden name=id value={{t.id}}><button>{{'Disable' if t.active else 'Enable'}}</button></form></td>
<td><form method=post style=display:inline>""" + CSRF + """<input type=hidden name=action value=reset><input type=hidden name=id value={{t.id}}><input name=password type=password placeholder="New password" required><button>Reset</button></form></td></tr>{% endfor %}</table></div></div>""",
                True, rows=q("SELECT * FROM users WHERE role='teacher' ORDER BY name"))



# ---------- extra modules (admin only) ----------
MODS = {
    "notices": ("Notices", [("title", "Title"), ("body", "Details"), ("date", "Date", "date"), ("category", "Section: Class 10 / Class 12 / Class 10 & 12 / General"), ("attachment", "PDF or photo", "file")]),
    "homework": ("Homework", [("cls", "Class"), ("section", "Section"), ("subject", "Subject"), ("task", "Homework"), ("due", "Due date", "date")]),
    "timetable": ("Timetable", [("cls", "Class"), ("section", "Section"), ("day", "Day"), ("period", "Period"), ("subject", "Subject"), ("teacher", "Teacher")]),
    "library": ("Library", [("title", "Book title"), ("author", "Author"), ("copies", "Copies", "number"), ("issued_to", "Issued to"), ("due", "Due date", "date")]),
    "inventory": ("Inventory", [("item", "Item"), ("qty", "Quantity", "number"), ("location", "Location"), ("note", "Note")]),
    "transport": ("Transport", [("route", "Route"), ("vehicle", "Vehicle no"), ("driver", "Driver"), ("phone", "Driver phone"), ("students", "Students / stops")]),
    "faculty": ("Faculty & Staff", [("name", "Name"), ("role", "Designation"), ("subject", "Subject"), ("photo", "Photo", "file")]),
    "events": ("Events", [("title", "Event"), ("date", "Date", "date"), ("details", "Details"), ("photo", "Photo", "file")]),
    "gallery": ("Gallery", [("caption", "Caption"), ("photo", "Photo", "file")]),
}


def init_extra():
    c = sqlite3.connect(DB)
    for k, (_, fs) in MODS.items():
        c.execute("CREATE TABLE IF NOT EXISTS %s(id INTEGER PRIMARY KEY,%s)" % (k, ",".join(f[0] + " TEXT" for f in fs)))
        have = {r[1] for r in c.execute("PRAGMA table_info(%s)" % k)}
        for f in fs:
            if f[0] not in have:
                c.execute("ALTER TABLE %s ADD COLUMN %s TEXT" % (k, f[0]))
    c.executescript("""
    CREATE TABLE IF NOT EXISTS pages(slug TEXT PRIMARY KEY, html TEXT);
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY, name TEXT, session TEXT);
    CREATE TABLE IF NOT EXISTS marks(exam_id INTEGER, student_id INTEGER, subject TEXT, score REAL, maxm REAL,
      PRIMARY KEY(exam_id, student_id, subject));""")
    if not c.execute("SELECT 1 FROM notices").fetchone():
        c.executemany("INSERT INTO notices(title,body,date,category,attachment) VALUES(?,?,?,?,'')", [
            ("Correction of student academic details (UP Board 2027)", "UPMSP correction window for student details remains open until 12 November 2026. Check upmsp.edu.in.", "2026-11-02", "Class 10 & 12"),
            ("UP Board 2027 Date Sheet Released", "Class 10 (High School) and Class 12 (Intermediate) examinations: 5 to 24 February 2027. Morning shift 8:30 AM to 11:45 AM; afternoon shift 2:00 PM to 5:15 PM. Published by UPMSP on 12 October 2026. Download the official PDF from upmsp.edu.in.", "2026-10-12", "Class 10 & 12")])
    c.commit()
    c.close()


MODT = """<h3>{{title}}</h3><div class=card><form method=post enctype=multipart/form-data>""" + CSRF + """{% for f in fs %}<input name={{f[0]}} type={{f[2] if f|length>2 else 'text'}} placeholder="{{f[1]}}" title="{{f[1]}}">{% endfor %}<button>Add</button></form></div>
<div class=card><div class=tw><table><tr>{% for f in fs %}<th>{{f[1]}}</th>{% endfor %}<th></th></tr>
{% for r in rows %}<tr>{% for f in fs %}<td>{% if f|length>2 and f[2]=='file' %}{% if r[f[0]] %}{% if r[f[0]].endswith('.pdf') %}<a href="{{r[f[0]]}}" target=_blank>PDF</a>{% else %}<img src="{{r[f[0]]}}" style="height:48px">{% endif %}{% endif %}{% else %}{{r[f[0]]}}{% endif %}</td>{% endfor %}<td><form method=post action=/erp/m/{{mod}}/{{r.id}}/delete>""" + CSRF + """<button>Delete</button></form></td></tr>{% endfor %}</table></div></div>"""


@app.route("/erp/m/<mod>", methods=["GET", "POST"])
@login_required("admin")
def module(mod):
    if mod not in MODS:
        abort(404)
    title, fs = MODS[mod]
    if request.method == "POST":
        vals = [save_photo(request.files.get(f[0])) if len(f) > 2 and f[2] == "file" else request.form.get(f[0], "").strip()[:500] for f in fs]
        if mod == "notices" and not vals[2]:
            vals[2] = today()
        ex("INSERT INTO %s(%s) VALUES(%s)" % (mod, ",".join(f[0] for f in fs), ",".join("?" * len(fs))), vals)
        return redirect("/erp/m/" + mod)
    return page(MODT, True, title=title, fs=fs, mod=mod, rows=q("SELECT * FROM %s ORDER BY id DESC" % mod))


@app.post("/erp/m/<mod>/<int:i>/delete")
@login_required("admin")
def module_delete(mod, i):
    if mod not in MODS:
        abort(404)
    ex("DELETE FROM %s WHERE id=?" % mod, (i,))
    return redirect("/erp/m/" + mod)


@app.route("/notices")
def public_notices():
    rows = q("SELECT * FROM notices ORDER BY date DESC, id DESC LIMIT 100")
    secs = [("Class 10 (High School)", lambda c: "10" in c), ("Class 12 (Intermediate)", lambda c: "12" in c),
            ("General Notices", lambda c: "10" not in c and "12" not in c)]
    groups = [(t, [r for r in rows if f(r["category"] or "")]) for t, f in secs]
    return page("""<div class=card><h2>Notices &amp; Announcements</h2><p>Important school announcements and official UP Board updates for students and parents. Latest notices are at the top.</p>
<a class="btn gold" href="https://upmsp.edu.in" target=_blank rel=noopener>Official UP Board website (upmsp.edu.in)</a></div>
{% for t,items in groups %}<div class=card><h3>{{t}}</h3><div class=tw><table><tr><th>Notice</th><th>Published</th><th></th></tr>
{% for n in items %}<tr><td><b>{{n.title}}</b><br>{{n.body}}</td><td>{{n.date}}</td><td>{% if n.attachment %}<a class=btn href="{{n.attachment}}" target=_blank>Download</a>{% endif %}</td></tr>{% endfor %}</table></div></div>
{% else %}<div class=card><p>No notices yet.</p></div>{% endfor %}<script>setTimeout(function(){location.reload()},30000)</script>""", groups=[x for x in groups if x[1]])


NL = "{% for n in rows %}<p><b>{{n.title}}</b> <small>{{n.date}}</small><br>{{n.body}}</p>{% else %}<p>No notices yet.</p>{% endfor %}"


def latest():
    return q("SELECT * FROM notices ORDER BY id DESC LIMIT 3")


@app.route("/notices/latest")
def notices_latest():
    return render_template_string(NL, rows=latest())


ENQ = '<div class=card id=enquiry><h3>Admission Enquiry</h3><form method=post action=/enquiry>' + CSRF + """<input name=name placeholder="Student / parent name" required><br>
<input name=phone placeholder="Phone number" required><br><input name=cls placeholder="Class applying for"><br>
<textarea name=message placeholder="Message" rows=3></textarea><br><button>Send enquiry</button></form></div>"""


@app.route("/")
def home():
    return page(PUBLIC[""] + '<div class=card><h3>Latest Notices</h3><div id=nl>' + NL + '</div></div>' + ENQ +
                '<script>setInterval(function(){fetch("/notices/latest").then(function(r){return r.text()}).then(function(t){document.getElementById("nl").innerHTML=t})},20000)</script>',
                rows=latest())


# ---------- colour templates ----------
THEMES = {"navy": ("#0b1f4b", "#c9a227", "#f6f7fb", "#1d3a82", "Navy & Gold"),
          "green": ("#0b4d2c", "#e0b73a", "#f4f8f5", "#17703f", "Green & Gold"),
          "maroon": ("#5c0f1e", "#d4a63a", "#faf6f4", "#8a1c30", "Maroon & Gold"),
          "purple": ("#2e1a5e", "#e2b43c", "#f7f5fb", "#4a2c96", "Royal Purple & Gold"),
          "teal": ("#0b4f5c", "#f0b429", "#f3f8f9", "#13788a", "Teal & Gold"),
          "black": ("#1c1c1c", "#d4af37", "#f7f7f7", "#3a3a3a", "Black & Gold")}


SITE_DEFAULT = {"school": "Saba Public Inter College", "tagline": "Learn · Grow · Excel", "phone": "9794333054, 9170133055",
                "email": "sabapublicintercollege@gmail.com", "address": "Sihin, Paharpur, Sathiaon, Azamgarh, Uttar Pradesh – 276406"}
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


def all_settings():
    return {r["k"]: r["v"] for r in q("SELECT k,v FROM settings")}


@app.context_processor
def inject_site():
    try:
        st = all_settings()
        th = THEMES.get(st.get("theme"), THEMES["forest"])
        if st.get("theme") == "custom" and HEX.match(st.get("c1", "")) and HEX.match(st.get("c2", "")):
            th = (st["c1"], st["c2"], "#f6f7fb", st["c1"], "Custom")
        return {"th": th, "site": dict(SITE_DEFAULT, **{k: v for k, v in st.items() if k in SITE_DEFAULT and v})}
    except Exception:
        return {"th": THEMES["forest"], "site": SITE_DEFAULT}


@app.route("/erp/settings", methods=["GET", "POST"])
@login_required("admin")
def settings():
    if request.method == "POST":
        f = request.form
        if f.get("action") == "site":
            for k in SITE_DEFAULT:
                ex("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, f.get(k, "").strip()[:150]))
            flash("School details saved.")
        elif f.get("theme") in list(THEMES) + ["custom"]:
            if f["theme"] == "custom":
                if not (HEX.match(f.get("c1", "")) and HEX.match(f.get("c2", ""))):
                    flash("Pick two valid colours.")
                    return redirect("/erp/settings")
                for k in ("c1", "c2"):
                    ex("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, f[k]))
            ex("INSERT OR REPLACE INTO settings(k,v) VALUES('theme',?)", (f["theme"],))
            flash("Colour template changed.")
        return redirect("/erp/settings")
    st = all_settings()
    return page("<h3>Website Settings</h3><div class=msg>Enquiry email alerts: <b>{{'ON' if mail_on else 'OFF (see README to turn on)'}}</b></div><div class=card><h4>School details shown on the website</h4><form method=post>" + CSRF + """<input type=hidden name=action value=site>
{% for k,label in fields %}<label>{{label}}<br><input name={{k}} value="{{site[k]}}" style="width:100%"></label><br>{% endfor %}<button>Save details</button></form></div>
<div class=card><h4>Colour template</h4><form method=post>""" + CSRF + """<div class=grid>{% for k,t in themes.items() %}
<label class=card><input type=radio name=theme value={{k}} {{'checked' if k==cur}}> <b>{{t[4]}}</b><br>
<span class=sw style="background:{{t[0]}}"></span><span class=sw style="background:{{t[1]}}"></span><span class=sw style="background:{{t[3]}}"></span></label>{% endfor %}
<label class=card><input type=radio name=theme value=custom {{'checked' if cur=='custom'}}> <b>Custom colours</b><br>Main <input type=color name=c1 value="{{c1}}"> Accent <input type=color name=c2 value="{{c2}}"></label></div>
<button>Apply colour template</button></form></div>""", True, mail_on=bool(os.environ.get("SMTP_HOST")), themes=THEMES, cur=st.get("theme", "forest"), c1=st.get("c1", "#123B32"), c2=st.get("c2", "#D6B45C"),
                site=dict(SITE_DEFAULT, **{k: v for k, v in st.items() if k in SITE_DEFAULT and v}),
                fields=[("school", "School name"), ("tagline", "Tagline"), ("address", "Address line"), ("phone", "Phone numbers"), ("email", "Email")])


def save_photo(f):
    ext = f.filename.rsplit(".", 1)[-1].lower() if f and f.filename and "." in f.filename else ""
    if ext not in ("jpg", "jpeg", "png", "gif", "webp", "pdf"):
        return ""
    os.makedirs(UPLOADS, exist_ok=True)
    name = secrets.token_hex(6) + "." + ext
    f.save(os.path.join(UPLOADS, name))
    return "/static/uploads/" + name


@app.route("/faculty")
def pub_faculty():
    return page("""<div class=card><h2>Faculty &amp; Staff</h2>{% if not rows %}<p>Staff list coming soon.</p>{% endif %}</div><div class=grid>
{% for r in rows %}<div class=card style="text-align:center">{% if r.photo %}<img src="{{r.photo}}" style="width:150px;height:150px;object-fit:cover;border-radius:50%;border:3px solid var(--g)">{% endif %}
<h4 style="margin:8px 0 2px">{{r.name}}</h4><p style="margin:0">{{r.role}}<br>{{r.subject}}</p></div>{% endfor %}</div>""", rows=q("SELECT * FROM faculty ORDER BY id"))


@app.route("/events")
def pub_events():
    return page("""<div class=card><h2>Events &amp; Activities</h2>{% if not rows %}<p>No events yet.</p>{% endif %}</div>
{% for r in rows %}<div class=card>{% if r.photo %}<img src="{{r.photo}}" style="max-width:100%;border-radius:8px">{% endif %}<h3>{{r.title}}</h3><small>{{r.date}}</small><p>{{r.details}}</p></div>{% endfor %}""",
                rows=q("SELECT * FROM events ORDER BY id DESC"))


@app.route("/gallery")
def pub_gallery():
    return page("""<div class=card><h2>School Gallery</h2>{% if not rows %}<p>Photos coming soon.</p>{% endif %}</div><div class=grid>
{% for r in rows %}<div class=card style="padding:8px">{% if r.photo %}<img src="{{r.photo}}" style="width:100%;border-radius:6px">{% endif %}<p style="margin:6px 0 0">{{r.caption}}</p></div>{% endfor %}</div>""",
                rows=q("SELECT * FROM gallery ORDER BY id DESC"))


# ---------- website editor (admin only) ----------
EDITABLE = ["about", "founder", "programmes", "contact", "location"]
UPLOADS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")


@app.route("/erp/pages")
@login_required("admin")
def pages_list():
    os.makedirs(UPLOADS, exist_ok=True)
    files = sorted(os.listdir(UPLOADS))
    return page("""<h3>Edit Website Pages</h3><div class=card>{% for p in pages %}<p><a href=/erp/pages/{{p}}>{{p|capitalize}}</a> <small>(<a href=/{{p}} target=_blank>view</a>)</small></p>{% endfor %}</div>
<div class=card><h4>Upload photo</h4><form method=post action=/erp/upload enctype=multipart/form-data>""" + CSRF + """<input type=file name=photo accept="image/*" required><button>Upload</button></form>
<p>Use an uploaded photo in a page with: <code>&lt;img src="/static/uploads/FILE" style="max-width:100%"&gt;</code></p>
{% for f in files %}<p>/static/uploads/{{f}}</p>{% else %}<p>No photos uploaded yet.</p>{% endfor %}</div>""", True, pages=EDITABLE, files=files)


@app.route("/erp/pages/<slug>", methods=["GET", "POST"])
@login_required("admin")
def page_edit(slug):
    if slug not in EDITABLE:
        abort(404)
    if request.method == "POST":
        if request.form.get("action") == "reset":
            ex("DELETE FROM pages WHERE slug=?", (slug,))
            flash("Page reset to default.")
        else:
            ex("INSERT OR REPLACE INTO pages(slug,html) VALUES(?,?)", (slug, request.form.get("html", "")[:50000]))
            flash("Page saved.")
        return redirect("/erp/pages/" + slug)
    row = q("SELECT html FROM pages WHERE slug=?", (slug,), True)
    return page("""<h3>Edit page: {{slug}}</h3><div class=card><form method=post>""" + CSRF + """<input type=hidden name=action value=save>
<textarea name=html rows=18 style="width:100%;font-family:monospace">{{html}}</textarea><button>Save page</button></form>
<form method=post>""" + CSRF + """<input type=hidden name=action value=reset><button onclick="return confirm('Reset to default?')">Reset to default</button></form>
<p><a href=/{{slug}} target=_blank>View page</a> &middot; <a href=/erp/pages>Back</a></p></div>""", True, slug=slug, html=row["html"] if row else PUBLIC[slug])


@app.post("/erp/upload")
@login_required("admin")
def upload():
    f = request.files.get("photo")
    ext = f.filename.rsplit(".", 1)[-1].lower() if f and "." in f.filename else ""
    if ext not in ("jpg", "jpeg", "png", "gif", "webp"):
        flash("Only jpg, png, gif or webp photos are allowed.")
    else:
        os.makedirs(UPLOADS, exist_ok=True)
        name = secrets.token_hex(6) + "." + ext
        f.save(os.path.join(UPLOADS, name))
        flash("Uploaded. Use this path in a page: /static/uploads/" + name)
    return redirect("/erp/pages")


@app.route("/erp/enquiries")
@login_required("admin")
def enquiries_list():
    return page("<h3>Admission Enquiries</h3><div class=card><div class=tw><table><tr><th>Date</th><th>Name</th><th>Phone</th><th>Class</th><th>Message</th><th></th><th></th></tr>"
                '{% for e in rows %}<tr><td>{{e.created}}</td><td>{{e.name}}</td><td>{{e.phone}}</td><td>{{e.cls}}</td><td>{{e.message}}</td><td><a href="tel:{{e.phone}}">Call</a></td>'
                "<td><form method=post action=/erp/enquiries/{{e.id}}/delete>" + CSRF + "<button>Delete</button></form></td></tr>"
                "{% else %}<tr><td>No enquiries yet.</td></tr>{% endfor %}</table></div></div>", True, rows=q("SELECT * FROM enquiries ORDER BY id DESC"))


@app.post("/erp/enquiries/<int:i>/delete")
@login_required("admin")
def enquiry_delete(i):
    ex("DELETE FROM enquiries WHERE id=?", (i,))
    return redirect("/erp/enquiries")


# ---------- exams, marks, results, report cards ----------
def grade(p):
    return "A+" if p >= 90 else "A" if p >= 80 else "B" if p >= 60 else "C" if p >= 45 else "D" if p >= 33 else "F"


def pick_group(f):
    groups = q("SELECT DISTINCT cls,section FROM students ORDER BY cls,section")
    grp = f.get("grp") or (f"{groups[0]['cls']}|{groups[0]['section']}" if groups else "|")
    return groups, grp


@app.route("/erp/exams", methods=["GET", "POST"])
@login_required("admin")
def exams():
    if request.method == "POST":
        ex("INSERT INTO exams(name,session) VALUES(?,?)", (request.form["name"].strip()[:80], request.form.get("session", "")[:20]))
        return redirect("/erp/exams")
    return page("<h3>Examinations</h3><div class=card><form method=post>" + CSRF + """<input name=name placeholder="Exam name (Half Yearly...)" required><input name=session placeholder="Session 2026-27"><button>Create exam</button></form></div>
<div class=card><table>{% for e in rows %}<tr><td>{{e.name}}</td><td>{{e.session}}</td><td><a href=/erp/exams/{{e.id}}/marks>Marks entry</a> | <a href=/erp/exams/{{e.id}}/results>Results</a></td></tr>{% endfor %}</table></div>""",
                True, rows=q("SELECT * FROM exams ORDER BY id DESC"))


@app.route("/erp/exams/<int:eid>/marks", methods=["GET", "POST"])
@login_required("admin")
def marks_entry(eid):
    e = q("SELECT * FROM exams WHERE id=?", (eid,), True) or abort(404)
    f = request.form if request.method == "POST" else request.args
    groups, grp = pick_group(f)
    subject, maxm = f.get("subject", "").strip(), f.get("maxm") or "100"
    cls, sec = grp.split("|", 1)
    studs = q("SELECT * FROM students WHERE cls=? AND section=? ORDER BY name", (cls, sec))
    if request.method == "POST" and subject:
        for s in studs:
            v = f.get(f"m{s['id']}", "").strip()
            if v:
                try:
                    db().execute("INSERT OR REPLACE INTO marks(exam_id,student_id,subject,score,maxm) VALUES(?,?,?,?,?)",
                                 (eid, s["id"], subject, float(v), float(maxm)))
                except ValueError:
                    flash("Some marks were not numbers and were skipped.")
        db().commit()
        flash("Marks saved.")
        return redirect(f"/erp/exams/{eid}/marks?grp={grp}&subject={subject}&maxm={maxm}")
    got = {r["student_id"]: r["score"] for r in q("SELECT student_id,score FROM marks WHERE exam_id=? AND subject=?", (eid, subject))}
    return page("<h3>{{e.name}} - Marks entry</h3><form method=get>" + GSEL + """<input name=subject value="{{subject}}" placeholder=Subject required><input name=maxm type=number value="{{maxm}}"><button>Load</button></form>
{% if subject %}<form method=post>""" + CSRF + """<input type=hidden name=grp value="{{grp}}"><input type=hidden name=subject value="{{subject}}"><input type=hidden name=maxm value="{{maxm}}">
<div class=card><table>{% for s in studs %}<tr><td>{{s.adm_no}}</td><td>{{s.name}}</td><td><input type=number step=0.01 name="m{{s.id}}" value="{{got.get(s.id,'')}}"></td></tr>{% endfor %}</table></div><button>Save marks</button></form>{% endif %}""",
                True, e=e, groups=groups, grp=grp, subject=subject, maxm=maxm, studs=studs, got=got)


@app.route("/erp/exams/<int:eid>/results")
@login_required("admin")
def results(eid):
    e = q("SELECT * FROM exams WHERE id=?", (eid,), True) or abort(404)
    groups, grp = pick_group(request.args)
    cls, sec = grp.split("|", 1)
    out = []
    for r in q("SELECT s.id,s.adm_no,s.name,COALESCE(SUM(m.score),0) t,COALESCE(SUM(m.maxm),0) mx FROM students s "
               "LEFT JOIN marks m ON m.student_id=s.id AND m.exam_id=? WHERE s.cls=? AND s.section=? GROUP BY s.id ORDER BY s.name", (eid, cls, sec)):
        p = r["t"] / r["mx"] * 100 if r["mx"] else 0
        out.append(dict(r, p=round(p, 1), gr=grade(p) if r["mx"] else "-"))
    return page("<h3>{{e.name}} - Results</h3><form method=get>" + GSEL + """<button>Show</button></form><div class=card><div class=tw><table>
<tr><th>Adm</th><th>Name</th><th>Total</th><th>%</th><th>Grade</th><th></th></tr>{% for r in out %}<tr><td>{{r.adm_no}}</td><td>{{r.name}}</td><td>{{r.t}}/{{r.mx}}</td><td>{{r.p}}</td><td>{{r.gr}}</td>
<td><a href=/erp/exams/{{e.id}}/card/{{r.id}}>Report card</a></td></tr>{% endfor %}</table></div></div>""", True, e=e, groups=groups, grp=grp, out=out)


@app.route("/erp/exams/<int:eid>/card/<int:sid>")
@login_required("admin")
def card(eid, sid):
    e = q("SELECT * FROM exams WHERE id=?", (eid,), True) or abort(404)
    s = q("SELECT * FROM students WHERE id=?", (sid,), True) or abort(404)
    ms = q("SELECT * FROM marks WHERE exam_id=? AND student_id=? ORDER BY subject", (eid, sid))
    t, mx = sum(m["score"] for m in ms), sum(m["maxm"] for m in ms)
    p = round(t / mx * 100, 1) if mx else 0
    return page("""<div class=card><h2>Saba Public Inter College - Report Card</h2><p>{{e.name}} {{e.session}}<br>{{s.name}} (Adm {{s.adm_no}}), Class {{s.cls}}-{{s.section}}<br>Father: {{s.father}}</p>
<table><tr><th>Subject</th><th>Marks</th><th>Max</th></tr>{% for m in ms %}<tr><td>{{m.subject}}</td><td>{{m.score}}</td><td>{{m.maxm}}</td></tr>{% endfor %}
<tr><th>Total</th><th>{{t}}</th><th>{{mx}}</th></tr></table><p>Percentage: <b>{{p}}%</b> &middot; Grade: <b>{{gr}}</b></p><button class=np onclick="window.print()">Print</button></div>""",
                True, e=e, s=s, ms=ms, t=t, mx=mx, p=p, gr=grade(p) if mx else "-")


# ---------- data export and backup ----------
@app.route("/erp/data")
@login_required("admin")
def data():
    return page("""<h3>Reports, Export &amp; Backup</h3><div class=card><p>Download CSV (opens in Excel):</p>
<a class=btn href=/erp/export/students>Students</a> <a class=btn href=/erp/export/attendance>Attendance</a> <a class=btn href=/erp/export/fees>Fees</a> <a class=btn href=/erp/export/enquiries>Enquiries</a></div>
<div class=card><p>Full database backup (keep it safe):</p><a class=btn href=/erp/backup>Download backup</a></div>""", True)


@app.route("/erp/export/<name>")
@login_required("admin")
def export(name):
    sql = {"students": "SELECT * FROM students",
           "enquiries": "SELECT created,name,phone,cls,message FROM enquiries ORDER BY id DESC",
           "attendance": "SELECT s.adm_no,s.name,a.day,a.status FROM attendance a JOIN students s ON s.id=a.student_id ORDER BY a.day",
           "fees": "SELECT s.adm_no,s.name,f.category,f.amount,f.paid_on FROM fees f JOIN students s ON s.id=f.student_id ORDER BY f.id"}.get(name) or abort(404)
    rows = q(sql)
    out = io.StringIO()
    w = csv.writer(out)
    if rows:
        w.writerow(rows[0].keys())
        w.writerows([list(r) for r in rows])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={name}.csv"})


@app.route("/erp/backup")
@login_required("admin")
def backup():
    import tempfile
    p = os.path.join(tempfile.gettempdir(), "saba_backup.db")
    if os.path.exists(p):
        os.remove(p)
    dst = sqlite3.connect(p)
    db().backup(dst)
    dst.close()
    return send_file(p, as_attachment=True, download_name="saba_backup_%s.db" % today())


init()
init_extra()
if __name__ == "__main__":
    app.run(debug=False)
