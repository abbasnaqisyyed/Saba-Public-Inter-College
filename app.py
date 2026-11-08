import os, sqlite3, datetime, secrets, csv, io, json
from functools import wraps
from flask import (Flask, request, redirect, render_template_string, g,
                   session, abort, flash, Response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
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
BASE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{{ seo_title }}</title>
<meta name=description content="{{ seo_description }}">
<meta name=robots content="{{ robots_directive }}">
<link rel=canonical href="{{ canonical_url }}">
<meta property=og:type content=website>
<meta property=og:site_name content="Saba Public Inter College">
<meta property=og:title content="{{ seo_title }}">
<meta property=og:description content="{{ seo_description }}">
<meta property=og:url content="{{ canonical_url }}">
<meta name=twitter:card content=summary>
<meta name=twitter:title content="{{ seo_title }}">
<meta name=twitter:description content="{{ seo_description }}">
{{ seo_jsonld|safe }}
<style>:root{--n:#0b1f4b;--g:#c9a227}*{box-sizing:border-box}
body{margin:0;font-family:Georgia,serif;color:#222;background:#f6f7fb}
header{background:var(--n);color:#fff;padding:12px 18px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;border-bottom:4px solid var(--g)}
header b{color:var(--g);font-size:18px}nav a{color:#fff;margin-right:12px;text-decoration:none;font-family:system-ui;font-size:14px}nav a:hover{color:var(--g)}
main{max-width:980px;margin:0 auto;padding:16px}
.hero{background:linear-gradient(135deg,var(--n),#1d3a82);color:#fff;padding:40px 18px;text-align:center;border-radius:8px}.hero h1{margin:0 0 8px;color:var(--g)}
.card{background:#fff;border-radius:8px;padding:16px;margin:12px 0;box-shadow:0 1px 4px #0002}
table{border-collapse:collapse;width:100%;font-family:system-ui;font-size:14px}td,th{border-bottom:1px solid #ddd;padding:7px;text-align:left}
.tw{overflow-x:auto}input,select,textarea,button{padding:8px;font-size:15px;margin:3px 0;max-width:100%}
button,.btn{background:var(--n);color:#fff;border:0;border-radius:5px;cursor:pointer;padding:8px 12px;text-decoration:none;font-size:15px}
.msg{background:#fff6d6;padding:8px;border-left:4px solid var(--g);font-family:system-ui;margin:8px 0}
@media print{header,.np{display:none}}</style></head><body>
<header><div><b>Saba Public Inter College</b><br><small>Azamgarh, Uttar Pradesh &middot; Est. 2003</small></div>
<nav class=np>{% if erp %}{% if g.user.role=='admin' %}<a href=/erp>Dashboard</a>{% endif %}
<a href=/erp/students>Students</a><a href=/erp/attendance>Attendance</a><a href=/erp/report>Monthly</a>
{% if g.user.role=='admin' %}<a href=/erp/fees>Fees</a><a href=/erp/teachers>Teachers</a><a href=/erp/exams>Exams</a>{% for k in ['notices','homework','timetable','library','inventory','transport'] %}<a href=/erp/m/{{k}}>{{k|capitalize}}</a>{% endfor %}<a href=/erp/data>Data</a>{% endif %}
<a href=/erp/password>Password</a><a href=/erp/logout>Logout</a>
{% else %}<a href=/>Home</a><a href=/about>About</a><a href=/founder>Founder</a><a href=/programmes>Programmes</a><a href=/faculty>Faculty</a><a href=/notices>Notices</a><a href=/events>Events</a><a href=/gallery>Gallery</a><a href=/contact>Contact</a><a href=/location>Location</a><a href=/erp/login>Staff Login</a>{% endif %}</nav></header>
<main>{% for m in get_flashed_messages() %}<div class=msg>{{m}}</div>{% endfor %}{{ body|safe }}</main></body></html>"""

CSRF = '<input type=hidden name=csrf value="{{csrf()}}">'
GSEL = ('<select name=grp>{% for c in groups %}<option value="{{c.cls}}|{{c.section}}" '
        '{{"selected" if grp==c.cls+"|"+c.section}}>Class {{c.cls}}-{{c.section}}</option>{% endfor %}</select>')

PUBLIC = {
    "": """<div class=hero><h1>Saba Public Inter College</h1>
<p>UP Board &middot; Classes 1 to 12 (10+2) &middot; Arts &amp; Science<br>Azamgarh, Uttar Pradesh</p></div>
<div class=card><h3>Admission Enquiry</h3><form method=post action=/enquiry>""" + CSRF + """
<input name=name placeholder="Student / parent name" required><br>
<input name=phone placeholder="Phone number" required><br>
<input name=cls placeholder="Class applying for"><br>
<textarea name=message placeholder="Message" rows=3></textarea><br><button>Send enquiry</button></form></div>""",
    "about": """<div class=card><h2>About the School</h2>
<p>Saba Public Inter College, established in 2003 in Azamgarh, Uttar Pradesh, offers UP Board education from Class 1 to 12.</p>
<p><b>Founder:</b> Dr. Syed Kaisar Husain</p></div>""",
    "programmes": """<div class=card><h2>Academic Programmes</h2><p>Classes 1 to 10 (UP Board), and Classes 11-12 in two streams:</p>
<ul><li><b>Science Stream</b></li><li><b>Arts Stream</b></li></ul></div>""",
    "founder": """<div class=card><h2>Founder &amp; Principal</h2>
<div style="display:flex;flex-wrap:wrap;gap:18px;align-items:flex-start">
<img src="/static/principal.jpg" alt="Dr. Syed Kaisar Husain" style="width:100%;max-width:300px;border-radius:8px;border:3px solid #c9a227">
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
    "contact": """<div class=card><h2>Contact Us</h2><p>Saba Public Inter College, Azamgarh, Uttar Pradesh<br>
Phone: 9170133055, 9794333054<br>Email: sabapublicintercollege@gmail.com</p></div>""",
}


SEO_PAGES = {
    "/": ("Saba Public Inter College | UP Board School in Azamgarh", "Saba Public Inter College, established in 2003, provides UP Board education in Azamgarh, Uttar Pradesh. Explore classes, programmes, notices and admissions."),
    "/about": ("About Saba Public Inter College | Azamgarh", "Learn about Saba Public Inter College in Azamgarh, Uttar Pradesh, established in 2003 by Dr. Syed Kaisar Husain."),
    "/programmes": ("Academic Programmes | Saba Public Inter College", "Explore UP Board academic programmes at Saba Public Inter College, Azamgarh, including secondary and intermediate education."),
    "/founder": ("Founder & Principal | Saba Public Inter College", "Meet Dr. Syed Kaisar Husain, Founder and Principal of Saba Public Inter College, established in 2003 in Azamgarh, Uttar Pradesh."),
    "/faculty": ("Faculty & Staff | Saba Public Inter College", "Faculty and staff information for Saba Public Inter College, Azamgarh, Uttar Pradesh."),
    "/events": ("School Events & Activities | Saba Public Inter College", "School events, student activities and celebrations at Saba Public Inter College in Azamgarh."),
    "/notices": ("School Notices | Saba Public Inter College", "Latest school notices and announcements from Saba Public Inter College, Azamgarh, Uttar Pradesh."),
    "/gallery": ("School Gallery | Saba Public Inter College", "View school photographs and activities from Saba Public Inter College, Azamgarh, Uttar Pradesh."),
    "/location": ("School Location | Saba Public Inter College, Azamgarh", "Find Saba Public Inter College in the Azamgarh, Uttar Pradesh area and view its location on Google Maps."),
    "/contact": ("Contact Saba Public Inter College | Azamgarh", "Contact Saba Public Inter College, Azamgarh, Uttar Pradesh, for admissions and general enquiries.")
}


def page(tpl, erp=False, **ctx):
    path = request.path
    title, description = SEO_PAGES.get(path, ("Saba Public Inter College | Azamgarh", "Official website of Saba Public Inter College, Azamgarh, Uttar Pradesh."))
    private_page = path.startswith("/erp") or erp
    canonical = request.url_root.rstrip("/") + (path if path != "/" else "/")
    school_data = {
        "@context": "https://schema.org", "@type": "School",
        "name": "Saba Public Inter College",
        "alternateName": ["Saba Public Inter College Azamgarh", "Saba Inter College"],
        "description": "UP Board school in Azamgarh, Uttar Pradesh, established in 2003.",
        "url": request.url_root.rstrip("/") + "/",
        "foundingDate": "2003",
        "telephone": ["+919170133055", "+919794333054"],
        "email": "sabapublicintercollege@gmail.com",
        "address": {"@type": "PostalAddress", "addressLocality": "Azamgarh", "addressRegion": "Uttar Pradesh", "addressCountry": "IN"}
    }
    jsonld = "" if private_page else '<script type="application/ld+json">' + json.dumps(school_data, ensure_ascii=False) + '</script>'
    return render_template_string(BASE, erp=erp, body=render_template_string(tpl, **ctx),
        seo_title=("Staff Portal | Saba Public Inter College" if private_page else title),
        seo_description=("Restricted staff portal for Saba Public Inter College." if private_page else description),
        robots_directive=("noindex, nofollow" if private_page else "index, follow, max-image-preview:large"),
        canonical_url=canonical, seo_jsonld=jsonld)


@app.get("/robots.txt")
def robots_txt():
    base = request.url_root.rstrip("/")
    return Response("User-agent: *\nAllow: /\nDisallow: /erp\nSitemap: " + base + "/sitemap.xml\n", mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap_xml():
    base = request.url_root.rstrip("/")
    urls = [base + (path if path != "/" else "/") for path in SEO_PAGES]
    body = '<?xml version="1.0" encoding="UTF-8"?>' + '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + ''.join('<url><loc>' + u + '</loc></url>' for u in urls) + '</urlset>'
    return Response(body, mimetype="application/xml")


for _n, _t in PUBLIC.items():
    app.add_url_rule("/" + _n, "pub_" + (_n or "home"), (lambda t=_t: page(t)))


@app.post("/enquiry")
def enquiry():
    f = request.form
    ex("INSERT INTO enquiries(name,phone,cls,message,created) VALUES(?,?,?,?,?)",
       (f["name"][:100], f["phone"][:20], f.get("cls", "")[:20], f.get("message", "")[:500], today()))
    flash("Thank you. We will contact you soon.")
    return redirect("/")


# ---------- auth ----------
@app.route("/erp/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = q("SELECT * FROM users WHERE username=? AND active=1", (request.form["username"],), True)
        if u and check_password_hash(u["pw"], request.form["password"]):
            session.clear()
            session["uid"] = u["id"]
            return redirect("/erp" if u["role"] == "admin" else "/erp/attendance")
        flash("Wrong username or password.")
    return page("<div class=card style='max-width:340px;margin:30px auto'><h3>Staff Login</h3><form method=post>"
                + CSRF + "<input name=username placeholder=Username required><br>"
                "<input name=password type=password placeholder=Password required><br><button>Login</button></form></div>")


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
<div class=card><h3>Recent admission enquiries</h3><div class=tw><table>{% for e in enq %}<tr><td>{{e.created}}</td><td>{{e.name}}</td><td>{{e.phone}}</td><td>{{e.cls}}</td><td>{{e.message}}</td></tr>
{% else %}<tr><td>None yet.</td></tr>{% endfor %}</table></div></div>""", True,
                a=n("SELECT COUNT(*) FROM students"), t=n("SELECT COUNT(*) FROM users WHERE role='teacher'"),
                p=n("SELECT COUNT(*) FROM attendance WHERE day=? AND status='Present'", (today(),)),
                pend=pending, enq=q("SELECT * FROM enquiries ORDER BY id DESC LIMIT 5"))


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
    "notices": ("Notices", [("title", "Title"), ("body", "Details"), ("date", "Date", "date")]),
    "homework": ("Homework", [("cls", "Class"), ("section", "Section"), ("subject", "Subject"), ("task", "Homework"), ("due", "Due date", "date")]),
    "timetable": ("Timetable", [("cls", "Class"), ("section", "Section"), ("day", "Day"), ("period", "Period"), ("subject", "Subject"), ("teacher", "Teacher")]),
    "library": ("Library", [("title", "Book title"), ("author", "Author"), ("copies", "Copies", "number"), ("issued_to", "Issued to"), ("due", "Due date", "date")]),
    "inventory": ("Inventory", [("item", "Item"), ("qty", "Quantity", "number"), ("location", "Location"), ("note", "Note")]),
    "transport": ("Transport", [("route", "Route"), ("vehicle", "Vehicle no"), ("driver", "Driver"), ("phone", "Driver phone"), ("students", "Students / stops")]),
}


def init_extra():
    c = sqlite3.connect(DB)
    for k, (_, fs) in MODS.items():
        c.execute("CREATE TABLE IF NOT EXISTS %s(id INTEGER PRIMARY KEY,%s)" % (k, ",".join(f[0] + " TEXT" for f in fs)))
    c.executescript("""
    CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY, name TEXT, session TEXT);
    CREATE TABLE IF NOT EXISTS marks(exam_id INTEGER, student_id INTEGER, subject TEXT, score REAL, maxm REAL,
      PRIMARY KEY(exam_id, student_id, subject));""")
    c.commit()
    c.close()


MODT = """<h3>{{title}}</h3><div class=card><form method=post>""" + CSRF + """{% for f in fs %}<input name={{f[0]}} type={{f[2] if f|length>2 else 'text'}} placeholder="{{f[1]}}" title="{{f[1]}}">{% endfor %}<button>Add</button></form></div>
<div class=card><div class=tw><table><tr>{% for f in fs %}<th>{{f[1]}}</th>{% endfor %}<th></th></tr>
{% for r in rows %}<tr>{% for f in fs %}<td>{{r[f[0]]}}</td>{% endfor %}<td><form method=post action=/erp/m/{{mod}}/{{r.id}}/delete>""" + CSRF + """<button>Delete</button></form></td></tr>{% endfor %}</table></div></div>"""


@app.route("/erp/m/<mod>", methods=["GET", "POST"])
@login_required("admin")
def module(mod):
    if mod not in MODS:
        abort(404)
    title, fs = MODS[mod]
    if request.method == "POST":
        vals = [request.form.get(f[0], "").strip()[:500] for f in fs]
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
    rows = q("SELECT * FROM notices ORDER BY id DESC LIMIT 50")
    return page("<div class=card><h2>Notices &amp; Announcements</h2>{% for n in rows %}<p><b>{{n.title}}</b> <small>{{n.date}}</small><br>{{n.body}}</p>{% else %}<p>No notices.</p>{% endfor %}</div>", rows=rows)


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
<a class=btn href=/erp/export/students>Students</a> <a class=btn href=/erp/export/attendance>Attendance</a> <a class=btn href=/erp/export/fees>Fees</a></div>
<div class=card><p>Full database backup (keep it safe):</p><a class=btn href=/erp/backup>Download backup</a></div>""", True)


@app.route("/erp/export/<name>")
@login_required("admin")
def export(name):
    sql = {"students": "SELECT * FROM students",
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
