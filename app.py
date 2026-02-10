from flask import Flask, render_template_string, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.secret_key = "blueshield-secret"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DB_NAME = "database.db"
DEVELOPER_WHITELIST = ["127.0.0.1"]

# ---------------- DB ----------------

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        success INTEGER,
        timestamp TEXT
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        blocked_until TEXT
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        timestamp TEXT
    )""")
    db.commit()
    db.close()

def create_admin():
    db = get_db()
    try:
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                   ("admin", "admin123", "admin"))
        db.commit()
    except:
        pass
    db.close()

# ---------------- Auth ----------------

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if row:
        return User(row["id"], row["username"], row["password"], row["role"])
    return None

# ---------------- Alerts ----------------

def raise_alert(level, message):
    db = get_db()
    db.execute("INSERT INTO alerts (level, message, timestamp) VALUES (?, ?, ?)",
               (level, message, datetime.utcnow().isoformat()))
    db.commit()
    db.close()

# ---------------- UI ----------------

BASE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>BlueShield SOC</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-dark text-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-black px-3">
  <a class="navbar-brand" href="/dashboard">🛡️ BlueShield SOC</a>
  <div class="ms-auto">
    <a class="btn btn-outline-warning me-2" href="/alerts">Alerts</a>
    <a class="btn btn-outline-info me-2" href="/simulate">Attack Simulator</a>
    <a class="btn btn-outline-danger" href="/logout">Logout</a>
  </div>
</nav>
<div class="container py-4">
  {{ content|safe }}
</div>
</body>
</html>
"""

LOGIN_HTML = """
<div class="card p-4 bg-secondary mx-auto" style="max-width: 400px;">
  <h3>🛡️ BlueShield SOC Login</h3>
  <form method="post">
    <input class="form-control my-2" name="username" placeholder="Username" required>
    <input class="form-control my-2" name="password" type="password" placeholder="Password" required>
    <button class="btn btn-warning w-100 mt-2">Login</button>
  </form>
  <p class="text-danger mt-2">{{ msg }}</p>
</div>
"""

DASHBOARD_HTML = """
<h2>Dashboard</h2>
<div class="row">
  <div class="col-md-6">
    <canvas id="chart"></canvas>
  </div>
  <div class="col-md-6">
    <div class="card bg-secondary p-3">
      <h5>Recent Login Attempts</h5>
      <table class="table table-dark table-striped">
        <tr><th>IP</th><th>Status</th><th>Time</th></tr>
        {% for a in attempts %}
        <tr>
          <td>{{ a.ip }}</td>
          <td>{{ "SUCCESS" if a.success else "FAILED" }}</td>
          <td>{{ a.timestamp }}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>
</div>

<script>
const ctx = document.getElementById('chart');
new Chart(ctx, {
  type: 'bar',
  data: {
    labels: ['Success', 'Failed'],
    datasets: [{
      label: 'Login Attempts',
      data: [{{ success_count }}, {{ fail_count }}]
    }]
  }
});
</script>
"""

ALERTS_HTML = """
<h2>🚨 SOC Alerts</h2>
<table class="table table-dark table-striped">
<tr><th>Level</th><th>Message</th><th>Time</th></tr>
{% for a in alerts %}
<tr>
  <td>
    <span class="badge bg-{{ 'danger' if a.level == 'HIGH' else 'warning' }}">
      {{ a.level }}
    </span>
  </td>
  <td>{{ a.message }}</td>
  <td>{{ a.timestamp }}</td>
</tr>
{% endfor %}
</table>
"""

SIM_HTML = """
<h2>Attack Simulator</h2>
<p>Simulate brute-force attempts to trigger SOC alerts.</p>
<a class="btn btn-danger" href="/run-sim">Run Attack Simulation</a>
"""

# ---------------- Routes ----------------

@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        db = get_db()
        ip = request.remote_addr
        username = request.form["username"]
        password = request.form["password"]

        user_row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user_row and user_row["password"] == password:
            login_user(User(user_row["id"], user_row["username"], user_row["password"], user_row["role"]))
            db.execute("INSERT INTO login_attempts (ip, success, timestamp) VALUES (?, ?, ?)",
                       (ip, 1, datetime.utcnow().isoformat()))
            db.commit()
            db.close()
            return redirect(url_for("dashboard"))
        else:
            db.execute("INSERT INTO login_attempts (ip, success, timestamp) VALUES (?, ?, ?)",
                       (ip, 0, datetime.utcnow().isoformat()))
            db.commit()
            db.close()
            raise_alert("MEDIUM", f"Failed login attempt from {ip}")
            msg = "Invalid username or password"

    return render_template_string(BASE_HTML, content=render_template_string(LOGIN_HTML, msg=msg))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    attempts = db.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 10").fetchall()
    success_count = db.execute("SELECT COUNT(*) c FROM login_attempts WHERE success = 1").fetchone()["c"]
    fail_count = db.execute("SELECT COUNT(*) c FROM login_attempts WHERE success = 0").fetchone()["c"]
    db.close()
    return render_template_string(BASE_HTML, content=render_template_string(
        DASHBOARD_HTML, attempts=attempts, success_count=success_count, fail_count=fail_count))

@app.route("/alerts")
@login_required
def alerts():
    db = get_db()
    alerts = db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20").fetchall()
    db.close()
    return render_template_string(BASE_HTML, content=render_template_string(ALERTS_HTML, alerts=alerts))

@app.route("/simulate")
@login_required
def simulate():
    return render_template_string(BASE_HTML, content=render_template_string(SIM_HTML))

@app.route("/run-sim")
@login_required
def run_sim():
    db = get_db()
    for _ in range(10):
        fake_ip = f"10.0.0.{random.randint(2, 250)}"
        db.execute("INSERT INTO login_attempts (ip, success, timestamp) VALUES (?, ?, ?)",
                   (fake_ip, 0, datetime.utcnow().isoformat()))
        raise_alert("HIGH", f"Brute-force attempt detected from {fake_ip}")
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------------- Main ----------------

if __name__ == "__main__":
    init_db()
    create_admin()
    app.run(debug=True)
