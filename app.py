from flask import Flask, render_template, request, redirect, session
import psycopg2
import requests
from user_agents import parse

app = Flask(__name__)
app.secret_key = "secret123"


# ---------------- DB CONNECTION ----------------
def get_connection():
    return psycopg2.connect(
        host="localhost",
        database="cyber_twin",
        user="postgres",
        password="sql1507"
    )


# ---------------- LOCATION API ----------------
def get_location(ip):
    try:
        if ip == "127.0.0.1":
            return "Localhost", "Local"

        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = res.json()

        if data.get("status") == "success":
            return data.get("country", "Unknown"), data.get("city", "Unknown")

        return "Unknown", "Unknown"

    except:
        return "Unknown", "Unknown"


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ---------------- SQL INJECTION DETECTION ----------------
        sql_keywords = [
            "'", "--", ";", "/*", "*/",
            "DROP", "SELECT", "INSERT",
            "DELETE", "UPDATE", "UNION",
            "OR 1=1", "AND 1=1"
        ]

        user_input = (username + " " + password).upper()

        for keyword in sql_keywords:
            if keyword in user_input:

                conn = get_connection()
                cur = conn.cursor()

                cur.execute("""
                    INSERT INTO login_logs
                    (username, status, ip_address, browser,
                     operating_system, device_type, country, city, attack_type)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    username,
                    "FAILED",
                    request.remote_addr,
                    "Unknown",
                    "Unknown",
                    "Unknown",
                    "Unknown",
                    "Unknown",
                    "SQL Injection Attempt"
                ))

                conn.commit()
                conn.close()

                return render_template("login.html",
                                       error="🚫 SQL Injection Detected!")

        # ---------------- IP ----------------
        ip = request.remote_addr or "Unknown"

        # ---------------- LOCATION ----------------
        country, city = get_location(ip)

        # ---------------- USER AGENT SAFE ----------------
        ua_string = request.headers.get("User-Agent", "")
        ua = parse(ua_string)

        browser = ua.browser.family if ua.browser else "Unknown"
        os = ua.os.family if ua.os else "Unknown"

        if ua.is_mobile:
            device = "Mobile"
        elif ua.is_tablet:
            device = "Tablet"
        else:
            device = "Desktop"

        conn = get_connection()
        cur = conn.cursor()

        # ---------------- BRUTE FORCE CHECK ----------------
        cur.execute("""
            SELECT COUNT(*) FROM login_logs
            WHERE username=%s AND status='FAILED'
        """, (username,))

        failed_count = cur.fetchone()[0]

        if failed_count >= 3:
            conn.close()
            return "<h2>🚫 User Blocked (Too many failed attempts)</h2>"

        # ---------------- CHECK LOGIN ----------------
        cur.execute("""
            SELECT * FROM login
            WHERE username=%s AND password=%s
        """, (username, password))

        user = cur.fetchone()

        # ---------------- FAILED LOGIN ----------------
        if not user:

            cur.execute("""
                INSERT INTO login_logs
                (username, status, ip_address, browser,
                 operating_system, device_type, country, city, attack_type)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                username,
                "FAILED",
                ip,
                browser,
                os,
                device,
                country,
                city,
                "Normal Login Failed"
            ))

            conn.commit()
            conn.close()

            return render_template("login.html",
                                   error="Invalid Username or Password")

        # ---------------- SUCCESS LOGIN ----------------
        cur.execute("""
            INSERT INTO login_logs
            (username, status, ip_address, browser,
             operating_system, device_type, country, city, attack_type)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            username,
            "SUCCESS",
            ip,
            browser,
            os,
            device,
            country,
            city,
            "Normal Login Success"
        ))

        # reset failed logs
        cur.execute("""
            DELETE FROM login_logs
            WHERE username=%s AND status='FAILED'
        """, (username,))

        conn.commit()
        conn.close()

        session["user"] = username
        return redirect("/dashboard")

    return render_template("login.html")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    return """
    <h2>Cyber Security Digital Twin Dashboard</h2>
    <a href='/students'>Students</a><br>
    <a href='/admin'>Security Logs</a><br>
    <a href='/logout'>Logout</a>
    """


# ---------------- STUDENTS ----------------
@app.route("/students")
def students():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM students")
    data = cur.fetchall()

    conn.close()

    return render_template("students.html", students=data)


# ---------------- ADMIN ----------------
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM login_logs ORDER BY id DESC")
    logs = cur.fetchall()

    conn.close()

    return render_template("admin.html", logs=logs)


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)