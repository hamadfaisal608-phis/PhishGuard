import os
import re
import secrets
import socket
import sqlite3
import sys
import threading
import time
import webbrowser
from urllib.parse import urlparse

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)


def get_secret_key():
    # use the SECRET_KEY variable if it is set (hosting), else keep a random key in a file
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path) as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    try:
        with open(path, "w") as f:
            f.write(key)
    except OSError:
        pass
    return key


app.secret_key = get_secret_key()
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

# when the site is hosted online it runs behind the host's proxy
if os.environ.get("RENDER") or os.environ.get("BEHIND_PROXY"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config["SESSION_COOKIE_SECURE"] = True


# ---------------- database ----------------

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        result TEXT NOT NULL,
        score INTEGER NOT NULL,
        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    conn.close()


init_db()


# ---------------- csrf and login attempts ----------------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            flash("Session expired, please try again.", "warning")
            return redirect(request.referrer or url_for("dashboard"))


failed_logins = {}      # ip -> list of times, lost when the server restarts
MAX_TRIES = 5
WAIT_SECONDS = 300


def too_many_tries(ip):
    now = time.time()
    recent = [t for t in failed_logins.get(ip, []) if now - t < WAIT_SECONDS]
    failed_logins[ip] = recent
    return len(recent) >= MAX_TRIES


# ---------------- phishing checks ----------------

OFFICIAL_DOMAINS = {
    "paypal.com", "paypal.me", "amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
    "apple.com", "icloud.com", "microsoft.com", "microsoftonline.com", "live.com",
    "outlook.com", "office.com", "netflix.com", "facebook.com", "fb.com",
    "instagram.com", "whatsapp.com", "google.com", "gmail.com", "youtube.com",
    "github.com", "linkedin.com", "twitter.com", "x.com", "ebay.com", "binance.com",
    "wikipedia.org",
}
BRANDS = ["paypal", "amazon", "microsoft", "netflix", "facebook", "instagram",
          "whatsapp", "binance", "linkedin", "google", "apple", "ebay", "icloud"]
SHORT_BRANDS = ["apple", "ebay"]    # short names are only matched as a whole word
KEYWORDS = ["login", "signin", "sign-in", "secure", "account", "update", "verify",
            "banking", "bank", "password", "confirm", "click", "urgent", "suspend",
            "limited", "wallet", "credential"]
SHORTENERS = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd",
              "buff.ly", "adf.ly", "cutt.ly", "shorturl.at"]
BAD_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work"]
SECOND_LEVEL = ["co", "com", "org", "net", "gov", "edu", "ac"]

HOST_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
IP_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
MAX_URL_LENGTH = 2048


def main_domain(host):
    # a.b.example.com -> example.com, shop.example.co.uk -> example.co.uk
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def result_dict(result, score, reasons, url):
    return {"result": result, "score": score, "reasons": reasons, "url": url}


def check_url(url):
    original = (url or "").strip()
    if not original:
        return result_dict("Error", 0, ["Please enter a URL."], "")
    if len(original) > MAX_URL_LENGTH:
        return result_dict("Error", 0, ["The URL is too long (max %d characters)." % MAX_URL_LENGTH], original[:80] + "...")
    if re.search(r"\s", original):
        return result_dict("Error", 0, ["A URL cannot contain spaces."], original)

    if original.lower().startswith(("javascript:", "data:", "vbscript:", "file:")):
        return result_dict("Phishing", 10, ["This is not a web address, it runs code or opens local data."], original)

    has_scheme = "://" in original
    if has_scheme:
        scheme = original.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return result_dict("Error", 0, ["Only http and https links can be checked (found '%s')." % scheme], original)
        full_url = original
    else:
        full_url = "https://" + original    # no scheme typed, so assume https

    try:
        parsed = urlparse(full_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        parsed.port             # a wrong port raises ValueError
    except ValueError:
        return result_dict("Error", 0, ["This URL is not written correctly."], original)

    is_ip = False
    match = IP_PATTERN.match(host)
    if match:
        if all(int(n) <= 255 for n in match.groups()):
            is_ip = True
        else:
            return result_dict("Error", 0, ["This IP address is not valid (numbers go up to 255)."], original)
    if not is_ip and not HOST_PATTERN.match(host):
        return result_dict("Error", 0, ["This does not look like a website address. Try something like example.com"], original)

    domain = host if is_ip else main_domain(host)
    is_https = full_url.lower().startswith("https://")

    # known real website over https
    if domain in OFFICIAL_DOMAINS and is_https:
        return result_dict("Safe", 0, ["This is the official domain of a well known website (%s)." % domain], original)

    score = 0
    reasons = []

    if has_scheme and not is_https:
        score += 2
        reasons.append("Does not use HTTPS")

    if is_ip:
        score += 3
        reasons.append("Uses an IP address instead of a domain name")

    if "@" in parsed.netloc:
        score += 3
        reasons.append("Has an @ sign before the domain, which can hide the real website")

    dots = host.count(".")
    if not is_ip and dots >= 4:
        score += 2
        reasons.append("Too many subdomains (%d dots)" % dots)

    if len(original) > 75:
        score += 1
        reasons.append("The URL is very long (%d characters)" % len(original))

    if "-" in host.replace("xn--", ""):
        score += 1
        reasons.append("Domain contains a hyphen")

    if "xn--" in host:
        score += 2
        reasons.append("Domain uses look-alike (punycode) characters")

    # brand name used in a domain that is not the real one
    if not is_ip:
        words = set(re.split(r"[.\-]", host))
        for brand in BRANDS:
            if brand in SHORT_BRANDS:
                found = brand in words
            else:
                found = brand in host
            if found:
                score += 3
                reasons.append("Uses the brand name '%s' but is not its official domain" % brand)
                break

    text = (host + parsed.path + "?" + parsed.query).lower()
    words_found = [w for w in KEYWORDS if w in text]
    if words_found:
        score += min(len(words_found), 3)
        reasons.append("Suspicious words: " + ", ".join(words_found[:6]))

    for s in SHORTENERS:
        if host == s or host.endswith("." + s):
            score += 2
            reasons.append("Uses a URL shortener (%s), the real destination is hidden" % s)
            break

    for tld in BAD_TLDS:
        if host.endswith(tld):
            score += 2
            reasons.append("Risky domain ending (%s)" % tld)
            break

    if "//" in parsed.path:
        score += 1
        reasons.append("Has double slashes in the path")

    if score >= 4:
        result = "Phishing"
    elif score >= 2:
        result = "Suspicious"
    else:
        result = "Safe"
        if not reasons:
            reasons.append("No phishing signs found")
        elif not has_scheme:
            reasons.append("No http or https was typed, so https was assumed")
    return result_dict(result, score, reasons, original)


# ---------------- pages ----------------

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
        elif not re.match(r"^[A-Za-z0-9_.]{3,30}$", username):
            flash("Username must be 3 to 30 characters: letters, numbers, dot or underscore.", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        elif len(password) > 128:
            flash("Password is too long (max 128 characters).", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            conn = get_db()
            exists = conn.execute("SELECT id FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
            if exists:
                flash("This username is already taken.", "danger")
            else:
                try:
                    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                                 (username, generate_password_hash(password)))
                    conn.commit()
                    conn.close()
                    flash("Account created. Please log in.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("This username is already taken.", "danger")
            conn.close()

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if too_many_tries(ip):
            flash("Too many wrong attempts. Please wait 5 minutes.", "danger")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            failed_logins.pop(ip, None)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Welcome, " + user["username"], "success")
            return redirect(url_for("dashboard"))

        failed_logins.setdefault(ip, []).append(time.time())
        flash("Wrong username or password.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You are logged out.", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    user_id = session.get("user_id")    # None means guest

    if request.method == "POST":
        data = check_url(request.form.get("url", ""))
        if user_id and data["result"] != "Error":
            conn = get_db()
            conn.execute("INSERT INTO history (user_id, url, result, score) VALUES (?, ?, ?, ?)",
                         (user_id, data["url"], data["result"], data["score"]))
            # keep only the last 100 checks of this user
            conn.execute("DELETE FROM history WHERE user_id = ? AND id NOT IN "
                         "(SELECT id FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 100)",
                         (user_id, user_id))
            conn.commit()
            conn.close()
        # redirect so that refreshing the page does not scan again
        session["last_result"] = data
        return redirect(url_for("dashboard"))

    result = session.pop("last_result", None)

    history = []
    if user_id:
        conn = get_db()
        history = conn.execute("SELECT url, result, score, checked_at FROM history "
                               "WHERE user_id = ? ORDER BY id DESC LIMIT 8", (user_id,)).fetchall()
        conn.close()

    return render_template("dashboard.html", result=result, history=history,
                           username=session.get("username"), logged_in=bool(user_id))


@app.route("/clear-history", methods=["POST"])
def clear_history():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    conn = get_db()
    conn.execute("DELETE FROM history WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    flash("History cleared.", "success")
    return redirect(url_for("dashboard"))


@app.errorhandler(404)
def page_not_found(e):
    if request.path == "/favicon.ico":
        return "", 204
    flash("That page does not exist.", "warning")
    return redirect(url_for("dashboard"))


@app.errorhandler(413)
def request_too_large(e):
    flash("That request was too large.", "danger")
    return redirect(url_for("dashboard"))


# ---------------- running the app ----------------

PORT = int(os.environ.get("PORT", 5000))
URL = "http://127.0.0.1:%d" % PORT


def from_vscode():
    # True when the program was started from VS Code (Run button, its terminal or debugger)
    if os.environ.get("TERM_PROGRAM", "").lower() == "vscode":
        return True
    if any(k.startswith("VSCODE_") for k in os.environ):
        return True
    return "debugpy" in sys.modules or "pydevd" in sys.modules


def port_in_use(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


if __name__ == "__main__":
    # python app.py            -> start the server (browser opens only from VS Code)
    # python app.py browser    -> open the browser from any terminal
    # python app.py nobrowser  -> never open the browser
    args = [a.lower() for a in sys.argv[1:]]
    is_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"   # debug mode starts a second process

    if not is_child and port_in_use(PORT):
        print("Port %d is already in use. Close the other window or use another port:" % PORT)
        print("  set PORT=5050   (then run python app.py again)")
        sys.exit(1)

    print("PhishGuard running at " + URL)

    open_it = "browser" in args or (from_vscode() and "nobrowser" not in args)
    if open_it and not is_child:
        threading.Timer(1.5, webbrowser.open, args=(URL,)).start()

    app.run(debug=True, host="127.0.0.1", port=PORT)
