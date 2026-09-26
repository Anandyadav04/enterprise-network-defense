"""
enterprise_network/web_app/app.py
─────────────────────────────────
Lightweight Enterprise Web Portal (DMZ Target Server).

Hosts a corporate web portal with endpoints that serve as realistic
targets for penetration testing demonstrations:

  GET  /               — Corporate home portal
  GET  /api/status     — Health & telemetry check
  GET  /api/search?q=  — Search endpoint (SQL injection target)
  POST /api/login      — Auth endpoint (brute-force target)
  GET  /docs/download  — Document download (path traversal target)
"""

import os
import json
import time
import logging
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("enterprise-web-app")

# ── In-memory SQLite for realistic SQL query simulation ──────────
DB_PATH = "/tmp/enterprise.db"

def init_db():
    """Initialize a sample employee database for search demonstrations."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    sample_data = [
        (1, "Alice Johnson", "Engineering", "alice@enterprise.local", "Senior Engineer"),
        (2, "Bob Martinez", "IT Security", "bob@enterprise.local", "SOC Analyst"),
        (3, "Carol Williams", "Finance", "carol@enterprise.local", "CFO"),
        (4, "David Chen", "Engineering", "david@enterprise.local", "DevOps Lead"),
        (5, "Eve Richardson", "HR", "eve@enterprise.local", "HR Director"),
        (6, "Frank O'Brien", "IT Security", "frank@enterprise.local", "Pen Tester"),
        (7, "Grace Kim", "Marketing", "grace@enterprise.local", "CMO"),
        (8, "Henry Patel", "Engineering", "henry@enterprise.local", "Backend Dev"),
    ]
    c.executemany("INSERT OR IGNORE INTO employees VALUES (?,?,?,?,?)", sample_data)
    conn.commit()
    conn.close()
    logger.info("Employee database initialized with %d records", len(sample_data))


# ── Startup ──────────────────────────────────────────────────────
REQUEST_LOG = []
START_TIME = time.time()

init_db()

# ── Valid credentials for brute-force demo ───────────────────────
VALID_CREDENTIALS = {
    "admin": "Enterprise@2024",
    "root": "toor",
}

# ── HTML Templates ───────────────────────────────────────────────
PORTAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Corp — Internal Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a1628; color: #e0e8f0; }
        .header { background: linear-gradient(135deg, #1a2332 0%, #0d47a1 100%);
                   padding: 30px; text-align: center; border-bottom: 3px solid #2196f3; }
        .header h1 { font-size: 2rem; color: #fff; }
        .header p { color: #90caf9; margin-top: 8px; }
        .content { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        .card { background: #1a2332; border: 1px solid #1e3a5f; border-radius: 12px;
                padding: 24px; margin-bottom: 20px; transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); border-color: #2196f3; }
        .card h3 { color: #64b5f6; margin-bottom: 10px; }
        .card p { color: #90a4ae; line-height: 1.6; }
        .status { display: inline-block; background: #1b5e20; color: #a5d6a7;
                  padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; }
        .footer { text-align: center; color: #546e7a; padding: 30px; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏢 Enterprise Corp — Internal Portal</h1>
        <p>Secure Employee Access | Network Monitoring Active</p>
    </div>
    <div class="content">
        <div class="card">
            <h3>📊 Network Operations Center</h3>
            <p>Real-time monitoring of all corporate infrastructure. Current status:
               <span class="status">● All Systems Operational</span></p>
        </div>
        <div class="card">
            <h3>🔍 Employee Directory</h3>
            <p>Search our corporate directory at <code>/api/search?q=name</code></p>
        </div>
        <div class="card">
            <h3>📄 Document Center</h3>
            <p>Access corporate documents at <code>/docs/download?file=annual_report.pdf</code></p>
        </div>
        <div class="card">
            <h3>🔐 Secure Login</h3>
            <p>Authenticate via <code>POST /api/login</code> with credentials</p>
        </div>
    </div>
    <div class="footer">
        &copy; 2024 Enterprise Corp — Confidential. Unauthorized access is prohibited.
    </div>
</body>
</html>
"""


# ── Routes ───────────────────────────────────────────────────────

@app.route("/")
def home():
    """Corporate Home Portal."""
    _log_request(request)
    return render_template_string(PORTAL_HTML)


@app.route("/api/status")
def status():
    """Health & telemetry endpoint."""
    _log_request(request)
    uptime = time.time() - START_TIME
    return jsonify({
        "status": "operational",
        "server": "enterprise-web-app",
        "uptime_seconds": round(uptime, 1),
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.1.0",
        "services": {
            "database": "connected",
            "auth": "active",
            "file_server": "active",
        },
        "total_requests": len(REQUEST_LOG),
    })


@app.route("/api/search")
def search():
    """
    Employee search endpoint.
    
    This endpoint intentionally uses string formatting for the SQL query
    to serve as a realistic SQL injection demonstration target.
    In a real application, parameterized queries should ALWAYS be used.
    """
    _log_request(request)
    query = request.args.get("q", "")

    if not query:
        return jsonify({"error": "Missing search query parameter 'q'"}), 400

    # Log the raw query for detection pipeline visibility
    logger.warning("SEARCH QUERY: q='%s' from %s", query, request.remote_addr)

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Deliberately vulnerable to SQL injection for demonstration
        sql = f"SELECT * FROM employees WHERE name LIKE '%{query}%' OR department LIKE '%{query}%'"
        logger.info("Executing SQL: %s", sql)
        c.execute(sql)
        results = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"query": query, "results": results, "count": len(results)})
    except Exception as e:
        logger.error("SQL error: %s", e)
        return jsonify({"error": "Database error", "detail": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    """
    Authentication endpoint — target for brute-force simulations.
    Accepts JSON or form-encoded credentials.
    """
    _log_request(request)

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    logger.warning("LOGIN ATTEMPT: user='%s' from %s", username, request.remote_addr)

    # Intentional delay to make brute-force observable in traffic
    time.sleep(0.1)

    if VALID_CREDENTIALS.get(username) == password:
        return jsonify({
            "status": "success",
            "message": "Authentication successful",
            "token": "eyJhbGciOiJIUzI1NiJ9.DEMO_TOKEN.signature",
            "user": username,
        })
    else:
        return jsonify({"status": "failed", "message": "Invalid credentials"}), 401


@app.route("/docs/download")
def docs_download():
    """
    Document download endpoint — target for path traversal simulations.
    """
    _log_request(request)
    filename = request.args.get("file", "")

    if not filename:
        return jsonify({"error": "Missing 'file' parameter"}), 400

    logger.warning("FILE REQUEST: file='%s' from %s", filename, request.remote_addr)

    # Detect path traversal attempts
    if ".." in filename or filename.startswith("/"):
        logger.critical("PATH TRAVERSAL DETECTED: '%s' from %s", filename, request.remote_addr)
        return jsonify({
            "error": "Access denied",
            "detail": "Path traversal attempt detected and logged",
        }), 403

    # Simulate serving a legitimate document
    available_docs = {
        "annual_report.pdf": {"size": "2.4 MB", "type": "application/pdf"},
        "security_policy.pdf": {"size": "890 KB", "type": "application/pdf"},
        "employee_handbook.pdf": {"size": "1.1 MB", "type": "application/pdf"},
        "network_topology.png": {"size": "450 KB", "type": "image/png"},
    }

    if filename in available_docs:
        doc = available_docs[filename]
        return jsonify({
            "status": "ok",
            "file": filename,
            "size": doc["size"],
            "content_type": doc["type"],
            "message": "Document ready for download",
        })
    else:
        return jsonify({"error": f"File '{filename}' not found"}), 404


@app.route("/robots.txt")
def robots():
    """Simulated robots.txt for reconnaissance scanning."""
    _log_request(request)
    return (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/internal/\n"
        "Disallow: /backup/\n"
        "Disallow: /config/\n"
    ), 200, {"Content-Type": "text/plain"}


@app.route("/admin/")
@app.route("/admin/<path:subpath>")
def admin_panel(subpath=""):
    """Restricted admin area — triggers security events on access attempts."""
    _log_request(request)
    logger.critical("ADMIN ACCESS ATTEMPT from %s path=/admin/%s", request.remote_addr, subpath)
    return jsonify({"error": "Unauthorized", "message": "This area is restricted"}), 403


# ── Helpers ──────────────────────────────────────────────────────

def _log_request(req):
    """Log every request for observability."""
    REQUEST_LOG.append({
        "time": datetime.utcnow().isoformat(),
        "method": req.method,
        "path": req.path,
        "remote_addr": req.remote_addr,
        "user_agent": req.headers.get("User-Agent", ""),
    })


# ── Main ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Enterprise Web App starting on 0.0.0.0:80")
    app.run(host="0.0.0.0", port=80, debug=False)
