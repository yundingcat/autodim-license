"""
AutoDimEngine äºç«¯æææå¡å¨
----------------------------
é¨ç½²å° Railway / Render ç­å¹³å°å³å¯è¿è¡ã
ç®¡çåå°: https://ä½ çåå/admin
ç®¡çå¯ç : é¦æ¬¡å¯å¨æ¶ä»æ§å¶å°æ¥å¿è·åï¼æè®¾ç¯å¢åé ADMIN_PASSWORD
"""

import os
import sqlite3
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

from flask import Flask, request, jsonify, render_template_string, abort, g
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# â ï¸ é¨ç½²æ¶å¡å¿éè¿ç¯å¢åé ADMIN_PASSWORD è®¾ç½®ç®¡çå¯ç ã
# æ¬å°å¼åé»è®¤å¼ä»ç¨äºæµè¯ï¼ä¸è¦å¨çäº§ç¯å¢ä½¿ç¨ã
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "q5589441")
# ä¼åç¨ Railway æä¹å·ï¼æ²¡æåç¨æ¬å° data ç®å½
_DB_DIR = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", os.path.join(os.path.dirname(__file__), "data"))
DB_PATH = os.path.join(_DB_DIR, "license.db")

# ââ å¬é¥ï¼ä¸æä»¶ä¸­åµå¥çå¬é¥ä¸è´ï¼ââ
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlQEuSHMaOxNAW30G2pG1
h1H+M+IeMMFOXaIkM60KJf4BugR4H8A/GJbQfqiB4TBHEWyOPjd/urZQ+bWG8KnC
n3oyQvaYPL5HXjHyk1zJHoDKlkXuqVp1MfefGG8bPHX1X4ztca/ceoHeQx2fxTzX
juYUeQlSIjZcP4d8ZBGqqRwQuPgDQoh3smE1HJy5h40onj7FVmhV5vDb0ipZuFVl
rMdkDNsXtZdxARWNKyjdHsMaveaapJvIEuYYxYK0XQuZs9IHCq3+B87v3nekpvws
0OG/nyGC+jS9CCRD9dB4rSqJEImgW6d+GzbdtbSCfXe8ZhhKRQYobWazNbcSUhRM
wwIDAQAB
-----END PUBLIC KEY-----"""

PUBLIC_KEY = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)


# ââ æ°æ®åº ââ

@contextmanager
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def init_db():
    os.makedirs(_DB_DIR, exist_ok=True)
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_code TEXT NOT NULL,
                license_code TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                last_seen TEXT,
                notes TEXT DEFAULT ''
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_code TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        db.commit()


init_db()


# ââ å·¥å·å½æ° ââ

def verify_rsa_signature(machine_code: str, expiry: str, license_code_b64: str) -> bool:
    """éªè¯ RSA ç­¾åçæ¿æ´»ç """
    try:
        data = f"{machine_code}|{expiry}".encode("utf-8")
        signature = base64.b64decode(license_code_b64)
        PUBLIC_KEY.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def check_admin_auth():
    """ç®åå¯ç è®¤è¯"""
    token = request.headers.get("X-Admin-Token", "")
    return token == ADMIN_PASSWORD


# ââ API è·¯ç± ââ

@app.route("/api/verify", methods=["POST"])
def api_verify():
    """æä»¶å¯å¨æ¶è°ç¨ï¼éªè¯æºå¨ç +æ¿æ´»ç æ¯å¦ææ"""
    data = request.get_json(force=True)
    machine_code = data.get("machine_code", "").strip().upper()
    license_code = data.get("license_code", "").strip()
    version = data.get("version", "0")

    if not machine_code or not license_code:
        return jsonify({"ok": False, "reason": "ç¼ºå°åæ°"}), 400

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr or ""

    with get_db() as db:
        # æ¥æ¾è¯¥æºå¨ç å·²æçæ¿æ´»è®°å½
        row = db.execute(
            "SELECT * FROM users WHERE machine_code = ? AND license_code = ?",
            (machine_code, license_code)
        ).fetchone()

        if row:
            # å·²æè®°å½
            if row["status"] == "banned":
                db.execute(
                    "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                    (machine_code, "verify_banned", f"å·²è¢«å°ç¦", ip, now)
                )
                db.commit()
                return jsonify({"ok": False, "reason": "æ­¤æ¿æ´»ç å·²è¢«å°ç¦ï¼è¯·èç³»ä¾åºå"}), 403

            expiry = row["expiry_date"]
            if expiry != "99991231" and expiry < datetime.now().strftime("%Y%m%d"):
                return jsonify({"ok": False, "reason": "æ¿æ´»ç å·²è¿æ", "expiry": expiry}), 403

            db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, row["id"]))
            db.execute(
                "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                (machine_code, "verify_ok", f"çæ¬:{version}", ip, now)
            )
            db.commit()
            return jsonify({"ok": True, "expiry": expiry})

        else:
            # æ°æ¿æ´»ï¼éè¦éªè¯ RSA ç­¾å
            # å°è¯å¸¸è§æææï¼ä»æ¿æ´»ç è½æåå°æææï¼
            # æ¿æ´»ç åªæ¯ç­¾åï¼ä¸å«æææï¼éè¦ä»æ¿æ´»ç çæé»è¾åæ¨
            # ç®åæ¹æ¡ï¼æ¥åå®¢æ·ç«¯åæ¶ä¼  expiry
            expiry = data.get("expiry", "99991231")
            if not verify_rsa_signature(machine_code, expiry, license_code):
                db.execute(
                    "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                    (machine_code, "verify_fail", f"ç­¾åæ æ", ip, now)
                )
                db.commit()
                return jsonify({"ok": False, "reason": "æ¿æ´»ç æ æ"}), 403

            if expiry != "99991231" and expiry < datetime.now().strftime("%Y%m%d"):
                return jsonify({"ok": False, "reason": "æ¿æ´»ç å·²è¿æ", "expiry": expiry}), 403

            db.execute(
                "INSERT INTO users (machine_code, license_code, expiry_date, status, created_at, last_seen) VALUES (?,?,?,?,?,?)",
                (machine_code, license_code, expiry, "active", now, now)
            )
            db.execute(
                "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                (machine_code, "activate", f"é¦æ¬¡æ¿æ´» çæ¬:{version}", ip, now)
            )
            db.commit()
            return jsonify({"ok": True, "expiry": expiry, "new": True})


@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    """æä»¶å®æå¿è·³ä¸æ¥"""
    data = request.get_json(force=True)
    machine_code = data.get("machine_code", "").strip().upper()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr or ""

    with get_db() as db:
        db.execute("UPDATE users SET last_seen = ? WHERE machine_code = ?", (now, machine_code))
        db.execute(
            "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
            (machine_code, "heartbeat", "", ip, now)
        )
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/check_command", methods=["POST"])
def api_check_command():
    """å½ä»¤æ§è¡åæ£æ¥ç¨æ·æ¯å¦è¢« ban"""
    data = request.get_json(force=True)
    machine_code = data.get("machine_code", "").strip().upper()
    command = data.get("command", "").strip()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr or ""

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE machine_code = ? AND status = 'active'",
            (machine_code,)
        ).fetchone()

        if not row:
            db.execute(
                "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                (machine_code, "cmd_denied", f"å½ä»¤:{command} ç¨æ·ä¸å­å¨", ip, now)
            )
            db.commit()
            return jsonify({"ok": False, "reason": "æªæ¿æ´»"}), 403

        if row["status"] == "banned":
            db.execute(
                "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                (machine_code, "cmd_denied", f"å½ä»¤:{command} å·²å°ç¦", ip, now)
            )
            db.commit()
            return jsonify({"ok": False, "reason": "å·²å°ç¦"}), 403

        expiry = row["expiry_date"]
        if expiry != "99991231" and expiry < datetime.now().strftime("%Y%m%d"):
            return jsonify({"ok": False, "reason": "å·²è¿æ"}), 403

        db.execute(
            "INSERT INTO logs (machine_code, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
            (machine_code, "cmd_ok", f"å½ä»¤:{command}", ip, now)
        )
        db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, row["id"]))
        db.commit()

    return jsonify({"ok": True})


# ââ ç®¡çåå° ââ

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AutoDimEngine ææç®¡ç</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; background: #f0f2f5; color: #333; }
.header { background: #1a1a2e; color: #fff; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 18px; }
.tabs { display: flex; gap: 4px; padding: 12px 24px; background: #fff; border-bottom: 1px solid #e0e0e0; }
.tab { padding: 8px 20px; cursor: pointer; border-radius: 6px; font-size: 14px; border: none; background: transparent; color: #666; }
.tab.active { background: #1a1a2e; color: #fff; }
.container { max-width: 1200px; margin: 24px auto; padding: 0 24px; }
.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); padding: 20px; margin-bottom: 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #eee; }
th { background: #fafafa; font-weight: 600; color: #555; }
tr:hover { background: #f8f9ff; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; }
.badge-active { background: #e6f7e6; color: #1a7a1a; }
.badge-banned { background: #fde8e8; color: #c41e1e; }
.badge-expired { background: #fff3cd; color: #856404; }
.btn { padding: 6px 14px; border-radius: 6px; border: none; cursor: pointer; font-size: 12px; font-weight: 500; }
.btn-danger { background: #dc3545; color: #fff; }
.btn-success { background: #28a745; color: #fff; }
.btn-sm { padding: 4px 10px; font-size: 11px; }
.loading { text-align: center; color: #999; padding: 40px; }
.stats { display: flex; gap: 16px; margin-bottom: 20px; }
.stat { flex: 1; background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.stat-val { font-size: 28px; font-weight: 700; color: #1a1a2e; }
.stat-label { font-size: 12px; color: #999; margin-top: 4px; }
</style>
</head>
<body>
<div class="header">
    <h1>AutoDimEngine ææç®¡ç</h1>
    <span style="font-size:12px;opacity:.6" id="serverTime"></span>
</div>
<div class="tabs">
    <button class="tab active" onclick="showTab('users')">ç¨æ·ç®¡ç</button>
    <button class="tab" onclick="showTab('logs')">æä½æ¥å¿</button>
    <button class="tab" onclick="showTab('stats')">ç»è®¡æ¦è§</button>
</div>
<div class="container" id="content">
    <div id="tab-users"></div>
    <div id="tab-logs" style="display:none"></div>
    <div id="tab-stats" style="display:none"></div>
</div>

<script>
const ADMIN_TOKEN = localStorage.getItem('admin_token') || '';

function showTab(name) {
    document.querySelectorAll('#content > div').forEach(d => d.style.display = 'none');
    document.getElementById('tab-' + name).style.display = 'block';
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    if (name === 'users') loadUsers();
    if (name === 'logs') loadLogs();
    if (name === 'stats') loadStats();
}

async function fetchAPI(path, method = 'GET', body = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN_TOKEN } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    return r.json();
}

async function loadUsers() {
    const data = await fetchAPI('/admin/api/users');
    let html = '<div class="card"><table><tr><th>æºå¨ç </th><th>æ¿æ´»ç </th><th>å°ææ¥</th><th>ç¶æ</th><th>é¦æ¬¡æ¿æ´»</th><th>æè¿å¨çº¿</th><th>æä½</th></tr>';
    for (const u of data.users || []) {
        const badge = u.status === 'active' ? 'badge-active' : 'badge-banned';
        const statusText = u.status === 'active' ? (u.expired ? 'å·²è¿æ' : 'æ­£å¸¸') : 'å·²å°ç¦';
        if (u.expired) badge = 'badge-expired';
        html += `<tr>
            <td style="font-family:monospace;font-size:12px">${u.machine_code}</td>
            <td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${u.license_code}">${u.license_code.substring(0,40)}...</td>
            <td>${u.expiry_date === '99991231' ? 'æ°¸ä¹' : u.expiry_date}</td>
            <td><span class="badge ${badge}">${statusText}</span></td>
            <td>${u.created_at}</td>
            <td>${u.last_seen || '-'}</td>
            <td>${u.status === 'active' 
                ? `<button class="btn btn-danger btn-sm" onclick="banUser('${u.machine_code}')">å°ç¦</button>`
                : `<button class="btn btn-success btn-sm" onclick="unbanUser('${u.machine_code}')">è§£å°</button>`
            }</td>
        </tr>`;
    }
    html += '</table></div>';
    document.getElementById('tab-users').innerHTML = html;
}

async function banUser(mc) {
    if (!confirm('ç¡®å®å°ç¦ ' + mc + ' åï¼è¯¥ç¨æ·å°æ æ³ä½¿ç¨æä»¶ã')) return;
    await fetchAPI('/admin/api/ban', 'POST', { machine_code: mc });
    loadUsers();
}

async function unbanUser(mc) {
    if (!confirm('ç¡®å®è§£å° ' + mc + ' åï¼')) return;
    await fetchAPI('/admin/api/unban', 'POST', { machine_code: mc });
    loadUsers();
}

async function loadLogs() {
    const data = await fetchAPI('/admin/api/logs?limit=200');
    let html = '<div class="card"><table><tr><th>æ¶é´</th><th>æºå¨ç </th><th>æä½</th><th>è¯¦æ</th><th>IP</th></tr>';
    for (const l of data.logs || []) {
        html += `<tr>
            <td>${l.created_at}</td>
            <td style="font-family:monospace;font-size:12px">${l.machine_code}</td>
            <td>${l.action}</td>
            <td>${l.detail || '-'}</td>
            <td>${l.ip || '-'}</td>
        </tr>`;
    }
    html += '</table></div>';
    document.getElementById('tab-logs').innerHTML = html;
}

async function loadStats() {
    const data = await fetchAPI('/admin/api/stats');
    document.getElementById('tab-stats').innerHTML = `
        <div class="stats">
            <div class="stat"><div class="stat-val">${data.total_users || 0}</div><div class="stat-label">æ»ç¨æ·æ°</div></div>
            <div class="stat"><div class="stat-val">${data.active_users || 0}</div><div class="stat-label">æ´»è·ç¨æ·</div></div>
            <div class="stat"><div class="stat-val">${data.banned_users || 0}</div><div class="stat-label">å·²å°ç¦</div></div>
            <div class="stat"><div class="stat-val">${data.today_commands || 0}</div><div class="stat-label">ä»æ¥å½ä»¤</div></div>
        </div>`;
}

// åå§å
if (!ADMIN_TOKEN) {
    const pwd = prompt('è¯·è¾å¥ç®¡çå¯ç :');
    if (!pwd) { document.body.innerHTML = '<h3 style="text-align:center;margin-top:40px">éè¦å¯ç </h3>'; }
    else { localStorage.setItem('admin_token', pwd); location.reload(); }
} else {
    loadUsers();
    setInterval(() => document.getElementById('serverTime').textContent = new Date().toLocaleString(), 1000);
}
</script>
</body>
</html>"""


@app.route("/admin")
def admin_page():
    return render_template_string(ADMIN_HTML)


@app.route("/admin/api/users")
def admin_users():
    if not check_admin_auth():
        return jsonify({"error": "æªææ"}), 401
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM users ORDER BY last_seen DESC"
        ).fetchall()
        users = []
        for r in rows:
            expired = r["expiry_date"] != "99991231" and r["expiry_date"] < datetime.now().strftime("%Y%m%d")
            users.append({
                "machine_code": r["machine_code"],
                "license_code": r["license_code"],
                "expiry_date": r["expiry_date"],
                "status": r["status"] if not expired else "expired",
                "expired": expired,
                "created_at": r["created_at"],
                "last_seen": r["last_seen"],
                "notes": r["notes"],
            })
        return jsonify({"users": users})


@app.route("/admin/api/logs")
def admin_logs():
    if not check_admin_auth():
        return jsonify({"error": "æªææ"}), 401
    limit = request.args.get("limit", "100")
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM logs ORDER BY id DESC LIMIT {int(limit)}"
        ).fetchall()
        logs = [dict(r) for r in rows]
        return jsonify({"logs": logs})


@app.route("/admin/api/stats")
def admin_stats():
    if not check_admin_auth():
        return jsonify({"error": "æªææ"}), 401
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
        banned = db.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0]
        today_cmds = db.execute(
            "SELECT COUNT(*) FROM logs WHERE created_at LIKE ?", (today + "%",)
        ).fetchone()[0]
        return jsonify({
            "total_users": total,
            "active_users": active,
            "banned_users": banned,
            "today_commands": today_cmds,
        })


@app.route("/admin/api/ban", methods=["POST"])
def admin_ban():
    if not check_admin_auth():
        return jsonify({"error": "æªææ"}), 401
    data = request.get_json(force=True)
    mc = data.get("machine_code", "")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as db:
        db.execute("UPDATE users SET status = 'banned' WHERE machine_code = ?", (mc,))
        db.execute(
            "INSERT INTO logs (machine_code, action, detail, created_at) VALUES (?,?,?,?)",
            (mc, "admin_ban", "ç®¡çåå°ç¦", now)
        )
        db.commit()
    return jsonify({"ok": True})


@app.route("/admin/api/unban", methods=["POST"])
def admin_unban():
    if not check_admin_auth():
        return jsonify({"error": "æªææ"}), 401
    data = request.get_json(force=True)
    mc = data.get("machine_code", "")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as db:
        db.execute("UPDATE users SET status = 'active' WHERE machine_code = ?", (mc,))
        db.execute(
            "INSERT INTO logs (machine_code, action, detail, created_at) VALUES (?,?,?,?)",
            (mc, "admin_unban", "ç®¡çåè§£å°", now)
        )
        db.commit()
    return jsonify({"ok": True})


# ââ é¦é¡µ ââ

@app.route("/")
def index():
    return jsonify({"service": "AutoDimEngine License Server", "version": "1.0", "status": "running"})


if __name__ == "__main__":
    print(f"\n  === AutoDimEngine æææå¡å¨ ===")
    print(f"  ç®¡çåå°: http://localhost:5000/admin")
    print(f"  ç®¡çå¯ç : {ADMIN_PASSWORD}")
    print(f"  æ°æ®æä»¶: {DB_PATH}")
    print(f"  ================================\n")
    app.run(host="0.0.0.0", port=5000, debug=True)

