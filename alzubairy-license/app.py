import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, Response, jsonify, redirect, render_template_string, request, url_for


DATA_DIR = Path(os.environ.get("ALZUBAIRY_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "licenses.sqlite3"
PRIVATE_KEY_PATH = DATA_DIR / "license_signing_ed25519.pem"
PUBLIC_KEY_PATH = DATA_DIR / "license_signing_ed25519.pub"
ADMIN_USER = os.environ.get("ALZUBAIRY_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ALZUBAIRY_ADMIN_PASSWORD", "")
PERSONAL_DEVICE_LIMIT = 3

app = Flask(__name__)


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def initialize():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_hash TEXT NOT NULL UNIQUE,
                license_hint TEXT NOT NULL,
                plan TEXT NOT NULL CHECK(plan IN ('personal', 'business', 'business_pro', 'enterprise')),
                customer_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'expired')),
                max_devices INTEGER NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
                device_id TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                app_version TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                UNIQUE(license_id, device_id)
            );
            CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id);
            CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email);
            """
        )
    signing_key()


def signing_key():
    if PRIVATE_KEY_PATH.exists():
        return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    PRIVATE_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(PRIVATE_KEY_PATH, 0o600)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    PUBLIC_KEY_PATH.write_text(base64.b64encode(public).decode("ascii"), encoding="utf-8")
    return key


def hash_license(value):
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def new_license_key(plan):
    prefix = {
        "personal": "ALZ-PER",
        "business": "ALZ-BIZ",
        "business_pro": "ALZ-PRO",
        "enterprise": "ALZ-ENT",
    }[plan]
    return f"{prefix}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"


def signed_entitlement(row, device_id):
    issued = utc_now()
    payload = {
        "iss": "Alzubairy Remote Licensing",
        "license_id": row["id"],
        "plan": row["plan"],
        "device_id": device_id,
        "max_devices": row["max_devices"],
        "iat": issued.isoformat(),
        "check_after": (issued + timedelta(hours=24)).isoformat(),
        "offline_until": (issued + timedelta(days=7)).isoformat(),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = signing_key().sign(encoded)
    return {
        "payload": base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        "algorithm": "Ed25519",
    }


def authorized():
    auth = request.authorization
    return bool(
        ADMIN_PASSWORD
        and auth
        and secrets.compare_digest(auth.username or "", ADMIN_USER)
        and secrets.compare_digest(auth.password or "", ADMIN_PASSWORD)
    )


def admin_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not authorized():
            return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Alzubairy Admin"'})
        return function(*args, **kwargs)

    return wrapped


@app.get("/health")
def health():
    return jsonify(status="ok", service="alzubairy-license")


@app.get("/api/v1/public-key")
def public_key():
    return jsonify(algorithm="Ed25519", public_key=PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip())


@app.post("/api/v1/personal/register")
def register_personal():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    name = str(body.get("name", "")).strip()[:120]
    if "@" not in email or len(email) > 254:
        return jsonify(error="valid_email_required"), 400
    with db() as connection:
        existing = connection.execute(
            "SELECT id FROM licenses WHERE email = ? AND plan = 'personal'", (email,)
        ).fetchone()
        if existing:
            return jsonify(error="personal_license_exists", message="Use the existing personal license."), 409
        key = new_license_key("personal")
        connection.execute(
            """INSERT INTO licenses
               (license_hash, license_hint, plan, customer_name, email, max_devices, created_at)
               VALUES (?, ?, 'personal', ?, ?, ?, ?)""",
            (hash_license(key), key[-8:], name, email, PERSONAL_DEVICE_LIMIT, utc_now().isoformat()),
        )
    return jsonify(license_key=key, plan="personal", max_devices=PERSONAL_DEVICE_LIMIT), 201


@app.post("/api/v1/licenses/activate")
def activate():
    body = request.get_json(silent=True) or {}
    license_key = str(body.get("license_key", "")).strip()
    device_id = str(body.get("device_id", "")).strip()[:160]
    device_name = str(body.get("device_name", "")).strip()[:160]
    app_version = str(body.get("app_version", "")).strip()[:40]
    if not license_key or not device_id:
        return jsonify(error="license_key_and_device_id_required"), 400
    now = utc_now()
    with db() as connection:
        license_row = connection.execute(
            "SELECT * FROM licenses WHERE license_hash = ?", (hash_license(license_key),)
        ).fetchone()
        if not license_row:
            return jsonify(error="invalid_license"), 404
        if license_row["status"] != "active":
            return jsonify(error=f"license_{license_row['status']}"), 403
        if license_row["expires_at"] and datetime.fromisoformat(license_row["expires_at"]) <= now:
            connection.execute("UPDATE licenses SET status = 'expired' WHERE id = ?", (license_row["id"],))
            return jsonify(error="license_expired"), 403
        device = connection.execute(
            "SELECT * FROM devices WHERE license_id = ? AND device_id = ?",
            (license_row["id"], device_id),
        ).fetchone()
        if device and device["revoked"]:
            return jsonify(error="device_revoked"), 403
        if not device:
            count = connection.execute(
                "SELECT COUNT(*) FROM devices WHERE license_id = ? AND revoked = 0",
                (license_row["id"],),
            ).fetchone()[0]
            if count >= license_row["max_devices"]:
                return jsonify(error="device_limit_reached", max_devices=license_row["max_devices"]), 409
            connection.execute(
                """INSERT INTO devices
                   (license_id, device_id, device_name, app_version, first_seen_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (license_row["id"], device_id, device_name, app_version, now.isoformat(), now.isoformat()),
            )
        else:
            connection.execute(
                "UPDATE devices SET device_name = ?, app_version = ?, last_seen_at = ? WHERE id = ?",
                (device_name, app_version, now.isoformat(), device["id"]),
            )
        entitlement = signed_entitlement(license_row, device_id)
    return jsonify(active=True, plan=license_row["plan"], entitlement=entitlement)


ADMIN_PAGE = """
<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>لوحة تراخيص الزبيري</title>
<style>
body{margin:0;background:#07111f;color:#eaf4ff;font-family:Tahoma,Arial,sans-serif}.wrap{max-width:1180px;margin:auto;padding:28px}
h1{margin:0 0 8px}.sub{color:#8fa9c7}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}.card,.panel{background:#0d1c30;border:1px solid #1d3654;border-radius:16px;padding:18px}.num{font-size:30px;color:#5ed8ff;font-weight:bold}
form{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}input,select,button{border:1px solid #294969;border-radius:9px;padding:11px;background:#091626;color:white}button{background:linear-gradient(90deg,#176bff,#713cff);cursor:pointer;font-weight:bold}table{width:100%;border-collapse:collapse;margin-top:18px}th,td{padding:12px;border-bottom:1px solid #1d3654;text-align:right}.active{color:#63e6a5}.suspended,.expired{color:#ff7a90}.key{direction:ltr;text-align:left;background:#07111f;padding:12px;border-radius:9px;color:#8fe7ff;word-break:break-all}@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}form{grid-template-columns:1fr}table{font-size:12px}}
</style></head><body><div class="wrap"><h1>لوحة تراخيص الزبيري Remote</h1><div class="sub">إدارة الباقات والأجهزة والتفعيل</div>
{% if created_key %}<div class="panel"><b>تم إنشاء الترخيص — انسخه الآن:</b><div class="key">{{ created_key }}</div></div>{% endif %}
<div class="cards"><div class="card"><div class="num">{{ stats.total }}</div>كل التراخيص</div><div class="card"><div class="num">{{ stats.personal }}</div>شخصي مجاني</div><div class="card"><div class="num">{{ stats.business }}</div>تجاري</div><div class="card"><div class="num">{{ stats.devices }}</div>الأجهزة</div></div>
<div class="panel"><h2>إصدار ترخيص جديد</h2><form method="post" action="{{ url_for('admin_create') }}"><input name="customer_name" placeholder="اسم العميل" required><input name="email" type="email" placeholder="البريد"><select name="plan"><option value="business">Business</option><option value="business_pro">Business Pro</option><option value="enterprise">Enterprise</option><option value="personal">شخصي مجاني</option></select><input name="max_devices" type="number" min="1" value="10" required><button>إنشاء الترخيص</button></form></div>
<div class="panel"><h2>التراخيص</h2><table><thead><tr><th>العميل</th><th>الباقة</th><th>الحالة</th><th>الأجهزة</th><th>الرمز</th><th>تاريخ الإنشاء</th></tr></thead><tbody>{% for item in licenses %}<tr><td>{{ item.customer_name or item.email or '—' }}</td><td>{{ item.plan }}</td><td class="{{ item.status }}">{{ item.status }}</td><td>{{ item.device_count }}/{{ item.max_devices }}</td><td>…{{ item.license_hint }}</td><td>{{ item.created_at[:10] }}</td></tr>{% endfor %}</tbody></table></div>
</div></body></html>
"""


@app.get("/admin")
@admin_required
def admin():
    with db() as connection:
        rows = connection.execute(
            """SELECT l.*, COUNT(d.id) AS device_count FROM licenses l
               LEFT JOIN devices d ON d.license_id = l.id AND d.revoked = 0
               GROUP BY l.id ORDER BY l.id DESC"""
        ).fetchall()
        stats = {
            "total": len(rows),
            "personal": sum(row["plan"] == "personal" for row in rows),
            "business": sum(row["plan"] != "personal" for row in rows),
            "devices": sum(row["device_count"] for row in rows),
        }
    return render_template_string(ADMIN_PAGE, licenses=rows, stats=stats, created_key=request.args.get("key", ""))


@app.post("/admin/licenses")
@admin_required
def admin_create():
    plan = request.form.get("plan", "business")
    if plan not in {"personal", "business", "business_pro", "enterprise"}:
        return jsonify(error="invalid_plan"), 400
    try:
        max_devices = max(1, min(int(request.form.get("max_devices", "1")), 100000))
    except ValueError:
        return jsonify(error="invalid_max_devices"), 400
    key = new_license_key(plan)
    with db() as connection:
        connection.execute(
            """INSERT INTO licenses
               (license_hash, license_hint, plan, customer_name, email, max_devices, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                hash_license(key), key[-8:], plan,
                request.form.get("customer_name", "")[:120],
                request.form.get("email", "")[:254].lower(),
                max_devices, utc_now().isoformat(),
            ),
        )
    return redirect(url_for("admin", key=key))


initialize()

