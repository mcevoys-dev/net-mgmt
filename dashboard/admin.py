"""
Admin login and the Credentials page (Settings → Credentials).

Lets an administrator replace the API key or token for each integration from
the browser. Design rules, because the rest of the dashboard has no login:

- The page only works once an admin password is set on the server
  (`python3 app.py --set-admin-password`); only its salted hash is stored.
- Keys are write-only: the page shows whether a key is set, when it changed
  and whether its file is private, never the key itself.
- Only credentials can be changed here, never the addresses they are sent to
  (otherwise someone could point an integration at their own server and
  collect the stored key).
- A new key is tested with one read-only call before it is saved; a failing
  key is only saved if "save anyway" is ticked.
- Files are written atomically, owner-only (0600); the previous version is
  kept as <file>.previous (also 0600). Each change is logged to Events.
- Login attempts are rate-limited, every form carries a CSRF token, the
  session cookie is HttpOnly + SameSite=Strict and expires after
  admin.session_minutes.
"""
import hmac
import json
import os
import secrets
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import abort, redirect, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import settings

TIMEOUT = 15
MAX_FAILS, LOCK_SECONDS = 5, 300      # per connecting address
MAX_FAILS_ALL = 20                     # across all addresses, same window
_fails = {}   # remote address -> [timestamps of failed logins]


# ── credential definitions ───────────────────────────────────────────────────

def _read_kv(path):
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def _test_mist(cfg, f, current):
    r = requests.get(cfg.mist.api_base.rstrip("/") + "/self", timeout=TIMEOUT,
                     headers={"Authorization": f"Token {f['token']}"})
    return r.ok, f"Mist answered HTTP {r.status_code}" + ("" if r.ok else " (token rejected)")


def _test_central(cfg, f, current):
    base = cfg.central.api_base.rstrip("/")
    r = requests.get(base + "/monitoring/v1/switches", params={"limit": 1}, timeout=TIMEOUT,
                     headers={"Authorization": f"Bearer {f['access_token']}"})
    if r.ok:
        return True, "Central accepted the access token"
    if r.status_code == 401 and f.get("refresh_token") and f.get("client_id") and f.get("client_secret"):
        rr = requests.post(base + "/oauth2/token", timeout=TIMEOUT, params={
            "client_id": f["client_id"], "client_secret": f["client_secret"],
            "grant_type": "refresh_token", "refresh_token": f["refresh_token"]})
        if rr.ok:
            tok = rr.json()
            f["access_token"] = tok["access_token"]
            f["refresh_token"] = tok.get("refresh_token", f["refresh_token"])
            return True, "Access token had expired; refreshed it with the refresh token"
        return False, f"Access token rejected and refresh failed (HTTP {rr.status_code})"
    return False, f"Central answered HTTP {r.status_code}"


def _test_opnsense(cfg, f, current):
    r = requests.get(cfg.opnsense.url.rstrip("/") + "/api/routes/gateway/status", timeout=TIMEOUT,
                     auth=(f["key"], f["secret"]), verify=cfg.opnsense.verify_tls)
    return r.ok, f"OPNsense answered HTTP {r.status_code}" + ("" if r.ok else " (key/secret rejected)")


def _test_ntopng(cfg, f, current):
    r = requests.get(cfg.ntopng.url.rstrip("/") + "/lua/rest/v2/get/ntopng/interfaces.lua",
                     timeout=TIMEOUT, allow_redirects=False,
                     headers={"Authorization": f"Token {f['token']}"})
    ok = r.ok and "json" in r.headers.get("content-type", "")
    return ok, "ntopng accepted the token" if ok else f"ntopng answered HTTP {r.status_code} (token rejected)"


def _test_ha(cfg, f, current):
    r = requests.get(cfg.home_assistant.url.rstrip("/") + "/api/", timeout=TIMEOUT,
                     headers={"Authorization": f"Bearer {f['token']}"})
    return r.ok, f"Home Assistant answered HTTP {r.status_code}"


def _test_anthropic(cfg, f, current):
    r = requests.get("https://api.anthropic.com/v1/models", timeout=TIMEOUT,
                     headers={"x-api-key": f["key"], "anthropic-version": "2023-06-01"})
    return r.ok, "Claude API accepted the key" if r.ok else f"Claude API answered HTTP {r.status_code}"


def specs(cfg):
    """One entry per integration: fields, how to build the file, how to test."""
    return [
        {"id": "mist", "name": "Juniper Mist", "on": cfg.mist.enabled, "file": cfg.mist.token_file,
         "fields": [("token", "API token")], "test": _test_mist,
         "render": lambda f: f["token"] + "\n", "load": lambda p: {}},
        {"id": "central", "name": "Aruba Central", "on": cfg.central.enabled, "file": cfg.central.token_file,
         "fields": [("access_token", "Access token"), ("refresh_token", "Refresh token"),
                    ("client_id", "Client ID"), ("client_secret", "Client secret")],
         "partial": True, "test": _test_central,
         "render": lambda f: json.dumps({**f, "created_at": int(time.time() * 1000)}, indent=2) + "\n",
         "load": lambda p: json.loads(p.read_text()) if p.exists() else {}},
        {"id": "opnsense", "name": "OPNsense", "on": cfg.opnsense.enabled, "file": cfg.opnsense.key_file,
         "fields": [("key", "API key"), ("secret", "API secret")], "test": _test_opnsense,
         "render": lambda f: f"key={f['key']}\nsecret={f['secret']}\n", "load": _read_kv},
        {"id": "ntopng", "name": "ntopng", "on": cfg.ntopng.enabled, "file": cfg.ntopng.token_file,
         "fields": [("token", "API token")], "test": _test_ntopng,
         "render": lambda f: f["token"] + "\n", "load": lambda p: {}},
        {"id": "home_assistant", "name": "Home Assistant", "on": cfg.home_assistant.enabled,
         "file": cfg.home_assistant.token_file, "fields": [("token", "Long-lived access token")],
         "test": _test_ha, "render": lambda f: f["token"] + "\n", "load": lambda p: {}},
        {"id": "assistant", "name": "Claude (Ask panel)", "on": cfg.assistant.enabled,
         "file": cfg.assistant.key_file, "fields": [("key", "API key")], "test": _test_anthropic,
         "render": lambda f: f["key"] + "\n", "load": lambda p: {}},
    ]


def file_status(path):
    if not path.exists():
        return {"set": False}
    st = path.stat()
    return {"set": st.st_size > 0,
            "changed": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "private": not (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)),
            "mode": oct(st.st_mode & 0o777)}


def write_private(path, text):
    """Atomic owner-only write; keeps the previous file as <name>.previous."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        prev = path.with_name(path.name + ".previous")
        fd = os.open(prev, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(path.read_text())
        os.chmod(prev, 0o600)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ── admin password ───────────────────────────────────────────────────────────

def password_path(cfg):
    return settings.secret_path(cfg, cfg.admin.password_file)


def set_password(cfg):
    """CLI: prompt for a new admin password and store its hash."""
    import getpass
    pw = getpass.getpass("New admin password (12+ characters): ")
    if len(pw) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if getpass.getpass("Repeat it: ") != pw:
        raise SystemExit("Passwords did not match.")
    write_private(password_path(cfg), generate_password_hash(pw) + "\n")
    print(f"Admin password set ({password_path(cfg)}). Settings → Credentials is now available.")


def _secret_key(cfg):
    p = settings.data_path(cfg, ".flask_secret")
    if not p.exists():
        write_private(p, secrets.token_hex(32))
    return p.read_text().strip()


# ── Flask wiring ─────────────────────────────────────────────────────────────

def install(app, g):
    cfg = g["CFG"]
    page = g["_ui"]._page
    app.secret_key = _secret_key(cfg)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_NAME="netdash_admin")
    LOGIN = page(LOGIN_HTML)
    CREDS = page(CREDS_HTML)

    def enabled():
        return password_path(cfg).exists()

    def logged_in():
        t = session.get("admin_at")
        return bool(t) and time.time() - t < cfg.admin.session_minutes * 60

    def client_ip():
        # For the Events message only; a client can set this header itself.
        return request.headers.get("CF-Connecting-IP") or request.remote_addr or "?"

    def csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def check_csrf():
        if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "-")):
            abort(400, "Form expired; reload the page and try again.")

    def render(tpl, **kw):
        return render_template_string(tpl, title="Credentials", active="credentials",
                                      last_updated=g["last_updated_str"](), csrf=csrf(),
                                      admin_on=enabled(), **kw)

    @app.route("/settings/credentials", methods=["GET"])
    def credentials_page():
        if not enabled() or not logged_in():
            return render(LOGIN, error=None)
        session["admin_at"] = time.time()          # sliding timeout
        rows = []
        for s in specs(cfg):
            p = settings.secret_path(cfg, s["file"])
            rows.append({**s, "path": str(p), "status": file_status(p)})
        return render(CREDS, rows=rows, msg=session.pop("msg", None))

    @app.route("/settings/login", methods=["POST"])
    def admin_login():
        check_csrf()
        ip = request.remote_addr or "?"        # the real connection, not a header
        now = time.time()
        recent = [t for t in _fails.get(ip, []) if now - t < LOCK_SECONDS]
        total = sum(1 for ts in _fails.values() for t in ts if now - t < LOCK_SECONDS)
        if len(recent) >= MAX_FAILS or total >= MAX_FAILS_ALL:
            return render(LOGIN, error="Too many attempts. Wait five minutes and try again."), 429
        stored = password_path(cfg).read_text().strip() if enabled() else ""
        if stored and check_password_hash(stored, request.form.get("password", "")):
            _fails.pop(ip, None)
            session.clear()
            session["admin_at"] = now
            return redirect("/settings/credentials")
        _fails[ip] = recent + [now]
        time.sleep(1)
        return render(LOGIN, error="Wrong password."), 401

    @app.route("/settings/logout", methods=["POST"])
    def admin_logout():
        check_csrf()
        session.clear()
        return redirect("/settings/credentials")

    @app.route("/settings/credentials/<cid>", methods=["POST"])
    def credentials_save(cid):
        if not enabled() or not logged_in():
            abort(403)
        check_csrf()
        spec = next((s for s in specs(cfg) if s["id"] == cid), None)
        if not spec:
            abort(404)
        path = settings.secret_path(cfg, spec["file"])
        current = spec["load"](path) if spec.get("partial") or spec["id"] == "opnsense" else {}
        fields = {}
        for name, label in spec["fields"]:
            v = (request.form.get(name) or "").strip()
            if not v and spec.get("partial"):
                v = str(current.get(name, ""))
            if not v:
                session["msg"] = ("danger", f"{spec['name']}: {label} is required.")
                return redirect("/settings/credentials#" + cid)
            if any(ch in v for ch in "\r\n"):
                session["msg"] = ("danger", f"{spec['name']}: {label} must be one line.")
                return redirect("/settings/credentials#" + cid)
            fields[name] = v
        if spec.get("partial"):
            fields = {**{k: v for k, v in current.items() if k not in fields}, **fields}
        force = request.form.get("force") == "1"
        try:
            ok, detail = spec["test"](cfg, fields, current)
        except Exception as e:
            ok, detail = False, f"test call failed: {str(e)[:150]}"
        if not ok and not force:
            session["msg"] = ("danger", f"{spec['name']}: not saved, the test failed ({detail}). "
                                        "Tick \"save anyway\" to store it regardless.")
            return redirect("/settings/credentials#" + cid)
        write_private(path, spec["render"](fields))
        session["admin_at"] = time.time()
        note = "" if ok else " (saved without a passing test)"
        g["_event_log"].add("settings", "info", f"{spec['name']} credential updated from {client_ip()}{note}")
        session["msg"] = ("good" if ok else "warn",
                          f"{spec['name']}: saved. {detail}. It is used from the next poll; no restart needed.")
        return redirect("/settings/credentials#" + cid)


LOGIN_HTML = r"""
{% call page_head('Credentials', 'API keys and tokens for each integration') %}{% endcall %}
<section class="card" style="max-width:520px">
  {% if not admin_on %}
  <div class="card-h"><div><div class="card-t">{{ icon('fw') }} Not set up yet</div></div></div>
  <div class="card-b">
    <p class="note" style="font-size:.86rem">This page changes the keys the dashboard uses, so it needs an admin password.
    Set one on the dashboard's server, then reload this page:</p>
    <pre class="mono" style="background:var(--surface2);padding:.7rem;border-radius:8px;margin-top:.6rem;white-space:pre-wrap">python3 app.py --set-admin-password</pre>
  </div>
  {% else %}
  <div class="card-h"><div><div class="card-t">{{ icon('fw') }} Admin sign-in</div><div class="card-sub">Sessions end after 15 minutes without activity</div></div></div>
  <form class="card-b" method="post" action="/settings/login" style="display:flex;flex-direction:column;gap:.7rem">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label class="tbl-filter" style="max-width:none">{{ icon('fw') }}<input type="password" name="password" placeholder="Admin password" autocomplete="current-password" autofocus required></label>
    {% if error %}<div class="pill pill-danger" style="padding:.4rem .6rem;font-size:.8rem">{{ error }}</div>{% endif %}
    <button class="btn btn-primary" type="submit" style="align-self:flex-start">Sign in</button>
  </form>
  {% endif %}
</section>
"""

CREDS_HTML = r"""
{% call page_head('Credentials', 'Replace the API key or token for an integration. Keys are never shown, only replaced.') %}
  <form method="post" action="/settings/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="btn" type="submit">Sign out</button></form>
{% endcall %}
{% if msg %}
<div class="info-banner" style="margin:0 0 1rem;{{ 'background:var(--danger-soft);color:var(--danger)' if msg[0] == 'danger' else ('background:var(--warn-soft)' if msg[0] == 'warn' else 'background:var(--good-soft)') }}">{{ icon('info') }}<span>{{ msg[1] }}</span></div>
{% endif %}
<div class="grid">
  {% for r in rows %}
  <section class="card c6" id="{{ r.id }}">
    <div class="card-h">
      <div><div class="card-t">{{ icon('fw') }} {{ r.name }}{% if not r.on %} <span class="pill pill-muted">not enabled</span>{% endif %}</div>
        <div class="card-sub mono" style="font-size:.72rem">{{ r.path }}</div></div>
      <div class="card-x">
        {% if r.status.set %}<span class="status"><i class="dot good"></i>set</span>{% else %}<span class="status"><i class="dot danger"></i>missing</span>{% endif %}
      </div>
    </div>
    <div class="card-b" style="padding-top:.3rem">
      {% if r.status.set %}
      <div class="note">Last changed {{ r.status.changed | local_time('%d %b %Y %H:%M') }}
        {% if not r.status.private %} · <span class="warn" style="font-weight:600">readable by other users ({{ r.status.mode }}); saving here makes it private</span>{% endif %}</div>
      {% endif %}
      <form method="post" action="/settings/credentials/{{ r.id }}" style="display:flex;flex-direction:column;gap:.55rem;margin-top:.7rem" autocomplete="off">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        {% for name, label in r.fields %}
        <label class="tbl-filter" style="max-width:none">{{ icon('fw') }}<input type="password" name="{{ name }}" placeholder="{{ label }}{{ ' (blank = keep current)' if r.partial }}" autocomplete="new-password" spellcheck="false"></label>
        {% endfor %}
        <div style="display:flex;align-items:center;gap:.8rem;flex-wrap:wrap">
          <button class="btn btn-primary btn-sm" type="submit">Test and save</button>
          <label class="note" style="display:inline-flex;gap:.35rem;align-items:center"><input type="checkbox" name="force" value="1"> save anyway if the test fails</label>
        </div>
      </form>
    </div>
  </section>
  {% endfor %}
</div>
<p class="note" style="margin-top:.5rem">Each new key is tested with one read-only call before it is saved. Files are written owner-only;
the previous version is kept next to it as <span class="mono">.previous</span>. Changes are logged on the Events page (without the key).
Addresses (URLs) are changed in config.yaml on the server, not here.</p>
"""
