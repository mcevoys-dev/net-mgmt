"""
Website and port checks for the Services page.

    chk = ServiceChecker(sites, ports, interval=300, ...)
    chk.start()          # background thread
    chk.snapshot()       # latest results for the pages

Each site is fetched over HTTP(S), following redirects. It counts as up when
the final status is below 400 (or the one given in `expect_status`) and, if
`contains` is set, the page includes that text. HTTPS certificates are
checked for days left.

Each port gets a TCP connect, and with `tls: tls` (implicit TLS, e.g. 465,
993) or `tls: starttls` (SMTP STARTTLS, e.g. 25, 587) a TLS handshake whose
certificate is checked as well. `sni` names the certificate's host when you
connect by IP address.

A check has to fail twice in a row before it is reported down, so a single
timeout does not raise an alarm. Down, recovered and certificate-expiring
changes are reported through `on_event`.
"""
import re
import smtplib
import socket
import ssl
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

HISTORY = 288          # results kept per check (24 hours at 5-minute checks)
FAILS_TO_DOWN = 2
UA = "network-dashboard/1.0 (uptime check)"


def _cert_days(der_or_dict):
    """Days until the certificate expires, from getpeercert() output."""
    not_after = der_or_dict.get("notAfter") if isinstance(der_or_dict, dict) else None
    if not not_after:
        return None
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    return round((exp - datetime.now(timezone.utc)).total_seconds() / 86400, 1)


def _tls_cert(host, port, server_name, timeout):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as s:
            return s.getpeercert()


def check_site(site, timeout):
    t0 = time.monotonic()
    out = {"ok": False, "status": None, "ms": None, "cert_days": None, "error": None, "final_url": None}
    try:
        r = requests.get(site["url"], timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": UA}, verify=site.get("verify_tls", True))
        out["ms"] = round((time.monotonic() - t0) * 1000)
        out["status"] = r.status_code
        out["final_url"] = r.url if r.url.rstrip("/") != site["url"].rstrip("/") else None
        want = site.get("expect_status")
        ok = (r.status_code == want) if want else r.status_code < 400
        if ok and site.get("contains") and site["contains"] not in r.text:
            ok, out["error"] = False, f"page does not contain “{site['contains']}”"
        elif not ok:
            out["error"] = f"HTTP {r.status_code}"
        out["ok"] = ok
    except requests.exceptions.SSLError as e:
        out["error"] = "certificate problem: " + _short(e)
    except requests.exceptions.Timeout:
        out["error"] = f"no answer within {timeout} s"
    except Exception as e:
        out["error"] = _short(e)
    u = urlparse(site["url"])
    if u.scheme == "https" and site.get("verify_tls", True):
        try:
            out["cert_days"] = _cert_days(_tls_cert(u.hostname, u.port or 443, u.hostname, timeout))
        except Exception:
            pass
    return out


def check_port(p, timeout):
    t0 = time.monotonic()
    out = {"ok": False, "ms": None, "cert_days": None, "error": None, "banner": None}
    host, port, mode = p["host"], int(p["port"]), (p.get("tls") or "none").lower()
    name = p.get("sni") or host
    try:
        if mode == "starttls":
            with smtplib.SMTP(host, port, timeout=timeout) as s:
                s.ehlo()
                out["banner"] = (s.ehlo_resp or b"").decode(errors="replace").split("\n")[0][:80] or None
                _starttls(s, name)
                out["cert_days"] = _cert_days(s.sock.getpeercert())
        elif mode == "tls":
            out["cert_days"] = _cert_days(_tls_cert(host, port, name, timeout))
        else:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        out["ok"] = True
        out["ms"] = round((time.monotonic() - t0) * 1000)
    except ssl.SSLCertVerificationError as e:
        out["error"] = "certificate problem: " + _short(e.verify_message or e)
    except (socket.timeout, TimeoutError):
        out["error"] = f"no answer within {timeout} s"
    except ConnectionRefusedError:
        out["error"] = "connection refused"
    except Exception as e:
        out["error"] = _short(e)
    return out


def _starttls(s, name):
    """STARTTLS checked against `name`, not the address connected to.

    smtplib.starttls() verifies the certificate against the host it connected
    to, which fails when that is an IP address.
    """
    code, resp = s.docmd("STARTTLS")
    if code != 220:
        raise smtplib.SMTPResponseException(code, resp)
    s.sock = ssl.create_default_context().wrap_socket(s.sock, server_hostname=name)
    s.file = None


def _short(e):
    msg = str(e)
    for marker in ("Caused by ", "] "):
        if marker in msg:
            msg = msg.split(marker)[-1]
    msg = re.sub(r"\s*\(_ssl\.c:\d+\)?", "", msg)
    return msg.strip("()'\" .")[:140]


class ServiceChecker:
    def __init__(self, sites, ports, interval=300, timeout=10, cert_warn_days=21,
                 slow_ms=3000, on_event=None):
        self.checks = ([{**s, "kind": "site", "key": "site:" + s["name"]} for s in sites]
                       + [{**p, "kind": "port", "key": "port:" + p["name"]} for p in ports])
        self.interval, self.timeout = interval, timeout
        self.cert_warn, self.slow_ms = cert_warn_days, slow_ms
        self.on_event = on_event or (lambda kind, sev, msg: None)
        self._lock = threading.Lock()
        self._state = {c["key"]: {"history": deque(maxlen=HISTORY), "fails": 0, "down": False,
                                  "since": None, "last": None, "cert_warned": False} for c in self.checks}
        self._updated = None
        self._started = False

    def start(self):
        if self._started or not self.checks:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="site-checks").start()

    def _loop(self):
        while True:
            try:
                self.run_once()
            except Exception as e:
                print(f"[Services] check round failed: {e}", flush=True)
            time.sleep(self.interval)

    def run_once(self):
        def one(c):
            return c, (check_site(c, self.timeout) if c["kind"] == "site" else check_port(c, self.timeout))
        with ThreadPoolExecutor(max_workers=min(8, len(self.checks) or 1)) as ex:
            results = list(ex.map(one, self.checks))
        now = time.time()
        for c, res in results:
            self._record(c, res, now)
        self._updated = datetime.now(timezone.utc).isoformat()

    def _record(self, c, res, now):
        what = "Website" if c["kind"] == "site" else "Service"
        with self._lock:
            st = self._state[c["key"]]
            st["history"].append((now, res["ok"], res["ms"]))
            st["last"] = {**res, "at": now}
            if res["ok"]:
                if st["down"]:
                    self.on_event("service_up", "info",
                                  f"{what} {c['name']} is back up (was down {_ago(now - st['since'])}).")
                    st["since"] = now
                st.update(fails=0, down=False)
                st["since"] = st["since"] or now
            else:
                st["fails"] += 1
                if st["fails"] == FAILS_TO_DOWN and not st["down"]:
                    st.update(down=True, since=now)
                    self.on_event("service_down", "crit", f"{what} {c['name']} is down: {res['error']}.")
            days = res.get("cert_days")
            if days is not None:
                if days <= self.cert_warn and not st["cert_warned"]:
                    st["cert_warned"] = True
                    self.on_event("cert_expiring", "warn",
                                  f"Certificate for {c['name']} expires in {int(days)} day(s).")
                elif days > self.cert_warn:
                    st["cert_warned"] = False

    def snapshot(self):
        rows = []
        now = time.time()
        with self._lock:
            for c in self.checks:
                st = self._state[c["key"]]
                hist = list(st["history"])
                last = st["last"] or {}
                ups = [h for h in hist if h[1]]
                times = [h[2] for h in ups if h[2] is not None]
                cert = last.get("cert_days")
                if st["last"] is None:
                    level = "pending"
                elif st["down"]:
                    level = "danger"
                elif not last.get("ok") or (cert is not None and cert <= self.cert_warn) \
                        or (last.get("ms") or 0) >= self.slow_ms:
                    level = "warn"
                else:
                    level = "good"
                rows.append({
                    "name": c["name"], "kind": c["kind"], "group": c.get("group") or "",
                    "target": c["url"] if c["kind"] == "site" else f"{c['host']}:{c['port']}",
                    "tls": c.get("tls") or ("https" if c.get("url", "").startswith("https") else ""),
                    "level": level, "down": st["down"], "ok": last.get("ok"),
                    "status": last.get("status"), "ms": last.get("ms"), "error": last.get("error"),
                    "final_url": last.get("final_url"), "cert_days": cert,
                    "uptime_pct": round(100 * len(ups) / len(hist), 1) if hist else None,
                    "avg_ms": round(sum(times) / len(times)) if times else None,
                    "since": (now - st["since"]) if st["since"] else None,
                    "spark": [(h[2] if h[1] else None) for h in hist[-48:]],
                    "checked": last.get("at"),
                })
        return {"updated": self._updated, "rows": rows, "cert_warn": self.cert_warn,
                "slow_ms": self.slow_ms, "interval": self.interval}


def _ago(s):
    s = int(s)
    return f"{s // 3600}h {s % 3600 // 60}m" if s >= 3600 else f"{max(1, s // 60)}m"
