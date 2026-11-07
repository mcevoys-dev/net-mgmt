"""
Mail server monitoring: Stalwart health and Listmonk newsletter sends.

    mon = MailMonitor(stalwart_url, listmonk_url, listmonk_cred_reader, ...)
    mon.start()          # background thread
    mon.snapshot()       # latest view for the pages

Stalwart: its /healthz/live and /healthz/ready endpoints, which need no
credentials. Pair this with port checks (SMTP, submission, IMAP) on the
Services page.

Listmonk (read-only API user): recent campaigns and how many were sent, list
sizes, bounces in the last 7 days, and for each list in `watch_lists`, how
long since it last got a finished campaign. A watched list that goes longer
than `max_gap_hours` without one is flagged, which catches a newsletter job
that silently stopped sending.
"""
import threading
import time
from datetime import datetime, timezone

import requests

DAY = 86400
BAD_STATES = {"cancelled", "paused"}


def _ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class MailMonitor:
    def __init__(self, stalwart_url, listmonk_url, cred_reader, watch_lists=(), max_gap_hours=60,
                 poll_seconds=300, on_event=None):
        self.stalwart = (stalwart_url or "").rstrip("/")
        self.listmonk = (listmonk_url or "").rstrip("/")
        self.cred_reader = cred_reader            # callable -> (api_user, token) or None
        self.watch = list(watch_lists or [])
        self.max_gap = max_gap_hours * 3600
        self.poll_seconds = poll_seconds
        self.on_event = on_event or (lambda kind, sev, msg: None)
        self._lock = threading.Lock()
        self._snap = {"updated": None}
        self._prev = None
        self._started = False

    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="mail").start()

    def _loop(self):
        while True:
            self.poll_once()
            time.sleep(self.poll_seconds)

    def snapshot(self):
        with self._lock:
            return dict(self._snap)

    def poll_once(self):
        view = {"stalwart": self._stalwart() if self.stalwart else None,
                "listmonk": self._listmonk() if self.listmonk else None}
        try:
            self._compare(view)
        except Exception as e:
            print(f"[Mail] compare failed: {e}", flush=True)
        with self._lock:
            self._snap = {**view, "updated": datetime.now(timezone.utc).isoformat()}

    # ── Stalwart ──────────────────────────────────────────────────────────
    def _stalwart(self):
        out = {"url": self.stalwart, "live": None, "ready": None, "error": None, "ms": None}
        try:
            t0 = time.monotonic()
            for k in ("live", "ready"):
                r = requests.get(f"{self.stalwart}/healthz/{k}", timeout=8)
                out[k] = r.status_code == 200
            out["ms"] = round((time.monotonic() - t0) * 1000)
        except Exception as e:
            out["error"] = str(e)[:140]
        out["ok"] = bool(out["live"] and out["ready"])
        return out

    # ── Listmonk ──────────────────────────────────────────────────────────
    def get(self, path, params=None):
        user, token = self.cred_reader()
        r = requests.get(f"{self.listmonk}/api{path}", params=params, timeout=15,
                         headers={"Authorization": f"token {user}:{token}"})
        if r.status_code in (401, 403):
            raise PermissionError(f"Listmonk answered HTTP {r.status_code}: API user rejected or lacks a permission")
        r.raise_for_status()
        return r.json().get("data")

    def _listmonk(self):
        now = time.time()
        out = {"url": self.listmonk, "error": None, "campaigns": [], "lists": [], "watched": [],
               "bounces_7d": None, "bounce_types": {}}
        try:
            camps = (self.get("/campaigns", {"page": 1, "per_page": 60, "order_by": "created_at",
                                             "order": "desc"}) or {}).get("results") or []
            lists = (self.get("/lists", {"page": 1, "per_page": "all"}) or {}).get("results") or []
        except FileNotFoundError:
            out["error"] = "No credentials yet: add them under Admin → Credentials."
            out["no_creds"] = True
            return out
        except Exception as e:
            out["error"] = str(e)[:200]
            return out
        for c in camps:
            started = _ts(c.get("started_at"))
            ended = _ts(c.get("updated_at")) if c.get("status") == "finished" else None
            out["campaigns"].append({
                "id": c.get("id"), "name": c.get("name") or "", "subject": c.get("subject") or "",
                "status": c.get("status") or "", "lists": [x.get("name") for x in c.get("lists") or []],
                "sent": c.get("sent") or 0, "to_send": c.get("to_send") or 0,
                "views": c.get("views"), "clicks": c.get("clicks"), "bounces": c.get("bounces"),
                "created": _ts(c.get("created_at")), "started": started, "ended": ended,
            })
        out["lists"] = [{"id": x.get("id"), "name": x.get("name"),
                         "subscribers": x.get("subscriber_count"),
                         "statuses": x.get("subscriber_statuses") or {}} for x in lists]
        for name in self.watch:
            last = next((c for c in out["campaigns"] if name in c["lists"] and c["status"] == "finished"), None)
            recent_bad = next((c for c in out["campaigns"] if name in c["lists"]
                               and c["status"] in BAD_STATES and (c["created"] or 0) > now - 2 * DAY), None)
            known = any(x["name"] == name for x in out["lists"])
            age = (now - (last["ended"] or last["started"] or last["created"])) if last else None
            short = last and last["to_send"] and last["sent"] < last["to_send"]
            level = ("danger" if not known or age is None or age > 2 * self.max_gap or recent_bad
                     else "warn" if age > self.max_gap or short else "good")
            out["watched"].append({"name": name, "known": known, "age": age, "level": level,
                                   "last": last, "short": bool(short), "problem": recent_bad,
                                   "subscribers": next((x["subscribers"] for x in out["lists"] if x["name"] == name), None)})
        try:
            b = self.get("/bounces", {"page": 1, "per_page": 100, "order_by": "created_at", "order": "desc"}) or {}
            recent = [x for x in b.get("results") or [] if (_ts(x.get("created_at")) or 0) > now - 7 * DAY]
            out["bounces_7d"] = len(recent)
            for x in recent:
                out["bounce_types"][x.get("type") or "?"] = out["bounce_types"].get(x.get("type") or "?", 0) + 1
        except Exception:
            pass                     # bounces need their own permission; optional
        return out

    # ── changes → events ──────────────────────────────────────────────────
    def _compare(self, view):
        prev, self._prev = self._prev, view
        if prev is None:
            return
        s, o = view["stalwart"], prev["stalwart"]
        if s and o and s["ok"] != o["ok"]:
            if s["ok"]:
                self.on_event("mail_up", "info", "Mail server (Stalwart) reports healthy again.")
            else:
                self.on_event("mail_down", "crit", "Mail server (Stalwart) health check failing: "
                              + (s["error"] or f"live={s['live']} ready={s['ready']}"))
        lm, lo = view["listmonk"], prev["listmonk"]
        if not lm or not lo:
            return
        if lm["error"] and not lo["error"] and not lm.get("no_creds"):
            self.on_event("listmonk_down", "crit", f"Listmonk is not answering: {lm['error'][:140]}")
        elif lo["error"] and not lm["error"]:
            self.on_event("listmonk_up", "info", "Listmonk is answering again.")
        ow = {w["name"]: w for w in lo["watched"]}
        for w in lm["watched"]:
            o = ow.get(w["name"])
            if o and o["level"] == "good" and w["level"] != "good":
                why = ("no finished send in " + _hours(w["age"])) if w["age"] else "no finished send found"
                if w["problem"]:
                    why = f"campaign “{w['problem']['name']}” is {w['problem']['status']}"
                elif w["short"]:
                    why = f"last send reached {w['last']['sent']} of {w['last']['to_send']}"
                self.on_event("newsletter_late", "warn", f"Newsletter list {w['name']}: {why}.")
            elif o and o["level"] != "good" and w["level"] == "good":
                self.on_event("newsletter_ok", "info", f"Newsletter list {w['name']} sent again.")
        oc = {c["id"]: c for c in lo["campaigns"]}
        for c in lm["campaigns"]:
            p = oc.get(c["id"])
            if p and p["status"] != c["status"] and c["status"] in BAD_STATES:
                self.on_event("campaign", "warn", f"Listmonk campaign “{c['name']}” is now {c['status']}.")


def _hours(s):
    h = int(s // 3600)
    return f"{h // 24}d {h % 24}h" if h >= 24 else f"{h}h"
