"""
Proxmox Backup Server monitoring (read-only API token with the Audit role).

    mon = PBSMonitor(url, token_reader, ...)
    mon.start()          # background thread
    mon.snapshot()       # latest view for the pages

Every `poll_seconds`: server status, datastore usage and the estimated date
each datastore fills up, snapshot counts and verification results, garbage
collection, verify / prune / sync jobs and failed tasks in the last 24
hours. Changes (server unreachable, a datastore filling up, a job or a
verification failing) are reported through `on_event`.
"""
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DAY = 86400


def token_header(raw):
    """`user@realm!name:secret` (PBS style) or `user@realm!name=secret`."""
    raw = raw.strip()
    if ":" not in raw and "=" in raw:
        raw = raw.replace("=", ":", 1)
    return f"PBSAPIToken={raw}"


def _pct(used, total):
    return round(100 * used / total) if total else None


def _gb(b):
    return round((b or 0) / 1e9, 1)


def _ok(state):
    return state in (None, "", "OK", "ok") or str(state).startswith("OK")


NO_CREDS = "No credentials yet: add them under Admin → Credentials."


class PBSMonitor:
    def __init__(self, url, token_reader, verify_tls=False, poll_seconds=300, storage_warn_pct=85,
                 gc_max_age_days=8, full_warn_days=90, on_event=None):
        self.url = url.rstrip("/")
        self.token_reader = token_reader
        self.verify = verify_tls
        self.poll_seconds = poll_seconds
        self.storage_warn = storage_warn_pct
        self.gc_max_age = gc_max_age_days * DAY
        self.full_warn = full_warn_days * DAY
        self.on_event = on_event or (lambda kind, sev, msg: None)
        self._lock = threading.Lock()
        self._snap = {"updated": None, "error": None}
        self._prev = None
        self._fails = 0
        self._seen_tasks = set()
        self._started = False

    # ── HTTP ──────────────────────────────────────────────────────────────
    def get(self, path, params=None):
        r = requests.get(f"{self.url}/api2/json{path}", params=params, verify=self.verify, timeout=15,
                         headers={"Authorization": token_header(self.token_reader())})
        if r.status_code in (401, 403):
            raise PermissionError(f"HTTP {r.status_code}: token rejected or lacks the Audit role")
        r.raise_for_status()
        return r.json().get("data")

    def _try(self, path, params=None, default=None):
        """For optional endpoints (older PBS versions, missing rights)."""
        try:
            return self.get(path, params)
        except PermissionError:
            raise
        except Exception:
            return default

    # ── public ────────────────────────────────────────────────────────────
    def snapshot(self):
        with self._lock:
            return dict(self._snap)

    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="pbs").start()

    def _loop(self):
        while True:
            self.poll_once()
            time.sleep(self.poll_seconds)

    def poll_once(self):
        try:
            view = self._collect()
            if self._fails >= 2:
                self.on_event("pbs_up", "info", "Proxmox Backup Server is answering again.")
            self._fails = 0
            self._compare(view)
            with self._lock:
                self._snap = {**view, "updated": datetime.now(timezone.utc).isoformat(), "error": None}
        except FileNotFoundError:
            with self._lock:
                self._snap["error"] = NO_CREDS
        except Exception as e:
            self._fails += 1
            if self._fails == 2:
                self.on_event("pbs_down", "crit", f"Proxmox Backup Server is not answering: {str(e)[:140]}")
            with self._lock:
                self._snap["error"] = str(e)[:200]
            print(f"[PBS] poll failed: {e}", flush=True)

    # ── data ──────────────────────────────────────────────────────────────
    def _collect(self):
        now = time.time()
        version = self.get("/version") or {}
        node = self._try("/nodes/localhost/status", default={}) or {}
        usage = self.get("/status/datastore-usage") or []
        gc_jobs = {j.get("store"): j for j in (self._try("/admin/gc", default=[]) or [])}
        verify_jobs = self._try("/admin/verify", default=[]) or []
        prune_jobs = self._try("/admin/prune", default=[]) or []
        sync_jobs = self._try("/admin/sync", default=[]) or []

        stores = []
        for u in usage:
            name = u.get("store")
            if not name:
                continue
            total, used = u.get("total") or 0, u.get("used") or 0
            full = u.get("estimated-full-date")
            snaps = self._try(f"/admin/datastore/{quote(name)}/snapshots", default=None)
            conf = self._try(f"/config/datastore/{quote(name)}", default={}) or {}
            gc = gc_jobs.get(name) or {}
            if not gc:
                st = self._try(f"/admin/datastore/{quote(name)}/gc", default={}) or {}
                gc = {"last-run-state": None, "last-run-endtime": None, **st}
            stores.append({
                "name": name,
                "error": u.get("error"),
                "used_pct": _pct(used, total), "used_gb": _gb(used), "total_gb": _gb(total),
                "free_gb": _gb(u.get("avail")),
                "full_date": full if isinstance(full, (int, float)) and full > 0 else None,
                "full_in": (full - now) if isinstance(full, (int, float)) and full > now else None,
                "gc": {
                    "state": gc.get("last-run-state"),
                    "ended": gc.get("last-run-endtime"),
                    "next": gc.get("next-run"),
                    "schedule": gc.get("schedule") or conf.get("gc-schedule"),
                    "removed_gb": _gb(gc.get("removed-bytes")),
                    "pending_gb": _gb(gc.get("pending-bytes")),
                    "age": (now - gc["last-run-endtime"]) if gc.get("last-run-endtime") else None,
                },
                "snapshots": self._snap_summary(snaps, now),
                "keep": {k[5:]: v for k, v in conf.items() if k.startswith("keep-")},
                "prune_schedule": conf.get("prune-schedule"),
            })

        def job(j, kind):
            return {"id": j.get("id"), "kind": kind, "store": j.get("store"),
                    "remote": j.get("remote"), "remote_store": j.get("remote-store"),
                    "schedule": j.get("schedule"), "enabled": not j.get("disable"),
                    "state": j.get("last-run-state"), "ended": j.get("last-run-endtime"),
                    "next": j.get("next-run"),
                    "keep": {k[5:]: v for k, v in j.items() if k.startswith("keep-")}}
        jobs = ([job(j, "verify") for j in verify_jobs] + [job(j, "prune") for j in prune_jobs]
                + [job(j, "sync") for j in sync_jobs])
        for s in stores:
            s["prune_jobs"] = [j for j in jobs if j["kind"] == "prune" and j["store"] == s["name"] and j["enabled"]]
            s["verify_jobs"] = [j for j in jobs if j["kind"] == "verify" and j["store"] == s["name"] and j["enabled"]]
            s["retention"] = bool(s["prune_jobs"] or s["prune_schedule"] and s["keep"])

        tasks = self._try("/nodes/localhost/tasks",
                          {"errors": 1, "since": int(now - DAY), "limit": 50}, default=[]) or []
        failed = [{"upid": t.get("upid"), "type": t.get("worker_type"), "id": t.get("worker_id"),
                   "start": t.get("starttime"), "status": t.get("status") or ""} for t in tasks
                  if t.get("endtime") and not _ok(t.get("status")) and not str(t.get("status", "")).startswith("WARNINGS")]
        mem = node.get("memory") or {}
        root = node.get("root") or {}
        return {
            "version": version.get("version"), "release": version.get("release"),
            "node": {"cpu": round(100 * node["cpu"]) if node.get("cpu") is not None else None,
                     "mem": _pct(mem.get("used"), mem.get("total")),
                     "rootfs": _pct(root.get("used"), root.get("total")),
                     "uptime": node.get("uptime"),
                     "kversion": (node.get("current-kernel") or {}).get("release") or node.get("kversion")},
            "stores": stores, "jobs": jobs, "failed_tasks": failed,
            "warn_pct": self.storage_warn,
        }

    @staticmethod
    def _snap_summary(snaps, now):
        if snaps is None:
            return None
        groups = {}
        verified = failed = never = 0
        size = 0
        oldest = None
        for sn in snaps:
            key = f"{sn.get('backup-type')}/{sn.get('backup-id')}"
            t = sn.get("backup-time") or 0
            g = groups.setdefault(key, {"group": key, "type": sn.get("backup-type"), "id": sn.get("backup-id"),
                                        "count": 0, "newest": 0, "comment": None, "last_verify": None})
            g["count"] += 1
            if t >= g["newest"]:
                g["newest"], g["comment"] = t, sn.get("comment") or g["comment"]
                g["last_verify"] = (sn.get("verification") or {}).get("state")
            oldest = t if oldest is None or t < oldest else oldest
            state = (sn.get("verification") or {}).get("state")
            if state == "ok":
                verified += 1
            elif state == "failed":
                failed += 1
            else:
                never += 1
            size += sn.get("size") or 0
        rows = sorted(groups.values(), key=lambda g: (g["type"] or "", _num(g["id"])))
        for g in rows:
            g["age"] = now - g["newest"] if g["newest"] else None
        return {"count": len(snaps), "groups": rows, "verified": verified, "failed": failed,
                "unverified": never, "oldest_days": round((now - oldest) / DAY) if oldest else None,
                "failed_list": [f"{sn.get('backup-type')}/{sn.get('backup-id')}" for sn in snaps
                                if (sn.get("verification") or {}).get("state") == "failed"][:20]}

    # ── changes → events ──────────────────────────────────────────────────
    def _compare(self, view):
        prev, self._prev = self._prev, view
        for t in view["failed_tasks"]:
            if t["upid"] in self._seen_tasks:
                continue
            self._seen_tasks.add(t["upid"])
            if prev is not None:
                self.on_event("pbs_task_failed", "crit",
                              f"Backup server task {t['type']} {t['id'] or ''} failed: {t['status'][:120]}")
        if prev is None:
            return
        old = {s["name"]: s for s in prev["stores"]}
        for s in view["stores"]:
            o = old.get(s["name"])
            if not o:
                continue
            if (s["used_pct"] or 0) >= self.storage_warn > (o["used_pct"] or 0):
                self.on_event("pbs_storage", "warn",
                              f"Backup datastore {s['name']} is {s['used_pct']}% full ({s['free_gb']} GB free).")
            if s["gc"]["ended"] != o["gc"]["ended"] and not _ok(s["gc"]["state"]):
                self.on_event("pbs_gc_failed", "crit",
                              f"Garbage collection on datastore {s['name']} failed: {s['gc']['state']}")
            sf, of = (s["snapshots"] or {}).get("failed", 0), (o["snapshots"] or {}).get("failed", 0)
            if sf > of:
                self.on_event("pbs_verify_failed", "crit",
                              f"{sf - of} more backup(s) on {s['name']} failed verification ({sf} in total).")
        oj = {(j["kind"], j["id"]): j for j in prev["jobs"]}
        for j in view["jobs"]:
            o = oj.get((j["kind"], j["id"]))
            if o and j["ended"] != o["ended"] and not _ok(j["state"]):
                self.on_event(f"pbs_{j['kind']}_job", "crit",
                              f"Backup server {j['kind']} job {j['id']} failed: {str(j['state'])[:120]}")


def _num(v):
    try:
        return (0, int(v))
    except (TypeError, ValueError):
        return (1, str(v))
