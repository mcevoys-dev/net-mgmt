"""
Proxmox VE cluster monitoring (read-only API token, PVEAuditor role).

    mon = ProxmoxMonitor(hosts, token, ...)
    mon.start()          # background thread
    mon.snapshot()       # latest view for the pages

Polls every `poll_seconds`: cluster status and quorum, nodes, guests, storage,
HA, replication, backup jobs and recent failed tasks. Backup snapshots on
Proxmox Backup Server storage are listed every `backup_scan_seconds`.

Requests go to the first host in `hosts` that answers, so the page keeps
working while any one node is down. Changes between polls (a node going
offline or restarting, quorum lost, HA moving a guest, replication or task
failures, storage filling up) are reported through `on_event`.
"""
import re
import threading
import time
from datetime import datetime, timezone

_START = re.compile(r"Starting Backup of VM (\d+)")
_ARCHIVE = re.compile(r"archive '(?:vm|ct)/(\d+)/(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)'")
_FINISH = re.compile(r"Finished Backup of VM (\d+) \(([\d:]+)\)")
_FAIL = re.compile(r"ERROR: Backup of VM (\d+) failed - (.*)")


def parse_vzdump_log(lines, task_start):
    """{vmid: {"ok", "time", "duration", "error"}} from a vzdump task log.

    Time is the archive's UTC timestamp when the log names one, else the
    task's start time. Read-only tokens can read task logs even where
    Proxmox hides backup files, so this is the fallback for backup ages.
    """
    out = {}
    for line in lines:
        m = _START.search(line)
        if m:
            out.setdefault(int(m.group(1)), {"ok": None, "time": task_start, "duration": None, "error": None})
            continue
        m = _ARCHIVE.search(line)
        if m:
            ts = datetime.strptime(m.group(2), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            out.setdefault(int(m.group(1)), {"ok": None, "time": ts, "duration": None, "error": None})["time"] = ts
            continue
        m = _FINISH.search(line)
        if m:
            out.setdefault(int(m.group(1)), {"time": task_start, "error": None}).update(ok=True, duration=m.group(2))
            continue
        m = _FAIL.search(line)
        if m:
            out.setdefault(int(m.group(1)), {"time": task_start, "duration": None}).update(ok=False, error=m.group(2)[:160])
    return out

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _pct(used, total):
    return round(100 * used / total) if total else None


def _eff(s):
    """The fill level that matters: data actually written for ZFS, else Proxmox's used %."""
    return s.get("written") if s.get("written") is not None else s.get("used")


class ProxmoxMonitor:
    def __init__(self, hosts, token_reader, verify_tls=False, poll_seconds=60,
                 backup_scan_seconds=900, backup_max_age_hours=26, storage_warn_pct=85,
                 on_event=None):
        self.hosts = [h.rstrip("/") for h in hosts]
        self.token_reader = token_reader          # callable -> "user@realm!id=secret"
        self.verify = verify_tls
        self.poll_seconds, self.backup_scan_seconds = poll_seconds, backup_scan_seconds
        self.backup_max_age = backup_max_age_hours * 3600
        self.storage_warn = storage_warn_pct
        self.on_event = on_event or (lambda kind, sev, msg: None)
        self._lock = threading.Lock()
        self._snap = {"updated": None, "error": None, "host": None}
        self._prev = None
        self._seen_tasks = set()
        self._backups = {"latest": {}, "orphans": [], "count": 0, "unverified": 0, "scanned": None}
        self._last_scan = 0.0
        self._log_cache = {}      # upid -> parsed vzdump log (finished logs never change)
        self._started = False

    # ── HTTP ──────────────────────────────────────────────────────────────
    def get(self, path, params=None):
        headers = {"Authorization": f"PVEAPIToken={self.token_reader()}"}
        last = None
        for host in self.hosts:
            try:
                r = requests.get(f"{host}/api2/json{path}", params=params, headers=headers,
                                 verify=self.verify, timeout=10)
                if r.status_code in (401, 403):
                    raise PermissionError(f"HTTP {r.status_code} from {host}: token rejected or lacks rights")
                r.raise_for_status()
                self._snap["host"] = host
                return r.json().get("data")
            except PermissionError:
                raise
            except Exception as e:
                last = e
        raise ConnectionError(f"no Proxmox host answered ({last})")

    # ── public ────────────────────────────────────────────────────────────
    def snapshot(self):
        with self._lock:
            return dict(self._snap)

    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="proxmox").start()

    def _loop(self):
        while True:
            self.poll_once()
            time.sleep(self.poll_seconds)

    def poll_once(self):
        try:
            if time.time() - self._last_scan >= self.backup_scan_seconds:
                self._scan_backups()
            view = self._collect()
            self._compare(view)
            with self._lock:
                self._snap = {**view, "updated": datetime.now(timezone.utc).isoformat(),
                              "error": None, "host": self._snap.get("host")}
        except Exception as e:
            with self._lock:
                self._snap["error"] = str(e)[:200]
            print(f"[Proxmox] poll failed: {e}", flush=True)

    # ── data ──────────────────────────────────────────────────────────────
    def _collect(self):
        now = time.time()
        version = self.get("/version") or {}
        status = self.get("/cluster/status") or []
        resources = self.get("/cluster/resources") or []
        ha = self.get("/cluster/ha/status/current") or []

        cluster = next((x for x in status if x.get("type") == "cluster"), {})
        ips = {x["name"]: x.get("ip") for x in status if x.get("type") == "node"}
        nodes = []
        for r in sorted((x for x in resources if x.get("type") == "node"), key=lambda x: x["node"]):
            online = r.get("status") == "online"
            nodes.append({
                "name": r["node"], "ip": ips.get(r["node"]), "online": online,
                "uptime": r.get("uptime") if online else None,
                "cpu": round(100 * (r.get("cpu") or 0), 1) if online else None,
                "mem": _pct(r.get("mem"), r.get("maxmem")) if online else None,
                "mem_total_gb": round((r.get("maxmem") or 0) / 2 ** 30, 1),
                "cores": r.get("maxcpu"),
            })
        online_names = [n["name"] for n in nodes if n["online"]]
        for n in nodes:
            if n["online"]:
                try:
                    st = self.get(f"/nodes/{n['name']}/status") or {}
                    n["load"] = st.get("loadavg")
                    n["kernel"] = (st.get("current-kernel") or {}).get("release") or st.get("kversion", "")
                    n["pve"] = (st.get("pveversion") or "").split("/")[1] if "/" in (st.get("pveversion") or "") else ""
                    n["cpu_model"] = (st.get("cpuinfo") or {}).get("model")
                    n["rootfs"] = _pct((st.get("rootfs") or {}).get("used"), (st.get("rootfs") or {}).get("total"))
                except Exception:
                    pass

        ha_services = {x["sid"]: x for x in ha if x.get("type") == "service"}
        guests = []
        for r in resources:
            if r.get("type") not in ("qemu", "lxc") or r.get("template"):
                continue
            sid = f"{'vm' if r['type'] == 'qemu' else 'ct'}:{r['vmid']}"
            hs = ha_services.get(sid)
            guests.append({
                "vmid": r["vmid"], "name": r.get("name") or str(r["vmid"]),
                "kind": "VM" if r["type"] == "qemu" else "CT", "node": r.get("node"),
                "status": r.get("status"), "uptime": r.get("uptime") or 0,
                "cpu": round(100 * (r.get("cpu") or 0), 1),
                # qemu can report a little over its configured memory (overhead)
                "mem": min(_pct(r.get("mem"), r.get("maxmem")) or 0, 100) if r.get("maxmem") else None,
                "mem_gb": round((r.get("maxmem") or 0) / 2 ** 30, 1), "cores": r.get("maxcpu"),
                "ha": hs.get("state") if hs else None, "sid": sid,
            })
        guests.sort(key=lambda g: g["vmid"])

        storage = []
        for r in resources:
            if r.get("type") != "storage":
                continue
            storage.append({
                "node": r.get("node"), "name": r.get("storage"), "type": r.get("plugintype"),
                "status": r.get("status"), "shared": bool(r.get("shared")),
                "used": _pct(r.get("disk"), r.get("maxdisk")),
                "free_gb": round(((r.get("maxdisk") or 0) - (r.get("disk") or 0)) / 2 ** 30),
                "total_gb": round((r.get("maxdisk") or 0) / 2 ** 30),
            })
        self._zfs_written(storage, online_names)
        # shared storage is reported once per node; keep one row
        seen, uniq = set(), []
        for s in sorted(storage, key=lambda s: (s["shared"], s["name"], s["node"])):
            key = s["name"] if s["shared"] else (s["name"], s["node"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(s)

        repl = []
        for n in online_names:
            try:
                for j in self.get(f"/nodes/{n}/replication") or []:
                    sched = j.get("schedule") or "*/15"
                    try:
                        interval = int(sched.split("/")[1]) * 60 if sched.startswith("*/") else 3600
                    except (IndexError, ValueError):
                        interval = 3600
                    age = now - j["last_sync"] if j.get("last_sync") else None
                    repl.append({
                        "id": j.get("id"), "guest": j.get("guest"), "name": j.get("comment") or str(j.get("guest")),
                        "source": j.get("source"), "target": j.get("target"), "schedule": sched,
                        "last_sync": j.get("last_sync"), "age": age, "fail_count": j.get("fail_count") or 0,
                        "error": j.get("error"), "duration": j.get("duration"),
                        "late": age is None or age > 2 * interval + 300,
                    })
            except Exception:
                pass
        repl.sort(key=lambda j: j["guest"] or 0)

        jobs = self.get("/cluster/backup") or []
        not_backed = self.get("/cluster/backup-info/not-backed-up") or []
        runs, from_logs = [], {}
        for n in online_names:
            try:
                node_tasks = self.get(f"/nodes/{n}/tasks", {"typefilter": "vzdump", "limit": 3}) or []
            except Exception:
                continue
            for i, t in enumerate(node_tasks):
                if i == 0:
                    runs.append({"node": n, "start": t.get("starttime"), "end": t.get("endtime"),
                                 "status": t.get("status"), "ok": t.get("status") == "OK"})
                upid = t.get("upid")
                if not upid or not t.get("endtime"):
                    continue                      # still running: read it once it has finished
                if upid not in self._log_cache:
                    try:
                        log = self.get(f"/nodes/{n}/tasks/{upid}/log", {"limit": 10000}) or []
                        self._log_cache[upid] = parse_vzdump_log([x.get("t", "") for x in log], t.get("starttime"))
                    except Exception:
                        continue
                for vmid, r in self._log_cache[upid].items():
                    if vmid not in from_logs or (r["time"] or 0) > (from_logs[vmid]["time"] or 0):
                        from_logs[vmid] = r
        if len(self._log_cache) > 200:
            self._log_cache = dict(list(self._log_cache.items())[-100:])

        tasks = self.get("/cluster/tasks") or []
        recent = [t for t in tasks if t.get("status") and t.get("status") != "OK"
                  and now - (t.get("endtime") or t.get("starttime") or 0) < 86400]
        # "WARNINGS: n" means the task finished but logged warnings; not a failure
        failed = sorted((t for t in recent if not str(t.get("status")).startswith("WARNINGS")),
                        key=lambda t: -(t.get("starttime") or 0))
        warned = [t for t in recent if str(t.get("status")).startswith("WARNINGS")]

        bk = self._backups
        guest_ids = {g["vmid"] for g in guests}
        for g in guests:
            seen = bk["latest"].get(g["vmid"])
            logged = from_logs.get(g["vmid"])
            log_ok = logged["time"] if logged and logged["ok"] else None
            ts = max(t for t in (seen, log_ok, 0) if t is not None) or None
            g["backup_age"] = (now - ts) if ts else None
            g["backup_source"] = "file" if ts and ts == seen else ("task log" if ts else None)
            g["backup_failed"] = bool(logged and logged["ok"] is False and (logged["time"] or 0) >= (ts or 0))
            g["backup_error"] = logged.get("error") if g["backup_failed"] else None
            g["backup_stale"] = ts is None or now - ts > self.backup_max_age
            r = next((j for j in repl if j["guest"] == g["vmid"]), None)
            g["repl"] = r
        orphans = [o for o in bk["orphans"] if o["vmid"] not in guest_ids]

        quorum = next((x for x in ha if x.get("type") == "quorum"), {})
        master = next((x for x in ha if x.get("type") == "master"), {})
        fencing = next((x for x in ha if x.get("type") == "fencing"), {})
        lrms = [{"node": x.get("node"), "status": x.get("status", "")} for x in ha if x.get("type") == "lrm"]
        return {
            "version": version.get("version"), "release": version.get("release"),
            "cluster": {"name": cluster.get("name"), "quorate": bool(cluster.get("quorate")),
                        "nodes": cluster.get("nodes"), "online": len(online_names)},
            "nodes": nodes, "guests": guests, "storage": uniq, "replication": repl,
            "ha": {"quorum": quorum.get("status"), "master": master.get("node"),
                   "fencing": fencing.get("armed-state") or fencing.get("status"),
                   "lrms": lrms,
                   "services": [{"sid": s, "node": v.get("node"), "state": v.get("state"),
                                 "request": v.get("request_state")} for s, v in sorted(ha_services.items())]},
            "backup": {"jobs": [{"id": j.get("id"), "schedule": j.get("schedule"), "storage": j.get("storage"),
                                 "enabled": bool(j.get("enabled", 1)), "next": j.get("next-run"),
                                 "mode": j.get("mode"), "all": bool(j.get("all"))} for j in jobs],
                       "not_backed_up": [{"vmid": x.get("vmid"), "name": x.get("name"), "type": x.get("type")}
                                         for x in not_backed],
                       "runs": runs, "orphans": orphans, "count": bk["count"],
                       "files_visible": bk["count"] > 0, "from_logs": len(from_logs),
                       "unverified": bk["unverified"], "scanned": bk["scanned"]},
            "failed_tasks": [{"node": t.get("node"), "type": t.get("type"), "id": t.get("id"),
                              "status": t.get("status"), "start": t.get("starttime"), "user": t.get("user"),
                              "upid": t.get("upid")} for t in failed[:20]],
            "warned_tasks": len(warned),
        }

    def _scan_backups(self):
        """Newest backup per guest on every Proxmox Backup Server / dir storage."""
        resources = self.get("/cluster/resources", {"type": "storage"}) or []
        shared_done, latest, count, unverified, seen = set(), {}, 0, 0, set()
        for s in resources:
            if s.get("status") != "available" or s.get("plugintype") not in ("pbs", "dir", "nfs", "cifs"):
                continue
            if s.get("shared") and s["storage"] in shared_done:
                continue
            try:
                items = self.get(f"/nodes/{s['node']}/storage/{s['storage']}/content", {"content": "backup"}) or []
            except Exception:
                continue
            if s.get("shared"):
                shared_done.add(s["storage"])
            for b in items:
                vmid, ct = b.get("vmid"), b.get("ctime") or 0
                if vmid is None or b.get("volid") in seen:
                    continue
                seen.add(b.get("volid"))
                count += 1
                unverified += not b.get("verification")
                latest[vmid] = max(latest.get(vmid, 0), ct)
        now = time.time()
        self._backups = {"latest": latest, "count": count, "unverified": unverified,
                         "scanned": datetime.now(timezone.utc).isoformat(),
                         "orphans": [{"vmid": v, "age_days": round((now - t) / 86400)} for v, t in sorted(latest.items())]}
        self._last_scan = now

    def _zfs_written(self, storage, online):
        """ZFS storage: Proxmox's used % counts space reserved by thick-provisioned
        disks. Add what the pool has actually written (zpool alloc / size), so the
        page can show both and warn on the real figure."""
        zfs = [s for s in storage if s["type"] == "zfspool" and s["node"] in online]
        if not zfs:
            return
        try:
            pools = {c["storage"]: (c.get("pool") or "").split("/")[0] for c in self.get("/storage") or []}
        except Exception:
            return
        cache = {}
        for s in zfs:
            pool = pools.get(s["name"])
            if not pool:
                continue
            if s["node"] not in cache:
                try:
                    cache[s["node"]] = {p["name"]: p for p in self.get(f"/nodes/{s['node']}/disks/zfs") or []}
                except Exception:
                    cache[s["node"]] = {}
            p = cache[s["node"]].get(pool)
            if p and p.get("size"):
                s["pool"] = pool
                s["written"] = _pct(p.get("alloc"), p["size"])
                s["pool_free_gb"] = round((p.get("free") or 0) / 2 ** 30)
                s["pool_size_gb"] = round(p["size"] / 2 ** 30)

    # ── change detection → Events ────────────────────────────────────────
    def _compare(self, v):
        prev, ev = self._prev, self.on_event
        cur = {
            "quorate": v["cluster"]["quorate"],
            "nodes": {n["name"]: (n["online"], n["uptime"]) for n in v["nodes"]},
            "ha": {s["sid"]: (s["node"], s["state"]) for s in v["ha"]["services"]},
            "repl": {j["id"]: j["fail_count"] for j in v["replication"]},
            "storage": {(s["name"], s["node"]): (_eff(s) or 0) >= self.storage_warn for s in v["storage"]},
        }
        new_tasks = {t["upid"] for t in v["failed_tasks"]}
        if prev is not None:
            if prev["quorate"] and not cur["quorate"]:
                ev("proxmox", "crit", "Proxmox cluster lost quorum")
            elif not prev["quorate"] and cur["quorate"]:
                ev("proxmox", "info", "Proxmox cluster has quorum again")
            for name, (online, up) in cur["nodes"].items():
                was = prev["nodes"].get(name)
                if not was:
                    continue
                if was[0] and not online:
                    ev("proxmox", "crit", f"Proxmox node {name} went offline")
                elif not was[0] and online:
                    ev("proxmox", "info", f"Proxmox node {name} is back online")
                elif online and was[1] and up is not None and up < was[1]:
                    ev("proxmox", "warn", f"Proxmox node {name} restarted (up {up // 60} min)")
            for sid, (node, state) in cur["ha"].items():
                old = prev["ha"].get(sid)
                if old and old[0] != node:
                    ev("proxmox", "warn", f"HA moved {sid} from {old[0]} to {node}")
                if old and old[1] != state and state not in ("started", "stopped"):
                    ev("proxmox", "warn", f"HA service {sid} is {state}")
            for jid, fails in cur["repl"].items():
                if fails and fails > prev["repl"].get(jid, 0):
                    ev("proxmox", "warn", f"Replication job {jid} failed ({fails} in a row)")
            for key, over in cur["storage"].items():
                if over and not prev["storage"].get(key):
                    ev("proxmox", "warn", f"Proxmox storage {key[0]} on {key[1]} is over {self.storage_warn}% full")
            for t in v["failed_tasks"]:
                if t["upid"] not in self._seen_tasks:
                    ev("proxmox", "warn", f"Proxmox task {t['type']}{(' ' + str(t['id'])) if t['id'] else ''} on {t['node']} failed: {t['status']}")
        self._seen_tasks |= new_tasks
        self._prev = cur
