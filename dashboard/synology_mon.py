"""
Synology NAS monitoring through the DSM Web API.

    mon = SynologyMonitor(url, cred_reader, ...)
    mon.start()          # background thread
    mon.snapshot()       # latest view for the pages

Every `poll_seconds`: model, DSM version, uptime and temperature, CPU and
memory, each disk (status, SMART, temperature, SSD life), storage pools
(RAID state) and volumes (state and space), whether a DSM update is waiting
and the UPS, if one is connected. Changes (a disk, pool or volume leaving
the normal state, a volume filling up, a disk running hot, a DSM update
appearing, the NAS not answering) are reported through `on_event`.

Requests are POSTs, so the password and session ID never appear in a URL.
Each part is read separately: an API the account may not use shows as
"not permitted" instead of failing the whole page.
"""
import threading
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SESSION_ERRORS = {105, 106, 107, 119}     # not logged in, timed out, kicked, invalid SID
AUTH_ERRORS = {
    400: "wrong user name or password", 401: "account disabled",
    402: "permission denied (allow the DSM application for this account)",
    403: "2-step verification is on for this account (turn it off for the dashboard's account)",
    404: "2-step verification code failed", 407: "this address is blocked by DSM's auto-block",
}
NORMAL = {"normal", "initialized", "not_use", "background", ""}


NO_CREDS = "No credentials yet: add them under Admin → Credentials."


class DSMError(Exception):
    def __init__(self, code, api):
        self.code, self.api = code, api
        super().__init__(f"{api}: DSM error {code}")


def _gb(b):
    try:
        return round(int(b) / 1e9, 1)
    except (TypeError, ValueError):
        return None


def _uptime_seconds(v):
    """DSM reports uptime as seconds or as 'hours:minutes:seconds'."""
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.count(":") == 2:
        h, m, s = (int(x) for x in v.split(":"))
        return h * 3600 + m * 60 + s
    return None


def _find(d, key):
    """First value for `key` anywhere in nested dicts/lists."""
    if isinstance(d, dict):
        if key in d:
            return d[key]
        for v in d.values():
            r = _find(v, key)
            if r is not None:
                return r
    elif isinstance(d, list):
        for v in d:
            r = _find(v, key)
            if r is not None:
                return r
    return None


class SynologyMonitor:
    def __init__(self, url, cred_reader, verify_tls=False, poll_seconds=300, volume_warn_pct=85,
                 disk_temp_warn=55, on_event=None):
        self.url = url.rstrip("/")
        self.cred_reader = cred_reader            # callable -> (user, password)
        self.verify = verify_tls
        self.poll_seconds = poll_seconds
        self.volume_warn = volume_warn_pct
        self.temp_warn = disk_temp_warn
        self.on_event = on_event or (lambda kind, sev, msg: None)
        self._sid = None
        self._lock = threading.Lock()
        self._snap = {"updated": None, "error": None}
        self._prev = None
        self._fails = 0
        self._started = False

    # ── HTTP ──────────────────────────────────────────────────────────────
    def _post(self, api, version, method, **params):
        r = requests.post(f"{self.url}/webapi/entry.cgi", timeout=20, verify=self.verify,
                          data={"api": api, "version": version, "method": method, **params})
        r.raise_for_status()
        j = r.json()
        if not j.get("success"):
            raise DSMError((j.get("error") or {}).get("code"), api)
        return j.get("data") or {}

    def login(self):
        user, password = self.cred_reader()
        try:
            # session names the DSM application being signed in to: a non-admin
            # account is refused (error 402) for any name it has no privilege for.
            data = self._post("SYNO.API.Auth", 6, "login", account=user, passwd=password,
                              session="webui", format="sid")
        except DSMError as e:
            raise PermissionError(f"DSM sign-in failed: {AUTH_ERRORS.get(e.code, f'error {e.code}')}") from None
        self._sid = data.get("sid")
        return self._sid

    def call(self, api, version, method, **params):
        if not self._sid:
            self.login()
        try:
            return self._post(api, version, method, _sid=self._sid, **params)
        except DSMError as e:
            if e.code not in SESSION_ERRORS:
                raise
            self.login()
            return self._post(api, version, method, _sid=self._sid, **params)

    def _part(self, api, version, method, **params):
        """(data, None) or (None, reason) so one missing right does not sink the page."""
        try:
            return self.call(api, version, method, **params), None
        except DSMError as e:
            return None, ("not permitted for this account" if e.code in (105, 102, 103) else f"DSM error {e.code}")
        except (PermissionError, FileNotFoundError, ValueError):
            raise                          # bad or missing credentials: the whole poll fails
        except requests.ConnectionError:
            raise                          # NAS unreachable
        except Exception as e:
            return None, str(e)[:100]

    # ── public ────────────────────────────────────────────────────────────
    def snapshot(self):
        with self._lock:
            return dict(self._snap)

    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="synology").start()

    def _loop(self):
        while True:
            self.poll_once()
            time.sleep(self.poll_seconds)

    def poll_once(self):
        try:
            view = self._collect()
            if self._fails >= 2:
                self.on_event("nas_up", "info", f"The NAS ({view.get('model') or 'Synology'}) is answering again.")
            self._fails = 0
            self._compare(view)
            with self._lock:
                self._snap = {**view, "updated": datetime.now(timezone.utc).isoformat(), "error": None}
        except FileNotFoundError:
            with self._lock:
                self._snap["error"] = NO_CREDS
        except Exception as e:
            self._fails += 1
            self._sid = None
            if self._fails == 2:
                self.on_event("nas_down", "crit", f"The Synology NAS is not answering: {str(e)[:140]}")
            with self._lock:
                self._snap["error"] = str(e)[:200]
            print(f"[Synology] poll failed: {e}", flush=True)

    # ── data ──────────────────────────────────────────────────────────────
    def _collect(self):
        missing = {}
        info, why = self._part("SYNO.Core.System", 1, "info")
        if info is None:
            missing["system"] = why
            info = {}
        util, why = self._part("SYNO.Core.System.Utilization", 1, "get")
        if util is None:
            missing["utilization"] = why
            util = {}
        storage, why = self._part("SYNO.Storage.CGI.Storage", 1, "load_info")
        source = "Storage Manager"
        if storage is None:
            # Storage Manager needs an administrator. Info Center's storage view
            # (allowed for the "System monitoring" delegated role) has each disk's
            # health and temperature and each volume's state and space.
            ic, why2 = self._part("SYNO.Core.System", 1, "info", type="storage")
            if ic is None:
                missing["storage"] = why
                storage = {}
            else:
                storage, source = from_info_center(ic), "Info Center"
        upgrade, why = self._part("SYNO.Core.Upgrade.Server", 1, "check")
        if upgrade is None:
            missing["update"] = why
        ups, _ = self._part("SYNO.Core.ExternalDevice.UPS", 1, "get")

        cpu = util.get("cpu") or {}
        mem = util.get("memory") or {}
        cpu_pct = None
        if cpu:
            cpu_pct = sum(int(cpu.get(k) or 0) for k in ("user_load", "system_load", "other_load"))

        disks = []
        for d in storage.get("disks") or []:
            temp = d.get("temp")
            life = d.get("remain_life")
            if isinstance(life, dict):
                life = life.get("value")
            disks.append({
                "id": d.get("id"), "name": d.get("longName") or d.get("name") or d.get("id"),
                "model": " ".join(x for x in ((d.get("vendor") or "").strip(), (d.get("model") or "").strip()) if x),
                "type": d.get("diskType") or "", "size_gb": _gb(d.get("size_total")),
                "status": (d.get("status") or "").lower(),
                "smart": (d.get("smart_status") or "").lower(),
                "overview": (d.get("overview_status") or "").lower(),
                "temp": temp if isinstance(temp, (int, float)) and temp > 0 else None,
                "life": life if isinstance(life, (int, float)) and life >= 0 else None,
                "bad_sectors": d.get("unc") if isinstance(d.get("unc"), int) else None,
                "pool": d.get("used_by") or "",
                "firmware": d.get("firm") or "",
                "testing": d.get("testing"),
            })
        pools = []
        for p in storage.get("storagePools") or []:
            size = p.get("size") or {}
            total, used = _int(size.get("total")), _int(size.get("used"))
            pools.append({
                "id": p.get("id") or p.get("pool_path"),
                "name": p.get("display_name") or _pretty_id(p.get("id") or p.get("pool_path") or "pool"),
                "status": (p.get("status") or "").lower(),
                "raid": (p.get("device_type") or p.get("raidType") or "").replace("_", " "),
                "disks": len(p.get("disks") or []),
                "used_pct": round(100 * used / total) if total else None,
                "progress": _progress(p),
            })
        volumes = []
        for v in storage.get("volumes") or []:
            size = v.get("size") or {}
            total, used = _int(size.get("total")), _int(size.get("used"))
            volumes.append({
                "id": v.get("id") or v.get("vol_path"),
                "name": v.get("display_name") or v.get("vol_path") or _pretty_id(v.get("id") or "volume"),
                "status": (v.get("status") or "").lower(),
                "fs": v.get("fs_type") or "",
                "used_pct": round(100 * used / total) if total else None,
                "used_gb": _gb(used), "total_gb": _gb(total),
                "free_gb": _gb(total - used) if total else None,
                "pool": v.get("pool_path") or "",
                "progress": _progress(v),
            })
        update = None
        if upgrade is not None:
            avail = _find(upgrade, "available")
            update = {"available": bool(avail), "version": _find(upgrade, "version") if avail else None}
        ups_view = None
        if ups and (ups.get("enable") or ups.get("usb_ups_connect") or ups.get("status")):
            raw = str(ups.get("status") or ("connected" if ups.get("usb_ups_connect") else ""))
            ups_view = {"status": raw.replace("usb_ups_status_", "").replace("_", " "),
                        "model": ups.get("model") or "", "charge": ups.get("charge"),
                        "runtime": ups.get("runtime")}
        return {
            "model": info.get("model"), "dsm": info.get("firmware_ver") or info.get("version_string"),
            "uptime": _uptime_seconds(info.get("up_time") or info.get("uptime")),
            "temp": info.get("sys_temp") if isinstance(info.get("sys_temp"), (int, float)) else None,
            "temp_warn": bool(info.get("temperature_warning") or info.get("sys_tempwarn")),
            "ram_gb": round(int(info["ram_size"]) / 1024, 1) if str(info.get("ram_size") or "").isdigit() else None,
            "cpu": cpu_pct, "mem": mem.get("real_usage"),
            "disks": disks, "pools": pools, "volumes": volumes,
            "dsm_update": update, "ups": ups_view, "missing": missing, "source": source,
            "warn_pct": self.volume_warn, "temp_limit": self.temp_warn,
        }

    # ── changes → events ──────────────────────────────────────────────────
    def _compare(self, view):
        prev, self._prev = self._prev, view
        if prev is None:
            for d in view["disks"]:
                if not disk_ok(d):
                    self.on_event("nas_disk", "crit", f"NAS disk {d['name']} reports {disk_problem(d)}.")
            return
        od = {d["id"]: d for d in prev["disks"]}
        for d in view["disks"]:
            o = od.get(d["id"])
            if o is None:
                self.on_event("nas_disk", "info", f"NAS disk {d['name']} appeared ({d['model']}).")
                continue
            if disk_ok(o) and not disk_ok(d):
                self.on_event("nas_disk", "crit", f"NAS disk {d['name']} now reports {disk_problem(d)}.")
            elif not disk_ok(o) and disk_ok(d):
                self.on_event("nas_disk", "info", f"NAS disk {d['name']} is back to normal.")
            if (d["temp"] or 0) >= self.temp_warn > (o["temp"] or 0):
                self.on_event("nas_temp", "warn", f"NAS disk {d['name']} is running hot: {d['temp']} °C.")
        for d in prev["disks"]:
            if d["id"] not in {x["id"] for x in view["disks"]}:
                self.on_event("nas_disk", "crit", f"NAS disk {d['name']} is no longer detected.")
        for kind, label in (("pools", "storage pool"), ("volumes", "volume")):
            ov = {x["id"]: x for x in prev[kind]}
            for x in view[kind]:
                o = ov.get(x["id"])
                if not o:
                    continue
                if x["status"] != o["status"]:
                    sev = "info" if x["status"] in NORMAL else "crit"
                    self.on_event("nas_" + kind[:-1], sev, f"NAS {label} {x['name']} changed from "
                                  f"{o['status'] or '?'} to {x['status'] or '?'}.")
                if kind == "volumes" and (x["used_pct"] or 0) >= self.volume_warn > (o["used_pct"] or 0):
                    self.on_event("nas_volume", "warn",
                                  f"NAS volume {x['name']} is {x['used_pct']}% full ({x['free_gb']} GB free).")
        if (view["dsm_update"] or {}).get("available") and not (prev["dsm_update"] or {}).get("available"):
            self.on_event("nas_update", "info", f"A DSM update is available: {view['dsm_update']['version'] or 'new version'}.")


def from_info_center(ic):
    """Info Center's storage info, in the shape Storage Manager's load_info uses."""
    disks = [{
        "id": d.get("diskPath") or d.get("diskno"), "longName": d.get("diskno"),
        "model": d.get("model"), "vendor": "", "diskType": d.get("diskType"),
        "size_total": d.get("capacity"), "status": d.get("status"),
        "smart_status": "", "overview_status": d.get("overview_status") or d.get("summary_status_key"),
        "temp": d.get("temp"), "used_by": d.get("volume"),
        "testing": d.get("testing_type") if d.get("testing_type") not in (None, "", "idle") else None,
        "order": d.get("order"),
    } for d in ic.get("hdd_info") or []]
    disks.sort(key=lambda d: (d["order"] is None, d["order"] or 0))
    volumes = [{
        "id": v.get("volume") or v.get("name"), "display_name": _pretty_id(v.get("volume") or v.get("name") or "volume"),
        "status": v.get("status"), "fs_type": "",
        "size": {"total": v.get("total_size"), "used": v.get("used_size")},
    } for v in ic.get("vol_info") or []]
    return {"disks": disks, "volumes": volumes, "storagePools": []}


def disk_ok(d):
    return (d["status"] in NORMAL and d["smart"] in NORMAL | {"healthy", "safe"}
            and d["overview"] in NORMAL | {"healthy"} and not d.get("bad_sectors"))


def disk_problem(d):
    parts = []
    if d["status"] not in NORMAL:
        parts.append(f"status {d['status']}")
    if d["smart"] not in NORMAL | {"healthy", "safe"}:
        parts.append(f"SMART {d['smart']}")
    if d["overview"] not in NORMAL | {"healthy"} and not parts:
        parts.append(d["overview"])
    if d.get("bad_sectors"):
        parts.append(f"{d['bad_sectors']} bad sectors")
    return ", ".join(parts) or "a problem"


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _pretty_id(s):
    s = str(s).replace("reuse_", "Pool ").replace("volume_", "Volume ").replace("_", " ")
    return s[:1].upper() + s[1:]


def _progress(x):
    """RAID rebuild / data scrubbing / expansion in progress, as text."""
    p = x.get("progress") or {}
    step = p.get("step") or ""
    pct = p.get("percent")
    if step and step not in ("none", "") and pct not in (None, "", "-1", -1):
        return f"{step.replace('_', ' ')} {pct}%"
    if x.get("is_scheduled_scrubbing") or x.get("scrubbing_status") == "running":
        return "data scrubbing"
    return None
