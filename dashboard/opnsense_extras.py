"""
Firewall health, firmware, services, blocked traffic and top bandwidth from
OPNsense, polled in the background (read-only GET requests only).

    extras = OPNsenseExtras(get_json, lan_subnets, ...)
    extras.start()            # background thread
    extras.snapshot()         # latest results for the pages

Health, services and current bandwidth are refreshed every `fast_seconds`;
the firewall log (larger) every `log_seconds`; firmware status every
`firmware_seconds`. Each section keeps its own error so one failing call
never hides the others.
"""
import ipaddress
import re
import threading
import time
from collections import Counter
from datetime import datetime, timezone

CPU_RE = re.compile(r"CPU:.*?([\d.]+)% idle")


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class OPNsenseExtras:
    def __init__(self, get_json, lan_subnets, top_interfaces=("lan",), log_lines=1000,
                 fast_seconds=60, log_seconds=300, firmware_seconds=900, on_event=None):
        self.get = get_json
        self.lan = [ipaddress.ip_network(n) for n in lan_subnets]
        self.top_interfaces = list(top_interfaces)
        self.log_lines = int(log_lines)
        self.fast_seconds, self.log_seconds, self.firmware_seconds = fast_seconds, log_seconds, firmware_seconds
        self.on_event = on_event or (lambda kind, sev, msg: None)
        self._lock = threading.Lock()
        self._snap = {"health": {}, "firmware": {}, "services": [], "firewall": {}, "top": {},
                      "errors": {}, "updated": {}}
        self._prev_running = None
        self._prev_update = None
        self._started = False

    # ── public ────────────────────────────────────────────────────────────
    def snapshot(self):
        with self._lock:
            return {k: (dict(v) if isinstance(v, dict) else list(v)) for k, v in self._snap.items()}

    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._loop, daemon=True, name="opnsense-extras").start()

    # ── polling ───────────────────────────────────────────────────────────
    def _loop(self):
        last_log = last_fw = 0.0
        while True:
            now = time.time()
            self._section("health", self._health)
            self._section("services", self._services)
            self._section("top", self._top)
            if now - last_fw >= self.firmware_seconds:
                self._section("firmware", self._firmware)
                last_fw = now
            if now - last_log >= self.log_seconds:
                self._section("firewall", self._firewall)
                last_log = now
            time.sleep(self.fast_seconds)

    def _section(self, name, fn):
        try:
            value = fn()
            with self._lock:
                self._snap[name] = value
                self._snap["errors"].pop(name, None)
                self._snap["updated"][name] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            with self._lock:
                self._snap["errors"][name] = str(e)[:200]
            print(f"[OPNsense extras] {name} failed: {e}", flush=True)

    # ── sections ──────────────────────────────────────────────────────────
    def _health(self):
        t = self.get("/api/diagnostics/system/system_time")
        res = self.get("/api/diagnostics/system/system_resources").get("memory", {})
        disks = self.get("/api/diagnostics/system/system_disk").get("devices", [])
        info = self.get("/api/diagnostics/system/system_information")
        states = self.get("/api/diagnostics/firewall/pf_states")
        cpu = None
        try:
            act = self.get("/api/diagnostics/activity/get_activity")
            for line in act.get("headers", []):
                m = CPU_RE.search(line)
                if m:
                    cpu = round(100 - float(m.group(1)), 1)
        except Exception:
            pass
        mem_total, mem_used = _num(res.get("total")), _num(res.get("used"))
        root = next((d for d in disks if d.get("mountpoint") == "/"), disks[0] if disks else {})
        try:
            temps = self.get("/api/diagnostics/system/system_temperature")
        except Exception:
            temps = []
        temp_vals = [_num(x.get("temperature")) for x in temps if isinstance(x, dict)]
        temp_vals = [v for v in temp_vals if v is not None]
        load = [_num(x) for x in str(t.get("loadavg", "")).split(",")]
        st_cur, st_lim = _num(states.get("current")), _num(states.get("limit"))
        return {
            "name": info.get("name"),
            "version": next((v for v in info.get("versions", []) if v.startswith("OPNsense")), ""),
            "os": next((v for v in info.get("versions", []) if v.startswith("FreeBSD")), ""),
            "uptime": t.get("uptime"), "boottime": t.get("boottime"),
            "config_changed": t.get("config"),
            "load": [x for x in load if x is not None],
            "cpu": cpu,
            "mem_pct": round(100 * mem_used / mem_total) if mem_total and mem_used is not None else None,
            "mem_total_mb": round(mem_total / 1048576) if mem_total else None,
            "disk_pct": root.get("used_pct"), "disk_free": root.get("available"),
            "disk_total": root.get("total"),
            "temp": max(temp_vals) if temp_vals else None,
            "states": int(st_cur) if st_cur is not None else None,
            "states_pct": round(100 * st_cur / st_lim, 1) if st_cur and st_lim else None,
        }

    def _services(self):
        rows = self.get("/api/core/service/search").get("rows", [])
        out = [{"name": r.get("name") or r.get("id"), "description": r.get("description") or r.get("name"),
                "running": bool(int(r.get("running", 0) or 0)), "id": r.get("id")} for r in rows]
        running = {s["id"]: s["running"] for s in out}
        if self._prev_running is not None:
            for sid, up in running.items():
                was = self._prev_running.get(sid)
                if was is True and not up:
                    self.on_event("service", "crit", f"Firewall service '{self._label(out, sid)}' stopped")
                elif was is False and up:
                    self.on_event("service", "info", f"Firewall service '{self._label(out, sid)}' started")
        self._prev_running = running
        return sorted(out, key=lambda s: (s["running"], s["description"].lower()))

    @staticmethod
    def _label(services, sid):
        return next((s["description"] for s in services if s["id"] == sid), sid)

    def _firmware(self):
        st = self.get("/api/core/firmware/status")
        prod = st.get("product", {}) or {}
        status = (st.get("status") or "").lower()
        update = status in ("update", "upgrade")
        fw = {
            "status": status or "unknown",
            "message": st.get("status_msg") or "",
            "installed": prod.get("product_version") or prod.get("CORE_PKGVERSION") or "",
            "series": prod.get("CORE_SERIES") or "",
            "next": prod.get("CORE_NEXT") or "",
            "update_available": update,
            "updates": st.get("updates"),
            "download_size": st.get("download_size"),
            "needs_reboot": str(st.get("needs_reboot", "0")) == "1",
            "latest": prod.get("product_latest") or st.get("product_version") or "",
        }
        if self._prev_update is not None and update and not self._prev_update:
            self.on_event("firmware", "warn", f"OPNsense update available: {fw['message'] or fw['latest']}")
        self._prev_update = update
        return fw

    def _in_lan(self, ip):
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in self.lan)
        except ValueError:
            return False

    def _firewall(self):
        rows = self.get(f"/api/diagnostics/firewall/log?limit={self.log_lines}")
        rows = rows if isinstance(rows, list) else rows.get("rows", [])
        blocks = [r for r in rows if r.get("action") == "block"]
        ts = sorted(r.get("__timestamp__", "") for r in rows if r.get("__timestamp__"))
        inbound = [b for b in blocks if not self._in_lan(b.get("src", ""))]
        outbound = [b for b in blocks if self._in_lan(b.get("src", ""))]

        def port(b):
            p = b.get("dstport") or ""
            return f"{b.get('protoname', '')}/{p}" if p else (b.get("protoname") or "?")

        stats = self.get("/api/diagnostics/firewall/stats")
        pf = self.get("/api/diagnostics/firewall/pf_statistics/info").get("info", {})
        return {
            "lines": len(rows), "blocks": len(blocks), "passes": len(rows) - len(blocks),
            "from": ts[0] if ts else None, "to": ts[-1] if ts else None,
            "inbound_sources": Counter(b.get("src", "?") for b in inbound).most_common(8),
            "inbound_ports": Counter(port(b) for b in inbound).most_common(8),
            "outbound_devices": Counter(b.get("src", "?") for b in outbound).most_common(8),
            "outbound_targets": Counter(f"{b.get('dst', '?')} {port(b)}" for b in outbound).most_common(8),
            "by_rule": Counter((b.get("label") or b.get("rulenr") or "?") for b in blocks).most_common(5),
            "recent_blocks": [{"ts": b.get("__timestamp__"),
                               **{k: b.get(k) for k in ("interface", "dir", "src", "srcport",
                                                        "dst", "dstport", "protoname", "label")}}
                              for b in blocks[:25]],
            "by_interface": [(x.get("label"), x.get("value")) for x in (stats if isinstance(stats, list) else [])],
            "state_rate": (pf.get("state-table", {}).get("inserts", {}) or {}).get("rate"),
        }

    def _top(self):
        out = {}
        for ifname in self.top_interfaces:
            data = self.get(f"/api/diagnostics/traffic/top/{ifname}").get(ifname, {})
            recs = []
            for r in data.get("records", [])[:15]:
                peers = sorted(r.get("details", []), key=lambda d: -(d.get("rate_bits") or 0))
                recs.append({
                    "address": r.get("address"), "rate_in": r.get("rate_bits_in") or 0,
                    "rate_out": r.get("rate_bits_out") or 0, "rate": r.get("rate_bits") or 0,
                    "peer": peers[0].get("address") if peers else None,
                    "peers": len(peers),
                })
            out[ifname] = sorted(recs, key=lambda r: -r["rate"])
        return out
