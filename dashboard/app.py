#!/usr/bin/env python3
"""
Network Dashboard: one view of a home or small-office network built from
Juniper Mist (Wi-Fi), HPE Aruba Central (switches), OPNsense (WAN, DHCP),
an ARP scan of the LAN and, optionally, ntopng and Home Assistant.

    python3 app.py                      # uses config.yaml next to this file
    python3 app.py --config /path.yaml  # or $NETDASH_CONFIG
    python3 app.py --check              # test each configured integration, then exit

See README.md and docs/ for setup.
"""

import json
import os
import re
import time
import threading
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import ipaddress
import sys

import requests
import urllib3
from flask import Flask, jsonify, render_template_string, request

import admin
import settings
from gap_analysis import analyze_gap
from wireless_health import analyze_wireless_health
import ai_assistant
import ntopng_talkers
import topology as topology_mod
import reconcile as reconcile_mod
import mist_sle
import mist_client_events
from event_log import EventLog
from opnsense_extras import OPNsenseExtras
from ui import *  # noqa: F401,F403  page templates (BASE_HTML, OVERVIEW_HTML, ...)
import ui as _ui


def _config_arg():
    if __name__ == "__main__" and "--config" in sys.argv:
        i = sys.argv.index("--config")
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


try:
    CFG = settings.load(_config_arg())
except settings.ConfigError as e:
    sys.exit(f"config error: {e}")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

@app.template_filter("event_ago")
def _event_ago_filter(iso_ts):
    return fmt_relative(iso_ts)

@app.template_filter("ts_ago")
def _ts_ago_filter(unix_ts):
    """Relative time from a Unix-seconds timestamp (Mist client events)."""
    try:
        from datetime import datetime, timezone
        iso = datetime.fromtimestamp(float(unix_ts), tz=timezone.utc).isoformat()
        return fmt_relative(iso)
    except Exception:
        return ""

# ── Settings ──────────────────────────────────────────────────────────────────

MIST_TOKEN_FILE    = settings.secret_path(CFG, CFG.mist.token_file)
CENTRAL_TOKEN      = settings.secret_path(CFG, CFG.central.token_file)
ANTHROPIC_KEY_FILE = settings.secret_path(CFG, CFG.assistant.key_file)
NTOPNG_TOKEN_FILE  = settings.secret_path(CFG, CFG.ntopng.token_file)
OPNSENSE_KEY       = settings.secret_path(CFG, CFG.opnsense.key_file)
HA_TOKEN_FILE      = settings.secret_path(CFG, CFG.home_assistant.token_file)
EVENT_LOG_FILE     = settings.data_path(CFG, "event_log.jsonl")
_event_log = EventLog(EVENT_LOG_FILE, quiet_switches=CFG.inventory.quiet_switches,
                      primary_gateways=[w.gateway for w in CFG.opnsense.wans
                                        if w.gateway and w.type == "primary"])
topology_mod.EXTRA_SWITCH_UPLINKS = dict(CFG.inventory.switch_uplinks)
topology_mod.PRIMARY_GATEWAYS = {w.gateway for w in CFG.opnsense.wans
                                 if w.gateway and w.type == "primary"}

MIST_BASE     = CFG.mist.api_base.rstrip("/")
MIST_PORTAL   = CFG.mist.portal.rstrip("/")
CENTRAL_BASE  = CFG.central.api_base.rstrip("/")
OPNSENSE_HOST = CFG.opnsense.url.rstrip("/")
OPNSENSE_URL  = OPNSENSE_HOST
NTOPNG_URL    = CFG.ntopng.url.rstrip("/")
HA_URL        = CFG.home_assistant.url.rstrip("/")

# Mist org/site: from config, or discovered from the token on the first poll.
MIST_ORG_ID  = CFG.mist.org_id
MIST_SITE_ID = CFG.mist.site_id

POLL_INTERVAL = CFG.poll_interval   # seconds between background refreshes
# WAN links from config: gateway name (as OPNsense reports it) and/or interface.
WANS = CFG.opnsense.wans
WAN_IFACES = {w.interface for w in WANS if w.interface}
LAN_NETS = [ipaddress.ip_network(n) for n in CFG.site.lan_subnets]


def in_lan(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in LAN_NETS)
    except ValueError:
        return False

# ── In-memory cache ───────────────────────────────────────────────────────────

TRAFFIC_HISTORY_MAX = 30  # 30 samples = 30 minutes at 60s interval
WAN_METRICS_MAX = 240     # 240 samples = 4 hours at 60s interval (long window)
WAN_METRICS_SHORT = 30    # short window = 30 min

_cache = {
    "data": None,
    "error": None,
    "last_updated": None,
    "fetching": False,
}

# Rolling traffic history per interface: {"igb0": [{"ts": ..., "rx": ..., "tx": ...}, ...]}
_traffic_history: dict = {}

# Rolling WAN quality history per gateway:
# {"WAN": [{"ts":..., "latency":9.6, "jitter":1.2, "loss":0.0}, ...]}  (gateway name minus _GW)
_wan_metrics_history: dict = {}

# Rolling KPI count history for the overview cards (30 min window).
# {"wireless": [n, n, ...], "wifi_weak": [...], "wired": [...], "total": [...]}
KPI_HISTORY_MAX = 30  # 30 samples = 30 min at 60s interval
_kpi_history: dict = {"wireless": [], "wifi_weak": [], "wired": [], "total": []}

def _update_kpi_history(wireless, wifi_weak, wired, total):
    """Append the current KPI counts to their rolling histories."""
    for key, val in (("wireless", wireless), ("wifi_weak", wifi_weak),
                     ("wired", wired), ("total", total)):
        series = _kpi_history.setdefault(key, [])
        series.append(val if val is not None else 0)
        if len(series) > KPI_HISTORY_MAX:
            _kpi_history[key] = series[-KPI_HISTORY_MAX:]

def _parse_metric(val):
    """OPNsense returns strings like '9.6 ms' / '0.0 %'. Extract the float."""
    if val is None:
        return None
    try:
        import re as _re
        m = _re.search(r"[-+]?\d*\.?\d+", str(val))
        return float(m.group()) if m else None
    except Exception:
        return None

def _update_wan_metrics(gateways):
    """Record latency/jitter/loss per WAN gateway each poll."""
    ts = datetime.now(timezone.utc).isoformat()
    for g in gateways:
        name = g.get("name", "")
        if not name or name.upper().startswith("LAN"):
            continue
        key = name.replace("_GW", "").replace("_gw", "")
        entry = {
            "ts": ts,
            "latency": _parse_metric(g.get("delay")),
            "jitter":  _parse_metric(g.get("stddev")),
            "loss":    _parse_metric(g.get("loss")),
        }
        _wan_metrics_history.setdefault(key, []).append(entry)
        if len(_wan_metrics_history[key]) > WAN_METRICS_MAX:
            _wan_metrics_history[key] = _wan_metrics_history[key][-WAN_METRICS_MAX:]

# ── Credential loaders ────────────────────────────────────────────────────────

def load_mist_token() -> str:
    return MIST_TOKEN_FILE.read_text().strip()

def load_central_data() -> dict:
    return json.loads(CENTRAL_TOKEN.read_text())

def load_central_token() -> str:
    return load_central_data()["access_token"]

def refresh_central_token() -> str:
    """Use refresh_token + client credentials to get a new access token."""
    data = load_central_data()
    refresh_token  = data.get("refresh_token")
    client_id      = data.get("client_id")
    client_secret  = data.get("client_secret")

    if not all([refresh_token, client_id, client_secret]):
        raise ValueError("central_token.json missing refresh_token, client_id, or client_secret")

    token_payload = {
        "client_id":     client_id,
        "client_secret": client_secret,
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
    }

    # Central internal instance requires query params
    resp = requests.post(
        f"{CENTRAL_BASE}/oauth2/token",
        params=token_payload,
        timeout=15,
    )

    resp.raise_for_status()
    new_tokens = resp.json()

    # Merge new tokens back into file
    data["access_token"]  = new_tokens["access_token"]
    data["refresh_token"] = new_tokens.get("refresh_token", refresh_token)
    data["expires_in"]    = new_tokens.get("expires_in", 7200)
    data["created_at"]    = int(time.time() * 1000)

    CENTRAL_TOKEN.write_text(json.dumps(data, indent=2))
    print(f"[Central] Token refreshed successfully at {datetime.now().strftime('%H:%M:%S')}")
    return data["access_token"]

def load_opnsense_creds() -> tuple:
    creds = {}
    for line in OPNSENSE_KEY.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            creds[k.strip()] = v.strip()
    return creds["key"], creds["secret"]

# ── MAC vendor lookup (OUI) ───────────────────────────────────────────────────

@lru_cache(maxsize=512)
def mac_vendor(mac: str) -> str:
    """Look up MAC vendor via macvendors.com API (cached)."""
    try:
        r = requests.get(
            f"https://api.macvendors.com/{mac}",
            timeout=3
        )
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return ""

def enrich_mac(mac: str) -> dict:
    """Return mac + vendor string."""
    vendor = mac_vendor(mac.upper()) if mac else ""
    return {"mac": mac, "vendor": vendor}

# ── Mist API ──────────────────────────────────────────────────────────────────

class MistClient:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Token {load_mist_token()}"

    def get(self, path, **kw):
        return self.s.get(f"{MIST_BASE}{path}", timeout=15, **kw).json()

    def org_id(self):
        me = self.get("/self")
        return me.get("org_id") or me["privileges"][0]["org_id"]

    def sites(self, org_id):
        return self.get(f"/orgs/{org_id}/sites")

    def clients(self, site_id):
        try:
            return self.get(f"/sites/{site_id}/stats/clients")
        except Exception:
            return []

    def aps(self, site_id):
        try:
            return self.get(f"/sites/{site_id}/stats/devices", params={"type": "ap"})
        except Exception:
            return []

def fetch_mist() -> dict:
    global MIST_ORG_ID, MIST_SITE_ID
    c = MistClient()
    org_id = MIST_ORG_ID or c.org_id()
    MIST_ORG_ID = org_id
    sites = c.sites(org_id)
    # One site: by id, else by name, else the only/first site in the org.
    want_id, want_name = CFG.mist.site_id, (CFG.mist.site_name or "").lower()
    home_sites = [s for s in sites if (want_id and s.get("id") == want_id)
                  or (not want_id and want_name and s.get("name", "").lower() == want_name)]
    if not home_sites:
        home_sites = sites[:1]
    if home_sites and not MIST_SITE_ID:
        MIST_SITE_ID = home_sites[0]["id"]

    all_clients = []
    all_aps = []
    for site in home_sites:
        sid = site["id"]
        clients = c.clients(sid)
        aps = c.aps(sid)
        for cl in clients:
            cl["_site"] = site["name"]
        for ap in aps:
            ap["_site"] = site["name"]
        all_clients.extend(clients)
        all_aps.extend(aps)

    return {"clients": all_clients, "aps": all_aps}

# ── Aruba Central API ─────────────────────────────────────────────────────────

class CentralClient:
    def __init__(self):
        self.s = requests.Session()
        self._set_token(load_central_token())

    def _set_token(self, token: str):
        self.s.headers["Authorization"] = f"Bearer {token}"

    # (connect_timeout, read_timeout): fast connect, generous read for bulk data
    TIMEOUT = (5, 30)

    def get(self, path, params=None):
        try:
            r = self.s.get(f"{CENTRAL_BASE}{path}", params=params, timeout=self.TIMEOUT)
        except requests.exceptions.ReadTimeout:
            # one retry on a fresh connection in case the pooled socket went stale
            self.s.close()
            self.s = requests.Session()
            self._set_token(load_central_token())
            r = self.s.get(f"{CENTRAL_BASE}{path}", params=params, timeout=self.TIMEOUT)
        if r.status_code == 401:
            print("[Central] 401 received, refreshing token...")
            new_token = refresh_central_token()
            self._set_token(new_token)
            r = self.s.get(f"{CENTRAL_BASE}{path}", params=params, timeout=self.TIMEOUT)
        r.raise_for_status()
        return r.json()

    def _paginate(self, path, key, base_params, page=500):
        """Pull all pages so a single huge unbounded request can't stall."""
        out, offset = [], 0
        while True:
            params = {**base_params, "limit": page, "offset": offset}
            data = self.get(path, params=params)
            batch = data.get(key, [])
            out.extend(batch)
            if len(batch) < page:
                break
            offset += page
        return out

    def wired_clients(self, site=None):
        site = site if site is not None else CFG.central.site
        return self._paginate("/monitoring/v1/clients/wired", "clients",
                              {"site": site} if site else {})

    def switches(self):
        return self._paginate("/monitoring/v1/switches", "switches", {})

def fetch_central() -> dict:
    """Fetch switches and wired clients independently so a failure in one
    does not blank the other."""
    c = CentralClient()
    result = {"clients": [], "switches": []}
    errs = []

    try:
        result["switches"] = c.switches()
    except Exception as e:
        errs.append(f"switches: {e}")

    try:
        result["clients"] = c.wired_clients()
    except Exception as e:
        errs.append(f"clients: {e}")

    if errs:
        # surface partial failure but keep whatever succeeded
        raise CentralPartialError(errs, result)
    return result


class CentralPartialError(Exception):
    def __init__(self, errs, partial):
        self.partial = partial
        super().__init__("; ".join(errs))

# ── OPNsense API ──────────────────────────────────────────────────────────────

class OPNsenseClient:
    def __init__(self):
        key, secret = load_opnsense_creds()
        self.auth = (key, secret)

    def get(self, path):
        r = requests.get(f"{OPNSENSE_HOST}{path}",
                         auth=self.auth, verify=CFG.opnsense.verify_tls, timeout=10)
        r.raise_for_status()
        return r.json()

    def gateways(self):
        return self.get("/api/routes/gateway/status")

    def interfaces(self):
        return self.get("/api/interfaces/overview/export")

    def dhcp_leases(self):
        return self.get("/api/dhcpv4/leases/searchLease")

    def traffic_stats(self):
        """Get cumulative interface byte counters for delta-based bps calculation."""
        return self.get("/api/diagnostics/interface/getInterfaceStatistics")

# Firewall health, firmware, services, blocked traffic and top bandwidth.
# Polled on its own thread (started in __main__) so the main poll stays fast.
OPN_EXTRAS = OPNsenseExtras(
    lambda path: OPNsenseClient().get(path),
    CFG.site.lan_subnets,
    top_interfaces=CFG.opnsense.top_interfaces,
    log_lines=CFG.opnsense.firewall_log_lines,
    on_event=lambda kind, sev, msg: _event_log.add(kind, sev, msg),
) if CFG.opnsense.enabled else None

# Track previous counters for delta calculation
_prev_counters: dict = {}

def _update_traffic_history(stats_data: dict):
    """Calculate bytes/sec from cumulative counters and append to rolling history."""
    global _prev_counters
    ts = time.time()

    statistics = stats_data.get("statistics", {})

    # Build per-device stats, keeping only the entry with highest received-bytes
    iface_stats = {}
    for key, val in statistics.items():
        device = val.get("name", "")
        if WAN_IFACES and device not in WAN_IFACES:
            continue
        rx = int(val.get("received-bytes", 0))
        existing = iface_stats.get(device)
        if existing is None or rx > int(existing.get("received-bytes", 0)):
            iface_stats[device] = val

    for device, stats in iface_stats.items():
        rx_bytes = int(stats.get("received-bytes", stats.get("ibytes", 0)))
        tx_bytes = int(stats.get("sent-bytes", stats.get("obytes", 0)))

        if device in _prev_counters:
            prev = _prev_counters[device]
            dt = ts - prev["ts"]
            if dt > 0:
                rx_bps = max(0, (rx_bytes - prev["rx"]) / dt)
                tx_bps = max(0, (tx_bytes - prev["tx"]) / dt)

                if device not in _traffic_history:
                    _traffic_history[device] = []

                _traffic_history[device].append({
                    "ts": ts,
                    "rx": rx_bps,
                    "tx": tx_bps,
                })

                if len(_traffic_history[device]) > TRAFFIC_HISTORY_MAX:
                    _traffic_history[device] = _traffic_history[device][-TRAFFIC_HISTORY_MAX:]

        _prev_counters[device] = {"ts": ts, "rx": rx_bytes, "tx": tx_bytes}

def fetch_opnsense() -> dict:
    c = OPNsenseClient()

    # Gateways
    gw_data = c.gateways()
    gateways = gw_data.get("items", gw_data.get("gateways", []))

    # Filter to WAN gateways only (exclude LAN/loopback)
    wan_gws = [g for g in gateways
               if not g.get("name", "").upper().startswith("LAN")]

    # Record latency/jitter/loss history per WAN gateway
    try:
        _update_wan_metrics(wan_gws)
    except Exception as e:
        print(f"[WAN metrics] Error: {e}")

    # Interfaces
    try:
        iface_data = c.interfaces()
        if isinstance(iface_data, list):
            interfaces = iface_data
        else:
            interfaces = list(iface_data.values())
        # Only physical WAN interfaces
        wan_ifaces = [i for i in interfaces
                      if i.get("description", "").upper() not in ("LAN", "LOOPBACK", "ZT", "")
                      and not i.get("device", "").startswith("lo")
                      and not i.get("device", "").startswith("zt")
                      and not i.get("device", "").startswith("enc")
                      and not i.get("device", "").startswith("pf")]
    except Exception:
        wan_ifaces = []

    # DHCP leases
    try:
        lease_data = c.dhcp_leases()
        leases = lease_data.get("rows", [])
        print(f"[OPNsense] DHCP leases fetched: {len(leases)}")
    except Exception as e:
        print(f"[OPNsense] DHCP lease error: {e}")
        leases = []

    # Traffic history
    try:
        traffic_data = c.traffic_stats()
        if isinstance(traffic_data, dict):
            _update_traffic_history(traffic_data)
    except Exception as e:
        print(f"[Traffic] Error: {e}")

    return {
        "gateways": wan_gws,
        "interfaces": wan_ifaces,
        "dhcp_leases": leases,
        "dhcp_total": len([l for l in leases if l.get("state", "").lower() == "active"]),
    }

# ── ARP Scan ─────────────────────────────────────────────────────────────────

ARP_SCAN_INTERVAL = CFG.arp_scan.interval
_arp_cache: dict = {"hosts": [], "last_scanned": None}

# Per-device first/last-seen history, keyed by MAC, persisted across restarts so
# we can spot devices that have been present a long time vs transient ones.
SEEN_HISTORY_FILE = settings.data_path(CFG, "device_seen_history.json")
_seen_history: dict = {}   # mac -> {"first": iso, "last": iso}

def load_seen_history():
    global _seen_history
    try:
        if SEEN_HISTORY_FILE.exists():
            _seen_history = json.loads(SEEN_HISTORY_FILE.read_text())
    except Exception as e:
        print(f"[SEEN] Could not load history: {e}")
        _seen_history = {}

def save_seen_history():
    try:
        SEEN_HISTORY_FILE.write_text(json.dumps(_seen_history))
    except Exception as e:
        print(f"[SEEN] Could not save history: {e}")

def update_seen_history(hosts: list):
    """Record first/last-seen timestamps for each MAC in this scan."""
    now = datetime.now(timezone.utc).isoformat()
    for h in hosts:
        mac = h.get("mac", "").lower()
        if not mac:
            continue
        if mac in _seen_history:
            _seen_history[mac]["last"] = now
        else:
            _seen_history[mac] = {"first": now, "last": now}
    save_seen_history()

def seen_for(mac: str) -> dict:
    """Return {first, last} for a MAC, or empty dict if unknown."""
    return _seen_history.get((mac or "").lower(), {})

def fmt_relative(iso_ts: str) -> str:
    """Human-friendly 'time ago' from an ISO timestamp."""
    if not iso_ts:
        return "—"
    try:
        then = datetime.fromisoformat(iso_ts)
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - then
        secs = int(delta.total_seconds())
        if secs < 60:
            return "just now"
        mins = secs // 60
        if mins < 60:
            return f"{mins}m ago"
        hours = mins // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        return f"{days}d ago"
    except Exception:
        return "—"

def fetch_arp_scan(subnet) -> list:
    """Run arp-scan on one subnet and return list of {ip, mac, vendor} dicts."""
    import subprocess
    cmd = ["arp-scan"]
    if CFG.arp_scan.interface:
        cmd += ["--interface", CFG.arp_scan.interface]
    try:
        result = subprocess.run(
            cmd + [subnet],
            capture_output=True, text=True, timeout=60
        )
        hosts = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                ip = parts[0].strip()
                mac = parts[1].strip()
                vendor = parts[2].strip()
                # Skip header/footer lines
                if not in_lan(ip):
                    continue
                hosts.append({"ip": ip, "mac": mac.lower(), "vendor": vendor})
        return hosts
    except Exception as e:
        print(f"[ARP] Error: {e}")
        return []

def enrich_arp_hosts(arp_hosts: list, dhcp_leases: list) -> list:
    """Cross-reference arp hosts against DHCP leases to flag static IPs."""
    dhcp_macs = {l.get("mac", "").lower() for l in dhcp_leases}
    dhcp_ips   = {l.get("address", "") for l in dhcp_leases}
    dhcp_map   = {l.get("mac", "").lower(): l.get("hostname", "") for l in dhcp_leases}

    out = []
    for h in arp_hosts:
        mac = h["mac"]
        ip  = h["ip"]
        is_dhcp = mac in dhcp_macs or ip in dhcp_ips
        hostname = dhcp_map.get(mac, "")
        seen = seen_for(mac)
        out.append({
            **h,
            "hostname": hostname,
            "type": "DHCP" if is_dhcp else "Static",
            "type_class": "pill-accent" if is_dhcp else "pill-warn",
            "last_seen": fmt_relative(seen.get("last")),
            "first_seen": fmt_relative(seen.get("first")),
        })
    return sorted(out, key=lambda x: tuple(int(p) for p in x["ip"].split(".")))

def arp_poll_loop():
    """Separate poll loop for arp-scan — runs every 5 minutes."""
    while True:
        try:
            hosts = [h for net in CFG.site.lan_subnets for h in fetch_arp_scan(net)]
            if hosts:
                _arp_cache["hosts"] = hosts
                _arp_cache["last_scanned"] = datetime.now(timezone.utc).isoformat()
                update_seen_history(hosts)
                print(f"[ARP] Found {len(hosts)} hosts")
        except Exception as e:
            print(f"[ARP] Poll error: {e}")
        time.sleep(ARP_SCAN_INTERVAL)

# ── Combined fetch ────────────────────────────────────────────────────────────

def fetch_all() -> dict:
    results = {}
    errors = []

    results["mist"] = {"clients": [], "aps": []}
    if CFG.mist.enabled:
        try:
            results["mist"] = fetch_mist()
        except Exception as e:
            errors.append(f"Mist: {e}")

    results["central"] = {"clients": [], "switches": []}
    if CFG.central.enabled:
        try:
            results["central"] = fetch_central()
        except CentralPartialError as e:
            # keep whatever succeeded (e.g. switches up, clients timed out)
            results["central"] = e.partial
            errors.append(f"Central (partial): {e}")
        except Exception as e:
            errors.append(f"Central: {e}")

    results["opnsense"] = {"gateways": [], "interfaces": [], "dhcp_leases": [], "dhcp_total": 0}
    if CFG.opnsense.enabled:
        try:
            results["opnsense"] = fetch_opnsense()
        except Exception as e:
            errors.append(f"OPNsense: {e}")

    # Top talkers from ntopng — SECONDARY source, feeds the AI assistant only.
    # Failures (dead token after a Redis reset, ntopng down) must NOT raise a
    # dashboard banner; they degrade quietly to "AI can't see flows".
    if CFG.ntopng.enabled and NTOPNG_TOKEN_FILE.exists():
        try:
            tok = NTOPNG_TOKEN_FILE.read_text().strip()
            tt = ntopng_talkers.fetch_top_talkers(NTOPNG_URL, tok, top_n=5)
            results["top_talkers"] = tt.get("talkers", [])
            if tt.get("error"):
                # Log, don't banner. A stale token just means no flow data for AI.
                print(f"[ntopng] top-talkers unavailable: {tt['error']}", flush=True)
        except Exception as e:
            results["top_talkers"] = []
            print(f"[ntopng] top-talkers fetch failed: {e}", flush=True)
    else:
        results["top_talkers"] = []

    # Mist SLEs — SECONDARY enrichment (wireless-experience scores from PACE).
    # Like ntopng, failures degrade quietly: no SLE panel rather than a banner.
    results["sle_cards"], results["client_failures"] = [], []
    if not (CFG.mist.enabled and MIST_SITE_ID):
        results["fetched_at"] = datetime.now(timezone.utc).isoformat()
        results["errors"] = errors
        return results
    try:
        results["sle_cards"] = mist_sle.fetch_sles(
            requests, MIST_BASE, load_mist_token(), MIST_SITE_ID,
            window_hours=24,
        )
    except Exception as e:
        results["sle_cards"] = []
        print(f"[SLE] fetch failed: {e}", flush=True)

    # Mist client failure events — SECONDARY enrichment. Filters the
    # success-heavy event stream down to actual failures (auth/DHCP/DNS/etc).
    try:
        failures = mist_client_events.fetch_failures(
            requests, MIST_BASE, load_mist_token(), MIST_SITE_ID,
            window_hours=24,
        )
        # Enrich with hostname/IP from Mist clients + ARP census (by MAC)
        mist_client_events.enrich_failures(
            failures,
            mist_clients=results.get("mist", {}).get("clients", []),
            arp_hosts=_arp_cache.get("hosts", []),
        )
        results["client_failures"] = failures
    except Exception as e:
        results["client_failures"] = []
        print(f"[CLIENT_EVENTS] fetch failed: {e}", flush=True)

    results["fetched_at"] = datetime.now(timezone.utc).isoformat()
    results["errors"] = errors
    return results

# ── Background polling ────────────────────────────────────────────────────────

def push_ha_sensors(data: dict):
    """Push key network metrics to Home Assistant as sensors via REST API."""
    if not CFG.home_assistant.enabled:
        return
    try:
        token = HA_TOKEN_FILE.read_text().strip()
    except FileNotFoundError:
        return  # HA token not configured, skip silently

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    mist     = data.get("mist", {})
    central  = data.get("central", {})
    opnsense = data.get("opnsense", {})
    arp_count = len(_arp_cache.get("hosts", []))

    aps      = mist.get("aps", [])
    switches = central.get("switches", [])
    gateways = opnsense.get("gateways", [])
    ap_up    = sum(1 for a in aps if a.get("status") == "connected")
    sw_up    = sum(1 for s in switches if s.get("status", "").lower() == "up")

    # Build gateway status dict
    gw_status = {}
    for g in gateways:
        name = g.get("name", "").replace("_GW", "")
        gw_status[name] = {
            "status": g.get("status", "unknown"),
            "delay":  g.get("delay", ""),
            "loss":   g.get("loss", ""),
        }

    sensors = [
        {
            "entity_id": "sensor.network_wifi_clients",
            "state": len(mist.get("clients", [])),
            "attributes": {
                "friendly_name": "WiFi Clients",
                "icon": "mdi:wifi",
                "unit_of_measurement": "devices",
            }
        },
        {
            "entity_id": "sensor.network_wired_clients",
            "state": len(central.get("clients", [])),
            "attributes": {
                "friendly_name": "Wired Clients",
                "icon": "mdi:ethernet",
                "unit_of_measurement": "devices",
            }
        },
        {
            "entity_id": "sensor.network_total_devices",
            "state": arp_count or opnsense.get("dhcp_total", 0),
            "attributes": {
                "friendly_name": "Total Network Devices",
                "icon": "mdi:devices",
                "unit_of_measurement": "devices",
            }
        },
        {
            "entity_id": "sensor.network_aps_online",
            "state": ap_up,
            "attributes": {
                "friendly_name": "APs Online",
                "icon": "mdi:access-point",
                "unit_of_measurement": "APs",
                "total": len(aps),
            }
        },
        {
            "entity_id": "sensor.network_switches_online",
            "state": sw_up,
            "attributes": {
                "friendly_name": "Switches Online",
                "icon": "mdi:network-outline",
                "unit_of_measurement": "switches",
                "total": len(switches),
            }
        },
    ]

    # Add per-WAN sensors (entity ids use each WAN's ha_slug from config)
    for w in WANS:
        if not w.gateway:
            continue
        raw, slug = w.gateway.replace("_GW", "").replace("_gw", ""), w.ha_slug
        gw = gw_status.get(raw, {})
        status = gw.get("status", "unknown")
        sc = "Online" if status.lower() in ("none", "up") else "Down" if status.lower() == "down" else "Degraded"
        sensors.append({
            "entity_id": f"sensor.network_wan_{slug}_status",
            "state": sc,
            "attributes": {
                "friendly_name": f"WAN {slug.replace('_', ' ').title()} Status",
                "icon": "mdi:wan",
                "latency": gw.get("delay", ""),
                "packet_loss": gw.get("loss", ""),
            }
        })

    # Add WAN throughput sensors (current bytes/sec)
    wan_device_map = {w.ha_slug: w.interface for w in WANS if w.interface}
    for slug, device in wan_device_map.items():
        history = _traffic_history.get(device, [])
        if history:
            latest = history[-1]
            rx_mbps = round(latest["rx"] / 1_000_000, 3)
            tx_mbps = round(latest["tx"] / 1_000_000, 3)
            sensors.append({
                "entity_id": f"sensor.network_wan_{slug}_download",
                "state": rx_mbps,
                "attributes": {
                    "friendly_name": f"WAN {slug.replace('_',' ').title()} Download",
                    "icon": "mdi:download-network",
                    "unit_of_measurement": "Mbps",
                    "state_class": "measurement",
                }
            })
            sensors.append({
                "entity_id": f"sensor.network_wan_{slug}_upload",
                "state": tx_mbps,
                "attributes": {
                    "friendly_name": f"WAN {slug.replace('_',' ').title()} Upload",
                    "icon": "mdi:upload-network",
                    "unit_of_measurement": "Mbps",
                    "state_class": "measurement",
                }
            })

    # Push each sensor
    for sensor in sensors:
        entity_id = sensor.pop("entity_id")
        try:
            requests.post(
                f"{HA_URL}/api/states/{entity_id}",
                headers=headers,
                json=sensor,
                timeout=5,
            )
        except Exception as e:
            print(f"[HA] Failed to push {entity_id}: {e}")

    print(f"[HA] Pushed {len(sensors)} sensors")


def poll_loop():
    while True:
        try:
            _cache["fetching"] = True
            data = fetch_all()
            _cache["data"] = data
            _cache["last_updated"] = datetime.now(timezone.utc).isoformat()
            _cache["error"] = data["errors"] if data["errors"] else None
            push_ha_sensors(data)
            # Record KPI counts for the overview sparklines
            try:
                mist_d = data.get("mist", {})
                central_d = data.get("central", {})
                wh = analyze_wireless_health(mist_d.get("clients", []), mist_d.get("aps", []))
                _update_kpi_history(
                    wireless=len(mist_d.get("clients", [])),
                    wifi_weak=wh["summary"]["weak"],
                    wired=len(central_d.get("clients", [])),
                    total=len(_arp_cache.get("hosts", [])),
                )
            except Exception as e:
                print(f"[KPI] history update failed: {e}", flush=True)
            # Detect and log state-change events
            try:
                gap = build_gap(data)
                _event_log.process_poll(
                    data,
                    _arp_cache.get("hosts", []),
                    gap.get("gap_devices", []),
                )
                # Log new Mist client failures (deduped, baselined on first run)
                _event_log.process_client_failures(data.get("client_failures", []))
            except Exception as e:
                print(f"[EVENTS] poll processing failed: {e}", flush=True)
        except Exception as e:
            _cache["error"] = str(e)
        finally:
            _cache["fetching"] = False
        time.sleep(POLL_INTERVAL)

# ── Helpers ───────────────────────────────────────────────────────────────────

def fmt_bytes(b):
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "—"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def fmt_uptime(s):
    try:
        s = int(s)
    except (TypeError, ValueError):
        return "—"
    if s < 60:
        return f"{s}s"
    m, _ = divmod(s, 60)
    if m < 60:
        return f"{m}m"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m" if m else f"{h}h"
    d, h = divmod(h, 24)
    if d < 7:
        return f"{d}d {h}h" if h else f"{d}d"
    w, d = divmod(d, 7)
    if w < 8:
        return f"{w}w {d}d" if d else f"{w}w"
    mo, d = divmod(d + w * 7, 30)
    return f"{mo}mo {d}d" if d else f"{mo}mo"

def band_label(b):
    return {"5": "5 GHz", "2.4": "2.4 GHz", "6": "6 GHz"}.get(str(b), b or "—")

def rssi_class(r):
    if r is None: return "muted"
    if r >= -65: return "good"
    if r >= -75: return "warn"
    return "danger"

def gw_status_class(s):
    s = (s or "").lower().strip()
    if s in ("none", "online", "up", ""): return "good"
    if s in ("down", "loss", "highdelay", "highloss"): return "danger"
    return "warn"

def gw_status_label(s, sc):
    s = (s or "").lower().strip()
    if sc == "good": return "Online"
    if sc == "danger": return "Down"
    # warn cases
    mapping = {
        "delay":     "High Latency",
        "highdelay": "High Latency",
        "loss":      "Packet Loss",
        "highloss":  "Packet Loss",
        "unknown":   "Degraded",
    }
    return mapping.get(s, s.title() or "Degraded")


def get_data():
    return _cache.get("data") or {}

def last_updated_str():
    ts = _cache.get("last_updated")
    if not ts:
        return "Loading..."
    dt = datetime.fromisoformat(ts)
    return dt.strftime("%H:%M:%S UTC")

def enrich_wireless_clients(clients, aps):
    # Build AP MAC → name + switch/port lookup
    ap_lookup = {}
    for ap in aps:
        mac = ap.get("mac", "")
        lldp = ap.get("lldp_stat", {})
        if mac:
            ap_lookup[mac.lower()] = {
                "name":        ap.get("name", ""),
                "mac":         mac,
                "switch_name": lldp.get("system_name", ""),
                "switch_port": lldp.get("port_id", ""),
            }

    out = []
    for c in clients:
        rssi = c.get("rssi")
        rc = rssi_class(rssi)
        if rssi is None:
            rl = "—"
        elif rssi >= -65:
            rl = f"{rssi} dBm ▲"
        elif rssi >= -75:
            rl = f"{rssi} dBm ◆"
        else:
            rl = f"{rssi} dBm ▼"

        ap_mac = (c.get("ap_mac") or "").lower()
        ap_info = ap_lookup.get(ap_mac, {})
        ap_display = c.get("ap_name") or ap_info.get("name") or ap_mac or "—"
        ap_serial  = ap_info.get("mac") or ap_mac or ""

        out.append({
            **c,
            "hostname": c.get("hostname") or c.get("username") or "",
            "ip": c.get("ip", ""),
            "band": band_label(c.get("band", "")),
            "rssi_class": rc,
            "rssi_label": rl,
            "ap_display":   ap_display,
            "ap_serial":    ap_serial if ap_serial != ap_display else "",
            "ap_url":       mist_ap_url(ap_mac) if ap_mac else "",
            "client_url":   mist_client_url(c.get("mac", "")),
            "ap_switch":    ap_info.get("switch_name", ""),
            "ap_port":      ap_info.get("switch_port", ""),
            "tx": fmt_bytes(c.get("tx_bytes")),
            "rx": fmt_bytes(c.get("rx_bytes")),
            "uptime": fmt_uptime(c.get("uptime")),
            "last_seen": fmt_relative(seen_for(c.get("mac", "")).get("last")),
            "vendor": mac_vendor(c.get("mac", "").upper()) if c.get("mac") else "",
        })
    return sorted(out, key=lambda x: x.get("hostname") or x.get("mac") or "")

def enrich_wired_clients(clients, switches):
    # Build serial → name lookup
    sw_lookup = {sw.get("serial", ""): sw.get("name", "") for sw in switches}

    out = []
    for c in clients:
        mac = c.get("macaddr", "")
        serial = c.get("associated_device", "")
        sw_name = sw_lookup.get(serial, "")
        out.append({
            **c,
            "name": c.get("name") or c.get("hostname") or "",
            "vendor": mac_vendor(mac.upper()) if mac else "",
            "switch_display": sw_name or serial or "—",
            "switch_serial":  serial if sw_name and serial != sw_name else "",
            "last_seen": fmt_relative(seen_for(mac).get("last")),
        })
    return sorted(out, key=lambda x: x.get("name") or x.get("macaddr") or "")

def enrich_aps(aps):
    out = []
    for ap in aps:
        mac = ap.get("mac", "")
        lldp = ap.get("lldp_stat", {})
        out.append({
            **ap,
            "uptime": fmt_uptime(ap.get("uptime")),
            "mist_url": mist_ap_url(mac) if mac else mist_aps_url(),
            "switch_name": lldp.get("system_name", ""),
            "switch_port": lldp.get("port_id", ""),
            "switch_port_desc": lldp.get("port_desc", ""),
        })
    return sorted(out, key=lambda x: x.get("name") or x.get("mac") or "")

def mist_ap_url(ap_mac: str) -> str:
    """Build Mist AP detail deep link from MAC address.
    MAC a8:f7:d9:b1:31:00 → UUID 00000000-0000-0000-1000-a8f7d9b13100"""
    try:
        clean = ap_mac.lower().replace(":", "").replace("-", "")
        ap_id = f"00000000-0000-0000-1000-{clean}"
        return f"{MIST_PORTAL}/?org_id={MIST_ORG_ID}#!ap/detail/{ap_id}/{MIST_SITE_ID}"
    except Exception:
        return f"{MIST_PORTAL}/?org_id={MIST_ORG_ID}#!ap"

def mist_clients_url() -> str:
    """Mist site clients view."""
    return f"{MIST_PORTAL}/?org_id={MIST_ORG_ID}#!clients/{MIST_SITE_ID}"

def mist_client_url(client_mac: str) -> str:
    """Deep link to a specific client's insights page.
    Real format (verified): #!dashboard/insights/client/{bare_mac}/{site_id}"""
    try:
        clean = (client_mac or "").lower().replace(":", "").replace("-", "").replace(".", "")
        if not clean:
            return mist_clients_url()
        return (f"{MIST_PORTAL}/?org_id={MIST_ORG_ID}"
                f"#!dashboard/insights/client/{clean}/{MIST_SITE_ID}")
    except Exception:
        return mist_clients_url()

def mist_aps_url() -> str:
    """Mist site APs view."""
    return f"{MIST_PORTAL}/?org_id={MIST_ORG_ID}#!ap/{MIST_SITE_ID}"

def mist_client_url(mac: str) -> str:
    """Mist client detail deep link."""
    try:
        clean = mac.lower().replace(":", "").replace("-", "")
        return f"{MIST_PORTAL}/?org_id={MIST_ORG_ID}#!clients/{MIST_SITE_ID}/{clean}"
    except Exception:
        return mist_clients_url()


def build_sparkline(history: list, width=280, height=60) -> str:
    """Generate an SVG sparkline for rx/tx history with auto-scaled Y axis."""
    if not history:
        return ""

    n = len(history)
    w, h = width, height
    pad = 2

    rx_vals = [s["rx"] for s in history]
    tx_vals = [s["tx"] for s in history]

    # Auto-scale to actual data with 20% headroom
    max_val = max(max(rx_vals), max(tx_vals), 1)
    max_bps = max_val * 1.2

    def x_pos(i):
        return pad + (i / max(n - 1, 1)) * (w - 2 * pad)

    def y_pos(val):
        ratio = min(val / max_bps, 1.0)
        return h - pad - ratio * (h - 2 * pad)

    def make_path(values):
        pts = [(x_pos(i), y_pos(v)) for i, v in enumerate(values)]
        if not pts:
            return ""
        d = f"M {pts[0][0]:.1f},{pts[0][1]:.1f}"
        for x, y in pts[1:]:
            d += f" L {x:.1f},{y:.1f}"
        return d

    rx_path = make_path(rx_vals)
    tx_path = make_path(tx_vals)

    cur_rx = rx_vals[-1] if rx_vals else 0
    cur_tx = tx_vals[-1] if tx_vals else 0

    def fmt_bps(b):
        if b >= 1e9: return f"{b/1e9:.2f} Gbps"
        if b >= 1e6: return f"{b/1e6:.1f} Mbps"
        if b >= 1e3: return f"{b/1e3:.1f} Kbps"
        return f"{b:.0f} bps"

    # Y-axis label at top
    top_label = fmt_bps(max_bps)

    svg = f"""<div class="sparkline-wrap">
      <div class="sparkline-scale">{top_label}</div>
      <svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" class="sparkline-svg">
        <line x1="{pad}" y1="{h/2:.0f}" x2="{w-pad}" y2="{h/2:.0f}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
        <line x1="{pad}" y1="{pad}" x2="{w-pad}" y2="{pad}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
        <path d="{rx_path} L {x_pos(n-1):.1f},{h} L {pad},{h} Z" fill="rgba(0,180,216,0.08)" stroke="none"/>
        <path d="{tx_path} L {x_pos(n-1):.1f},{h} L {pad},{h} Z" fill="rgba(63,185,80,0.08)" stroke="none"/>
        <path d="{rx_path}" fill="none" stroke="#00b4d8" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="{tx_path}" fill="none" stroke="#3fb950" stroke-width="1.5" stroke-linejoin="round"/>
      </svg>
      <div class="sparkline-legend">
        <span class="sparkline-rx">↓ {fmt_bps(cur_rx)}</span>
        <span class="sparkline-tx">↑ {fmt_bps(cur_tx)}</span>
        <span class="sparkline-period">30 min</span>
      </div>
    </div>"""
    return svg

def build_kpi_sparkline(series: list, color="#00b4d8", width=200, height=28) -> str:
    """Compact single-line sparkline for a KPI count series (no labels)."""
    if not series or len(series) < 2:
        return ""
    n = len(series)
    w, h = width, height
    pad = 2
    lo = min(series)
    hi = max(series)
    span = (hi - lo) or 1  # avoid div-by-zero on a flat line

    def x_pos(i):
        return pad + (i / max(n - 1, 1)) * (w - 2 * pad)

    def y_pos(v):
        # higher value = higher on chart; flat line sits mid-height
        if hi == lo:
            return h / 2
        ratio = (v - lo) / span
        return h - pad - ratio * (h - 2 * pad)

    pts = [(x_pos(i), y_pos(v)) for i, v in enumerate(series)]
    d = f"M {pts[0][0]:.1f},{pts[0][1]:.1f}" + "".join(
        f" L {x:.1f},{y:.1f}" for x, y in pts[1:])
    # subtle area fill under the line
    area = d + f" L {pts[-1][0]:.1f},{h} L {pts[0][0]:.1f},{h} Z"
    # rgba fill from the hex color
    fill = color.replace("#", "")
    r, g, b = int(fill[0:2], 16), int(fill[2:4], 16), int(fill[4:6], 16)
    return f"""<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" class="kpi-spark" preserveAspectRatio="none">
      <path d="{area}" fill="rgba({r},{g},{b},0.10)" stroke="none"/>
      <path d="{d}" fill="none" stroke="{color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
    </svg>"""

def build_wan_quality_sparkline(history: list, width=280, height=60) -> str:
    """Sparkline for latency (cyan) + jitter (amber) over the last ~30 min.
    history: [{ts, latency, jitter, loss}, ...]. Breaks line on None gaps."""
    if not history:
        return ""
    hist = history[-WAN_METRICS_SHORT:]
    n = len(hist)
    w, h = width, height
    pad = 2

    lat_vals = [s.get("latency") for s in hist]
    jit_vals = [s.get("jitter") for s in hist]
    nums = [v for v in (lat_vals + jit_vals) if isinstance(v, (int, float))]
    if not nums:
        return ""
    max_val = max(max(nums), 1) * 1.2

    def x_pos(i):
        return pad + (i / max(n - 1, 1)) * (w - 2 * pad)

    def y_pos(val):
        ratio = min(val / max_val, 1.0)
        return h - pad - ratio * (h - 2 * pad)

    def make_path(values):
        """Build a path, breaking (new M) wherever a value is None."""
        d, started = "", False
        for i, v in enumerate(values):
            if not isinstance(v, (int, float)):
                started = False
                continue
            cmd = "M" if not started else "L"
            d += f"{cmd} {x_pos(i):.1f},{y_pos(v):.1f} "
            started = True
        return d.strip()

    lat_path = make_path(lat_vals)
    jit_path = make_path(jit_vals)

    cur_lat = next((v for v in reversed(lat_vals) if isinstance(v, (int, float))), None)
    cur_jit = next((v for v in reversed(jit_vals) if isinstance(v, (int, float))), None)

    top_label = f"{max_val:.0f} ms"
    lat_disp = f"{cur_lat:.1f} ms" if cur_lat is not None else "—"
    jit_disp = f"{cur_jit:.1f} ms" if cur_jit is not None else "—"

    svg = f"""<div class="sparkline-wrap">
      <div class="sparkline-scale">{top_label}</div>
      <svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" class="sparkline-svg">
        <line x1="{pad}" y1="{h/2:.0f}" x2="{w-pad}" y2="{h/2:.0f}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
        <line x1="{pad}" y1="{pad}" x2="{w-pad}" y2="{pad}" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
        <path d="{lat_path}" fill="none" stroke="#00b4d8" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="{jit_path}" fill="none" stroke="#d29922" stroke-width="1.5" stroke-linejoin="round"/>
      </svg>
      <div class="sparkline-legend">
        <span style="color:#00b4d8">latency {lat_disp}</span>
        <span style="color:#d29922">jitter {jit_disp}</span>
        <span class="sparkline-period">30 min</span>
      </div>
    </div>"""
    return svg


def build_wan_cards(gateways, interfaces):
    """Merge gateway stats and interface info into unified WAN cards.
    Matches by interface name, excludes unassigned/loopback/ZT interfaces."""

    # Build interface lookup by device name (igb0, igb1, etc.)
    iface_by_device = {}
    for i in interfaces:
        desc = i.get("description", "")
        device = i.get("device", "")
        # Skip unassigned, loopback, ZeroTier
        if desc.lower() in ("", "unassigned interface", "loopback") \
           or device.startswith(("lo", "zt", "enc", "pf")):
            continue
        ipv4 = i.get("ipv4", [{}])
        ip = ipv4[0].get("ipaddr", "") if ipv4 else ""
        iface_by_device[device] = {
            "description": desc,
            "device": device,
            "ip": ip,
            "status": i.get("status", ""),
        }

    # Name remapping from config: gateway (minus _GW), interface or display
    # name -> display name, sort order, icon, primary/backup.
    NAME_MAP = {}
    for order, w in enumerate(WANS):
        meta = {"display": w.name, "order": order, "icon": w.icon, "type": w.type}
        for key in (w.gateway.replace("_GW", "").replace("_gw", ""), w.interface, w.name):
            if key:
                NAME_MAP[key] = meta

    def remap(raw_name):
        return NAME_MAP.get(raw_name, {"display": raw_name, "order": 99, "icon": "globe", "type": "iface"})

    # Build gateway cards
    cards = {}
    for g in gateways:
        name = g.get("name", "")
        if name.upper().startswith("LAN"):
            continue
        raw = name.replace("_GW", "").replace("_gw", "")
        meta = remap(raw)
        status = g.get("status", "").lower()
        sc = gw_status_class(status)
        sl = gw_status_label(status, sc)
        cards[raw] = {
            "name":         meta["display"],
            "raw":          raw,
            "order":        meta["order"],
            "icon":         meta["icon"],
            "type":         meta["type"],
            "gateway":      g.get("address", "—"),
            "delay":        g.get("delay", "—"),
            "loss":         g.get("loss", "—"),
            "stddev":       g.get("stddev", "—"),
            "status_class": sc,
            "status_label": sl,
            "ip":           "",
            "device":       g.get("if", ""),
        }

    # Merge interface info into cards
    for device, iface in iface_by_device.items():
        desc = iface["description"]
        meta = remap(device) if device in NAME_MAP else remap(desc)

        matched = None
        for card_key in cards:
            if card_key.lower() in desc.lower() or desc.lower() in card_key.lower():
                matched = card_key
                break

        if matched:
            cards[matched]["ip"] = iface["ip"]
            cards[matched]["device"] = device
            if iface["status"] == "up" and cards[matched]["status_label"] == "Down":
                cards[matched]["status_label"] = "No Signal"
        else:
            status = iface["status"]
            sc = "good" if status == "up" else ("danger" if status in ("down", "no carrier") else "warn")
            sl = "UP" if status == "up" else status.upper().replace("_", " ")
            cards[device] = {
                "name":         meta["display"],
                "raw":          device,
                "order":        meta["order"],
                "icon":         meta["icon"],
                "type":         meta["type"],
                "gateway":      "—",
                "delay":        "—",
                "loss":         "—",
                "stddev":       "—",
                "status_class": sc,
                "status_label": sl,
                "ip":           iface["ip"],
                "device":       device,
            }

    # Deduplicate by display name — merge data, prefer non-empty values
    merged = {}
    for card in sorted(cards.values(), key=lambda x: x["order"]):
        name = card["name"]
        if name not in merged:
            merged[name] = card
        else:
            existing = merged[name]
            # Merge: fill in missing fields from the other card
            for field in ("ip", "gateway", "delay", "loss", "stddev", "device"):
                if not existing.get(field) or existing[field] == "—":
                    existing[field] = card.get(field, "—")
            # Use better status
            if card["status_class"] == "good":
                existing["status_class"] = "good"
                existing["status_label"] = card["status_label"]

    # Add sparklines from traffic history
    iface_map = {w.name: w.interface for w in WANS if w.interface}
    for card in merged.values():
        iface = iface_map.get(card["name"]) or card.get("device", "")
        history = _traffic_history.get(iface, [])
        card["sparkline"] = build_sparkline(history)
        # WAN quality sparkline (latency + jitter), keyed by gateway raw name
        q_hist = _wan_metrics_history.get(card.get("raw", ""), [])
        card["quality_sparkline"] = build_wan_quality_sparkline(q_hist)

    return sorted(merged.values(), key=lambda x: x["order"])


# ── Gap analysis ──────────────────────────────────────────────────────────────
# MACs to treat as infrastructure beyond the auto-detected APs/switches
# (inventory.extra_infrastructure_macs), and this machine's own NIC.
# Matching is by 5-octet prefix, so a base MAC also covers its +1 interfaces.
EXTRA_INFRA_MACS = CFG.inventory.extra_infrastructure_macs
SELF_MAC = CFG.inventory.self_mac

def build_gap(d):
    mist    = d.get("mist", {})
    central = d.get("central", {})
    dhcp    = d.get("opnsense", {}).get("dhcp_leases", [])
    return analyze_gap(
        arp_hosts        = _arp_cache.get("hosts", []),
        mist_clients     = mist.get("clients", []),
        central_wired    = central.get("clients", []),
        dhcp_leases      = dhcp,
        mist_aps         = mist.get("aps", []),
        switches         = central.get("switches", []),
        extra_infra_macs = EXTRA_INFRA_MACS,
        self_mac         = SELF_MAC,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def overview():
    d = get_data()
    mist     = d.get("mist", {})
    central  = d.get("central", {})
    opnsense = d.get("opnsense", {})

    wifi_clients  = mist.get("clients", [])
    aps           = mist.get("aps", [])
    wired_clients = central.get("clients", [])
    switches      = central.get("switches", [])
    wan_cards     = build_wan_cards(
                        opnsense.get("gateways", []),
                        opnsense.get("interfaces", [])
                    )

    ap_up    = sum(1 for a in aps if a.get("status") == "connected")
    sw_up    = sum(1 for s in switches if s.get("status", "").lower() == "up")

    arp_total = len(_arp_cache.get("hosts", []))

    gap = build_gap(d)
    whealth = analyze_wireless_health(mist.get("clients", []), mist.get("aps", []))

    # KPI sparklines (each colored to match its card's accent)
    spark_wireless = build_kpi_sparkline(_kpi_history.get("wireless", []), color="#00b4d8")
    spark_wifi     = build_kpi_sparkline(_kpi_history.get("wifi_weak", []), color="#d29922")
    spark_wired    = build_kpi_sparkline(_kpi_history.get("wired", []), color="#00b4d8")
    spark_total    = build_kpi_sparkline(_kpi_history.get("total", []), color="#8b949e")

    return render_template_string(OVERVIEW_HTML,
        title="Overview",
        active="home",
        last_updated=last_updated_str(),
        errors=d.get("errors", []),
        wan_cards=wan_cards,
        wifi_count=len(wifi_clients),
        wired_count=len(wired_clients),
        ap_up=ap_up,
        ap_total=len(aps),
        switch_up=sw_up,
        switch_total=len(switches),
        switches=switches,
        dhcp_total=opnsense.get("dhcp_total", 0),
        arp_total=arp_total,
        gap_count=gap["counts"]["gap"],
        wifi_weak=whealth["summary"]["weak"],
        wifi_poor=whealth["summary"]["poor"],
        top_talkers=d.get("top_talkers", []),
        opnsense_url=OPNSENSE_URL,
        spark_wireless=spark_wireless,
        spark_wifi=spark_wifi,
        spark_wired=spark_wired,
        spark_total=spark_total,
        recent_events=_event_log.recent(5),
        sle_cards=d.get("sle_cards", []),
        client_failures=d.get("client_failures", [])[:5],
        client_fail_summary=mist_client_events.summarize(d.get("client_failures", [])),
        client_fail_total=len(d.get("client_failures", [])),
    )

@app.route("/wireless")
def wireless():
    d = get_data()
    mist = d.get("mist", {})
    clients = enrich_wireless_clients(mist.get("clients", []), mist.get("aps", []))
    return render_template_string(WIRELESS_HTML,
        title="Wireless",
        active="wireless",
        last_updated=last_updated_str(),
        clients=clients,
        mist_clients_url=mist_clients_url(),
    )

@app.route("/wired")
def wired():
    d = get_data()
    central = d.get("central", {})
    clients = enrich_wired_clients(central.get("clients", []), central.get("switches", []))
    return render_template_string(WIRED_HTML,
        title="Wired",
        active="wired",
        last_updated=last_updated_str(),
        clients=clients,
    )

@app.route("/aps")
def access_points():
    d = get_data()
    aps = enrich_aps(d.get("mist", {}).get("aps", []))
    return render_template_string(APS_HTML,
        title="Access Points",
        active="aps",
        last_updated=last_updated_str(),
        aps=aps,
        mist_aps_url=mist_aps_url(),
    )

@app.route("/devices")
def devices():
    d = get_data()
    mist = d.get("mist", {})
    dhcp_leases = d.get("opnsense", {}).get("dhcp_leases", [])
    hosts = enrich_arp_hosts(_arp_cache.get("hosts", []), dhcp_leases)
    static_count = sum(1 for h in hosts if h["type"] == "Static")

    # Flag which hosts are "unaccounted" (in the gap — not seen by Mist/Central)
    from gap_analysis import norm_mac
    gap = build_gap(d)
    gap_macs = {norm_mac(g["mac"]) for g in gap["gap_devices"]}
    gap_vendors = {norm_mac(g["mac"]): g.get("vendor", "") for g in gap["gap_devices"]}
    for h in hosts:
        nm = norm_mac(h.get("mac", ""))
        h["unaccounted"] = nm in gap_macs
        if h["unaccounted"] and not h.get("vendor"):
            h["vendor"] = gap_vendors.get(nm, "")
    gap_count = len(gap_macs)

    last_scanned = _arp_cache.get("last_scanned")
    if last_scanned:
        last_scanned = datetime.fromisoformat(last_scanned).strftime("%H:%M UTC")
    else:
        last_scanned = "pending..."

    # Source reconciliation: union devices across ARP/Mist/Central, flag mismatches
    central = d.get("central", {})
    recon = reconcile_mod.reconcile(
        _arp_cache.get("hosts", []),
        mist.get("clients", []),
        central.get("clients", []),
        mist.get("aps", []),
        switches=central.get("switches", []),
        extra_infra_macs=EXTRA_INFRA_MACS,
        self_mac=SELF_MAC,
    )

    return render_template_string(DEVICES_HTML,
        title="All Devices",
        active="devices",
        last_updated=last_updated_str(),
        hosts=hosts,
        static_count=static_count,
        gap_count=gap_count,
        last_scanned=last_scanned,
        recon_summary=recon["summary"],
        recon_rows=recon["rows"],
    )

@app.route("/gap")
def gap_view():
    d = get_data()
    gap = build_gap(d)
    return render_template_string(GAP_HTML,
        title="Unaccounted Devices",
        active="gap",
        last_updated=last_updated_str(),
        counts=gap["counts"],
        devices=gap["gap_devices"],
    )

@app.route("/api/gap")
def api_gap():
    return jsonify(build_gap(get_data()))

@app.route("/events")
def events_page():
    return render_template_string(EVENTS_HTML,
        title="Events",
        active="events",
        last_updated=last_updated_str(),
        events=_event_log.all(),
    )

@app.route("/client-issues")
def client_issues_page():
    d = get_data()
    failures = list(d.get("client_failures", []))
    # attach a Mist deep-link per failure
    for f in failures:
        f["mist_url"] = mist_client_url(f.get("mac", ""))
    return render_template_string(CLIENT_ISSUES_HTML,
        title="Client Issues",
        active="clientissues",
        last_updated=last_updated_str(),
        failures=failures,
    )

@app.route("/api/debug-macs")
def api_debug_macs():
    """Temporary diagnostic: show the real MAC field names and formats from
    each live data source, so we can see why reconciliation isn't matching."""
    d = get_data()
    mist = d.get("mist", {})
    central = d.get("central", {})
    arp = _arp_cache.get("hosts", [])

    def mac_keys(obj):
        return {k: v for k, v in obj.items() if "mac" in k.lower()}

    return jsonify({
        "counts": {
            "arp": len(arp),
            "mist_clients": len(mist.get("clients", [])),
            "mist_aps": len(mist.get("aps", [])),
            "central_clients": len(central.get("clients", [])),
        },
        "arp_sample": [h.get("mac") for h in arp[:3]],
        "mist_client_sample": [mac_keys(c) for c in mist.get("clients", [])[:3]],
        "mist_ap_sample": [mac_keys(a) for a in mist.get("aps", [])[:2]],
        "central_client_sample": [mac_keys(c) for c in central.get("clients", [])[:3]],
    })

@app.route("/wireless-health")
def wireless_health():
    d = get_data()
    mist = d.get("mist", {})
    health = analyze_wireless_health(mist.get("clients", []), mist.get("aps", []))
    return render_template_string(WHEALTH_HTML,
        title="Wireless Health",
        active="whealth",
        last_updated=last_updated_str(),
        s=health["summary"],
        weak_clients=health["weak_clients"],
        per_ap=health["per_ap"],
        bands=health["bands"],
    )

@app.route("/topology")
def topology_page():
    import json as _json
    d = get_data()
    mist = d.get("mist", {})
    central = d.get("central", {})
    tree = topology_mod.build_topology(
        d.get("opnsense", {}),
        central.get("switches", []),
        mist.get("aps", []),
        mist.get("clients", []),
        include_clients=True,   # JS filters client visibility via the toggle
        wired_clients=central.get("clients", []),
        include_wired=True,     # JS filters wired visibility via the toggle
    )
    return render_template_string(TOPOLOGY_HTML,
        title="Topology",
        active="topology",
        last_updated=last_updated_str(),
        tree_json=_json.dumps(tree),
    )

@app.route("/api/topology")
def api_topology():
    d = get_data()
    mist = d.get("mist", {})
    central = d.get("central", {})
    inc = request.args.get("clients", "0") in ("1", "true", "yes")
    tree = topology_mod.build_topology(
        d.get("opnsense", {}),
        central.get("switches", []),
        mist.get("aps", []),
        mist.get("clients", []),
        include_clients=inc,
    )
    return jsonify({"tree": tree, "stats": topology_mod.topology_stats(tree)})

@app.route("/api/wireless-health")
def api_wireless_health():
    d = get_data()
    mist = d.get("mist", {})
    return jsonify(analyze_wireless_health(mist.get("clients", []), mist.get("aps", [])))

@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").lower().strip()
    if len(q) < 2:
        return jsonify([])

    d = get_data()
    mist    = d.get("mist", {})
    central = d.get("central", {})
    results = []
    seen_ips = set()

    # Build AP MAC → name + switch/port lookup
    ap_lookup = {}
    for ap in mist.get("aps", []):
        mac = ap.get("mac", "")
        lldp = ap.get("lldp_stat", {})
        if mac:
            ap_lookup[mac.lower()] = {
                "name":        ap.get("name", ""),
                "switch_name": lldp.get("system_name", ""),
                "switch_port": lldp.get("port_id", ""),
            }
    sw_lookup  = {sw.get("serial", ""): sw.get("name", "") for sw in central.get("switches", [])}

    # Search wireless clients
    for c in mist.get("clients", []):
        name = (c.get("hostname") or c.get("username") or "").lower()
        ip   = (c.get("ip") or "").lower()
        mac  = (c.get("mac") or "").lower()
        if q in name or q in ip or q in mac:
            rssi = c.get("rssi")
            rl = f"{rssi} dBm" if rssi else "—"
            ap_mac = (c.get("ap_mac") or "").lower()
            ap_info = ap_lookup.get(ap_mac, {})
            ap_name = c.get("ap_name") or ap_info.get("name") or ap_mac or "—"
            results.append({
                "source":         "wireless",
                "name":           c.get("hostname") or c.get("username") or c.get("mac"),
                "ip":             c.get("ip", ""),
                "mac":            c.get("mac", ""),
                "ap_display":     ap_name,
                "rssi_label":     rl,
                "vendor":         mac_vendor(mac.upper()) if mac else "",
                "switch_display": ap_info.get("switch_name") or None,
                "interface_port": ap_info.get("switch_port") or None,
            })
            seen_ips.add(c.get("ip", ""))

    # Search wired clients
    for c in central.get("clients", []):
        name   = (c.get("name") or c.get("hostname") or "").lower()
        ip     = (c.get("ip_address") or "").lower()
        mac    = (c.get("macaddr") or "").lower()
        if q in name or q in ip or q in mac:
            serial  = c.get("associated_device", "")
            sw_name = sw_lookup.get(serial, serial)
            results.append({
                "source":         "wired",
                "name":           c.get("name") or c.get("hostname") or c.get("macaddr"),
                "ip":             c.get("ip_address", ""),
                "mac":            c.get("macaddr", ""),
                "switch_display": sw_name or serial or "—",
                "interface_port": c.get("interface_port", ""),
                "vendor":         mac_vendor(mac.upper()) if mac else "",
                "ap_display":     None,
                "rssi_label":     None,
            })
            seen_ips.add(c.get("ip_address", ""))

    # Search ARP hosts (catches static IPs not in Mist/Central)
    for h in _arp_cache.get("hosts", []):
        ip     = h.get("ip", "")
        mac    = h.get("mac", "").lower()
        vendor = h.get("vendor", "").lower()
        hostname = h.get("hostname", "").lower()
        if ip in seen_ips:
            continue
        if q in ip or q in mac or q in vendor or q in hostname:
            results.append({
                "source":         "arp",
                "name":           h.get("hostname") or h.get("ip"),
                "ip":             ip,
                "mac":            mac,
                "vendor":         h.get("vendor", ""),
                "switch_display": None,
                "interface_port": None,
                "ap_display":     None,
                "rssi_label":     None,
            })

    return jsonify(results[:20])  # cap at 20 results

@app.route("/api/ask", methods=["POST"])
def api_ask():
    if not CFG.assistant.enabled or not ANTHROPIC_KEY_FILE.exists():
        return jsonify({"error": "The assistant is not set up. See docs/integrations.md#assistant."}), 200
    try:
        api_key = ANTHROPIC_KEY_FILE.read_text().strip()
    except Exception:
        return jsonify({"error": "Could not read API key."}), 200

    body = request.get_json(force=True, silent=True) or {}
    messages = body.get("messages", [])
    if not messages:
        return jsonify({"error": "No messages provided."}), 200

    # Cap conversation length to control token cost (keep last 10 turns)
    messages = messages[-10:]

    # Build fresh context from current snapshot + derived analytics
    d = get_data()
    gap = build_gap(d)
    mist = d.get("mist", {})
    health = analyze_wireless_health(mist.get("clients", []), mist.get("aps", []))
    context = ai_assistant.build_context(d, gap=gap, health=health, top_talkers=d.get("top_talkers", []))

    result = ai_assistant.ask(api_key, messages, context, model=CFG.assistant.model,
                              max_tokens=CFG.assistant.max_tokens)
    return jsonify(result)

@app.route("/api/wan-history")
def api_wan_history():
    window = request.args.get("window", "short")
    n = WAN_METRICS_SHORT if window == "short" else WAN_METRICS_MAX
    out = {}
    for key, hist in _wan_metrics_history.items():
        out[key] = hist[-n:]
    return jsonify({"window": window, "gateways": out})

@app.route("/api/traffic")
def api_traffic():
    return jsonify({
        "history": {k: v[-3:] for k, v in _traffic_history.items()},
        "prev_counters": {k: {"ts": v["ts"]} for k, v in _prev_counters.items()},
    })

@app.route("/api/data")
def api_data():
    """Raw JSON endpoint for debugging."""
    return jsonify(_cache.get("data", {}))

@app.route("/api/status")
def api_status():
    return jsonify({
        "last_updated": _cache.get("last_updated"),
        "fetching": _cache.get("fetching"),
        "errors": _cache.get("error"),
    })


# ── Startup ───────────────────────────────────────────────────────────────────

_ui.install(app, globals())
admin.install(app, globals())


def check_integrations() -> int:
    """--check: confirm each enabled integration's credentials and one API call."""
    import shutil

    def line(name, ok, msg):
        print(f"  {'OK  ' if ok else 'FAIL'}  {name:<15} {msg}")
        return ok

    def needs(name, path):
        if not path.exists():
            return line(name, False, f"credential file not found: {path}")
        return True

    print(f"config: {CFG.config_path or '(none found; using defaults)'}")
    print(f"site:   {CFG.site.name} · LAN {', '.join(CFG.site.lan_subnets)} · {CFG.site.timezone}")
    results = []
    if CFG.mist.enabled and needs("Mist", MIST_TOKEN_FILE):
        try:
            c = MistClient()
            org = MIST_ORG_ID or c.org_id()
            names = [x.get("name") for x in c.sites(org)]
            results.append(line("Mist", True, f"org {org}; sites: {', '.join(names) or 'none'}"))
        except Exception as e:
            results.append(line("Mist", False, str(e)[:160]))
    if CFG.central.enabled and needs("Aruba Central", CENTRAL_TOKEN):
        try:
            sw = CentralClient().switches()
            results.append(line("Aruba Central", True, f"{len(sw)} switch(es)"))
        except Exception as e:
            results.append(line("Aruba Central", False, str(e)[:160]))
    if CFG.opnsense.enabled and needs("OPNsense", OPNSENSE_KEY):
        try:
            gw = OPNsenseClient().gateways()
            names = [g.get("name") for g in gw.get("items", gw.get("gateways", []))]
            results.append(line("OPNsense", True, f"gateways: {', '.join(names) or 'none'}"))
            c = OPNsenseClient()
            for path in ("/api/diagnostics/system/system_time", "/api/core/service/search",
                         "/api/core/firmware/status", "/api/diagnostics/firewall/log?limit=1",
                         *(f"/api/diagnostics/traffic/top/{i}" for i in CFG.opnsense.top_interfaces)):
                try:
                    c.get(path)
                except Exception as e:
                    results.append(line("OPNsense extra", False, f"{path.split('?')[0]}: {str(e)[:100]}"))
            missing = [w.gateway for w in WANS if w.gateway and w.gateway not in names]
            if missing:
                results.append(line("OPNsense WANs", False, f"not reported by OPNsense: {', '.join(missing)}"))
        except Exception as e:
            results.append(line("OPNsense", False, str(e)[:160]))
    if CFG.arp_scan.enabled:
        exe = shutil.which("arp-scan")
        results.append(line("arp-scan", bool(exe), exe or "not installed (apt install arp-scan)"))
    if CFG.ntopng.enabled and needs("ntopng", NTOPNG_TOKEN_FILE):
        tt = ntopng_talkers.fetch_top_talkers(NTOPNG_URL, NTOPNG_TOKEN_FILE.read_text().strip(), top_n=1)
        results.append(line("ntopng", not tt.get("error"), tt.get("error") or "REST API answered"))
    if CFG.home_assistant.enabled and needs("Home Assistant", HA_TOKEN_FILE):
        try:
            r = requests.get(f"{HA_URL}/api/", timeout=5,
                             headers={"Authorization": f"Bearer {HA_TOKEN_FILE.read_text().strip()}"})
            results.append(line("Home Assistant", r.ok, f"HTTP {r.status_code}"))
        except Exception as e:
            results.append(line("Home Assistant", False, str(e)[:160]))
    if CFG.assistant.enabled:
        results.append(needs("Assistant", ANTHROPIC_KEY_FILE) and
                       line("Assistant", True, f"key file present; model {CFG.assistant.model}"))
    if not results:
        print("  (no integrations enabled; turn some on in config.yaml)")
    return 0 if all(results) else 1


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Network dashboard")
    ap.add_argument("--config", help="path to config.yaml (default: next to app.py, or $NETDASH_CONFIG)")
    ap.add_argument("--check", action="store_true", help="test each enabled integration and exit")
    ap.add_argument("--set-admin-password", action="store_true",
                    help="set the password for Settings → Credentials, then exit")
    args = ap.parse_args()
    if args.check:
        sys.exit(check_integrations())
    if args.set_admin_password:
        admin.set_password(CFG)
        sys.exit(0)

    # Load persisted device seen-history before scanning begins
    load_seen_history()

    # Initial fetch in background so server starts immediately
    threading.Thread(target=poll_loop, daemon=True).start()

    # Firewall health/services/log/bandwidth on their own cycle
    if OPN_EXTRAS:
        OPN_EXTRAS.start()

    # ARP scan runs on a separate, slower cycle
    if CFG.arp_scan.enabled:
        threading.Thread(target=arp_poll_loop, daemon=True).start()

    print(f"Starting {CFG.site.name} dashboard on http://{CFG.server.host}:{CFG.server.port}")
    app.run(host=CFG.server.host, port=CFG.server.port, debug=False)
