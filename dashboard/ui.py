"""Page templates and view helpers for the network dashboard.

app.py renders the *_HTML templates defined here and calls install(app,
globals()) once at startup. install() registers the Jinja helpers (paging and
filtering for Events and Client Issues, radio/client/AP/switch views, local
times, sidebar counts), the /switches page and its Central poller, and the
per-request context that shows or hides parts of the UI for integrations that
are switched off in config.yaml.
"""
import ipaddress
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from math import ceil
from urllib.parse import urlencode

LOCAL_TZ = timezone.utc   # replaced from site.timezone by install()


def _set_timezone(name):
    global LOCAL_TZ
    try:
        from zoneinfo import ZoneInfo
        LOCAL_TZ = ZoneInfo(name)
    except Exception:
        print(f"[UI] unknown timezone {name!r}; using UTC", flush=True)
        LOCAL_TZ = timezone.utc

__all__ = [
    "BASE_HTML", "OVERVIEW_HTML", "WIRELESS_HTML", "WIRED_HTML", "APS_HTML",
    "DEVICES_HTML", "GAP_HTML", "WHEALTH_HTML", "EVENTS_HTML",
    "CLIENT_ISSUES_HTML", "TOPOLOGY_HTML", "SWITCHES_HTML",
]

PER_PAGE = 100


# ── helpers exposed to templates ─────────────────────────────────────────────

def _local(dt):
    return dt.astimezone(LOCAL_TZ)


def _parse_iso(ts):
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _day_label(dt):
    today = _local(datetime.now(timezone.utc)).date()
    d = _local(dt).date()
    if d == today:
        return "Today"
    if (today - d).days == 1:
        return "Yesterday"
    return _local(dt).strftime("%a %d %b")


def local_time(value, fmt="%H:%M"):
    """ISO string or unix seconds -> local wall-clock string."""
    if value in (None, ""):
        return "—"
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, timezone.utc)
    else:
        dt = _parse_iso(value)
        if dt is None:
            return str(value)
    return _local(dt).strftime(fmt)


def qs(args, **changes):
    """Merge changes into the current query args; drops empties, resets page."""
    merged = dict(args)
    if "page" not in changes:
        merged.pop("page", None)
    merged.update(changes)
    clean = {k: v for k, v in merged.items() if v not in (None, "")}
    if str(clean.get("page")) == "1":
        clean.pop("page")
    return "?" + urlencode(clean) if clean else "?"


def _page_of(rows, args, per=PER_PAGE):
    total = len(rows)
    pages = max(1, ceil(total / per))
    try:
        page = min(max(1, int(args.get("page", 1))), pages)
    except ValueError:
        page = 1
    start = (page - 1) * per
    return rows[start:start + per], {
        "total": total, "page": page, "pages": pages,
        "first": start + 1 if total else 0, "last": min(start + per, total),
    }


def events_view(events, args):
    kind = args.get("kind", "")
    sev = args.get("sev", "")
    q = args.get("q", "").strip()
    ql = q.lower()

    kinds = Counter(e.get("kind", "other") for e in events)
    sevs = Counter(e.get("severity", "info") for e in events)
    rows = [e for e in events
            if (not kind or e.get("kind") == kind)
            and (not sev or e.get("severity") == sev)
            and (not ql or ql in e.get("message", "").lower())]
    repeats = Counter(e.get("message", "") for e in rows).most_common(6)

    page_rows, pager = _page_of(rows, args)
    items, last_day = [], None
    for e in page_rows:
        dt = _parse_iso(e.get("ts"))
        day = _day_label(dt) if dt else ""
        items.append({**e, "_day": day if day != last_day else None,
                      "_time": _local(dt).strftime("%H:%M:%S") if dt else ""})
        last_day = day
    return {
        "rows": items, "pager": pager, "kinds": kinds.most_common(),
        "sevs": sevs, "repeats": [r for r in repeats if r[1] > 1],
        "kind": kind, "sev": sev, "q": q, "all_total": len(events),
    }


def failures_view(failures, args):
    cat = args.get("cat", "")
    q = args.get("q", "").strip()
    ql = q.lower()
    sort = args.get("sort", "new")

    cats = Counter(f.get("category", "other") for f in failures)
    labels = {f.get("category", "other"): f.get("label", "") for f in failures}

    def who(f):
        return f.get("hostname") or f.get("ip") or f.get("mac") or "?"

    rows = [f for f in failures
            if (not cat or f.get("category") == cat)
            and (not ql or ql in " ".join(str(f.get(k) or "") for k in
                                           ("hostname", "ip", "mac", "label", "ssid", "text")).lower())]
    if sort == "device":
        rows.sort(key=lambda f: (who(f).lower(), -(f.get("timestamp") or 0)))
    elif sort == "signal":
        rows.sort(key=lambda f: f.get("rssi") if f.get("rssi") is not None else 0)
    else:
        rows.sort(key=lambda f: -(f.get("timestamp") or 0))

    offenders = Counter(who(f) for f in rows)
    offender_cats = {}
    for f in rows:
        offender_cats.setdefault(who(f), Counter())[f.get("label", "")] += 1
    top = [{"who": w, "n": n, "cats": offender_cats[w].most_common(3)}
           for w, n in offenders.most_common(8)]

    page_rows, pager = _page_of(rows, args)
    return {
        "rows": [{**f, "_who": who(f)} for f in page_rows], "pager": pager,
        "cats": [(c, labels.get(c, c), n) for c, n in cats.most_common()],
        "cat": cat, "q": q, "sort": sort, "top": top, "all_total": len(failures),
    }


# ── radio / client quality / AP health (from fields Mist already returns) ────

BAND_LABEL = {"24": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}
WIFI_GEN = {"be": "Wi-Fi 7", "ax": "Wi-Fi 6", "ac": "Wi-Fi 5", "n": "Wi-Fi 4",
            "g": "Legacy (g)", "a": "Legacy (a)", "b": "Legacy (b)"}
UTIL_WARN, UTIL_BAD = 40, 60          # % channel utilisation
RETRY_WARN, RETRY_BAD = 10, 30        # retries per 100 packets
MIN_PKTS = 1000                       # ignore retry % for nearly idle clients


def _tier(v, warn, bad):
    if v is None:
        return "muted"
    return "danger" if v >= bad else ("warn" if v >= warn else "good")


def radios(aps):
    """One row per AP radio, plus shared-channel groups per band."""
    rows = []
    for ap in aps:
        for key, r in sorted((ap.get("radio_stat") or {}).items()):
            if not isinstance(r, dict) or not r.get("channel"):
                continue
            band = key.replace("band_", "")
            util = r.get("util_all")
            rows.append({
                "ap": ap.get("name") or ap.get("mac"), "band": band,
                "band_label": BAND_LABEL.get(band, band), "channel": r.get("channel"),
                "width": r.get("bandwidth"), "power": r.get("power"),
                "util": util, "util_tier": _tier(util, UTIL_WARN, UTIL_BAD),
                "own": (r.get("util_tx") or 0) + (r.get("util_rx_in_bss") or 0),
                "other_bss": r.get("util_rx_other_bss") or 0,
                "non_wifi": r.get("util_non_wifi") or 0,
                "unknown": (r.get("util_unknown_wifi") or 0) + (r.get("util_undecodable_wifi") or 0),
                "noise": r.get("noise_floor"), "clients": r.get("num_clients") or 0,
            })
    shared = {}
    for r in rows:
        shared.setdefault((r["band"], r["channel"]), []).append(r["ap"])
    overlaps = [{"band": BAND_LABEL.get(b, b), "channel": ch, "aps": names}
                for (b, ch), names in sorted(shared.items(), key=lambda x: (x[0][0], x[0][1]))
                if len(names) > 1]
    by_band = {}
    for r in rows:
        by_band.setdefault(r["band"], []).append(r)
    bands = []
    for b in ("24", "5", "6"):
        rs = by_band.get(b)
        if not rs:
            continue
        utils = [r["util"] for r in rs if r["util"] is not None]
        avg = round(sum(utils) / len(utils)) if utils else None
        bands.append({"band": b, "label": BAND_LABEL[b], "avg": avg, "max": max(utils) if utils else None,
                      "tier": _tier(max(utils) if utils else None, UTIL_WARN, UTIL_BAD),
                      "clients": sum(r["clients"] for r in rs), "radios": len(rs)})
    return {"rows": rows, "overlaps": overlaps, "bands": bands}


def client_quality(c):
    pkts = (c.get("tx_pkts") or 0) + (c.get("rx_pkts") or 0)
    retries = (c.get("tx_retries") or 0) + (c.get("rx_retries") or 0)
    pct = round(100 * retries / pkts) if pkts >= MIN_PKTS else None
    proto = (c.get("proto") or "").lower()
    return {
        "retry": pct, "retry_tier": _tier(pct, RETRY_WARN, RETRY_BAD),
        "tx_rate": c.get("tx_rate"), "rx_rate": c.get("rx_rate"),
        "gen": WIFI_GEN.get(proto, proto.upper() or "—"), "proto": proto,
    }


def worst_links(clients, aps=(), n=10):
    ap_names = {(a.get("mac") or "").lower(): a.get("name") for a in aps}
    rows = []
    for c in clients:
        q = client_quality(c)
        if q["retry"] is not None:
            rows.append({**q, "name": c.get("hostname") or c.get("mac"), "mac": c.get("mac"),
                         "ip": c.get("ip"), "band": c.get("band"), "rssi": c.get("rssi"),
                         "ap": c.get("ap_display") or ap_names.get((c.get("ap_mac") or "").lower()) or c.get("ap_mac")})
    rows.sort(key=lambda r: -r["retry"])
    return rows[:n]


def client_mix(clients):
    def band_of(c):
        b = str(c.get("band") or "")
        return "2.4 GHz" if b.startswith("2") else ("5 GHz" if b.startswith("5") else ("6 GHz" if b.startswith("6") else "—"))
    gens = Counter(WIFI_GEN.get((c.get("proto") or "").lower(), "Unknown") for c in clients)
    order = ["Wi-Fi 7", "Wi-Fi 6", "Wi-Fi 5", "Wi-Fi 4", "Legacy (g)", "Legacy (a)", "Legacy (b)", "Unknown"]
    makers = Counter((c.get("manufacture") or "Unknown").replace(" Inc.", "").replace(" Co.,Ltd", "")
                     .replace(" Technologies", "").replace(" Electronics", "").strip() for c in clients)
    parked = [c for c in clients if c.get("dual_band") and band_of(c) == "2.4 GHz"]
    return {
        "total": len(clients),
        "bands": Counter(band_of(c) for c in clients).most_common(),
        "gens": [(g, gens[g]) for g in order if gens.get(g)],
        "makers": makers.most_common(8),
        "parked": len(parked),
        "parked_names": [c.get("hostname") or c.get("mac") for c in parked][:12],
    }


def ap_health(aps, port_power=None):
    """Per-AP hardware/power/uplink facts, plus fleet-level flags.

    PoE: Mist's LLDP power_draw is what the AP negotiated with the switch,
    not what it uses. Measured draw comes from Central's per-port data
    (port_power, keyed by (switch name, port)) when the switch poller has it.
    """
    port_power = port_power or {}
    rows = []
    for ap in aps:
        lldp = ap.get("lldp_stat") or {}
        eth0 = (ap.get("port_stat") or {}).get("eth0") or {}
        temp = (ap.get("env_stat") or {}).get("cpu_temp")
        mem_t, mem_u = ap.get("mem_total_kb") or 0, ap.get("mem_used_kb") or 0
        up = ap.get("uptime") if isinstance(ap.get("uptime"), (int, float)) else 0
        rows.append({
            "name": ap.get("name") or ap.get("mac"), "mac": ap.get("mac"),
            "status": ap.get("status"), "model": ap.get("model"),
            "uptime_s": up, "rebooted": bool(up) and up < 86400,
            "temp": temp if temp else None, "cpu": ap.get("cpu_util"),
            "mem": round(100 * mem_u / mem_t) if mem_t else None,
            "poe_req": round((lldp.get("power_draw") or lldp.get("power_allocated") or 0) / 1000, 1) or None,
            "poe_used": port_power.get((lldp.get("system_name") or "", lldp.get("port_id") or "")),
            "constrained": ap.get("power_constrained"),
            "switch": lldp.get("system_name"), "port": lldp.get("port_id"),
            "speed": eth0.get("speed"), "duplex": "full" if eth0.get("full_duplex") else ("half" if eth0 else None),
            "rx_errors": eth0.get("rx_errors"), "tx_errors": eth0.get("tx_errors"),
            "firmware": ap.get("version"), "certs": bool(ap.get("expiring_certs")),
            "config_reverted": ap.get("config_reverted"),
        })
    fw = Counter(r["firmware"] for r in rows if r["firmware"])
    return {
        "rows": sorted(rows, key=lambda r: r["name"] or ""),
        "firmware": fw.most_common(),
        "poe_req_total": round(sum(r["poe_req"] or 0 for r in rows), 1),
        "poe_used_total": (round(sum(r["poe_used"] for r in rows if r["poe_used"] is not None), 1)
                           if any(r["poe_used"] is not None for r in rows) else None),
        "poe_measured": sum(1 for r in rows if r["poe_used"] is not None),
        "rebooted": [r["name"] for r in rows if r["rebooted"]],
        "slow_links": [r["name"] for r in rows if r["speed"] and r["speed"] < 1000],
        "half_duplex": [r["name"] for r in rows if r["duplex"] == "half"],
        "errors": [r["name"] for r in rows if (r["rx_errors"] or 0) + (r["tx_errors"] or 0) > 0],
        "constrained": [r["name"] for r in rows if r["constrained"]],
        "certs": [r["name"] for r in rows if r["certs"]],
    }


# ── switch detail + ports (Aruba Central, polled in the background) ──────────

SWITCH_POLL_SECONDS = 300
_sw_cache = {"by_serial": {}, "fetched": None, "error": None}
_sw_lock = threading.Lock()
_sw_started = False


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _poll_switches(g):
    while True:
        try:
            switches = g["get_data"]().get("central", {}).get("switches", [])
            if switches:
                client = g["CentralClient"]()
                out = {}
                for sw in switches:
                    serial = sw.get("serial")
                    if not serial:
                        continue
                    entry = {"detail": {}, "ports": [], "error": None}
                    try:
                        entry["detail"] = client.get(f"/monitoring/v1/switches/{serial}")
                        entry["ports"] = client.get(f"/monitoring/v1/switches/{serial}/ports").get("ports", [])
                    except Exception as e:
                        entry["error"] = str(e)[:200]
                    out[serial] = entry
                failed = any(e["error"] for e in out.values())
                with _sw_lock:
                    _sw_cache["by_serial"] = out
                    _sw_cache["fetched"] = datetime.now(timezone.utc).isoformat()
                    _sw_cache["error"] = None
            else:
                failed = True   # main poll has not produced switches yet
        except Exception as e:
            failed = True
            with _sw_lock:
                _sw_cache["error"] = str(e)[:200]
            print(f"[SWITCHES] poll failed: {e}", flush=True)
        time.sleep(60 if failed else SWITCH_POLL_SECONDS)


def _uptime_now(det):
    """Central's uptime is as of its updated_at time; add the time since then."""
    up, at = _num(det.get("uptime")), _num(det.get("updated_at"))
    if up is None:
        return None
    if at:
        up += max(0, datetime.now(timezone.utc).timestamp() - at)
    return int(up)


def _speed_label(mbps):
    n = _num(mbps)
    if not n:
        return "—"
    return f"{n / 1000:g} Gbps" if n >= 1000 else f"{n:g} Mbps"


def switches_view(g):
    """Switch health + port table, joined with who is plugged into each port."""
    d = g["get_data"]()
    central = d.get("central", {})
    with _sw_lock:
        cache = dict(_sw_cache["by_serial"])
        fetched, error = _sw_cache["fetched"], _sw_cache["error"]

    # who is on each port: wired clients (Central) and APs (Mist LLDP)
    attached = {}
    for c in central.get("clients", []):
        key = (c.get("associated_device_name") or "", c.get("interface_port") or "")
        attached.setdefault(key, []).append({
            "kind": "client", "name": c.get("name") or c.get("hostname") or c.get("macaddr"),
            "ip": c.get("ip_address"), "mac": c.get("macaddr")})
    for ap in d.get("mist", {}).get("aps", []):
        lldp = ap.get("lldp_stat") or {}
        key = (lldp.get("system_name") or "", lldp.get("port_id") or "")
        attached.setdefault(key, []).append({
            "kind": "ap", "name": ap.get("name") or ap.get("mac"), "ip": ap.get("ip"), "mac": ap.get("mac")})

    out, fw = [], Counter()
    for sw in central.get("switches", []):
        serial, name = sw.get("serial"), sw.get("name") or sw.get("serial")
        entry = cache.get(serial, {})
        det = entry.get("detail") or {}
        fw[det.get("firmware_version") or sw.get("firmware_version")] += 1
        ports = []
        for p in entry.get("ports", []):
            pn = p.get("port_number") or p.get("port")
            up = (p.get("oper_state") or p.get("status") or "").lower() == "up"
            speed = _num(p.get("speed"))
            poe_w = _num(p.get("power_consumption"))
            devs = attached.get((name, pn), [])
            ports.append({
                "port": pn, "up": up, "admin_up": (p.get("admin_state") or "").lower() == "up",
                "speed": speed, "speed_label": _speed_label(p.get("speed")) if up else "—",
                "duplex": (p.get("duplex_mode") or "").replace("-", "") or None,
                "slow": up and speed is not None and 0 < speed < 1000 and p.get("phy_type") != "SFP",
                "half": up and (p.get("duplex_mode") or "").lower() == "half",
                "poe": (p.get("poe_state") or "").lower() == "up", "poe_w": poe_w,
                "vlan": p.get("vlan"), "mode": p.get("mode"), "uplink": p.get("is_uplink"),
                "down_reason": p.get("intf_state_down_reason"), "phy": p.get("phy_type"),
                "devices": devs,
            })
        ports.sort(key=lambda x: [int(t) if t.isdigit() else t for t in str(x["port"]).replace("/", " ").split()])
        mem_free = _num(det.get("mem_free", sw.get("mem_free")))
        up_ports = [p for p in ports if p["up"]]
        out.append({
            "name": name, "serial": serial, "model": det.get("model") or sw.get("model"),
            "status": det.get("status") or sw.get("status"), "ip": det.get("ip_address") or sw.get("ip_address"),
            "firmware": det.get("firmware_version") or sw.get("firmware_version"),
            "uptime": _uptime_now(det), "cpu": _num(det.get("cpu_utilization", sw.get("cpu_utilization"))),
            "mem_used": round(100 - mem_free) if mem_free is not None else None,
            "poe_w": _num(det.get("poe_consumption")), "fan": det.get("fan_speed"),
            "temp": None if str(det.get("temperature")) in ("None", "", "0") else det.get("temperature"),
            "clients": det.get("total_clients"), "health": det.get("nae_aggr_status"),
            "ports": ports, "ports_up": len(up_ports), "ports_total": len(ports),
            "slow": [p for p in ports if p["slow"]], "half": [p for p in ports if p["half"]],
            "error": entry.get("error"), "rebooted": bool(_uptime_now(det)) and _uptime_now(det) < 86400,
        })
    return {"switches": out, "firmware": [f for f in fw if f], "fetched": fetched, "error": error,
            "pending": not fetched}


def port_power(g):
    """{(switch name, port): measured PoE watts} from the last Central poll."""
    names = {sw.get("serial"): sw.get("name") for sw in g["get_data"]().get("central", {}).get("switches", [])}
    with _sw_lock:
        cache = dict(_sw_cache["by_serial"])
    out = {}
    for serial, entry in cache.items():
        for p in entry.get("ports", []):
            w = _num(p.get("power_consumption"))
            if w is not None:
                out[(names.get(serial) or "", p.get("port_number") or p.get("port") or "")] = w
    return out


def fmt_duration(s):
    s = int(s or 0)
    if s >= 86400:
        return f"{s // 86400}d {s % 86400 // 3600}h"
    if s >= 3600:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 60}m"


def top_failing(failures, n=5):
    c = Counter((f.get("hostname") or f.get("ip") or f.get("mac") or "?") for f in failures)
    return c.most_common(n)


def _is_private_host(host):
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return host in ("localhost",) or host.endswith((".local", ".lan", ".home.arpa"))


def install(app, g):
    """Register template helpers. `g` is app.py's globals()."""
    cfg = g["CFG"]
    _set_timezone(cfg.site.timezone)
    app.jinja_env.globals.update(
        ui_events_view=events_view,
        ui_failures_view=failures_view,
        ui_top_failing=top_failing,
        ui_qs=qs,
        ui_all_failures=lambda: g["get_data"]().get("client_failures", []),
        ui_data=lambda: g["get_data"](),
        ui_radios=radios,
        ui_cq=client_quality,
        ui_worst_links=worst_links,
        ui_client_mix=client_mix,
        ui_ap_health=lambda aps: ap_health(aps, port_power(g)),
        ui_band=lambda b: BAND_LABEL.get(str(b), b),
        UTIL_WARN=UTIL_WARN, UTIL_BAD=UTIL_BAD, RETRY_WARN=RETRY_WARN, RETRY_BAD=RETRY_BAD,
    )
    app.jinja_env.filters["duration"] = fmt_duration

    # Switches page + background poller for Central switch detail/ports.
    from flask import render_template_string

    def _start_switch_poller():
        global _sw_started
        with _sw_lock:
            if _sw_started:
                return
            _sw_started = True
        threading.Thread(target=_poll_switches, args=(g,), daemon=True, name="switch-poller").start()

    if cfg.central.enabled:
        app.before_request(_start_switch_poller)

    def switches_page():
        return render_template_string(SWITCHES_HTML, title="Switches", active="switches",
                                      last_updated=g["last_updated_str"](), v=switches_view(g))

    app.add_url_rule("/switches", "switches_page", switches_page)
    app.jinja_env.filters["local_time"] = local_time

    @app.context_processor
    def _ui_context():
        counts = {}
        updated = None
        try:
            d = g["get_data"]()
            counts = {
                "wireless": len(d.get("mist", {}).get("clients", [])),
                "aps": len(d.get("mist", {}).get("aps", [])),
                "wired": len(d.get("central", {}).get("clients", [])),
                "clientissues": len(d.get("client_failures", [])),
                "devices": len(g["_arp_cache"].get("hosts", [])),
            }
            updated = g["_cache"].get("last_updated")
        except Exception:
            pass
        from flask import request
        host = request.host.split(":")[0]
        links = []
        if cfg.ntopng.enabled:
            # Inside the LAN, open ntopng on the host the dashboard was reached
            # by; from outside, use ntopng.public_url if one is set.
            if cfg.ntopng.public_url and not _is_private_host(host):
                url = cfg.ntopng.public_url
            else:
                url = cfg.ntopng.url.replace("localhost", host).replace("127.0.0.1", host)
            links.append({"name": "Flows", "url": url, "icon": "flow"})
        if cfg.opnsense.enabled:
            links.append({"name": "OPNsense", "url": cfg.opnsense.url, "icon": "fw"})
        if cfg.mist.enabled:
            links.append({"name": "Mist", "url": cfg.mist.portal, "icon": "cloud"})
        links += [dict(x) for x in cfg.links]
        return {
            "ui_counts": counts,
            "ui_updated": local_time(updated, "%H:%M:%S") if updated else "Loading…",
            "ui_site": cfg.site.name,
            "ui_links": links,
            "ui_has": {"mist": cfg.mist.enabled, "central": cfg.central.enabled,
                       "assistant": cfg.assistant.enabled},
        }


# ── shell ────────────────────────────────────────────────────────────────────

BASE_HTML = r"""{%- macro page_head(title, sub='') -%}
<div class="page-head">
  <div>
    <h1>{{ title }}</h1>
    {% if sub %}<div class="page-sub">{{ sub }}</div>{% endif %}
  </div>
  <div class="page-actions">{{ caller() if caller else '' }}</div>
</div>
{%- endmacro -%}
{%- macro pager(p, args) -%}
{% if p.pages > 1 %}
<div class="pager">
  <span class="pager-info">{{ p.first }}–{{ p.last }} of {{ '{:,}'.format(p.total) }}</span>
  <a class="btn btn-sm {{ 'disabled' if p.page <= 1 }}" href="{{ ui_qs(args, page=1) }}" title="First">«</a>
  <a class="btn btn-sm {{ 'disabled' if p.page <= 1 }}" href="{{ ui_qs(args, page=p.page-1) }}">‹ Prev</a>
  <span class="pager-page">Page {{ p.page }} / {{ p.pages }}</span>
  <a class="btn btn-sm {{ 'disabled' if p.page >= p.pages }}" href="{{ ui_qs(args, page=p.page+1) }}">Next ›</a>
  <a class="btn btn-sm {{ 'disabled' if p.page >= p.pages }}" href="{{ ui_qs(args, page=p.pages) }}" title="Last">»</a>
</div>
{% endif %}
{%- endmacro -%}
{%- macro icon(name, cls='ic') -%}<svg class="{{ cls }}" aria-hidden="true"><use href="#i-{{ name }}"/></svg>{%- endmacro -%}
{%- macro ext() -%}<svg class="ic-ext" aria-hidden="true"><use href="#i-ext"/></svg>{%- endmacro -%}
{%- set NAV = [
  ('Monitor', [
    ('home', '/', 'Overview', 'home', none),
    ('events', '/events', 'Events', 'clock', none),
  ]),
  ('Wireless', [
    ('wireless', '/wireless', 'Wireless Clients', 'wifi', 'wireless'),
    ('whealth', '/wireless-health', 'WiFi Health', 'pulse', none),
    ('aps', '/aps', 'Access Points', 'ap', 'aps'),
    ('clientissues', '/client-issues', 'Client Issues', 'alert', 'clientissues'),
  ]),
  ('Wired & Devices', [
    ('switches', '/switches', 'Switches', 'switch', none),
    ('wired', '/wired', 'Wired Clients', 'plug', 'wired'),
    ('devices', '/devices', 'All Devices', 'devices', 'devices'),
    ('gap', '/gap', 'Unaccounted', 'search', none),
    ('topology', '/topology', 'Topology', 'topo', none),
  ]),
] -%}
{%- set CRUMB = {} -%}
{%- for sec, items in NAV -%}{%- for key, href, label, ic, cnt in items -%}{%- set _ = CRUMB.update({key: (sec, label)}) -%}{%- endfor -%}{%- endfor -%}
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>{{ title }} · {{ ui_site }}</title>
  <script>
    (function(){
      try {
        var t = localStorage.getItem('nd_theme');
        if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t;
        if (localStorage.getItem('nd_sidebar') === 'collapsed') document.documentElement.classList.add('sb-collapsed');
      } catch(e){}
    })();
  </script>
  <style>
    :root{
      --bg:#f3f4f6; --surface:#ffffff; --surface2:#f7f8fa; --surface3:#eef0f3;
      --border:#e2e5e9; --border-strong:#cfd4da;
      --text:#1d2329; --text2:#3d4650; --muted:#6b7480;
      --accent:#01a982; --accent-ink:#00805f; --accent-soft:rgba(1,169,130,.10);
      --info:#0d7fb0; --info-soft:rgba(13,127,176,.10);
      --good:#0f9d6b; --good-soft:rgba(15,157,107,.11);
      --warn:#c98500; --warn-dot:#f2b01e; --warn-soft:rgba(242,176,30,.16);
      --danger:#d93f3f; --danger-dot:#f0605d; --danger-soft:rgba(240,96,93,.12);
      --brand:#ff8300; --violet:#8b6cf0;
      --shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06);
      --shadow-lg:0 10px 30px rgba(16,24,40,.16);
      --radius:10px; --radius-sm:6px;
      --grid:rgba(0,0,0,.06);
      --mono:"JetBrains Mono","SFMono-Regular",ui-monospace,Menlo,Consolas,monospace;
      --ui:"Inter","Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;
      --sb-w:232px; --top-h:56px;
      color-scheme:light;
    }
    :root[data-theme="dark"]{
      --bg:#0e1116; --surface:#161a20; --surface2:#1b2028; --surface3:#232933;
      --border:#2a3039; --border-strong:#3a424d;
      --text:#e7eaee; --text2:#c5cbd3; --muted:#949daa;
      --accent:#1fc79c; --accent-ink:#3ad7ad; --accent-soft:rgba(31,199,156,.13);
      --info:#4cb8e8; --info-soft:rgba(76,184,232,.13);
      --good:#35d398; --good-soft:rgba(53,211,152,.13);
      --warn:#f4bb45; --warn-dot:#f4bb45; --warn-soft:rgba(244,187,69,.14);
      --danger:#ff7470; --danger-dot:#ff7470; --danger-soft:rgba(255,116,112,.14);
      --shadow:0 1px 2px rgba(0,0,0,.3);
      --shadow-lg:0 12px 32px rgba(0,0,0,.5);
      --grid:rgba(255,255,255,.06); --violet:#a48cff;
      color-scheme:dark;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html{font-size:14px;-webkit-text-size-adjust:100%}
    body{background:var(--bg);color:var(--text);font-family:var(--ui);line-height:1.45;min-height:100vh}
    a{color:inherit}
    .ic{width:18px;height:18px;flex-shrink:0;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
    .ic-sm{width:14px;height:14px}
    .ic-ext{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:2;vertical-align:-1px;margin-left:2px}

    /* ── Top bar ── */
    .topbar{position:fixed;inset:0 0 auto 0;height:var(--top-h);z-index:300;display:flex;align-items:center;
            gap:1rem;padding:0 1rem;background:var(--surface);border-bottom:1px solid var(--border)}
    .tb-left{display:flex;align-items:center;gap:.6rem;min-width:calc(var(--sb-w) - 1rem)}
    .brand{display:flex;align-items:center;gap:.55rem;text-decoration:none}
    .brand-mark{width:30px;height:30px;border-radius:7px;display:grid;place-items:center;
                background:linear-gradient(135deg,var(--accent),#0b6e8f);color:#fff;font-weight:800;font-size:.8rem;letter-spacing:.02em}
    .brand-name{font-weight:700;font-size:1rem;letter-spacing:-.01em}
    .brand-name small{display:block;font-size:.66rem;font-weight:600;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;margin-top:-2px}
    .icon-btn{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:8px;border:1px solid transparent;
              background:none;color:var(--text2);cursor:pointer}
    .icon-btn:hover{background:var(--surface3);color:var(--text)}
    .tb-search{flex:1;max-width:560px;margin:0 auto;position:relative}
    .tb-search input{width:100%;height:36px;border:1px solid var(--border-strong);border-radius:8px;background:var(--surface);
                     color:var(--text);font:inherit;padding:0 .8rem 0 2.2rem;outline:none}
    .tb-search input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
    .tb-search input::placeholder{color:var(--muted)}
    .tb-search .ic{position:absolute;left:.65rem;top:50%;transform:translateY(-50%);color:var(--muted);width:16px;height:16px;pointer-events:none}
    .tb-search kbd{position:absolute;right:.55rem;top:50%;transform:translateY(-50%);font:600 .68rem var(--ui);color:var(--muted);
                   border:1px solid var(--border-strong);border-radius:4px;padding:0 .3rem;background:var(--surface2)}
    .tb-right{display:flex;align-items:center;gap:.35rem}
    .tb-updated{font-size:.75rem;color:var(--muted);white-space:nowrap;margin-right:.3rem;display:flex;align-items:center;gap:.4rem}
    .live-dot{width:7px;height:7px;border-radius:50%;background:var(--good);box-shadow:0 0 0 3px var(--good-soft)}
    .btn{display:inline-flex;align-items:center;gap:.4rem;height:32px;padding:0 .8rem;border-radius:7px;font:600 .8rem var(--ui);
         border:1px solid var(--border-strong);background:var(--surface);color:var(--text);cursor:pointer;text-decoration:none;white-space:nowrap}
    .btn:hover{border-color:var(--text2)}
    .btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
    .btn-primary:hover{filter:brightness(1.05);border-color:var(--accent)}
    .btn-sm{height:28px;padding:0 .6rem;font-size:.75rem}
    .btn.disabled{opacity:.4;pointer-events:none}
    .theme-dark-only{display:none}
    :root[data-theme="dark"] .theme-dark-only{display:inline}
    :root[data-theme="dark"] .theme-light-only{display:none}

    /* search results */
    .search-results{position:absolute;top:calc(100% + 6px);left:0;right:0;background:var(--surface);border:1px solid var(--border);
                    border-radius:var(--radius);box-shadow:var(--shadow-lg);z-index:400;display:none;max-height:70vh;overflow-y:auto}
    .search-results.visible{display:block}
    .search-result{padding:.65rem .9rem;border-bottom:1px solid var(--border);display:block;color:var(--text);text-decoration:none}
    .search-result:last-child{border-bottom:none}
    .search-result:hover{background:var(--surface2)}
    .sr-header{display:flex;align-items:center;gap:.5rem;margin-bottom:.2rem}
    .sr-name{font-weight:600;font-size:.86rem}
    .sr-line{font-size:.75rem;color:var(--muted);display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;margin-top:.1rem}
    .sr-line-dim{opacity:.8}
    .sr-sep{color:var(--border-strong)}
    .sr-mac,.sr-port{font-family:var(--mono);font-size:.7rem}
    .sr-port{background:var(--surface3);border-radius:3px;padding:0 .3rem}
    .sr-vendor{font-style:italic}
    .sr-icon{display:none}
    .sr-badge{font-size:.62rem;font-weight:700;padding:.1rem .4rem;border-radius:4px;text-transform:uppercase;letter-spacing:.05em}
    .sr-badge-wifi{background:var(--info-soft);color:var(--info)}
    .sr-badge-wired{background:var(--good-soft);color:var(--good)}
    .sr-badge-arp{background:var(--surface3);color:var(--muted)}
    .sr-empty{padding:1rem;text-align:center;color:var(--muted);font-size:.82rem}

    /* ── Sidebar ── */
    .sidebar{position:fixed;top:var(--top-h);bottom:0;left:0;width:var(--sb-w);z-index:250;background:var(--surface);
             border-right:1px solid var(--border);overflow-y:auto;padding:.75rem .6rem 1rem;display:flex;flex-direction:column;
             transition:width .15s ease}
    .sb-sec{margin-bottom:.9rem}
    .sb-sec-t{font-size:.66rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:.35rem .65rem}
    .sb-link{display:flex;align-items:center;gap:.65rem;padding:.48rem .65rem;border-radius:7px;color:var(--text2);
             text-decoration:none;font-size:.86rem;font-weight:500;position:relative;white-space:nowrap}
    .sb-link:hover{background:var(--surface3);color:var(--text)}
    .sb-link.active{background:var(--accent-soft);color:var(--accent-ink);font-weight:650}
    .sb-link.active::before{content:"";position:absolute;left:-.6rem;top:.35rem;bottom:.35rem;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
    .sb-count{margin-left:auto;font-size:.7rem;font-weight:600;color:var(--muted);background:var(--surface3);border-radius:10px;padding:.05rem .45rem}
    .sb-link.active .sb-count{background:var(--surface);color:var(--accent-ink)}
    .sb-count.hot{background:var(--danger-soft);color:var(--danger)}
    .sb-foot{margin-top:auto;border-top:1px solid var(--border);padding-top:.6rem}
    .sb-label{overflow:hidden;text-overflow:ellipsis}
    .sb-collapse{width:100%;justify-content:flex-start;gap:.65rem;padding:.48rem .65rem;height:auto;border:none;font-weight:500;color:var(--muted)}
    .sb-collapse:hover{background:var(--surface3)}
    .sb-collapse .ic{transition:transform .15s}

    html.sb-collapsed{--sb-w:64px}
    html.sb-collapsed .sb-sec-t,html.sb-collapsed .sb-label,html.sb-collapsed .sb-count{display:none}
    html.sb-collapsed .sb-link,html.sb-collapsed .sb-collapse{justify-content:center;padding:.55rem 0}
    html.sb-collapsed .sb-collapse .ic{transform:rotate(180deg)}
    html.sb-collapsed .sb-sec{border-top:1px solid var(--border);padding-top:.5rem;margin-bottom:.5rem}
    html.sb-collapsed .sb-sec:first-child{border-top:none}
    html.sb-collapsed .tb-left{min-width:0}

    /* ── Main ── */
    .content{margin-left:var(--sb-w);padding:calc(var(--top-h) + 1.1rem) 1.5rem 3rem;transition:margin-left .15s ease;min-width:0}
    .content-inner{max-width:1600px;margin:0 auto}
    .crumbs{display:flex;align-items:center;gap:.35rem;font-size:.78rem;color:var(--muted);margin-bottom:.35rem}
    .crumbs a{text-decoration:none;color:var(--muted)}
    .crumbs a:hover{color:var(--text)}
    .crumbs b{color:var(--text2);font-weight:600}
    .page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1.1rem}
    .page-head h1{font-size:1.55rem;font-weight:750;letter-spacing:-.02em;line-height:1.2}
    .page-sub{font-size:.85rem;color:var(--muted);margin-top:.15rem}
    .page-actions{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}

    /* ── Cards & grid ── */
    .grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:1rem;margin-bottom:1rem}
    .c3{grid-column:span 3}.c4{grid-column:span 4}.c5{grid-column:span 5}.c6{grid-column:span 6}
    .c7{grid-column:span 7}.c8{grid-column:span 8}.c9{grid-column:span 9}.c12{grid-column:span 12}
    .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);
          display:flex;flex-direction:column;min-width:0}
    .card-h{display:flex;align-items:flex-start;justify-content:space-between;gap:.75rem;padding:.95rem 1.1rem .2rem}
    .card-t{font-size:.98rem;font-weight:700;letter-spacing:-.005em;display:flex;align-items:center;gap:.5rem}
    .card-t .ic{color:var(--muted);width:17px;height:17px}
    .card-sub{font-size:.78rem;color:var(--muted);margin-top:.1rem}
    .card-x{display:flex;align-items:center;gap:.5rem;flex-shrink:0}
    .card-b{padding:.75rem 1.1rem 1rem;flex:1;min-width:0}
    .card-b.flush{padding:.5rem 0 0}
    .card-link{font-size:.78rem;font-weight:600;color:var(--info);text-decoration:none;white-space:nowrap;display:inline-flex;align-items:center;gap:.2rem}
    .card-link:hover{text-decoration:underline}
    .card-foot{border-top:1px solid var(--border);padding:.55rem 1.1rem;font-size:.75rem;color:var(--muted);display:flex;justify-content:space-between;align-items:center;gap:.5rem}
    .empty{padding:2.2rem 1rem;text-align:center;color:var(--muted);font-size:.85rem}
    .empty .ic{width:34px;height:34px;display:block;margin:0 auto .5rem;opacity:.5}
    .note{font-size:.78rem;color:var(--muted);line-height:1.5}
    .info-banner{display:flex;gap:.6rem;align-items:flex-start;font-size:.8rem;color:var(--text2);background:var(--info-soft);
                 border-radius:8px;padding:.6rem .8rem;margin-top:.6rem}
    .info-banner .ic{color:var(--info);width:16px;height:16px;margin-top:1px}
    .error-banner{display:flex;gap:.6rem;align-items:center;background:var(--danger-soft);border:1px solid var(--danger);
                  color:var(--danger);border-radius:var(--radius);padding:.7rem 1rem;margin-bottom:1rem;font-size:.84rem;font-weight:500}

    /* stat tiles */
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin-bottom:1rem}
    .stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);
          padding:.9rem 1.05rem;text-decoration:none;color:inherit;display:block;position:relative}
    a.stat:hover{border-color:var(--accent)}
    .stat-l{font-size:.78rem;font-weight:600;color:var(--muted);display:flex;align-items:center;gap:.4rem}
    .stat-l .ic{width:15px;height:15px}
    .stat-v{font-size:1.9rem;font-weight:750;letter-spacing:-.02em;line-height:1.15;margin-top:.25rem;font-variant-numeric:tabular-nums}
    .stat-v small{font-size:1rem;color:var(--muted);font-weight:600}
    .stat-s{font-size:.76rem;color:var(--muted);margin-top:.1rem}
    .stat-spark{margin-top:.45rem;height:26px}
    .kpi-spark{width:100%;height:26px;display:block}
    .v-good{color:var(--good)}.v-warn{color:var(--warn)}.v-danger{color:var(--danger)}.v-info{color:var(--info)}

    /* status dots / pills */
    .dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0;background:var(--muted)}
    .dot.good{background:var(--good)}.dot.warn{background:var(--warn-dot)}.dot.danger{background:var(--danger-dot)}.dot.info{background:var(--info)}
    .status{display:inline-flex;align-items:center;gap:.4rem;font-size:.8rem;font-weight:500}
    .pill{display:inline-flex;align-items:center;gap:.3rem;border-radius:5px;padding:.08rem .45rem;font-size:.72rem;font-weight:600;white-space:nowrap}
    .pill-good{background:var(--good-soft);color:var(--good)}
    .pill-warn{background:var(--warn-soft);color:var(--warn)}
    .pill-danger{background:var(--danger-soft);color:var(--danger)}
    .pill-accent,.pill-info{background:var(--info-soft);color:var(--info)}
    .pill-muted{background:var(--surface3);color:var(--muted)}
    .cat-auth{background:var(--danger-soft);color:var(--danger)}
    .cat-dhcp,.cat-dns{background:var(--warn-soft);color:var(--warn)}
    .cat-assoc,.cat-roam,.cat-arp{background:var(--info-soft);color:var(--info)}
    .cat-other{background:var(--surface3);color:var(--muted)}
    .good{color:var(--good)}.warn{color:var(--warn)}.danger{color:var(--danger)}.muted{color:var(--muted)}
    .mono{font-family:var(--mono);font-size:.76rem}

    /* health rows (Central-style segmented bar) */
    .hbar{height:6px;border-radius:3px;display:flex;overflow:hidden;background:var(--surface3)}
    .hbar span{display:block;height:100%}
    .hbar .p{background:var(--danger-dot)}.hbar .f{background:var(--warn-dot)}.hbar .g{background:var(--good)}
    .hlegend{display:flex;gap:1rem;font-size:.72rem;color:var(--muted);margin:.4rem 0 .2rem}
    .hlegend span{display:inline-flex;align-items:center;gap:.35rem}
    .htable{width:100%;border-collapse:collapse;font-size:.84rem;margin-top:.4rem}
    .htable th{font-size:.7rem;font-weight:600;color:var(--muted);text-align:left;padding:.35rem 0;border-bottom:1px solid var(--border)}
    .htable td{padding:.55rem 0;border-bottom:1px solid var(--border);vertical-align:middle}
    .htable tr:last-child td{border-bottom:none}
    .htable td.n{text-align:right;width:4.5rem;font-variant-numeric:tabular-nums;font-weight:600}
    .htable td.n .dot{margin-right:.35rem}
    .htable td.n.zero{color:var(--muted);font-weight:400;opacity:.6}
    .htable td.n.zero .dot{display:none}
    .htable a{text-decoration:none;display:inline-flex;align-items:center;gap:.5rem;font-weight:600}
    .htable a:hover{color:var(--accent-ink)}
    .htable .ic{color:var(--muted);width:16px;height:16px}
    .htable td.bar{width:34%;padding-left:1rem}

    /* metric bars (SLE / top-N) */
    .mlist{display:flex;flex-direction:column;gap:.75rem}
    .mrow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.15rem .75rem;align-items:baseline}
    .mrow-l{font-size:.84rem;font-weight:600;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .mrow-v{font-size:.84rem;font-weight:700;font-variant-numeric:tabular-nums}
    .mrow-s{font-size:.72rem;color:var(--muted);grid-column:1/-1;margin-top:-.1rem}
    .mbar{grid-column:1/-1;height:6px;border-radius:3px;background:var(--surface3);overflow:hidden}
    .mbar span{display:block;height:100%;border-radius:3px;background:var(--good)}
    .mbar.warn span{background:var(--warn-dot)}.mbar.bad span{background:var(--danger-dot)}.mbar.info span{background:var(--info)}

    /* tables */
    .tbl-tools{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;padding:.2rem 1.1rem .7rem}
    .tbl-filter{position:relative;flex:1;max-width:340px;min-width:180px}
    .tbl-filter input{width:100%;height:32px;border:1px solid var(--border-strong);border-radius:7px;background:var(--surface);color:var(--text);
                      font:inherit;font-size:.82rem;padding:0 .7rem 0 2rem;outline:none}
    .tbl-filter input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
    .tbl-filter .ic{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);width:14px;height:14px;color:var(--muted)}
    .tbl-count{font-size:.76rem;color:var(--muted);margin-left:auto}
    .chips{display:flex;gap:.35rem;flex-wrap:wrap}
    .chip{height:28px;display:inline-flex;align-items:center;gap:.35rem;padding:0 .7rem;border-radius:14px;border:1px solid var(--border-strong);
          background:var(--surface);color:var(--text2);font:600 .75rem var(--ui);cursor:pointer;text-decoration:none;white-space:nowrap}
    .chip:hover{border-color:var(--text2)}
    .chip.on{background:var(--text);border-color:var(--text);color:var(--surface)}
    .chip b{font-weight:700;opacity:.75}
    .table-wrap{overflow-x:auto;border-top:1px solid var(--border)}
    table.t{width:100%;border-collapse:collapse;font-size:.83rem}
    table.t thead th{position:sticky;top:0;background:var(--surface2);color:var(--muted);font-size:.72rem;font-weight:650;
                     text-align:left;padding:.55rem .9rem;border-bottom:1px solid var(--border);white-space:nowrap;user-select:none}
    table.t.sortable thead th{cursor:pointer}
    table.t.sortable thead th:hover{color:var(--text)}
    table.t thead th.sort-asc::after{content:" ▲";font-size:.58rem;color:var(--accent)}
    table.t thead th.sort-desc::after{content:" ▼";font-size:.58rem;color:var(--accent)}
    table.t tbody tr{border-bottom:1px solid var(--border)}
    table.t tbody tr:last-child{border-bottom:none}
    table.t tbody tr:hover{background:var(--surface2)}
    table.t td{padding:.55rem .9rem;vertical-align:middle}
    table.t td.c,table.t th.c{text-align:center}
    table.t td.r,table.t th.r{text-align:right}
    .dev-name{font-weight:600;color:var(--text)}
    .dev-sub{font-family:var(--mono);font-size:.7rem;color:var(--muted);margin-top:1px}
    .dev-vendor{font-size:.72rem;color:var(--muted);margin-top:1px}
    .dev-link{color:var(--text);text-decoration:none}
    .dev-link:hover{color:var(--info);text-decoration:underline}
    .ext-link{font-size:.76rem;font-weight:600;color:var(--info);text-decoration:none;white-space:nowrap}
    .ext-link:hover{text-decoration:underline}
    .rssi{display:inline-flex;align-items:center;gap:.45rem;font-variant-numeric:tabular-nums;white-space:nowrap}
    .rssi-bars{display:inline-flex;align-items:flex-end;gap:2px;height:12px}
    .rssi-bars i{display:block;width:3px;border-radius:1px;background:var(--surface3)}
    .rssi-bars i:nth-child(1){height:4px}.rssi-bars i:nth-child(2){height:7px}.rssi-bars i:nth-child(3){height:10px}.rssi-bars i:nth-child(4){height:12px}
    .rssi.good .rssi-bars i{background:var(--good)}
    .rssi.warn .rssi-bars i:nth-child(-n+2){background:var(--warn-dot)}
    .rssi.danger .rssi-bars i:nth-child(1){background:var(--danger-dot)}
    .src-yes{color:var(--good);font-weight:700}
    .src-no{color:var(--muted);opacity:.35}
    tr.hidden{display:none}

    /* utilisation bars + notes */
    .ubar-row{display:flex;align-items:center;gap:.6rem}
    .ubar-v{font-weight:700;font-variant-numeric:tabular-nums;min-width:2.6rem;text-align:right}
    .ubar{flex:1;height:8px;border-radius:4px;background:var(--surface3);display:flex;overflow:hidden;min-width:120px}
    .ubar span{display:block;height:100%}
    .u-own{background:var(--info)}.u-obss{background:var(--violet)}.u-nw{background:var(--danger-dot)}.u-unk{background:var(--border-strong)}
    .notes{list-style:none;display:flex;flex-direction:column;gap:.4rem}
    .notes li{font-size:.84rem;padding-left:1.1rem;position:relative}
    .notes li::before{content:"";position:absolute;left:.1rem;top:.5rem;width:7px;height:7px;border-radius:50%;background:var(--warn-dot)}
    .gen-badge{font-size:.68rem;font-weight:700;border-radius:4px;padding:.05rem .35rem;background:var(--surface3);color:var(--text2);white-space:nowrap}
    .gen-badge.g6,.gen-badge.g7{background:var(--good-soft);color:var(--good)}
    .gen-badge.legacy{background:var(--warn-soft);color:var(--warn)}

    /* pager */
    .pager{display:flex;align-items:center;gap:.4rem;justify-content:flex-end;padding:.7rem 1.1rem;border-top:1px solid var(--border);flex-wrap:wrap}
    .pager-info{font-size:.76rem;color:var(--muted);margin-right:auto}
    .pager-page{font-size:.76rem;color:var(--text2);padding:0 .3rem}

    /* sparkline overrides for generated SVGs (work in both themes) */
    .sparkline-wrap{margin-top:.7rem;border-top:1px solid var(--border);padding-top:.55rem}
    .sparkline-svg{width:100%;height:56px;display:block}
    .sparkline-svg line{stroke:var(--grid)}
    .sparkline-svg path[stroke="#00b4d8"]{stroke:var(--info)}
    .sparkline-svg path[stroke="#3fb950"]{stroke:var(--good)}
    .sparkline-svg path[stroke="#d29922"]{stroke:var(--warn-dot)}
    .sparkline-scale{font-size:.66rem;color:var(--muted);text-align:right;margin-bottom:2px}
    .sparkline-legend{display:flex;gap:.8rem;align-items:center;margin-top:.3rem;font-size:.74rem;font-weight:600}
    .sparkline-legend span[style*="00b4d8"],.sparkline-rx{color:var(--info)!important}
    .sparkline-legend span[style*="d29922"]{color:var(--warn)!important}
    .sparkline-tx{color:var(--good)}
    .sparkline-period{color:var(--muted);margin-left:auto;font-weight:500}

    /* assistant drawer */
    .drawer{position:fixed;top:var(--top-h);right:0;bottom:0;width:min(420px,100vw);background:var(--surface);border-left:1px solid var(--border);
            box-shadow:var(--shadow-lg);z-index:350;display:flex;flex-direction:column;transform:translateX(105%);transition:transform .18s ease}
    .drawer.open{transform:none}
    .drawer-h{display:flex;align-items:center;justify-content:space-between;padding:.9rem 1rem;border-bottom:1px solid var(--border)}
    .drawer-h b{font-size:.95rem;display:flex;align-items:center;gap:.5rem}
    .drawer-h b .ic{color:var(--accent)}
    .ai-conversation{flex:1;overflow-y:auto;padding:1rem;display:flex;flex-direction:column;gap:.6rem}
    .ai-hint{font-size:.8rem;color:var(--muted);line-height:1.5}
    .ai-hint button{display:block;margin-top:.45rem;text-align:left;font:500 .8rem var(--ui);color:var(--text2);background:var(--surface2);
                    border:1px solid var(--border);border-radius:8px;padding:.45rem .65rem;cursor:pointer;width:100%}
    .ai-hint button:hover{border-color:var(--accent)}
    .ai-msg{font-size:.84rem;line-height:1.5;padding:.55rem .75rem;border-radius:10px;white-space:pre-wrap;word-break:break-word}
    .ai-msg-user{background:var(--accent);color:#fff;align-self:flex-end;max-width:88%}
    .ai-msg-ai{background:var(--surface2);border:1px solid var(--border);color:var(--text)}
    .ai-msg-error{background:var(--danger-soft);color:var(--danger)}
    .ai-thinking{color:var(--muted);font-style:italic}
    .ai-input-row{display:flex;gap:.5rem;padding:.8rem 1rem;border-top:1px solid var(--border)}
    #ai-input{flex:1;min-width:0;height:36px;border:1px solid var(--border-strong);border-radius:8px;background:var(--surface);color:var(--text);
              font:inherit;padding:0 .7rem;outline:none}
    #ai-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
    #ai-send:disabled{opacity:.5}
    .ai-clear{background:none;border:none;font:500 .75rem var(--ui);color:var(--muted);cursor:pointer;text-decoration:underline}

    .scrim{position:fixed;inset:var(--top-h) 0 0 0;background:rgba(0,0,0,.3);z-index:240;display:none}

    @media (max-width:1200px){.c3,.c4,.c5{grid-column:span 6}.c7,.c8,.c9{grid-column:span 12}}
    @media (max-width:900px){
      :root,html.sb-collapsed{--sb-w:248px}
      .sidebar{transform:translateX(-100%);transition:transform .18s ease;box-shadow:var(--shadow-lg)}
      html.sb-open .sidebar{transform:none}
      html.sb-open .scrim{display:block}
      html.sb-collapsed .sb-sec-t,html.sb-collapsed .sb-label,html.sb-collapsed .sb-count{display:initial}
      html.sb-collapsed .sb-link{justify-content:flex-start;padding:.48rem .65rem}
      .sb-foot{display:none}
      .content{margin-left:0;padding-left:1rem;padding-right:1rem}
      .tb-left{min-width:0}
      .brand-name small,.tb-updated span.t,.tb-search kbd{display:none}
      .c3,.c4,.c5,.c6,.c7,.c8,.c9,.c12{grid-column:span 12}
    }
    @media (max-width:600px){
      .brand-name{display:none}
      .tb-updated{display:none}
      .page-head h1{font-size:1.3rem}
    }
  </style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <defs>
    <symbol id="i-home" viewBox="0 0 24 24"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/><path d="M10 21v-6h4v6"/></symbol>
    <symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></symbol>
    <symbol id="i-wifi" viewBox="0 0 24 24"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1"/></symbol>
    <symbol id="i-pulse" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></symbol>
    <symbol id="i-ap" viewBox="0 0 24 24"><circle cx="12" cy="13" r="2"/><path d="M8.5 9.5a5 5 0 0 0 0 7"/><path d="M15.5 9.5a5 5 0 0 1 0 7"/><path d="M5.6 6.6a9 9 0 0 0 0 12.8"/><path d="M18.4 6.6a9 9 0 0 1 0 12.8"/></symbol>
    <symbol id="i-alert" viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></symbol>
    <symbol id="i-switch" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/></symbol>
    <symbol id="i-plug" viewBox="0 0 24 24"><path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v5"/></symbol>
    <symbol id="i-devices" viewBox="0 0 24 24"><rect x="2" y="4" width="14" height="10" rx="1.5"/><path d="M6 18h6M9 14v4"/><rect x="17" y="8" width="5" height="12" rx="1"/></symbol>
    <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></symbol>
    <symbol id="i-topo" viewBox="0 0 24 24"><rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-3h14v3"/></symbol>
    <symbol id="i-flow" viewBox="0 0 24 24"><path d="M3 17l6-6 4 4 8-8"/><path d="M14 7h7v7"/></symbol>
    <symbol id="i-fw" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/></symbol>
    <symbol id="i-cloud" viewBox="0 0 24 24"><path d="M17.5 19a4.5 4.5 0 1 0-1.4-8.78A6 6 0 0 0 4.5 12.5 3.5 3.5 0 0 0 6 19z"/></symbol>
    <symbol id="i-ext" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/></symbol>
    <symbol id="i-menu" viewBox="0 0 24 24"><path d="M3 6h18M3 12h18M3 18h18"/></symbol>
    <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
    <symbol id="i-moon" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></symbol>
    <symbol id="i-refresh" viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></symbol>
    <symbol id="i-spark" viewBox="0 0 24 24"><path d="M12 3l1.8 4.7L18.5 9.5l-4.7 1.8L12 16l-1.8-4.7L5.5 9.5l4.7-1.8z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"/></symbol>
    <symbol id="i-chev" viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></symbol>
    <symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></symbol>
    <symbol id="i-x" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></symbol>
    <symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></symbol>
    <symbol id="i-check" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/></symbol>
  </defs>
</svg>

<header class="topbar">
  <div class="tb-left">
    <button class="icon-btn" id="sb-toggle" title="Menu" aria-label="Toggle navigation">{{ icon('menu') }}</button>
    <a class="brand" href="/">
      <span class="brand-mark">HN</span>
      <span class="brand-name">{{ ui_site }}<small>Network Monitoring</small></span>
    </a>
  </div>
  <div class="tb-search">
    {{ icon('search') }}
    <input type="text" id="nav-search-input" placeholder="Search devices by name, IP or MAC" autocomplete="off"/>
    <kbd>/</kbd>
    <div class="search-results" id="search-results"></div>
  </div>
  <div class="tb-right">
    <span class="tb-updated" title="Data refreshes every 60 seconds"><span class="live-dot"></span><span class="t">Updated</span> <span id="last-updated">{{ ui_updated }}</span></span>
    <button class="icon-btn" onclick="location.reload()" title="Refresh now">{{ icon('refresh') }}</button>
    <button class="icon-btn" id="theme-toggle" title="Toggle light / dark">
      <span class="theme-light-only">{{ icon('moon') }}</span><span class="theme-dark-only">{{ icon('sun') }}</span>
    </button>
    <button class="btn btn-primary" id="ai-open" title="Ask the network assistant"{% if not ui_has.assistant %} hidden{% endif %}>{{ icon('spark', 'ic ic-sm') }} Ask</button>
  </div>
</header>

<nav class="sidebar" aria-label="Main">
  {% for sec, items in NAV if (sec != 'Wireless' or ui_has.mist) %}
  <div class="sb-sec">
    <div class="sb-sec-t">{{ sec }}</div>
    {% for key, href, label, ic, cnt in items if ui_has.central or key not in ('switches', 'wired') %}
    <a class="sb-link {{ 'active' if active == key }}" href="{{ href }}" title="{{ label }}">
      {{ icon(ic) }}<span class="sb-label">{{ label }}</span>
      {% if cnt and ui_counts.get(cnt) is not none %}<span class="sb-count {{ 'hot' if cnt == 'clientissues' and ui_counts[cnt] }}">{{ '{:,}'.format(ui_counts[cnt]) }}</span>{% endif %}
    </a>
    {% endfor %}
  </div>
  {% endfor %}
  {% if ui_links %}
  <div class="sb-sec">
    <div class="sb-sec-t">Tools</div>
    {% for ln in ui_links %}
    <a class="sb-link" target="_blank" rel="noopener" href="{{ ln.url }}" title="{{ ln.name }}">{{ icon(ln.icon) }}<span class="sb-label">{{ ln.name }} {{ ext() }}</span></a>
    {% endfor %}
  </div>
  {% endif %}
  <div class="sb-foot">
    <button class="btn sb-collapse" id="sb-collapse" title="Collapse sidebar">{{ icon('chev') }}<span class="sb-label">Collapse</span></button>
  </div>
</nav>
<div class="scrim" id="scrim"></div>

<main class="content">
  <div class="content-inner">
    <div class="crumbs">
      <a href="/">Home</a>
      {% if active != 'home' and CRUMB.get(active) %}
      <span>›</span><span>{{ CRUMB[active][0] }}</span><span>›</span><b>{{ CRUMB[active][1] }}</b>
      {% endif %}
    </div>
{% block content %}{% endblock %}
  </div>
</main>

<aside class="drawer" id="ai-drawer" aria-label="Network assistant">
  <div class="drawer-h">
    <b>{{ icon('spark') }} Network Assistant</b>
    <button class="icon-btn" id="ai-close" title="Close">{{ icon('x') }}</button>
  </div>
  <div id="ai-conversation" class="ai-conversation">
    <div class="ai-hint" id="ai-hint">Ask anything about the network: clients, APs, WAN, recent problems.
      <button type="button">Which devices are having the most trouble?</button>
      <button type="button">Is the internet connection healthy right now?</button>
      <button type="button">Which access point has the weakest clients?</button>
    </div>
  </div>
  <div class="ai-input-row">
    <input type="text" id="ai-input" placeholder="Ask about your network…" autocomplete="off"/>
    <button class="btn btn-primary" id="ai-send">Ask</button>
  </div>
</aside>

<script>
(function(){
  const root = document.documentElement;
  const store = {
    get(k){ try { return localStorage.getItem(k); } catch(e){ return null; } },
    set(k,v){ try { localStorage.setItem(k,v); } catch(e){} },
  };

  // Theme
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const t = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = t; store.set('nd_theme', t);
  });

  // Sidebar: collapse on desktop, slide-over on small screens
  const mobile = () => window.matchMedia('(max-width:900px)').matches;
  function toggleSidebar(){
    if (mobile()) { root.classList.toggle('sb-open'); return; }
    root.classList.toggle('sb-collapsed');
    store.set('nd_sidebar', root.classList.contains('sb-collapsed') ? 'collapsed' : 'open');
  }
  document.getElementById('sb-toggle').addEventListener('click', toggleSidebar);
  document.getElementById('sb-collapse').addEventListener('click', toggleSidebar);
  document.getElementById('scrim').addEventListener('click', () => root.classList.remove('sb-open'));

  // Auto-refresh every 60s, keeping scroll position. Paused while the user is
  // filtering, searching or chatting so a reload never throws away their work.
  window.__pauseRefresh = false;
  const SCROLL_KEY = 'nd_scroll:' + location.pathname + location.search;
  try {
    const y = sessionStorage.getItem(SCROLL_KEY);
    if (y) { sessionStorage.removeItem(SCROLL_KEY); window.scrollTo(0, parseInt(y, 10)); }
  } catch(e){}
  function busy(){
    if (window.__pauseRefresh) return true;
    if (document.getElementById('ai-drawer').classList.contains('open')) return true;
    const a = document.activeElement;
    if (a && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA')) return true;
    return Array.from(document.querySelectorAll('.tbl-filter input')).some(i => i.value.trim());
  }
  setInterval(() => {
    if (busy()) return;
    try { sessionStorage.setItem(SCROLL_KEY, String(window.scrollY)); } catch(e){}
    location.reload();
  }, 60000);

  // Generated sparklines have a fixed aspect ratio; let them fill their card
  document.querySelectorAll('.sparkline-svg,.kpi-spark').forEach(s => s.setAttribute('preserveAspectRatio', 'none'));

  // Table tools: text filter + chip filters + click-to-sort
  function cellText(td){
    if (td && td.dataset.v !== undefined) return td.dataset.v;
    return td ? td.innerText.trim().split('\n')[0].trim() : '';
  }
  function cmp(a, b){
    const ipRe = /^(\d+)\.(\d+)\.(\d+)\.(\d+)/;
    const ai = a.match(ipRe), bi = b.match(ipRe);
    if (ai && bi) { for (let i = 1; i <= 4; i++) { const d = +ai[i] - +bi[i]; if (d) return d; } return 0; }
    const an = parseFloat(a.replace(/^(-?\d+\.?\d*).*/, '$1')), bn = parseFloat(b.replace(/^(-?\d+\.?\d*).*/, '$1'));
    if (!isNaN(an) && !isNaN(bn)) return an - bn;
    if (a === '—' && b !== '—') return 1;
    if (b === '—' && a !== '—') return -1;
    return a.localeCompare(b, undefined, {numeric: true, sensitivity: 'base'});
  }
  document.querySelectorAll('table.t.sortable').forEach(table => {
    const ths = table.querySelectorAll('thead th');
    ths.forEach((th, col) => {
      if (th.dataset.nosort !== undefined) return;
      let dir = 0;
      th.addEventListener('click', () => {
        dir = dir === 1 ? -1 : 1;
        ths.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
        th.classList.add(dir === 1 ? 'sort-asc' : 'sort-desc');
        const tbody = table.tBodies[0];
        Array.from(tbody.rows)
          .sort((a, b) => dir * cmp(cellText(a.cells[col]), cellText(b.cells[col])))
          .forEach(r => tbody.appendChild(r));
      });
    });
  });
  document.querySelectorAll('[data-table]').forEach(box => {
    const table = document.getElementById(box.dataset.table);
    if (!table) return;
    const input = box.querySelector('.tbl-filter input');
    const chips = box.querySelectorAll('.chip[data-tag]');
    const count = box.querySelector('.tbl-count');
    const rows = Array.from(table.tBodies[0].rows);
    const onChip = box.querySelector('.chip.on[data-tag]');
    let tag = onChip ? onChip.dataset.tag : '';
    function apply(){
      const q = input ? input.value.trim().toLowerCase() : '';
      let shown = 0;
      rows.forEach(r => {
        const okTag = !tag || (' ' + (r.dataset.tags || '') + ' ').includes(' ' + tag + ' ');
        const okQ = !q || r.innerText.toLowerCase().includes(q);
        r.classList.toggle('hidden', !(okTag && okQ));
        if (okTag && okQ) shown++;
      });
      if (count) count.textContent = (shown === rows.length ? rows.length : shown + ' of ' + rows.length) + ' ' + (count.dataset.noun || 'rows');
    }
    if (input) input.addEventListener('input', apply);
    chips.forEach(c => c.addEventListener('click', () => {
      tag = c.dataset.tag;
      chips.forEach(x => x.classList.toggle('on', x === c));
      apply();
    }));
    apply();
  });

  // Global device search
  const searchInput = document.getElementById('nav-search-input');
  const searchResults = document.getElementById('search-results');
  let searchTimer = null;
  document.addEventListener('keydown', e => {
    if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) { e.preventDefault(); searchInput.focus(); }
  });
  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    if (q.length < 2) { searchResults.classList.remove('visible'); return; }
    searchTimer = setTimeout(() => doSearch(q), 250);
  });
  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Escape') { searchResults.classList.remove('visible'); searchInput.blur(); }
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('.tb-search')) searchResults.classList.remove('visible');
  });
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function doSearch(q){
    try {
      const resp = await fetch('/api/search?q=' + encodeURIComponent(q));
      renderResults(await resp.json());
    } catch(e) {
      searchResults.innerHTML = '<div class="sr-empty">Search unavailable</div>';
      searchResults.classList.add('visible');
    }
  }
  function renderResults(results){
    if (!results.length) {
      searchResults.innerHTML = '<div class="sr-empty">No devices found</div>';
    } else {
      searchResults.innerHTML = results.map(r => {
        const page = r.source === 'wireless' ? '/wireless' : r.source === 'wired' ? '/wired' : '/devices';
        const badge = r.source === 'wireless' ? '<span class="sr-badge sr-badge-wifi">WiFi</span>'
                    : r.source === 'wired' ? '<span class="sr-badge sr-badge-wired">Wired</span>'
                    : '<span class="sr-badge sr-badge-arp">ARP</span>';
        const l1 = [r.ip && esc(r.ip), r.mac && `<span class="sr-mac">${esc(r.mac)}</span>`].filter(Boolean).join('<span class="sr-sep">·</span>');
        const l2p = [];
        if (r.ap_display) l2p.push('AP ' + esc(r.ap_display));
        if (r.switch_display) l2p.push(esc(r.switch_display));
        if (r.interface_port) l2p.push(`<span class="sr-port">${esc(r.interface_port)}</span>`);
        const l3p = [];
        if (r.rssi_label && r.rssi_label !== '—') l3p.push(esc(r.rssi_label));
        if (r.vendor && r.vendor !== '(Unknown)') l3p.push(`<span class="sr-vendor">${esc(r.vendor)}</span>`);
        const sep = '<span class="sr-sep">·</span>';
        return `<a class="search-result" href="${page}?q=${encodeURIComponent(r.mac || r.ip || '')}">
          <div class="sr-header">${badge}<span class="sr-name">${esc(r.name || r.mac)}</span></div>
          ${l1 ? `<div class="sr-line">${l1}</div>` : ''}
          ${l2p.length ? `<div class="sr-line">${l2p.join(sep)}</div>` : ''}
          ${l3p.length ? `<div class="sr-line sr-line-dim">${l3p.join(sep)}</div>` : ''}
        </a>`;
      }).join('');
    }
    searchResults.classList.add('visible');
  }
  // Pages opened from search (?q=...) pre-fill their table filter
  const preQ = new URLSearchParams(location.search).get('q');
  if (preQ) {
    const f = document.querySelector('[data-table] .tbl-filter input');
    if (f && !f.value) { f.value = preQ; f.dispatchEvent(new Event('input')); }
  }

  // Network assistant drawer (conversation survives the 60s reloads)
  const drawer = document.getElementById('ai-drawer');
  const input = document.getElementById('ai-input');
  const send = document.getElementById('ai-send');
  const convo = document.getElementById('ai-conversation');
  const hint = document.getElementById('ai-hint');
  const STORE_KEY = 'netdash_ai_history';
  let history = [];
  function save(){ try { sessionStorage.setItem(STORE_KEY, JSON.stringify(history)); } catch(e){} }
  function load(){ try { history = JSON.parse(sessionStorage.getItem(STORE_KEY) || '[]') || []; } catch(e){ history = []; } }
  function openDrawer(){ drawer.classList.add('open'); try { sessionStorage.setItem('nd_ai_open', '1'); } catch(e){} input.focus(); }
  function closeDrawer(){ drawer.classList.remove('open'); try { sessionStorage.removeItem('nd_ai_open'); } catch(e){} }
  document.getElementById('ai-open').addEventListener('click', () => drawer.classList.contains('open') ? closeDrawer() : openDrawer());
  document.getElementById('ai-close').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  function addMsg(role, text, cls){
    hint.style.display = 'none';
    const div = document.createElement('div');
    div.className = 'ai-msg ' + (cls || (role === 'user' ? 'ai-msg-user' : 'ai-msg-ai'));
    div.textContent = text;
    convo.appendChild(div);
    convo.scrollTop = convo.scrollHeight;
    return div;
  }
  function ensureClearBtn(){
    if (document.getElementById('ai-clear-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'ai-clear-btn'; btn.className = 'ai-clear'; btn.textContent = 'Clear conversation';
    btn.addEventListener('click', () => {
      history = []; save();
      convo.querySelectorAll('.ai-msg').forEach(m => m.remove());
      hint.style.display = ''; btn.remove();
    });
    document.querySelector('.drawer-h').insertBefore(btn, document.getElementById('ai-close'));
  }
  function ask(text){
    const q = (text || input.value).trim();
    if (!q) return;
    addMsg('user', q);
    history.push({role: 'user', content: q});
    save(); ensureClearBtn();
    input.value = ''; send.disabled = true;
    const thinking = addMsg('ai', 'Thinking…', 'ai-msg-ai ai-thinking');
    fetch('/api/ask', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({messages: history})})
      .then(r => r.json()).then(data => {
        thinking.remove();
        if (data.error) { addMsg('ai', data.error, 'ai-msg-error'); }
        else { addMsg('ai', data.answer); history.push({role: 'assistant', content: data.answer}); save(); }
        send.disabled = false; input.focus();
      }).catch(e => { thinking.remove(); addMsg('ai', 'Request failed: ' + e, 'ai-msg-error'); send.disabled = false; });
  }
  send.addEventListener('click', () => ask());
  input.addEventListener('keydown', e => { if (e.key === 'Enter') ask(); });
  hint.querySelectorAll('button').forEach(b => b.addEventListener('click', () => ask(b.textContent)));
  load();
  if (history.length) { history.forEach(m => addMsg(m.role === 'user' ? 'user' : 'ai', m.content)); ensureClearBtn(); }
  try { if (sessionStorage.getItem('nd_ai_open')) openDrawer(); } catch(e){}
})();
</script>
</body>
</html>"""


def _page(body):
    return BASE_HTML.replace("{% block content %}{% endblock %}", body)


# ── Overview ─────────────────────────────────────────────────────────────────

OVERVIEW_HTML = _page(r"""
{% if errors %}<div class="error-banner">{{ icon('alert') }} Some data sources failed: {{ errors | join(" · ") }}</div>{% endif %}
{% call page_head('Network Overview', ui_site ~ ' · ' ~ (ap_total + switch_total) ~ ' managed devices · ' ~ (wifi_count + wired_count) ~ ' clients') %}
  <a class="btn" href="/events">{{ icon('clock', 'ic ic-sm') }} Events</a>
  <a class="btn" href="/topology">{{ icon('topo', 'ic ic-sm') }} Topology</a>
{% endcall %}

{% set wan_bad = wan_cards | selectattr('status_class', 'equalto', 'danger') | list | length %}
{% set wan_warn = wan_cards | selectattr('status_class', 'equalto', 'warn') | list | length %}
{% set wifi_fair = wifi_weak - wifi_poor %}
<div class="stats">
  {% if wan_cards %}
  <a class="stat" href="#internet">
    <div class="stat-l">{{ icon('globe') }} Internet</div>
    <div class="stat-v {{ 'v-danger' if wan_bad else ('v-warn' if wan_warn else 'v-good') }}">{{ wan_cards | length - wan_bad }}<small>/{{ wan_cards | length }}</small></div>
    <div class="stat-s">{% if wan_bad %}{{ wan_bad }} WAN down{% else %}WAN links online{% endif %}</div>
  </a>
  {% endif %}
  <a class="stat" href="/aps">
    <div class="stat-l">{{ icon('ap') }} Access Points</div>
    <div class="stat-v {{ 'v-good' if ap_up == ap_total else 'v-danger' }}">{{ ap_up }}<small>/{{ ap_total }}</small></div>
    <div class="stat-s">online</div>
  </a>
  <a class="stat" href="/switches">
    <div class="stat-l">{{ icon('switch') }} Switches</div>
    <div class="stat-v {{ 'v-good' if switch_up == switch_total else 'v-danger' }}">{{ switch_up }}<small>/{{ switch_total }}</small></div>
    <div class="stat-s">online</div>
  </a>
  <a class="stat" href="/wireless">
    <div class="stat-l">{{ icon('wifi') }} Wireless Clients</div>
    <div class="stat-v">{{ wifi_count }}</div>
    {% if spark_wireless %}<div class="stat-spark">{{ spark_wireless | safe }}</div>{% else %}<div class="stat-s">connected now</div>{% endif %}
  </a>
  <a class="stat" href="/wired">
    <div class="stat-l">{{ icon('switch') }} Wired Clients</div>
    <div class="stat-v">{{ wired_count }}</div>
    {% if spark_wired %}<div class="stat-spark">{{ spark_wired | safe }}</div>{% else %}<div class="stat-s">connected now</div>{% endif %}
  </a>
  <a class="stat" href="/devices">
    <div class="stat-l">{{ icon('devices') }} Devices Seen</div>
    <div class="stat-v">{{ arp_total or dhcp_total }}</div>
    <div class="stat-s">{% if gap_count %}<span class="warn">{{ gap_count }} unaccounted</span>{% else %}all accounted for{% endif %}</div>
  </a>
</div>

<div class="grid">
  <!-- Health -->
  <section class="card c6">
    <div class="card-h">
      <div><div class="card-t">{{ icon('pulse') }} Health</div><div class="card-sub">Current state of infrastructure and clients</div></div>
    </div>
    <div class="card-b">
      <div class="hlegend"><span><i class="dot danger"></i>Poor / offline</span><span><i class="dot warn"></i>Fair</span><span><i class="dot good"></i>Good</span></div>
      {% macro hrow(href, ic, label, poor, fair, good) -%}
      {% set tot = poor + fair + good %}
      <tr>
        <td><a href="{{ href }}">{{ icon(ic) }} {{ label }}</a></td>
        <td class="bar"><div class="hbar">{% if tot %}<span class="p" style="width:{{ 100*poor/tot }}%"></span><span class="f" style="width:{{ 100*fair/tot }}%"></span><span class="g" style="width:{{ 100*good/tot }}%"></span>{% endif %}</div></td>
        <td class="n {{ 'zero' if not poor }}"><i class="dot danger"></i>{{ poor }}</td>
        <td class="n {{ 'zero' if not fair }}"><i class="dot warn"></i>{{ fair }}</td>
        <td class="n {{ 'zero' if not good }}"><i class="dot good"></i>{{ good }}</td>
      </tr>
      {%- endmacro %}
      <table class="htable">
        <thead><tr><th>Type</th><th></th><th style="text-align:right">Poor</th><th style="text-align:right">Fair</th><th style="text-align:right">Good</th></tr></thead>
        <tbody>
          {% if wan_cards %}{{ hrow('#internet', 'globe', 'Internet (WAN)', wan_bad, wan_warn, wan_cards|length - wan_bad - wan_warn) }}{% endif %}
          {{ hrow('/aps', 'ap', 'Access points', ap_total - ap_up, 0, ap_up) }}
          {{ hrow('/switches', 'switch', 'Switches', switch_total - switch_up, 0, switch_up) }}
          {{ hrow('/wireless-health', 'wifi', 'Wireless clients', wifi_poor, wifi_fair, wifi_count - wifi_weak) }}
          {{ hrow('/wired', 'devices', 'Wired clients', 0, 0, wired_count) }}
        </tbody>
      </table>
      {% if wifi_weak %}
      <div class="info-banner">{{ icon('info') }}<span>{{ wifi_weak }} wireless client{{ 's' if wifi_weak != 1 }} on weak signal ({{ wifi_fair }} fair, {{ wifi_poor }} poor). <a class="card-link" href="/wireless-health">See which ones ›</a></span></div>
      {% endif %}
    </div>
  </section>

  <!-- Wireless experience -->
  <section class="card c6">
    <div class="card-h">
      <div><div class="card-t">{{ icon('wifi') }} Wireless Experience</div><div class="card-sub">Mist service levels · last 24 hours</div></div>
      <div class="card-x"><a class="card-link" href="/wireless-health">WiFi health ›</a></div>
    </div>
    <div class="card-b">
      {% if sle_cards %}
      <div class="mlist">
        {% for s in sle_cards %}
        <div class="mrow">
          <span class="mrow-l">{{ s.label }}</span>
          <span class="mrow-v {{ 'good' if s.tier == 'good' else ('warn' if s.tier == 'warn' else 'danger') }}">{{ s.success }}%</span>
          <div class="mbar {{ '' if s.tier == 'good' else ('warn' if s.tier == 'warn' else 'bad') }}"><span style="width:{{ s.success }}%"></span></div>
          {% if s.top_classifier and s.success < 100 %}<span class="mrow-s">Top issue: {{ s.top_classifier.name }} ({{ s.top_classifier.impact }}% of impact)</span>{% endif %}
        </div>
        {% endfor %}
      </div>
      {% else %}
      <div class="empty">{{ icon('wifi') }}No service-level data from Mist yet.</div>
      {% endif %}
    </div>
  </section>
</div>

{% set D = ui_data() %}
{% set rf = ui_radios(D.get('mist', {}).get('aps', [])) %}
{% set wl = ui_worst_links(D.get('mist', {}).get('clients', []), D.get('mist', {}).get('aps', []), 5) %}
<div class="grid">
  <section class="card c6">
    <div class="card-h">
      <div><div class="card-t">{{ icon('ap') }} Wi-Fi radios</div><div class="card-sub">How busy each band's channels are right now</div></div>
      <div class="card-x"><a class="card-link" href="/aps">Radios ›</a></div>
    </div>
    <div class="card-b">
      <div class="mlist">
        {% for b in rf.bands %}
        <div class="mrow">
          <span class="mrow-l">{{ b.label }} <span class="muted" style="font-weight:400">· {{ b.clients }} client{{ 's' if b.clients != 1 }} on {{ b.radios }} radio{{ 's' if b.radios != 1 }}</span></span>
          <span class="mrow-v {{ b.tier }}">{{ b.max }}%</span>
          <div class="mbar {{ '' if b.tier == 'good' else ('warn' if b.tier == 'warn' else 'bad') }}"><span style="width:{{ [b.max or 0, 1] | max }}%"></span></div>
          <span class="mrow-s">Busiest radio {{ b.max }}% · average {{ b.avg }}%</span>
        </div>
        {% endfor %}
      </div>
      {% if rf.overlaps %}<div class="info-banner">{{ icon('info') }}<span>{{ rf.overlaps | length }} channel{{ 's are' if rf.overlaps|length != 1 else ' is' }} shared by neighbouring APs: {% for o in rf.overlaps %}{{ o.aps | join(' & ') }} on {{ o.band }} ch {{ o.channel }}{{ '; ' if not loop.last }}{% endfor %}.</span></div>{% endif %}
    </div>
  </section>
  <section class="card c6">
    <div class="card-h">
      <div><div class="card-t">{{ icon('alert') }} Worst links</div><div class="card-sub">Clients retrying the most transmissions</div></div>
      <div class="card-x"><a class="card-link" href="/wireless-health">WiFi health ›</a></div>
    </div>
    <div class="card-b flush">
      {% if wl %}
      <table class="t"><tbody>
        {% for w in wl %}
        <tr>
          <td><div class="dev-name">{{ w.name }}</div><div class="dev-sub">{{ ui_band(w.band) }} · {{ w.ap }}</div></td>
          <td class="r mono muted">{{ (w.rssi ~ ' dBm') if w.rssi is not none else '' }}</td>
          <td class="r" style="width:1%;white-space:nowrap"><span class="{{ w.retry_tier }}" style="font-weight:700">{{ w.retry }}%</span> <span class="muted" style="font-size:.72rem">retries</span></td>
        </tr>
        {% endfor %}
      </tbody></table>
      {% else %}<div class="empty">Not enough traffic yet to measure retries.</div>{% endif %}
    </div>
  </section>
</div>

<!-- Internet -->
<div class="grid" id="internet">
  {% for w in wan_cards %}
  <section class="card {{ 'c6' if wan_cards|length > 1 else 'c12' }}">
    <div class="card-h">
      <div>
        <div class="card-t">{{ icon('globe') }} {{ w.name }}
          {% if w.type == 'primary' %}<span class="pill pill-info">Primary</span>{% elif w.type == 'backup' %}<span class="pill pill-warn">Backup</span>{% endif %}
        </div>
        <div class="card-sub">{{ w.device or '—' }} · gateway {{ w.gateway or '—' }}</div>
      </div>
      <div class="card-x">
        <span class="status"><i class="dot {{ w.status_class }}"></i>{{ w.status_label }}</span>
        <a class="ext-link" href="{{ opnsense_url }}" target="_blank" rel="noopener">OPNsense {{ ext() }}</a>
      </div>
    </div>
    <div class="card-b">
      <div class="stats" style="grid-template-columns:repeat(4,minmax(0,1fr));gap:.5rem;margin-bottom:0">
        <div><div class="stat-l">Latency</div><div class="mrow-v" style="font-size:1.05rem">{{ w.delay or '—' }}</div></div>
        <div><div class="stat-l">Jitter</div><div class="mrow-v" style="font-size:1.05rem">{{ w.stddev or '—' }}</div></div>
        <div><div class="stat-l">Loss</div><div class="mrow-v" style="font-size:1.05rem">{{ w.loss or '—' }}</div></div>
        <div><div class="stat-l">WAN IP</div><div class="mono" style="margin-top:.2rem">{{ w.ip or '—' }}</div></div>
      </div>
      {% if w.sparkline %}{{ w.sparkline | safe }}{% endif %}
      {% if w.quality_sparkline %}{{ w.quality_sparkline | safe }}{% endif %}
    </div>
  </section>
  {% endfor %}
</div>

<div class="grid">
  <!-- Client issues -->
  <section class="card c6">
    <div class="card-h">
      <div><div class="card-t">{{ icon('alert') }} Client Issues</div><div class="card-sub">{{ '{:,}'.format(client_fail_total) }} connection failures · last 24 hours</div></div>
      <div class="card-x"><a class="card-link" href="/client-issues">All issues ›</a></div>
    </div>
    <div class="card-b">
      {% if client_fail_total %}
      {% set maxn = client_fail_summary.values() | max %}
      <div class="stat-l" style="margin-bottom:.5rem">By failure type</div>
      <div class="mlist" style="gap:.55rem">
        {% for cat, n in client_fail_summary | dictsort(by='value', reverse=true) %}
        <a class="mrow" href="/client-issues?cat={{ cat }}" style="text-decoration:none">
          <span class="mrow-l">{{ cat | upper if cat in ('dns','dhcp','arp') else cat | capitalize }}</span>
          <span class="mrow-v">{{ '{:,}'.format(n) }}</span>
          <div class="mbar {{ 'bad' if cat == 'auth' else ('warn' if cat in ('dns','dhcp') else 'info') }}"><span style="width:{{ [100*n/maxn, 2] | max }}%"></span></div>
        </a>
        {% endfor %}
      </div>
      {% set worst = ui_top_failing(ui_all_failures(), 3) %}
      {% if worst %}
      <div class="stat-l" style="margin:1rem 0 .4rem">Most affected devices</div>
      <div class="chips">{% for w, n in worst %}<a class="chip" href="/client-issues?q={{ w | urlencode }}">{{ w }} <b>{{ '{:,}'.format(n) }}</b></a>{% endfor %}</div>
      {% endif %}
      {% else %}
      <div class="empty">{{ icon('check') }}No client connection failures in the last 24 hours.</div>
      {% endif %}
    </div>
    {% if client_failures %}
    <div class="card-foot"><span>Latest: <b>{{ client_failures[0].label }}</b> · {{ client_failures[0].hostname or client_failures[0].ip or client_failures[0].mac }}</span><span>{{ client_failures[0].timestamp | ts_ago }}</span></div>
    {% endif %}
  </section>

  <!-- Recent activity -->
  <section class="card c6">
    <div class="card-h">
      <div><div class="card-t">{{ icon('clock') }} Recent Activity</div><div class="card-sub">Changes and alerts detected by the dashboard</div></div>
      <div class="card-x"><a class="card-link" href="/events">All events ›</a></div>
    </div>
    <div class="card-b flush">
      {% if recent_events %}
      <table class="t">
        <tbody>
          {% for e in recent_events %}
          <tr>
            <td style="width:1%"><i class="dot {{ 'danger' if e.severity == 'crit' else ('warn' if e.severity == 'warn' else 'info') }}"></i></td>
            <td style="padding-left:0">{{ e.message }}</td>
            <td class="r muted" style="white-space:nowrap;font-size:.76rem">{{ e.ts | event_ago }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="empty">{{ icon('clock') }}No events yet. Changes appear here as they are detected.</div>
      {% endif %}
    </div>
  </section>
</div>

<div class="grid">
  <!-- Switches -->
  <section class="card c12">
    <div class="card-h">
      <div><div class="card-t">{{ icon('switch') }} Switches</div><div class="card-sub">Aruba Central · {{ switch_total }} total</div></div>
      <div class="card-x"><a class="card-link" href="/switches">Ports ›</a></div>
    </div>
    <div class="card-b flush">
      <div class="table-wrap">
        <table class="t">
          <thead><tr><th>Status</th><th>Name</th><th>Model</th><th>Serial</th></tr></thead>
          <tbody>
            {% for sw in switches %}
            <tr>
              <td style="width:1%;white-space:nowrap"><span class="status"><i class="dot {{ 'good' if sw.status == 'Up' else 'danger' }}"></i>{{ sw.status }}</span></td>
              <td><span class="dev-name">{{ sw.name or sw.serial }}</span></td>
              <td class="muted">{{ sw.model }}</td>
              <td class="mono muted">{{ sw.serial }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </section>
</div>
""")


# ── Wireless ─────────────────────────────────────────────────────────────────

_RSSI = r"""{% macro rssi(cls, label) -%}
<span class="rssi {{ cls }}"><span class="rssi-bars"><i></i><i></i><i></i><i></i></span>{{ label }}</span>
{%- endmacro %}"""

WIRELESS_HTML = _page(_RSSI + r"""
{% set bands = clients | map(attribute='band') | reject('none') | unique | sort | list %}
{% call page_head('Wireless Clients', (clients | length) ~ ' connected') %}
  <a class="btn" href="{{ mist_clients_url }}" target="_blank" rel="noopener">Open in Mist {{ ext() }}</a>
{% endcall %}
<section class="card" data-table="wl-table">
  <div class="tbl-tools" style="padding-top:.9rem">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter by name, IP, MAC, AP…"/></label>
    <div class="chips">
      <button class="chip on" data-tag="">All</button>
      {% for b in bands %}<button class="chip" data-tag="band-{{ b | replace(' ', '') }}">{{ b }}</button>{% endfor %}
      <button class="chip" data-tag="weak">Weak signal</button>
      <button class="chip" data-tag="retry">High retries</button>
      <button class="chip" data-tag="legacy">Wi-Fi 4 or older</button>
    </div>
    <span class="tbl-count" data-noun="clients"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="wl-table">
      <thead><tr>
        <th>Client</th><th>IP</th><th>SSID</th><th>Band</th><th>Signal</th><th class="r" title="Retried transmissions per 100 packets this session">Retries</th><th class="r" title="Current link rate, to / from the client">Rate</th><th>Access Point</th><th class="r">Traffic</th><th>Uptime</th>
      </tr></thead>
      <tbody>
        {% for c in clients %}
        {% set q = ui_cq(c) %}
        <tr data-tags="band-{{ (c.band or '') | replace(' ', '') }}{{ ' weak' if c.rssi_class in ('warn', 'danger') }}{{ ' retry' if q.retry_tier == 'danger' }}{{ ' legacy' if q.proto in ('n', 'g', 'a', 'b') }}">
          <td>
            <div class="dev-name">{% if c.client_url %}<a href="{{ c.client_url }}" target="_blank" rel="noopener" class="dev-link">{{ c.hostname or c.mac }}</a>{% else %}{{ c.hostname or c.mac }}{% endif %}</div>
            <div class="dev-sub">{{ c.mac }}</div>
            {% if c.vendor %}<div class="dev-vendor">{{ c.vendor }}</div>{% endif %}
          </td>
          <td class="mono">{{ c.ip or "—" }}</td>
          <td>{% if c.ssid %}<span class="pill pill-info">{{ c.ssid }}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
          <td style="white-space:nowrap">{{ c.band }}<div><span class="gen-badge {{ 'g6' if q.proto == 'ax' else ('g7' if q.proto == 'be' else ('legacy' if q.proto in ('g','a','b') else '')) }}">{{ q.gen }}</span></div></td>
          <td>{{ rssi(c.rssi_class, c.rssi_label) }}</td>
          <td class="r" data-v="{{ q.retry if q.retry is not none else -1 }}">{% if q.retry is not none %}<span class="{{ q.retry_tier }}" style="font-weight:600">{{ q.retry }}%</span>{% else %}<span class="muted">—</span>{% endif %}</td>
          <td class="r mono" style="white-space:nowrap" data-v="{{ q.tx_rate or 0 }}">{% if q.tx_rate %}{{ q.tx_rate | round | int }} / {{ (q.rx_rate or 0) | round | int }}<div class="dev-sub">Mbps</div>{% else %}—{% endif %}</td>
          <td>
            <div class="dev-name">{% if c.ap_url %}<a href="{{ c.ap_url }}" target="_blank" rel="noopener" class="dev-link">{{ c.ap_display }}</a>{% else %}{{ c.ap_display }}{% endif %}</div>
            {% if c.ap_switch %}<div class="dev-vendor">{{ c.ap_switch }}{% if c.ap_port %} · {{ c.ap_port }}{% endif %}</div>{% endif %}
          </td>
          <td class="mono r" style="white-space:nowrap">↑ {{ c.tx }}<br>↓ {{ c.rx }}</td>
          <td class="muted" style="white-space:nowrap">{{ c.uptime }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
""")


WIRED_HTML = _page(r"""
{% set sws = clients | map(attribute='switch_display') | reject('none') | unique | sort | list %}
{% call page_head('Wired Clients', (clients | length) ~ ' connected via Aruba switches') %}{% endcall %}
<section class="card" data-table="wd-table">
  <div class="tbl-tools" style="padding-top:.9rem">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter by name, IP, MAC, port…"/></label>
    {% if sws | length > 1 %}
    <div class="chips">
      <button class="chip on" data-tag="">All switches</button>
      {% for s in sws %}<button class="chip" data-tag="sw-{{ loop.index }}">{{ s }}</button>{% endfor %}
    </div>
    {% endif %}
    <span class="tbl-count" data-noun="clients"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="wd-table">
      <thead><tr><th>Client</th><th>IP address</th><th>Switch</th><th>Port</th><th>VLAN</th><th>Last seen</th></tr></thead>
      <tbody>
        {% for c in clients %}
        <tr data-tags="{% for s in sws %}{% if s == c.switch_display %}sw-{{ loop.index }}{% endif %}{% endfor %}">
          <td>
            <div class="dev-name">{{ c.name or c.macaddr }}</div>
            <div class="dev-sub">{{ c.macaddr }}</div>
            {% if c.vendor %}<div class="dev-vendor">{{ c.vendor }}</div>{% endif %}
          </td>
          <td class="mono">{{ c.ip_address or "—" }}</td>
          <td><div class="dev-name">{{ c.switch_display }}</div>{% if c.switch_serial %}<div class="dev-sub">{{ c.switch_serial }}</div>{% endif %}</td>
          <td class="mono">{{ c.interface_port or "—" }}</td>
          <td>{% if c.vlan %}<span class="pill pill-muted">VLAN {{ c.vlan }}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
          <td class="muted" style="font-size:.76rem">{{ c.last_seen or "—" }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
""")


APS_HTML = _page(r"""
{% set up = aps | selectattr('status', 'equalto', 'connected') | list | length %}
{% set raw_aps = ui_data().get('mist', {}).get('aps', []) %}
{% set h = ui_ap_health(raw_aps) %}
{% set rf = ui_radios(raw_aps) %}
{% call page_head('Access Points', up ~ ' of ' ~ (aps | length) ~ ' online') %}
  <a class="btn" href="{{ mist_aps_url }}" target="_blank" rel="noopener">Open in Mist {{ ext() }}</a>
{% endcall %}

<div class="stats">
  <div class="stat"><div class="stat-l">{{ icon('ap') }} Online</div><div class="stat-v {{ 'v-good' if up == aps|length else 'v-danger' }}">{{ up }}<small>/{{ aps | length }}</small></div></div>
  {% for b in rf.bands %}
  <div class="stat"><div class="stat-l">{{ icon('pulse') }} {{ b.label }} busiest</div>
    <div class="stat-v v-{{ b.tier }}">{{ b.max }}<small>%</small></div>
    <div class="stat-s">avg {{ b.avg }}% · {{ b.clients }} client{{ 's' if b.clients != 1 }}</div></div>
  {% endfor %}
  <div class="stat"><div class="stat-l">{{ icon('switch') }} PoE used</div>
    {% if h.poe_used_total is not none %}<div class="stat-v">{{ h.poe_used_total }}<small> W</small></div><div class="stat-s">measured by the switches · {{ h.poe_req_total }} W requested</div>
    {% else %}<div class="stat-v">—</div><div class="stat-s">{{ h.poe_req_total }} W requested · measured draw loads from Central shortly</div>{% endif %}</div>
  <div class="stat"><div class="stat-l">{{ icon('check') }} Firmware</div>
    <div class="stat-v {{ 'v-good' if h.firmware|length == 1 else 'v-warn' }}" style="font-size:1.2rem;margin-top:.55rem">{{ h.firmware[0][0] if h.firmware else '—' }}</div>
    <div class="stat-s">{{ 'all APs match' if h.firmware|length == 1 else (h.firmware|length) ~ ' versions running' }}</div></div>
</div>

{% set notes = [] %}
{% for o in rf.overlaps %}{% set _ = notes.append(o.aps | join(' and ') ~ ' share ' ~ o.band ~ ' channel ' ~ o.channel ~ '; neighbouring APs on one channel take turns to talk.') %}{% endfor %}
{% if h.rebooted %}{% set _ = notes.append((h.rebooted | join(', ')) ~ ' restarted in the last 24 hours.') %}{% endif %}
{% if h.slow_links %}{% set _ = notes.append((h.slow_links | join(', ')) ~ ' uplink is below 1 Gbps.') %}{% endif %}
{% if h.half_duplex %}{% set _ = notes.append((h.half_duplex | join(', ')) ~ ' uplink is half duplex.') %}{% endif %}
{% if h.errors %}{% set _ = notes.append((h.errors | join(', ')) ~ ' uplink is reporting errors.') %}{% endif %}
{% if h.constrained %}{% set _ = notes.append((h.constrained | join(', ')) ~ ' is power-constrained (not getting full PoE).') %}{% endif %}
{% if h.certs %}{% set _ = notes.append((h.certs | join(', ')) ~ ' has certificates about to expire.') %}{% endif %}
{% if notes %}
<section class="card" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('info') }} Worth a look</div></div></div>
  <div class="card-b" style="padding-top:.4rem"><ul class="notes">{% for n in notes %}<li>{{ n }}</li>{% endfor %}</ul></div>
</section>
{% endif %}

<section class="card" data-table="ap-table" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('ap') }} Access points</div><div class="card-sub">Status, hardware, power and uplink</div></div></div>
  <div class="tbl-tools">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter access points…"/></label>
    <span class="tbl-count" data-noun="access points"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="ap-table">
      <thead><tr>
        <th>Status</th><th>Name</th><th class="r">Clients</th><th>Uptime</th><th class="r">Temp</th><th class="r">CPU</th><th class="r">Memory</th><th class="r" title="Measured by the switch; Mist's negotiated figure underneath">PoE</th><th>Uplink</th><th>Firmware</th><th data-nosort></th>
      </tr></thead>
      <tbody>
        {% for ap in aps %}
        {% set r = (h.rows | selectattr('mac', 'equalto', ap.mac) | first) or {} %}
        <tr>
          <td style="white-space:nowrap"><span class="status"><i class="dot {{ 'good' if ap.status == 'connected' else 'danger' }}"></i>{{ 'Online' if ap.status == 'connected' else (ap.status or 'Unknown') | capitalize }}</span></td>
          <td><div class="dev-name">{{ ap.name or ap.mac }}</div><div class="dev-sub">{{ ap.model or '' }} · {{ ap.ip or '—' }}</div></td>
          <td class="r" style="font-weight:600">{{ ap.num_clients or 0 }}</td>
          <td style="white-space:nowrap" data-v="{{ r.uptime_s }}">{{ r.uptime_s | duration }}{% if r.rebooted %} <span class="pill pill-warn">restarted</span>{% endif %}</td>
          <td class="r">{{ (r.temp ~ ' °C') if r.temp else '—' }}</td>
          <td class="r">{{ (r.cpu ~ '%') if r.cpu is not none else '—' }}</td>
          <td class="r">{{ (r.mem ~ '%') if r.mem is not none else '—' }}</td>
          <td class="r" style="white-space:nowrap" data-v="{{ r.poe_used if r.poe_used is not none else (r.poe_req or 0) }}">{% if r.poe_used is not none %}{{ r.poe_used }} W{% else %}<span class="muted">—</span>{% endif %}{% if r.poe_req and r.poe_req != r.poe_used %}<div class="dev-sub">{{ r.poe_req }} W requested</div>{% endif %}{% if r.constrained %} <span class="pill pill-danger">limited</span>{% endif %}</td>
          <td>{% if r.switch %}<div>{{ r.switch }} <span class="mono muted">{{ r.port }}</span></div>{% endif %}
              <div class="dev-sub">{% if r.speed %}{{ r.speed if r.speed < 1000 else (r.speed // 1000) ~ 'G' }}{{ 'M' if r.speed < 1000 }} {{ r.duplex }}{% endif %}{% if (r.rx_errors or 0) + (r.tx_errors or 0) %} · <span class="danger">{{ (r.rx_errors or 0) + (r.tx_errors or 0) }} errors</span>{% endif %}</div></td>
          <td class="mono muted">{{ r.firmware or '—' }}</td>
          <td class="r"><a href="{{ ap.mist_url }}" target="_blank" rel="noopener" class="ext-link">Mist {{ ext() }}</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>

<section class="card" data-table="radio-table">
  <div class="card-h"><div><div class="card-t">{{ icon('wifi') }} Radios</div><div class="card-sub">Channel utilisation is how much of the time the channel is busy. Above {{ UTIL_WARN }}% clients start waiting; above {{ UTIL_BAD }}% it is congested.</div></div></div>
  <div class="tbl-tools">
    <div class="chips">
      <button class="chip on" data-tag="">All bands</button>
      {% for b in rf.bands %}<button class="chip" data-tag="band-{{ b.band }}">{{ b.label }}</button>{% endfor %}
    </div>
    <div class="hlegend" style="margin:0 0 0 auto">
      <span><i class="dot info"></i>This AP's traffic</span><span><i class="dot" style="background:var(--violet)"></i>Neighbouring Wi-Fi</span>
      <span><i class="dot danger"></i>Non-Wi-Fi interference</span><span><i class="dot" style="background:var(--border-strong)"></i>Other</span>
    </div>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="radio-table">
      <thead><tr><th>Access point</th><th>Band</th><th class="r">Channel</th><th class="r">Width</th><th class="r">Power</th><th style="min-width:220px">Utilisation</th><th class="r">Noise</th><th class="r">Clients</th></tr></thead>
      <tbody>
        {% for r in rf.rows %}
        <tr data-tags="band-{{ r.band }}">
          <td class="dev-name">{{ r.ap }}</td>
          <td style="white-space:nowrap">{{ r.band_label }}</td>
          <td class="r mono">{{ r.channel }}{% if rf.overlaps | selectattr('channel', 'equalto', r.channel) | selectattr('band', 'equalto', r.band_label) | list %} <span class="pill pill-warn" title="Shared with another AP">shared</span>{% endif %}</td>
          <td class="r muted">{{ r.width }} MHz</td>
          <td class="r muted">{{ r.power }} dBm</td>
          <td><div class="ubar-row"><span class="ubar-v v-{{ r.util_tier }}">{{ r.util }}%</span>
            <div class="ubar" title="own {{ r.own }}% · neighbours {{ r.other_bss }}% · non-Wi-Fi {{ r.non_wifi }}% · other {{ r.unknown }}%">
              <span class="u-own" style="width:{{ r.own }}%"></span><span class="u-obss" style="width:{{ r.other_bss }}%"></span><span class="u-nw" style="width:{{ r.non_wifi }}%"></span><span class="u-unk" style="width:{{ [r.util - r.own - r.other_bss - r.non_wifi, 0] | max }}%"></span>
            </div></div></td>
          <td class="r mono muted">{{ r.noise }} dBm</td>
          <td class="r" style="font-weight:600">{{ r.clients }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
""")


# ── Devices & gap ────────────────────────────────────────────────────────────

DEVICES_HTML = _page(r"""
{% call page_head('All Devices', (hosts | length) ~ ' found on the LAN · last ARP scan ' ~ last_scanned) %}
  <a class="btn" href="/gap">{{ icon('search', 'ic ic-sm') }} Unaccounted{% if gap_count %} <span class="pill pill-warn">{{ gap_count }}</span>{% endif %}</a>
{% endcall %}

<div class="stats">
  <div class="stat"><div class="stat-l">{{ icon('devices') }} Unique devices</div><div class="stat-v">{{ recon_summary.total_union }}</div><div class="stat-s">across all sources</div></div>
  <div class="stat"><div class="stat-l">{{ icon('search') }} ARP scan</div><div class="stat-v">{{ recon_summary.in_arp }}</div><div class="stat-s">{{ static_count }} static IPs</div></div>
  <div class="stat"><div class="stat-l">{{ icon('wifi') }} Mist wireless</div><div class="stat-v v-info">{{ recon_summary.in_wireless }}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('switch') }} Central wired</div><div class="stat-v v-good">{{ recon_summary.in_wired }}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('ap') }} Infrastructure</div><div class="stat-v">{{ recon_summary.infra }}</div></div>
</div>

<section class="card" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('info') }} Source mismatches</div><div class="card-sub">Each source sees a different set of devices; these are the differences</div></div></div>
  <div class="card-b">
    <table class="htable">
      <tbody>
        <tr><td>In the ARP scan but <b>no source claims them</b> (the gap)</td><td class="n {{ 'danger' if recon_summary.arp_only else 'zero' }}">{{ recon_summary.arp_only }}</td></tr>
        <tr><td>Mist sees but ARP missed <span class="muted">(client didn't answer the ARP probe)</span></td><td class="n {{ 'warn' if recon_summary.mist_not_arp else 'zero' }}">{{ recon_summary.mist_not_arp }}</td></tr>
        <tr><td>Central sees but ARP missed</td><td class="n {{ 'warn' if recon_summary.central_not_arp else 'zero' }}">{{ recon_summary.central_not_arp }}</td></tr>
        <tr><td>Counted as <b>both</b> wireless and wired</td><td class="n {{ 'danger' if recon_summary.double_counted else 'zero' }}">{{ recon_summary.double_counted }}</td></tr>
      </tbody>
    </table>
  </div>
</section>

<section class="card" data-table="dev-table" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('devices') }} Devices on the LAN</div><div class="card-sub">From arp-scan, matched with DHCP leases</div></div></div>
  <div class="tbl-tools">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter by IP, name, MAC, vendor…"/></label>
    <div class="chips">
      <button class="chip on" data-tag="">All</button>
      <button class="chip" data-tag="unaccounted">Unaccounted</button>
      <button class="chip" data-tag="static">Static IP</button>
      <button class="chip" data-tag="dhcp">DHCP</button>
    </div>
    <span class="tbl-count" data-noun="devices"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="dev-table">
      <thead><tr><th>IP address</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Address</th><th>Last seen</th><th>Managed</th></tr></thead>
      <tbody>
        {% for h in hosts %}
        <tr data-tags="{{ h.type | lower }}{{ ' unaccounted' if h.unaccounted }}">
          <td class="mono">{{ h.ip }}</td>
          <td>{% if h.hostname %}<span class="dev-name">{{ h.hostname }}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
          <td class="mono muted">{{ h.mac }}</td>
          <td class="muted" style="font-size:.78rem">{{ h.vendor or '—' }}</td>
          <td><span class="pill {{ 'pill-info' if h.type == 'DHCP' else 'pill-warn' }}">{{ h.type }}</span></td>
          <td class="muted" style="font-size:.76rem" title="first seen {{ h.first_seen }}">{{ h.last_seen }}</td>
          <td>{% if h.unaccounted %}<span class="status"><i class="dot warn"></i>Unaccounted</span>{% else %}<span class="status"><i class="dot good"></i>Managed</span>{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>

<details class="card" data-table="recon-table">
  <summary class="card-h" style="cursor:pointer;list-style:none;padding-bottom:.9rem">
    <div><div class="card-t">{{ icon('topo') }} Per-device source membership</div><div class="card-sub">Which sources report each device · click to expand</div></div>
    <span class="card-link">Show ›</span>
  </summary>
  <div class="tbl-tools">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter…"/></label>
    <span class="tbl-count" data-noun="devices"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="recon-table">
      <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th class="c">ARP</th><th class="c">Wireless</th><th class="c">Wired</th><th class="c">Infra</th></tr></thead>
      <tbody>
        {% for r in recon_rows %}
        <tr>
          <td class="mono">{{ r.ip or "—" }}</td>
          <td class="mono muted">{{ r.mac }}</td>
          <td class="muted" style="font-size:.78rem">{{ r.vendor }}</td>
          {% for v in (r.in_arp, r.in_wireless, r.in_wired, r.is_infra) %}
          <td class="c"><span class="{{ 'src-yes' if v else 'src-no' }}">{{ '✓' if v else '·' }}</span></td>
          {% endfor %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</details>
""")


GAP_HTML = _page(r"""
{% call page_head('Unaccounted Devices', counts.gap ~ ' of ' ~ counts.total_arp ~ ' devices on the wire are not claimed by Mist or Central') %}
  <a class="btn" href="/devices">{{ icon('devices', 'ic ic-sm') }} All devices</a>
{% endcall %}
<div class="stats">
  <div class="stat"><div class="stat-l">{{ icon('search') }} Unaccounted</div><div class="stat-v {{ 'v-warn' if counts.gap else 'v-good' }}">{{ counts.gap }}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('wifi') }} Wireless</div><div class="stat-v">{{ counts.wireless }}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('switch') }} Wired</div><div class="stat-v">{{ counts.wired }}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('ap') }} Infrastructure</div><div class="stat-v">{{ counts.infra }}</div></div>
</div>
<section class="card" data-table="gap-table">
  {% if devices %}
  <div class="card-h"><div><div class="card-sub">Usually static-IP gear, IoT on unmanaged ports, or infrastructure.</div></div></div>
  <div class="tbl-tools">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter…"/></label>
    <span class="tbl-count" data-noun="devices"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="gap-table">
      <thead><tr><th>IP address</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Lease</th></tr></thead>
      <tbody>
        {% for d in devices %}
        <tr>
          <td class="mono">{{ d.ip }}</td>
          <td>{% if d.hostname != "—" %}<span class="dev-name">{{ d.hostname }}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
          <td class="mono muted">{{ d.mac }}</td>
          <td class="muted" style="font-size:.78rem">{{ d.vendor }}</td>
          <td><span class="pill {{ 'pill-info' if d.type == 'DHCP' else 'pill-warn' }}">{{ d.type }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty">{{ icon('check') }}Everything on the network is accounted for by Mist or Central.</div>
  {% endif %}
</section>
""")


# ── WiFi health ──────────────────────────────────────────────────────────────

WHEALTH_HTML = _page(_RSSI + r"""
{% call page_head('WiFi Health', s.total ~ ' clients on ' ~ s.ap_count ~ ' access points · weak means ≤ ' ~ s.weak_threshold ~ ' dBm') %}
  <a class="btn" href="/client-issues">{{ icon('alert', 'ic ic-sm') }} Client issues</a>
{% endcall %}
<div class="stats">
  <div class="stat"><div class="stat-l">{{ icon('wifi') }} Clients</div><div class="stat-v">{{ s.total }}</div><div class="stat-s">on {{ s.ap_count }} APs</div></div>
  <div class="stat"><div class="stat-l"><i class="dot good"></i> Good signal</div><div class="stat-v v-good">{{ s.total - s.weak_only - s.poor }}</div><div class="stat-s">above {{ s.weak_threshold }} dBm</div></div>
  <div class="stat"><div class="stat-l"><i class="dot warn"></i> Weak signal</div><div class="stat-v {{ 'v-warn' if s.weak_only else 'v-good' }}">{{ s.weak_only }}</div><div class="stat-s">{{ s.poor_threshold }} to {{ s.weak_threshold }} dBm</div></div>
  <div class="stat"><div class="stat-l"><i class="dot danger"></i> Poor signal</div><div class="stat-v {{ 'v-danger' if s.poor else 'v-good' }}">{{ s.poor }}</div><div class="stat-s">≤ {{ s.poor_threshold }} dBm</div></div>
  <div class="stat"><div class="stat-l">{{ icon('pulse') }} Bands</div>
    <div class="mlist" style="gap:.3rem;margin-top:.45rem">
      {% for b in bands %}<div class="mrow"><span class="mrow-l" style="font-weight:500">{{ b.band }}</span><span class="mrow-v">{{ b.count }}</span></div>{% endfor %}
    </div>
  </div>
</div>

<div class="grid">
  <section class="card c5">
    <div class="card-h"><div><div class="card-t">{{ icon('ap') }} Load per access point</div><div class="card-sub">Client count and average signal</div></div></div>
    <div class="card-b flush">
      <div class="table-wrap">
        <table class="t sortable">
          <thead><tr><th>Access point</th><th class="r">Clients</th><th>Avg signal</th><th class="r">Weak</th></tr></thead>
          <tbody>
            {% for a in per_ap %}
            {% set cls = 'good' if a.avg_rssi and a.avg_rssi >= -65 else ('warn' if a.avg_rssi and a.avg_rssi >= -75 else 'danger') %}
            <tr>
              <td><div class="dev-name">{{ a.name }}</div><div class="dev-vendor">{% for band, n in a.bands.items() %}{{ band }} {{ n }}{% if not loop.last %} · {% endif %}{% endfor %}</div></td>
              <td class="r" style="font-weight:600">{{ a.count }}</td>
              <td>{% if a.avg_rssi is not none %}{{ rssi(cls, a.avg_rssi ~ ' dBm') }}{% else %}<span class="muted">—</span>{% endif %}</td>
              <td class="r">{% if a.weak %}<span class="pill pill-warn">{{ a.weak }}</span>{% else %}<span class="muted">0</span>{% endif %}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <section class="card c7" data-table="weak-table">
    <div class="card-h"><div><div class="card-t">{{ icon('alert') }} Weak-signal clients</div><div class="card-sub">{{ weak_clients | length }} below {{ s.weak_threshold }} dBm</div></div></div>
    {% if weak_clients %}
    <div class="tbl-tools">
      <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter…"/></label>
      <div class="chips"><button class="chip on" data-tag="">All</button><button class="chip" data-tag="poor">Poor only</button></div>
      <span class="tbl-count" data-noun="clients"></span>
    </div>
    <div class="table-wrap">
      <table class="t sortable" id="weak-table">
        <thead><tr><th>Client</th><th>Signal</th><th class="r">SNR</th><th>Band</th><th>SSID</th><th>Access point</th></tr></thead>
        <tbody>
          {% for w in weak_clients %}
          <tr data-tags="{{ w.severity }}">
            <td><div class="dev-name">{{ w.name }}</div>{% if w.ip %}<div class="dev-sub">{{ w.ip }}</div>{% endif %}</td>
            <td>{{ rssi('danger' if w.severity == 'poor' else 'warn', w.rssi ~ ' dBm') }}</td>
            <td class="r mono muted">{{ w.snr if w.snr is not none else '—' }}</td>
            <td class="muted" style="white-space:nowrap">{{ w.band }}</td>
            <td class="muted">{{ w.ssid or '—' }}</td>
            <td>{{ w.ap_name }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="empty">{{ icon('check') }}All clients are above {{ s.weak_threshold }} dBm.</div>
    {% endif %}
  </section>
</div>

{% set D = ui_data() %}
{% set rf = ui_radios(D.get('mist', {}).get('aps', [])) %}
{% set wl = ui_worst_links(D.get('mist', {}).get('clients', []), D.get('mist', {}).get('aps', []), 10) %}
{% set mix = ui_client_mix(D.get('mist', {}).get('clients', [])) %}
<div class="grid">
  <section class="card c5">
    <div class="card-h"><div><div class="card-t">{{ icon('pulse') }} Channel utilisation</div><div class="card-sub">Busiest radio per AP, by band · details on <a class="card-link" href="/aps">Access Points</a></div></div></div>
    <div class="card-b">
      {% for b in rf.bands %}
      <div class="stat-l" style="margin:{{ '0' if loop.first else '1rem' }} 0 .45rem">{{ b.label }} · {{ b.clients }} client{{ 's' if b.clients != 1 }}</div>
      <div class="mlist" style="gap:.5rem">
        {% for r in rf.rows | selectattr('band', 'equalto', b.band) %}
        <div class="mrow">
          <span class="mrow-l" style="font-weight:500">{{ r.ap }} <span class="muted mono" style="font-size:.74rem">ch {{ r.channel }}</span></span>
          <span class="mrow-v {{ r.util_tier }}">{{ r.util }}%</span>
          <div class="mbar {{ '' if r.util_tier == 'good' else ('warn' if r.util_tier == 'warn' else 'bad') }}"><span style="width:{{ [r.util, 1] | max }}%"></span></div>
        </div>
        {% endfor %}
      </div>
      {% endfor %}
      {% if rf.overlaps %}<div class="info-banner">{{ icon('info') }}<span>{% for o in rf.overlaps %}{{ o.aps | join(' & ') }} share {{ o.band }} channel {{ o.channel }}{{ '; ' if not loop.last else '.' }}{% endfor %}</span></div>{% endif %}
    </div>
  </section>

  <section class="card c7">
    <div class="card-h"><div><div class="card-t">{{ icon('alert') }} Worst links</div><div class="card-sub">Clients retrying the most transmissions this session (retries per 100 packets). High retries with a good signal usually means interference or a weak device radio.</div></div></div>
    <div class="card-b flush">
      {% if wl %}
      <div class="table-wrap">
        <table class="t">
          <thead><tr><th>Client</th><th class="r">Retries</th><th class="r">Signal</th><th>Band</th><th class="r">Rate</th><th>Access point</th></tr></thead>
          <tbody>
            {% for w in wl %}
            <tr>
              <td><div class="dev-name">{{ w.name }}</div><div class="dev-sub">{{ w.ip or w.mac }}</div></td>
              <td class="r"><span class="{{ w.retry_tier }}" style="font-weight:700">{{ w.retry }}%</span></td>
              <td class="r mono">{{ (w.rssi ~ ' dBm') if w.rssi is not none else '—' }}</td>
              <td style="white-space:nowrap">{{ ui_band(w.band) }} <span class="gen-badge {{ 'g6' if w.proto == 'ax' else ('legacy' if w.proto in ('g','a','b') else '') }}">{{ w.gen }}</span></td>
              <td class="r mono">{{ (w.tx_rate | round | int) if w.tx_rate else '—' }}</td>
              <td>{{ w.ap }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}<div class="empty">Not enough traffic yet to measure retries.</div>{% endif %}
    </div>
  </section>
</div>

<section class="card">
  <div class="card-h"><div><div class="card-t">{{ icon('devices') }} Client mix</div><div class="card-sub">{{ mix.total }} wireless clients</div></div></div>
  <div class="card-b">
    <div class="grid" style="margin:0">
      {% for title, items in (('Band', mix.bands), ('Wi-Fi generation', mix.gens), ('Makers', mix.makers)) %}
      <div class="c4">
        <div class="stat-l" style="margin-bottom:.5rem">{{ title }}</div>
        {% set top = (items | map(attribute=1) | max) if items else 1 %}
        <div class="mlist" style="gap:.5rem">
          {% for k, n in items %}
          <div class="mrow"><span class="mrow-l" style="font-weight:500">{{ k }}</span><span class="mrow-v">{{ n }}</span>
            <div class="mbar info"><span style="width:{{ 100 * n / top }}%"></span></div></div>
          {% endfor %}
        </div>
      </div>
      {% endfor %}
    </div>
    {% if mix.parked %}
    <div class="info-banner">{{ icon('info') }}<span><b>{{ mix.parked }}</b> dual-band client{{ 's' if mix.parked != 1 }} {{ 'are' if mix.parked != 1 else 'is' }} on 2.4 GHz even though {{ 'they' if mix.parked != 1 else 'it' }} could use 5 GHz: {{ mix.parked_names | join(', ') }}{{ '…' if mix.parked > 12 }}. Moving them would free up the busier band.</span></div>
    {% endif %}
  </div>
</section>
""")


# ── Events (server-side filter + paging) ─────────────────────────────────────

EVENTS_HTML = _page(r"""
{% set args = request.args.to_dict() %}
{% set v = ui_events_view(events, args) %}
{% call page_head('Events', '{:,}'.format(v.all_total) ~ ' events kept for 7 days · newest first') %}{% endcall %}

<div class="grid">
  <section class="card {{ 'c8' if v.repeats else 'c12' }}">
    <div class="card-h" style="padding-bottom:.6rem">
      <form class="tbl-tools" method="get" style="padding:0;flex:1">
        {% if v.kind %}<input type="hidden" name="kind" value="{{ v.kind }}">{% endif %}
        {% if v.sev %}<input type="hidden" name="sev" value="{{ v.sev }}">{% endif %}
        <label class="tbl-filter">{{ icon('search') }}<input type="text" name="q" value="{{ v.q }}" placeholder="Search event messages… (Enter)"/></label>
        <div class="chips">
          <a class="chip {{ 'on' if not v.kind }}" href="{{ ui_qs(args, kind='') }}">All types</a>
          {% for k, n in v.kinds %}<a class="chip {{ 'on' if v.kind == k }}" href="{{ ui_qs(args, kind=k) }}">{{ k | capitalize }} <b>{{ '{:,}'.format(n) }}</b></a>{% endfor %}
        </div>
        <div class="chips">
          <a class="chip {{ 'on' if not v.sev }}" href="{{ ui_qs(args, sev='') }}">Any severity</a>
          {% for sv, lbl in (('crit','Critical'),('warn','Warning'),('info','Info')) %}{% if v.sevs.get(sv) %}<a class="chip {{ 'on' if v.sev == sv }}" href="{{ ui_qs(args, sev=sv) }}"><i class="dot {{ 'danger' if sv == 'crit' else ('warn' if sv == 'warn' else 'info') }}"></i>{{ lbl }}</a>{% endif %}{% endfor %}
        </div>
        {% if v.q or v.kind or v.sev %}<a class="card-link" href="?">Clear filters</a>{% endif %}
      </form>
    </div>
    {% if v.rows %}
    <div class="table-wrap">
      <table class="t">
        <thead><tr><th style="width:1%"></th><th style="width:1%">Time</th><th style="width:1%">Type</th><th>Message</th></tr></thead>
        <tbody>
          {% for e in v.rows %}
          {% if e._day %}<tr><td colspan="4" style="background:var(--surface2);font-size:.72rem;font-weight:700;color:var(--muted);letter-spacing:.04em;text-transform:uppercase;padding:.4rem .9rem">{{ e._day }}</td></tr>{% endif %}
          <tr>
            <td><i class="dot {{ 'danger' if e.severity == 'crit' else ('warn' if e.severity == 'warn' else 'info') }}" title="{{ e.severity }}"></i></td>
            <td class="mono muted" style="white-space:nowrap" title="{{ e.ts }}">{{ e._time }}</td>
            <td><span class="pill pill-muted">{{ e.kind }}</span></td>
            <td>{{ e.message }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {{ pager(v.pager, args) }}
    {% else %}
    <div class="empty">{{ icon('clock') }}{% if v.q or v.kind or v.sev %}No events match these filters.{% else %}No events recorded in the last 7 days.{% endif %}</div>
    {% endif %}
  </section>

  {% if v.repeats %}
  <section class="card c4" style="align-self:start">
    <div class="card-h"><div><div class="card-t">{{ icon('pulse') }} Most repeated</div><div class="card-sub">Identical messages in this view</div></div></div>
    <div class="card-b">
      {% set top = v.repeats[0][1] %}
      <div class="mlist">
        {% for msg, n in v.repeats %}
        <a class="mrow" href="{{ ui_qs(args, q=msg) }}" style="text-decoration:none" title="Show only these">
          <span class="mrow-l" style="font-weight:500">{{ msg }}</span>
          <span class="mrow-v">{{ '{:,}'.format(n) }}</span>
          <div class="mbar info"><span style="width:{{ [100*n/top, 2] | max }}%"></span></div>
        </a>
        {% endfor %}
      </div>
    </div>
  </section>
  {% endif %}
</div>
""")


# ── Client issues (server-side filter + paging) ──────────────────────────────

CLIENT_ISSUES_HTML = _page(r"""
{% set args = request.args.to_dict() %}
{% set v = ui_failures_view(failures, args) %}
{% call page_head('Client Issues', '{:,}'.format(v.all_total) ~ ' wireless connection failures in the last 24 hours · from Mist') %}{% endcall %}

{% if v.all_total %}
<div class="stats">
  {% for c, label, n in v.cats %}
  <a class="stat" href="{{ ui_qs(args, cat='' if v.cat == c else c) }}" style="{{ 'border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-soft)' if v.cat == c }}">
    <div class="stat-l"><span class="pill cat-{{ c }}">{{ label or c }}</span></div>
    <div class="stat-v">{{ '{:,}'.format(n) }}</div>
    {% set pct = 100 * n / v.all_total %}<div class="stat-s">{{ '<1' if pct < 1 else pct | round(0) | int }}% of failures</div>
  </a>
  {% endfor %}
</div>

<div class="grid">
  <section class="card c8">
    <div class="card-h" style="padding-bottom:.6rem">
      <form class="tbl-tools" method="get" style="padding:0;flex:1">
        {% if v.cat %}<input type="hidden" name="cat" value="{{ v.cat }}">{% endif %}
        {% if v.sort != 'new' %}<input type="hidden" name="sort" value="{{ v.sort }}">{% endif %}
        <label class="tbl-filter">{{ icon('search') }}<input type="text" name="q" value="{{ v.q }}" placeholder="Device, IP, MAC, SSID… (Enter)"/></label>
        <div class="chips">
          {% for key, lbl in (('new','Newest'),('device','By device'),('signal','Weakest signal')) %}
          <a class="chip {{ 'on' if v.sort == key }}" href="{{ ui_qs(args, sort='' if key == 'new' else key) }}">{{ lbl }}</a>
          {% endfor %}
        </div>
        {% if v.q or v.cat %}<a class="card-link" href="?">Clear filters</a>{% endif %}
      </form>
    </div>
    {% if v.rows %}
    <div class="table-wrap">
      <table class="t">
        <thead><tr><th>Type</th><th>Device</th><th>IP</th><th>Band</th><th>Signal</th><th>When</th><th></th></tr></thead>
        <tbody>
          {% for f in v.rows %}
          <tr>
            <td><span class="pill cat-{{ f.category }}">{{ f.label }}</span></td>
            <td><div class="dev-name">{{ f.hostname or '—' }}</div><div class="dev-sub">{{ f.mac }}</div></td>
            <td class="mono">{{ f.ip or "—" }}</td>
            <td class="muted" style="white-space:nowrap">{{ f.band or "—" }}{% if f.ssid %}<div class="dev-vendor">{{ f.ssid }}</div>{% endif %}</td>
            <td class="muted" style="white-space:nowrap">{% if f.rssi is not none %}{{ f.rssi }} dBm{% else %}—{% endif %}</td>
            <td style="white-space:nowrap"><span class="mono">{{ f.timestamp | local_time }}</span><div class="dev-vendor">{{ f.timestamp | ts_ago }}</div></td>
            <td class="r"><a href="{{ f.mist_url }}" target="_blank" rel="noopener" class="ext-link">Mist {{ ext() }}</a></td>
          </tr>
          {% if f.text %}<tr class="sub"><td></td><td colspan="6" class="muted" style="font-size:.74rem;padding-top:0;border-top:none">{{ f.text }}</td></tr>{% endif %}
          {% endfor %}
        </tbody>
      </table>
    </div>
    {{ pager(v.pager, args) }}
    {% else %}
    <div class="empty">{{ icon('search') }}No failures match these filters.</div>
    {% endif %}
  </section>

  <section class="card c4" style="align-self:start">
    <div class="card-h"><div><div class="card-t">{{ icon('devices') }} Most affected devices</div><div class="card-sub">In the current view · click to filter</div></div></div>
    <div class="card-b">
      {% if v.top %}
      {% set top = v.top[0].n %}
      <div class="mlist">
        {% for t in v.top %}
        <a class="mrow" href="{{ ui_qs(args, q=t.who) }}" style="text-decoration:none">
          <span class="mrow-l">{{ t.who }}</span>
          <span class="mrow-v">{{ '{:,}'.format(t.n) }}</span>
          <div class="mbar warn"><span style="width:{{ [100*t.n/top, 2] | max }}%"></span></div>
          <span class="mrow-s">{% for lbl, n in t.cats %}{{ lbl }} {{ n }}{% if not loop.last %} · {% endif %}{% endfor %}</span>
        </a>
        {% endfor %}
      </div>
      {% else %}<div class="empty">Nothing to show.</div>{% endif %}
    </div>
  </section>
</div>
<style>table.t tr.sub:hover{background:none} table.t tbody tr:has(+ tr.sub){border-bottom:none}</style>
{% else %}
<section class="card"><div class="empty">{{ icon('check') }}No client failures in the last 24 hours. Wireless is healthy.</div></section>
{% endif %}
""")


# ── Topology ─────────────────────────────────────────────────────────────────

TOPOLOGY_HTML = _page(r"""
{% call page_head('Topology', 'WAN → firewall → switches → access points, from LLDP and inference') %}
  <label class="chip"><input type="checkbox" id="show-clients" style="accent-color:var(--accent)"> Wireless clients</label>
  <label class="chip"><input type="checkbox" id="show-wired" style="accent-color:var(--accent)"> Wired clients</label>
{% endcall %}
<section class="card">
  <div class="card-h" style="padding-bottom:.6rem">
    <div class="hlegend" style="margin:0;flex-wrap:wrap">
      <span><i class="dot" style="background:var(--info)"></i>WAN</span>
      <span><i class="dot" style="background:#7c5cff"></i>Firewall</span>
      <span><i class="dot" style="background:#2f9e6e"></i>Switch</span>
      <span><i class="dot" style="background:#d29922"></i>Access point</span>
      <span><i class="dot" style="background:#5a9fd4"></i>Wired client</span>
      <span><i class="dot" style="background:var(--muted)"></i>Wireless client</span>
      <span><i class="dot danger"></i>Down</span>
    </div>
    <span class="card-sub">Hover a node for details</span>
  </div>
  <div id="topo-wrap">
    <svg id="topo-svg" xmlns="http://www.w3.org/2000/svg"></svg>
    <div id="topo-tip" class="topo-tip" style="display:none"></div>
  </div>
</section>

<style>
  #topo-wrap{overflow:auto;padding:1rem 1.1rem 1.2rem;position:relative;border-top:1px solid var(--border);
             background-image:radial-gradient(var(--grid) 1px,transparent 1px);background-size:18px 18px}
  #topo-svg{display:block;min-width:100%}
  .topo-link{stroke:var(--border-strong);stroke-width:1.5;fill:none}
  .topo-link.down{stroke:var(--danger);stroke-dasharray:4 3;opacity:.7}
  .topo-node rect{fill:var(--surface)!important;filter:drop-shadow(0 1px 1.5px rgba(0,0,0,.12))}
  .topo-node{cursor:pointer}
  .topo-label{font-size:11px;font-weight:600;fill:var(--text);pointer-events:none;font-family:var(--ui)}
  .topo-sub{font-size:9px;fill:var(--muted);pointer-events:none;font-family:var(--ui)}
  .topo-tip{position:absolute;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.55rem .75rem;
            font-size:.76rem;pointer-events:none;z-index:10;box-shadow:var(--shadow-lg);max-width:260px}
  .topo-tip b{color:var(--text)}
  .topo-tip .row{color:var(--muted);margin-top:.15rem}
  label.chip{cursor:pointer;user-select:none}
</style>

<script id="topo-data" type="application/json">{{ tree_json | safe }}</script>
<script>
(function(){
  const RAW = JSON.parse(document.getElementById('topo-data').textContent);
  const svg = document.getElementById('topo-svg');
  const tip = document.getElementById('topo-tip');
  const wrap = document.getElementById('topo-wrap');
  const showClients = document.getElementById('show-clients');
  const showWired = document.getElementById('show-wired');
  const css = getComputedStyle(document.documentElement);
  const COL = {
    wan: css.getPropertyValue('--info').trim() || '#0d7fb0',
    router: '#7c5cff', switch: '#2f9e6e', ap: '#d29922',
    client: css.getPropertyValue('--muted').trim() || '#8b949e', wired: '#5a9fd4',
  };
  const DOWN = css.getPropertyValue('--danger').trim() || '#d93f3f';
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const NODE_W = 140, NODE_H = 40, H_GAP = 64, V_GAP = 16;

  try {
    showClients.checked = sessionStorage.getItem('nd_topo_clients') === '1';
    showWired.checked = sessionStorage.getItem('nd_topo_wired') === '1';
  } catch(e){}

  function prep(node){
    const n = Object.assign({}, node);
    let kids = node.children || [];
    if (!showClients.checked) kids = kids.filter(c => c.type !== 'client');
    if (!showWired.checked) kids = kids.filter(c => c.type !== 'wired');
    n.children = kids.map(prep);
    return n;
  }
  function layout(node, depth){
    node._x = depth * (NODE_W + H_GAP);
    if (!node.children || !node.children.length) { node._h = NODE_H + V_GAP; return node._h; }
    let h = 0;
    for (const c of node.children) h += layout(c, depth + 1);
    node._h = Math.max(h, NODE_H + V_GAP);
    return node._h;
  }
  function assignY(node, top){
    if (!node.children || !node.children.length) { node._y = top + (NODE_H + V_GAP) / 2; return; }
    let cursor = top;
    for (const c of node.children) { assignY(c, cursor); cursor += c._h; }
    node._y = (node.children[0]._y + node.children[node.children.length - 1]._y) / 2;
  }
  function collect(node, nodes, links, parent, seen){
    const already = seen.has(node.id);
    if (parent && parent.type !== 'root') links.push({from: parent, to: node});
    if (already) return;
    seen.add(node.id);
    if (node.type !== 'root') nodes.push(node);
    for (const c of (node.children || [])) collect(c, nodes, links, node, seen);
  }
  function el(tag, attrs){
    const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function render(){
    const root = prep(RAW);
    const wans = root.children;
    const router = wans[0].children[0];
    const totalH = layout(router, 1);
    assignY(router, 0);
    const nodes = [], links = [];
    collect(router, nodes, links, null, new Set());
    const wanGap = NODE_H + 22;
    const startY = router._y - (wans.length - 1) * wanGap / 2;
    wans.forEach((wn, i) => { wn._x = 0; wn._y = startY + i * wanGap; nodes.push(wn); links.push({from: wn, to: router}); });
    const minX = Math.min(...nodes.map(n => n._x));
    if (minX < 0) for (const n of nodes) n._x -= minX;
    const maxX = Math.max(...nodes.map(n => n._x)) + NODE_W + 20;
    const minY = Math.min(...nodes.map(n => n._y));
    const maxY = Math.max(...nodes.map(n => n._y + NODE_H));
    if (minY < 0) for (const n of nodes) n._y += -minY + 10;
    const vH = Math.max(totalH, maxY - minY) + 20;
    svg.setAttribute('viewBox', `0 0 ${maxX} ${vH}`);
    svg.setAttribute('width', maxX);
    svg.setAttribute('height', vH);
    svg.innerHTML = '';
    for (const l of links) {
      const x1 = l.from._x + NODE_W, y1 = l.from._y + 10, x2 = l.to._x, y2 = l.to._y + 10, mx = (x1 + x2) / 2;
      svg.appendChild(el('path', {d: `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`, class: 'topo-link' + (l.to.status === 'down' ? ' down' : '')}));
    }
    for (const n of nodes) {
      const g = el('g', {class: 'topo-node', transform: `translate(${n._x},${n._y})`});
      const isClient = n.type === 'client' || n.type === 'wired';
      const w = isClient ? 100 : NODE_W, h = isClient ? 24 : NODE_H;
      const col = COL[n.type] || COL.client;
      g.setAttribute('opacity', (n.type === 'wan' && n.role === 'backup') ? '0.6' : '1');
      const sw = (n.type === 'wan' && n.role === 'primary') ? 2.5 : (n.status === 'down' ? 2 : 1.5);
      g.appendChild(el('rect', {width: w, height: h, rx: 7, fill: 'var(--surface)', stroke: n.status === 'down' ? DOWN : col, 'stroke-width': sw}));
      g.appendChild(el('circle', {cx: 12, cy: h / 2, r: 4, fill: n.status === 'down' ? DOWN : col}));
      const label = el('text', {x: 24, y: isClient ? h / 2 + 3 : h / 2 - 1, class: 'topo-label'});
      label.textContent = n.label.length > 17 ? n.label.slice(0, 16) + '…' : n.label;
      g.appendChild(label);
      if (!isClient) {
        let sub = n.type;
        if (n.type === 'wan') sub = [n.meta.role, n.meta.latency].filter(Boolean).join(' · ') || 'WAN';
        if (n.type === 'ap') { const p = [n.meta.model, n.meta.uplink_port && 'port ' + n.meta.uplink_port].filter(Boolean); if (p.length) sub = p.join(' · '); }
        if (n.type === 'switch' && n.meta.model) sub = n.meta.model.slice(0, 20);
        if (n.type === 'router') sub = n.meta.role || 'router';
        const t = el('text', {x: 24, y: h / 2 + 11, class: 'topo-sub'});
        t.textContent = sub;
        g.appendChild(t);
      }
      g.addEventListener('mousemove', e => {
        const rows = Object.entries(n.meta || {}).filter(([k, v]) => v && typeof v !== 'object')
          .map(([k, v]) => `<div class="row">${esc(k)}: ${esc(v)}</div>`);
        tip.innerHTML = `<b>${esc(n.label)}</b> <span style="color:${col}">(${esc(n.type)})</span><div class="row">status: ${esc(n.status)}</div>` + rows.join('');
        tip.style.display = 'block';
        const wr = wrap.getBoundingClientRect();
        tip.style.left = (e.clientX - wr.left + wrap.scrollLeft + 14) + 'px';
        tip.style.top = (e.clientY - wr.top + wrap.scrollTop + 14) + 'px';
      });
      g.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
      svg.appendChild(g);
    }
  }
  function remember(){
    try {
      sessionStorage.setItem('nd_topo_clients', showClients.checked ? '1' : '0');
      sessionStorage.setItem('nd_topo_wired', showWired.checked ? '1' : '0');
    } catch(e){}
    render();
  }
  showClients.addEventListener('change', remember);
  showWired.addEventListener('change', remember);
  render();
})();
</script>
""")


# ── Switches ─────────────────────────────────────────────────────────────────

SWITCHES_HTML = _page(r"""
{% call page_head('Switches', (v.switches | length) ~ ' Aruba switches · ports refresh every 5 minutes from Central') %}{% endcall %}
{% if v.pending %}
<div class="info-banner" style="margin:0 0 1rem">{{ icon('info') }}<span>Fetching port details from Central; this page fills in within a minute of the dashboard starting.{% if v.error %} Last error: {{ v.error }}{% endif %}</span></div>
{% endif %}

{% set notes = [] %}
{% if v.firmware | length > 1 %}{% set _ = notes.append('The switches run different firmware: ' ~ (v.firmware | join(' and ')) ~ '.') %}{% endif %}
{% for sw in v.switches %}
  {% if sw.rebooted %}{% set _ = notes.append(sw.name ~ ' restarted ' ~ (sw.uptime | duration) ~ ' ago.') %}{% endif %}
  {% for p in sw.half %}{% set _ = notes.append(sw.name ~ ' port ' ~ p.port ~ ' is running half duplex.') %}{% endfor %}
  {% if sw.error %}{% set _ = notes.append(sw.name ~ ': could not read port details (' ~ sw.error ~ ').') %}{% endif %}
{% endfor %}
{% set slow = [] %}
{% for sw in v.switches %}{% for p in sw.slow %}{% set _ = slow.append((sw.name, p)) %}{% endfor %}{% endfor %}
{% if slow %}{% set _ = notes.append('slow') %}{% endif %}
{% if notes %}
<section class="card" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('info') }} Worth a look</div></div></div>
  <div class="card-b" style="padding-top:.4rem"><ul class="notes">
    {% for n in notes if n != 'slow' %}<li>{{ n }}</li>{% endfor %}
    {% if slow %}<li>{{ slow | length }} port{{ 's are' if slow | length != 1 else ' is' }} linked at 100 Mbps or less. That is normal for small devices such as alarm panels, phone adapters and cameras; check any that should be gigabit (a damaged cable often drops a link to 100 Mbps):
      <div class="chips" style="margin-top:.45rem">{% for sw_name, p in slow %}<span class="chip" style="cursor:default" title="{{ sw_name }} {{ p.port }} · {{ p.speed_label }}"><span class="mono">{{ p.port }}</span> {{ (p.devices | map(attribute='name') | join(', ')) or 'unknown device' }}{% if v.switches | length > 1 %} <b>{{ sw_name.split('-')[0] }}</b>{% endif %}</span>{% endfor %}</div></li>{% endif %}
  </ul></div>
</section>
{% endif %}

<div class="grid">
  {% for sw in v.switches %}
  <section class="card {{ 'c6' if v.switches | length > 1 else 'c12' }}">
    <div class="card-h">
      <div><div class="card-t">{{ icon('switch') }} {{ sw.name }}</div><div class="card-sub">{{ sw.model }} · {{ sw.ip or '—' }}</div></div>
      <div class="card-x"><span class="status"><i class="dot {{ 'good' if sw.status == 'Up' else 'danger' }}"></i>{{ sw.status }}</span></div>
    </div>
    <div class="card-b">
      <div class="stats" style="grid-template-columns:repeat(4,minmax(0,1fr));gap:.6rem;margin:0">
        <div><div class="stat-l">Ports up</div><div class="mrow-v" style="font-size:1.1rem">{{ sw.ports_up }}<span class="muted" style="font-weight:500">/{{ sw.ports_total or '—' }}</span></div></div>
        <div><div class="stat-l">Uptime</div><div class="mrow-v" style="font-size:1.1rem">{{ (sw.uptime | duration) if sw.uptime else '—' }}</div></div>
        <div><div class="stat-l">PoE</div><div class="mrow-v" style="font-size:1.1rem">{{ ((sw.poe_w | round(0) | int) ~ ' W') if sw.poe_w is not none else '—' }}</div></div>
        <div><div class="stat-l">Clients</div><div class="mrow-v" style="font-size:1.1rem">{{ sw.clients if sw.clients is not none else '—' }}</div></div>
      </div>
      <div class="mlist" style="margin-top:1rem;gap:.55rem">
        {% for label, val in (('CPU', sw.cpu), ('Memory used', sw.mem_used)) %}
        {% if val is not none %}
        <div class="mrow"><span class="mrow-l" style="font-weight:500">{{ label }}</span><span class="mrow-v">{{ val | round | int }}%</span>
          <div class="mbar {{ '' if val < 60 else ('warn' if val < 85 else 'bad') }}"><span style="width:{{ [val, 1] | max }}%"></span></div></div>
        {% endif %}
        {% endfor %}
      </div>
      <div class="note" style="margin-top:.8rem">Firmware <span class="mono">{{ sw.firmware or '—' }}</span>{% if sw.fan %} · fans {{ sw.fan }}{% endif %}{% if sw.temp %} · {{ sw.temp }}{% endif %}{% if sw.health %} · health {{ sw.health | lower }}{% endif %}</div>
    </div>
  </section>
  {% endfor %}
</div>

{% for sw in v.switches if sw.ports %}
<section class="card" data-table="ports-{{ loop.index }}" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('switch') }} {{ sw.name }} ports</div><div class="card-sub">What is plugged in comes from Central's wired clients and Mist's AP uplink data</div></div></div>
  <div class="tbl-tools">
    <label class="tbl-filter">{{ icon('search') }}<input type="text" placeholder="Filter ports or devices…"/></label>
    <div class="chips">
      <button class="chip" data-tag="">All</button>
      <button class="chip on" data-tag="up">Connected</button>
      <button class="chip" data-tag="poe">PoE</button>
      <button class="chip" data-tag="slow">Below 1 Gbps</button>
    </div>
    <span class="tbl-count" data-noun="ports"></span>
  </div>
  <div class="table-wrap">
    <table class="t sortable" id="ports-{{ loop.index }}">
      <thead><tr><th>Port</th><th>Status</th><th>Speed</th><th class="r">PoE</th><th>VLAN</th><th>Connected device</th></tr></thead>
      <tbody>
        {% for p in sw.ports %}
        <tr data-tags="{{ 'up' if p.up }}{{ ' poe' if p.poe }}{{ ' slow' if p.slow }}">
          <td class="mono" data-v="{{ loop.index }}">{{ p.port }}{% if p.uplink %} <span class="pill pill-info">uplink</span>{% endif %}</td>
          <td style="white-space:nowrap">{% if p.up %}<span class="status"><i class="dot good"></i>Up</span>
              {% elif not p.admin_up %}<span class="status"><i class="dot"></i>Disabled</span>
              {% else %}<span class="status muted"><i class="dot"></i>Down</span>{% endif %}</td>
          <td style="white-space:nowrap" data-v="{{ p.speed or 0 }}"><span class="{{ 'warn' if p.slow }}" style="{{ 'font-weight:600' if p.slow }}">{{ p.speed_label }}</span>{% if p.up and p.duplex %} <span class="muted" style="font-size:.74rem">{{ p.duplex | lower }}</span>{% endif %}</td>
          <td class="r" style="white-space:nowrap" data-v="{{ p.poe_w or 0 }}">{% if p.poe %}{{ (p.poe_w ~ ' W') if p.poe_w is not none else 'on' }}{% else %}<span class="muted">—</span>{% endif %}</td>
          <td class="muted">{{ p.vlan if p.vlan is not none else '—' }}{% if p.mode and p.mode != 'Access' %} <span class="pill pill-muted">{{ p.mode | lower }}</span>{% endif %}</td>
          <td>{% for dv in p.devices %}<div><span class="dev-name">{{ dv.name }}</span> {% if dv.kind == 'ap' %}<span class="pill pill-info">AP</span>{% endif %} <span class="mono muted">{{ dv.ip or '' }}</span></div>{% else %}{% if not p.up and p.down_reason and p.admin_up %}<span class="muted" style="font-size:.76rem">{{ p.down_reason }}</span>{% endif %}{% endfor %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endfor %}
""")
