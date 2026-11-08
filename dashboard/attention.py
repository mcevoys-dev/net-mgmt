"""
"Needs attention": one ranked list of everything wrong, for the top of the Overview.

Every page already works out its own problems (the "Worth a look" notes).
collect() gathers them from each page's view, tags each with where it came
from and a link, and ranks them: critical, then warning, then notes.

Each problem gets a stable key (its source plus its text with the numbers
taken out, so "87% full" and "88% full" stay the same problem). The key is
used to remember when a problem was first seen and to hide (snooze) one for
a while. That state lives in data_dir/attention.json.
"""
import hashlib
import json
import re
import threading
import time
from pathlib import Path

ORDER = {"danger": 0, "warn": 1, "info": 2}
SNOOZE_DAYS = (1, 7, 30)
PER_SOURCE = 3

# source key -> (label, link, Health table row it belongs to)
SOURCES = {
    "data":     ("Data sources", "/events", None),
    "wan":      ("Internet", "/#internet", "wan"),
    "firewall": ("Firewall", "/firewall", "firewall"),
    "proxmox":  ("Proxmox", "/proxmox", "proxmox"),
    "pbs":      ("Backup server", "/proxmox#backup-server", "pbs"),
    "nas":      ("NAS", "/nas", "nas"),
    "services": ("Websites & ports", "/services", "services"),
    "mail":     ("Mail", "/services#mail", "mail"),
    "aps":      ("Access points", "/aps", "aps"),
    "switches": ("Switches", "/switches", "switches"),
    "wifi":     ("Wi-Fi", "/wireless-health", "wifi"),
}

_MAIL_PREFIXES = ("Mail server", "Listmonk", "Newsletter")


def _key(source, text):
    norm = re.sub(r"\d+(\.\d+)?", "#", text.lower())
    return hashlib.sha1(f"{source}|{norm}".encode()).hexdigest()[:12]


def _item(source, sev, text):
    label, href, _ = SOURCES[source]
    return {"source": source, "label": label, "href": href, "sev": sev, "text": text,
            "key": _key(source, text)}


class State:
    """First-seen times and snoozes, saved as JSON next to the event log."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.first_seen, self.snoozed = {}, {}
        try:
            raw = json.loads(self.path.read_text())
            self.first_seen = raw.get("first_seen") or {}
            self.snoozed = raw.get("snoozed") or {}
        except (OSError, ValueError):
            pass

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"first_seen": self.first_seen, "snoozed": self.snoozed}, indent=1))
        tmp.replace(self.path)

    def touch(self, keys, now):
        """Record first-seen for new keys; forget keys that have cleared."""
        with self._lock:
            changed = False
            for k in keys:
                if k not in self.first_seen:
                    self.first_seen[k] = now
                    changed = True
            for k in list(self.first_seen):
                if k not in keys:
                    del self.first_seen[k]
                    changed = True
            for k in [k for k, s in self.snoozed.items() if s["until"] < now]:
                del self.snoozed[k]
                changed = True
            if changed:
                try:
                    self._save()
                except OSError as e:
                    print(f"[ATTENTION] could not save state: {e}", flush=True)
            return dict(self.first_seen), dict(self.snoozed)

    def snooze(self, key, days, text):
        with self._lock:
            self.snoozed[key] = {"until": time.time() + days * 86400, "days": days, "text": text[:300]}
            self._save()

    def unsnooze(self, key):
        with self._lock:
            if self.snoozed.pop(key, None) is not None:
                self._save()


def _notes(g, source, view_fn):
    try:
        v = view_fn(g)
    except Exception as e:                      # one broken page must not hide the rest
        return [_item(source, "warn", f"Could not check {SOURCES[source][0].lower()}: {e}")]
    if not v:
        return []
    if v.get("pending"):
        err = v.get("error")
        if err and "No credentials" not in str(err):
            return [_item(source, "danger", f"{SOURCES[source][0]}: {err}")]
        return []
    return [_item(source, sev, text) for sev, text in v.get("notes") or []]


def collect(g):
    import ui
    import ui_infra
    d = g["get_data"]()
    mist, central, opn = d.get("mist", {}), d.get("central", {}), d.get("opnsense", {})
    items = []

    for err in d.get("errors") or []:
        items.append(_item("data", "danger", f"Could not read {err}."))

    # Internet
    try:
        for w in g["build_wan_cards"](opn.get("gateways", []), opn.get("interfaces", [])):
            sc = w.get("status_class")
            if sc not in ("danger", "warn"):
                continue
            label = str(w.get("status_label") or "down").lower()
            q = ", ".join(f"{k} {w[k]}" for k in ("loss", "delay") if w.get(k) not in (None, "", "—"))
            text = f"{w['name']} is down." if label == "down" else f"{w['name']}: {label}{(' (' + q + ')') if q else ''}."
            items.append(_item("wan", sc, text))
    except Exception as e:
        items.append(_item("wan", "warn", f"Could not check internet links: {e}"))

    # Firewall, Proxmox, backup server, NAS
    if g["CFG"].opnsense.enabled:
        items += _notes(g, "firewall", ui.firewall_view)
    items += _notes(g, "proxmox", ui.proxmox_view)
    items += _notes(g, "pbs", ui_infra.pbs_view)
    items += _notes(g, "nas", ui_infra.nas_view)
    for it in _notes(g, "services", ui_infra.services_view):
        if it["text"].startswith(_MAIL_PREFIXES) or "hard bounces" in it["text"]:
            it = _item("mail", it["sev"], it["text"])
        items.append(it)

    # Access points
    aps = mist.get("aps", [])
    for ap in aps:
        if ap.get("status") != "connected":
            items.append(_item("aps", "danger", f"Access point {ap.get('name') or ap.get('mac')} is offline."))
    if aps:
        h = ui.ap_health(aps, ui.port_power(g))
        for names, sev, what in ((h["errors"], "warn", "uplink is reporting errors"),
                                 (h["half_duplex"], "warn", "uplink is half duplex"),
                                 (h["constrained"], "warn", "is not getting full PoE power"),
                                 (h["certs"], "warn", "has certificates about to expire"),
                                 (h["slow_links"], "info", "uplink is below 1 Gbps"),
                                 (h["rebooted"], "info", "restarted in the last 24 hours")):
            if names:
                items.append(_item("aps", sev, f"{', '.join(names)} {what}."))
        rf = ui.radios(aps)
        for b in rf["bands"]:
            if b["tier"] == "danger":
                busiest = max((r for r in rf["rows"] if r["band"] == b["band"] and r["util"] is not None),
                              key=lambda r: r["util"], default=None)
                where = f" ({busiest['ap']}, channel {busiest['channel']})" if busiest else ""
                items.append(_item("aps", "warn", f"{b['label']} is congested: busiest radio at {b['max']}%{where}."))
        if rf["overlaps"]:
            items.append(_item("aps", "info", "Neighbouring APs share a channel: " + "; ".join(
                f"{' & '.join(o['aps'])} on {o['band']} ch {o['channel']}" for o in rf["overlaps"]) + "."))

    # Switches
    for sw in central.get("switches", []):
        if (sw.get("status") or "").lower() != "up":
            items.append(_item("switches", "danger", f"Switch {sw.get('name') or sw.get('serial')} is offline."))
    if central.get("switches"):
        v = ui.switches_view(g)
        if len(v["firmware"]) > 1:
            items.append(_item("switches", "info", f"Switches run different firmware: {' and '.join(v['firmware'])}."))
        for sw in v["switches"]:
            for p in sw["half"]:
                items.append(_item("switches", "warn", f"{sw['name']} port {p['port']} is running half duplex."))
            if sw["error"]:
                items.append(_item("switches", "warn", f"{sw['name']}: could not read port details ({sw['error']})."))
            if sw["slow"]:
                items.append(_item("switches", "info", f"{sw['name']}: {len(sw['slow'])} port(s) linked at 100 Mbps or less "
                                   "(normal for small devices; check any that should be gigabit)."))

    # Wireless clients on poor signal
    clients = mist.get("clients", [])
    if clients:
        try:
            wh = g["analyze_wireless_health"](clients, aps)["summary"]
            if wh.get("poor"):
                items.append(_item("wifi", "info", f"{wh['poor']} of {len(clients)} wireless clients are on poor signal."))
        except Exception:
            pass

    # many late replication jobs usually share one cause: show them as one line
    late = [(i, m) for i in items if i["source"] == "proxmox"
            for m in [re.match(r"Replication (.+?) \((.+?)\) has not synced on schedule\.$", i["text"])] if m]
    if len(late) > 1:
        names = [m.group(1) for _, m in late]
        merged = _item("proxmox", "warn", f"{len(late)} replication jobs have not synced on schedule: "
                       + ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "") + ".")
        merged["key"] = _key("proxmox", "replication jobs late")
        drop = {id(i) for i, _ in late}
        at = items.index(late[0][0])
        items = [i for i in items[:at] if id(i) not in drop] + [merged] + [i for i in items[at:] if id(i) not in drop]

    # de-duplicate (same key twice), then rank
    seen, out = set(), []
    for it in items:
        if it["key"] not in seen:
            seen.add(it["key"])
            out.append(it)
    out.sort(key=lambda x: ORDER[x["sev"]])
    return out


def view(g, state):
    now = time.time()
    items = collect(g)
    first, snoozed = state.touch({i["key"] for i in items}, now)
    for i in items:
        i["age"] = now - first.get(i["key"], now)
    hidden = [dict(i, until=snoozed[i["key"]]["until"]) for i in items if i["key"] in snoozed]
    shown = [i for i in items if i["key"] not in snoozed]
    by_row = {}
    for i in shown:
        row = SOURCES[i["source"]][2]
        if row and i["sev"] != "info":
            by_row.setdefault(row, []).append(i["text"])
    urgent = [i for i in shown if i["sev"] != "info"]
    # at most PER_SOURCE lines from one source; the rest fold into "N more"
    rows, count, extra = [], {}, {}
    for i in urgent:
        count[i["source"]] = count.get(i["source"], 0) + 1
        if count[i["source"]] <= PER_SOURCE:
            rows.append(i)
        else:
            extra.setdefault(i["source"], []).append(i)
    for src, more in extra.items():
        last = max(n for n, r in enumerate(rows) if r.get("source") == src)
        rows.insert(last + 1, {"more": more, "label": SOURCES[src][0], "href": SOURCES[src][1]})
    return {
        "urgent": urgent,
        "rows": rows,
        "notes": [i for i in shown if i["sev"] == "info"],
        "hidden": hidden,
        "crit": sum(1 for i in shown if i["sev"] == "danger"),
        "warn": sum(1 for i in shown if i["sev"] == "warn"),
        "why": by_row,
        "snooze_days": SNOOZE_DAYS,
    }
