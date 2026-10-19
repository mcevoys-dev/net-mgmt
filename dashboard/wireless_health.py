"""
Wireless health analysis from Mist client + AP data.
Pure derivation — no new API calls. Consumes the same structures the
existing /wireless route uses:
  clients: [{mac, hostname, rssi, snr, ap_mac, band, ssid, proto, ...}]
  aps:     [{mac(no-sep), name, ...}]

band values from Mist arrive as "24" / "5" / "6" (24 == 2.4 GHz).
"""

WEAK_RSSI   = -70   # at/below this = weak
POOR_RSSI   = -75   # at/below this = poor (subset of weak)


def _band_ghz(b):
    """Normalize Mist band code to a display label."""
    return {"24": "2.4 GHz", "2.4": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}.get(str(b), str(b) or "—")


def analyze_wireless_health(clients, aps, weak=WEAK_RSSI, poor=POOR_RSSI):
    # AP MAC (no-sep, lower) -> friendly name
    ap_name = {}
    for ap in aps:
        m = (ap.get("mac") or "").lower()
        if m:
            ap_name[m] = ap.get("name") or m

    weak_clients = []
    per_ap = {}    # ap_mac -> {name, count, rssi_sum, weak, bands:{}}
    band_counts = {}

    for c in clients:
        rssi = c.get("rssi")
        ap_mac = (c.get("ap_mac") or "").lower()
        name = c.get("hostname") or c.get("username") or c.get("mac") or "—"
        band = _band_ghz(c.get("band"))

        # Band distribution
        band_counts[band] = band_counts.get(band, 0) + 1

        # Per-AP rollup
        ap = per_ap.setdefault(ap_mac, {
            "ap_mac": ap_mac,
            "name": ap_name.get(ap_mac, ap_mac or "—"),
            "count": 0, "rssi_sum": 0, "rssi_n": 0,
            "weak": 0, "bands": {},
        })
        ap["count"] += 1
        ap["bands"][band] = ap["bands"].get(band, 0) + 1
        if isinstance(rssi, (int, float)):
            ap["rssi_sum"] += rssi
            ap["rssi_n"] += 1

        # Weak-signal detection
        if isinstance(rssi, (int, float)) and rssi <= weak:
            weak_clients.append({
                "name": name,
                "mac": c.get("mac", ""),
                "ip": c.get("ip", ""),
                "rssi": rssi,
                "snr": c.get("snr"),
                "band": band,
                "ssid": c.get("ssid", ""),
                "ap_name": ap_name.get(ap_mac, ap_mac or "—"),
                "severity": "poor" if rssi <= poor else "weak",
            })

    # Finalize per-AP: avg rssi, sort by client count desc
    ap_list = []
    for ap in per_ap.values():
        avg = round(ap["rssi_sum"] / ap["rssi_n"]) if ap["rssi_n"] else None
        ap_list.append({
            "name": ap["name"],
            "ap_mac": ap["ap_mac"],
            "count": ap["count"],
            "avg_rssi": avg,
            "weak": sum(1 for w in weak_clients if w["ap_name"] == ap["name"]),
            "bands": ap["bands"],
        })
    ap_list.sort(key=lambda a: a["count"], reverse=True)

    # Weak clients: worst signal first
    weak_clients.sort(key=lambda w: w["rssi"])

    # Band distribution ordered 2.4 / 5 / 6 / other
    order = {"2.4 GHz": 0, "5 GHz": 1, "6 GHz": 2}
    bands = sorted(band_counts.items(), key=lambda kv: order.get(kv[0], 9))

    total = len(clients)
    return {
        "summary": {
            "total": total,
            "weak": len(weak_clients),
            "poor": sum(1 for w in weak_clients if w["severity"] == "poor"),
            "weak_only": sum(1 for w in weak_clients if w["severity"] == "weak"),
            "ap_count": len([a for a in ap_list if a["ap_mac"]]),
            "weak_threshold": weak,
            "poor_threshold": poor,
        },
        "weak_clients": weak_clients,
        "per_ap": ap_list,
        "bands": [{"band": b, "count": n} for b, n in bands],
    }
