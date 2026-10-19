"""
Mist SLE (Service Level Expectation) fetch + compute.

Mist's PACE engine scores 7 wireless-experience metrics. Each is exposed via
the "metric summary" endpoint:

  /api/v1/sites/{site}/sle/site/{site}/metric/{metric}/summary?start=&end=

Note the doubled path: `sle/site/{site}` is the *scope* (site vs ap vs client).

Success rate = 1 - (sum(degraded) / sum(total)), as a percentage.
Each classifier's share of total degraded explains *why* failures happened.

This module is read-only and self-contained: give it a base URL, token,
site id, and a requests-style session, and it returns computed SLE cards.
"""
import math
import time
from datetime import datetime, timezone

# The 7 metrics PACE monitors, with display labels and the "higher is better"
# framing. Order is roughly "most likely to have data on a small site" first.
SLE_METRICS = [
    ("time-to-connect",   "Time to Connect"),
    ("successful-connect", "Successful Connects"),
    ("coverage",          "Coverage"),
    ("roaming",           "Roaming"),
    ("throughput",        "Throughput"),
    ("capacity",          "Capacity"),
    ("ap-availability",   "AP Availability"),
]

# Human-friendly classifier names (Mist returns machine names)
CLASSIFIER_LABELS = {
    "dhcp": "DHCP",
    "authorization": "Authorization",
    "association": "Association",
    "dns": "DNS",
    "arp": "ARP",
    "internet-services": "Internet Services",
    "interference": "Wi-Fi Interference",
    "coverage": "Coverage",
    "capacity": "Capacity",
    "client-count": "Client Count",
    "client-load": "Client Load",
    "client-usage": "Client Usage",
    "network-issues": "Network Issues",
    "wifi-interference": "Wi-Fi Interference",
    "non-wifi-interference": "Non-Wi-Fi Interference",
    "band-steering": "Band Steering",
    "asymmetry-downlink": "Downlink Asymmetry",
    "asymmetry-uplink": "Uplink Asymmetry",
    "signal-quality": "Signal Quality",
    "throughput": "Throughput",
    "latency": "Latency",
    "jitter": "Jitter",
}


def _label_classifier(name):
    return CLASSIFIER_LABELS.get(name, name.replace("-", " ").title())


def _sum_clean(arr):
    """Sum an array that may contain None entries."""
    return sum(x for x in (arr or []) if x is not None)


def compute_metric(payload):
    """
    Given a metric-summary JSON payload, compute the success-rate % and the
    top contributing classifier. Returns None if there's no usable data.
    """
    sle = (payload or {}).get("sle", {})
    samples = sle.get("samples", {})
    total = _sum_clean(samples.get("total"))
    degraded = _sum_clean(samples.get("degraded"))

    if total <= 0:
        return None  # no activity in window -> metric not meaningful

    success = math.ceil((1 - (degraded / total)) * 100)
    success = max(0, min(100, success))

    # Find the top classifier by its share of total degraded
    top_classifier = None
    if degraded > 0:
        best = 0.0
        for c in payload.get("classifiers", []):
            c_deg = _sum_clean(c.get("samples", {}).get("degraded"))
            if c_deg > best:
                best = c_deg
                pct = round((c_deg / degraded) * 100)
                top_classifier = {"name": _label_classifier(c.get("name", "")),
                                  "impact": pct}

    impact = payload.get("impact", {}) or {}
    return {
        "success": success,
        "degraded_sum": degraded,
        "total_sum": total,
        "top_classifier": top_classifier,
        "num_users": impact.get("num_users", 0),
        "num_aps": impact.get("num_aps", 0),
    }


def health_tier(success):
    """Map a success % to a health tier for UI coloring."""
    if success >= 95:
        return "good"
    if success >= 85:
        return "warn"
    return "bad"


def fetch_sles(session, base_url, token, site_id, window_hours=24):
    """
    Fetch all SLE metrics for a site and return computed cards.
    `session` is a requests.Session (or anything with .get()).
    Returns a list of dicts, only for metrics that have real data.
    """
    end = int(time.time())
    start = end - window_hours * 3600
    headers = {"Authorization": f"Token {token}"}

    cards = []
    for metric, label in SLE_METRICS:
        url = (f"{base_url}/sites/{site_id}/sle/site/{site_id}"
               f"/metric/{metric}/summary?start={start}&end={end}")
        try:
            r = session.get(url, headers=headers, timeout=15)
            if r.status_code != 200:
                continue
            computed = compute_metric(r.json())
            if computed is None:
                continue  # skip metrics with no data (sparse on small sites)
            computed["metric"] = metric
            computed["label"] = label
            computed["tier"] = health_tier(computed["success"])
            cards.append(computed)
        except Exception as e:
            print(f"[SLE] {metric} fetch failed: {e}", flush=True)
            continue

    return cards
