"""
Mist client failure events.

Mist logs 150+ client state-changes; most are successes (CLIENT_IP_ASSIGNED,
CLIENT_DNS_OK, ...). This module fetches recent events and keeps only the
*failure* types — the needles that explain SLE degradation and are worth
surfacing / logging.

Endpoint (ms timestamps):
  /api/v1/sites/{site}/clients/events/search?start=&end=&limit=

The failure type strings below were confirmed against real site data — Mist
uses MARVIS_EVENT_* prefixes for most negative events, plus a few CLIENT_*
failure suffixes. Success and routine-disconnect events are excluded.
"""
import time

# Failure event types -> (friendly label, category). Confirmed from live data.
FAILURE_TYPES = {
    "MARVIS_EVENT_CLIENT_AUTH_DENIED":      ("Auth Denied", "auth"),
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE":     ("Auth Failure", "auth"),
    "CLIENT_REASSOCIATION_FAILURE":         ("Reassociation Failure", "assoc"),
    "MARVIS_DNS_FAILURE":                   ("DNS Failure", "dns"),
    "MARVIS_EVENT_CLIENT_DHCP_STUCK":       ("DHCP Stuck", "dhcp"),
    "MARVIS_EVENT_CLIENT_DHCP_FAILURE":     ("DHCP Failure", "dhcp"),
    "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE":   ("DHCPv6 Failure", "dhcp"),
    "MARVIS_EVENT_CLIENT_ARP_FAILURE":      ("Gateway ARP Failure", "arp"),
    "MARVIS_EVENT_CLIENT_ARP_TIMEOUT":      ("Gateway ARP Timeout", "arp"),
    "SA_QUERY_TIMEOUT":                     ("SA Query Timeout", "roam"),
    # A few extra plausible ones (harmless if never seen):
    "MARVIS_EVENT_CLIENT_DNS_FAILURE":      ("DNS Failure", "dns"),
    "CLIENT_ASSOCIATION_FAILURE":           ("Association Failure", "assoc"),
}

# Routine / success types we explicitly ignore (documented for clarity).
IGNORED_PREFIX_OK = ("CLIENT_IP_ASSIGNED", "CLIENT_DNS_OK", "CLIENT_GW_ARP_OK",
                     "CLIENT_AUTH_ASSOCIATION", "CLIENT_AUTHENTICATED",
                     "CLIENT_AUTH_REASSOCIATION", "CLIENT_REASSOCIATION",
                     "CLIENT_DEASSOCIATION", "CLIENT_DEAUTHENTICATED",
                     "CLIENT_DEAUTHENTICATION", "MARVIS_EVENT_STA_LEAVING")


def _band_label(b):
    return {"24": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}.get(str(b), str(b) or "")


def normalize_event(e):
    """Turn a raw Mist event into a compact normalized failure record."""
    etype = e.get("type", "")
    label, category = FAILURE_TYPES.get(etype, (etype, "other"))
    return {
        "type": etype,
        "label": label,
        "category": category,
        "mac": e.get("mac", ""),
        "ip": e.get("ip", ""),
        "hostname": e.get("hostname", ""),   # may be filled by enrichment
        "ap": e.get("ap", ""),
        "ssid": e.get("ssid", ""),
        "band": _band_label(e.get("band")),
        "rssi": e.get("rssi"),
        "text": e.get("text", ""),
        "timestamp": e.get("timestamp", 0),   # unix seconds (float)
    }


def is_failure(etype):
    return etype in FAILURE_TYPES


def _norm_mac(m):
    return (m or "").replace(":", "").replace("-", "").replace(".", "").lower()


def enrich_failures(failures, mist_clients=None, arp_hosts=None):
    """Fill in hostname/ip for each failure from Mist clients + ARP, by MAC."""
    info = {}
    for c in (mist_clients or []):
        m = _norm_mac(c.get("mac"))
        if m:
            info.setdefault(m, {})
            if c.get("hostname"):
                info[m]["hostname"] = c.get("hostname")
            if c.get("ip"):
                info[m]["ip"] = c.get("ip")
    for h in (arp_hosts or []):
        m = _norm_mac(h.get("mac"))
        if m:
            info.setdefault(m, {})
            info[m].setdefault("ip", h.get("ip", ""))
            if h.get("hostname"):
                info[m].setdefault("hostname", h.get("hostname"))
    for f in failures:
        m = _norm_mac(f.get("mac"))
        extra = info.get(m, {})
        if not f.get("hostname") and extra.get("hostname"):
            f["hostname"] = extra["hostname"]
        if not f.get("ip") and extra.get("ip"):
            f["ip"] = extra["ip"]
    return failures


def fetch_failures(session, base_url, token, site_id,
                   window_hours=24, page_limit=1000, max_pages=3):
    """
    Fetch recent client events and return only failures, newest-first.

    Pages through results (the stream is success-heavy, so we sample up to
    max_pages * page_limit events looking for failures). Returns a list of
    normalized failure records.
    """
    end_ms = int(time.time() * 1000)
    start_ms = end_ms - window_hours * 3600 * 1000
    headers = {"Authorization": f"Token {token}"}

    failures = []
    url = (f"{base_url}/sites/{site_id}/clients/events/search"
           f"?start={start_ms}&end={end_ms}&limit={page_limit}")

    pages = 0
    while url and pages < max_pages:
        try:
            r = session.get(url, headers=headers, timeout=20)
            if r.status_code != 200:
                break
            data = r.json()
        except Exception as e:
            print(f"[CLIENT_EVENTS] fetch failed: {e}", flush=True)
            break

        for ev in data.get("results", []):
            if is_failure(ev.get("type", "")):
                failures.append(normalize_event(ev))

        pages += 1
        nxt = data.get("next")
        if nxt:
            # 'next' is a path; make it absolute against the API root
            root = base_url.split("/api/v1")[0]
            url = root + nxt if nxt.startswith("/") else nxt
        else:
            url = None

    failures.sort(key=lambda x: x["timestamp"], reverse=True)
    return failures


def summarize(failures):
    """Counts by category for a compact summary."""
    summary = {}
    for f in failures:
        summary[f["category"]] = summary.get(f["category"], 0) + 1
    return summary
