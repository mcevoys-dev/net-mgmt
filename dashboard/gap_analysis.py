"""
Gap analysis: devices on the network (ARP ground-truth) that neither
management plane (Mist wireless / Central wired) accounts for.
"""

# ---- Local OUI vendor lookup (no network call, no rate limit) ----
try:
    from mac_vendor_lookup import MacLookup
    _MAC_LOOKUP = MacLookup()
except Exception:
    _MAC_LOOKUP = None


def norm_mac(mac: str) -> str:
    """Bare lowercase hex — the format all sources reconcile to."""
    return (mac or "").replace(":", "").replace("-", "").replace(".", "").lower()


def oui5(mac: str) -> str:
    """First 5 octets (10 hex chars) — identifies a device's interface family."""
    return norm_mac(mac)[:10]


def vendor_of(mac: str) -> str:
    """Local OUI vendor string, '' if unknown or lib unavailable."""
    if not _MAC_LOOKUP or not mac:
        return ""
    try:
        return _MAC_LOOKUP.lookup(mac)
    except Exception:
        return ""


def analyze_gap(arp_hosts, mist_clients, central_wired,
                dhcp_leases, mist_aps, switches=None,
                extra_infra_macs=None, self_mac=None):
    switches = switches or []
    extra_infra_macs = extra_infra_macs or []

    wireless = {norm_mac(c.get("mac")) for c in mist_clients}
    wired    = {norm_mac(c.get("macaddr")) for c in central_wired}

    infra_prefixes = set()
    for a in mist_aps:
        infra_prefixes.add(oui5(a.get("mac")))
    for s in switches:
        infra_prefixes.add(oui5(s.get("macaddr")))
    for m in extra_infra_macs:
        infra_prefixes.add(oui5(m))
    if self_mac:
        infra_prefixes.add(oui5(self_mac))
    infra_prefixes.discard("")

    dhcp_by_mac = {norm_mac(l.get("mac")): l for l in dhcp_leases}
    dhcp_by_ip  = {l.get("address", ""): l for l in dhcp_leases}

    gap_devices = []
    n_wireless = n_wired = n_infra = 0

    for h in arp_hosts:
        m = norm_mac(h.get("mac"))
        ip = h.get("ip", "")

        if m in wireless:
            n_wireless += 1
            continue
        if m in wired:
            n_wired += 1
            continue
        if oui5(m) in infra_prefixes:
            n_infra += 1
            continue

        lease = dhcp_by_mac.get(m) or dhcp_by_ip.get(ip) or {}
        gap_devices.append({
            "ip": ip,
            "mac": h.get("mac", ""),
            "hostname": lease.get("hostname") or "—",
            "type": "DHCP" if lease else "Static",
            "vendor": vendor_of(h.get("mac")) or h.get("vendor", "") or "Unknown",
        })

    def ip_key(d):
        try:
            return tuple(int(p) for p in d["ip"].split("."))
        except Exception:
            return (999, 999, 999, 999)
    gap_devices.sort(key=ip_key)

    return {
        "counts": {
            "total_arp": len(arp_hosts),
            "wireless":  n_wireless,
            "wired":     n_wired,
            "infra":     n_infra,
            "accounted": n_wireless + n_wired,
            "gap":       len(gap_devices),
        },
        "gap_devices": gap_devices,
    }
