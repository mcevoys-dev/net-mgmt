"""
Device source reconciliation.

Unions every device across the three sources the dashboard polls — ARP scan,
Mist (wireless), Central (wired) — keyed by MAC, and records which sources see
each one. This is the "diff" that answers: why does the ARP total differ from
the wireless + wired page counts?

The mismatch is normal and expected: each source measures a slightly different
set. A Mist client may not answer an ARP probe; an ARP device may be powered
off in Central's view but still cached; infra devices show in ARP but aren't
"clients" anywhere. This makes that explicit per device instead of by eye.
"""


from gap_analysis import norm_mac as _norm, oui5


def reconcile(arp_hosts, mist_clients, central_wired, mist_aps,
              switches=None, extra_infra_macs=None, self_mac=None):
    """
    Returns:
      rows: per-device dicts with in_arp/in_wireless/in_wired/is_infra flags
      summary: counts of each mismatch category
    """
    switches = switches or []
    extra_infra_macs = extra_infra_macs or []

    arp_by_mac = {}
    for h in arp_hosts:
        m = _norm(h.get("mac"))
        if m:
            arp_by_mac[m] = h

    wireless = {_norm(c.get("mac")) for c in mist_clients if c.get("mac")}
    wired    = {_norm(c.get("macaddr")) for c in central_wired if c.get("macaddr")}

    # infra prefixes (5-octet) from APs, switches, extras, self
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

    def is_infra(mac):
        return oui5(mac) in infra_prefixes

    # Union of all MACs across sources
    all_macs = set(arp_by_mac) | wireless | wired

    rows = []
    for m in all_macs:
        h = arp_by_mac.get(m, {})
        in_arp = m in arp_by_mac
        in_wl  = m in wireless
        in_wd  = m in wired
        infra  = is_infra(m)
        rows.append({
            "mac": h.get("mac", m),
            "ip": h.get("ip", ""),
            "vendor": h.get("vendor", "") or "Unknown",
            "in_arp": in_arp,
            "in_wireless": in_wl,
            "in_wired": in_wd,
            "is_infra": infra,
            # a device is a "mismatch" if it isn't cleanly seen everywhere we'd
            # expect: e.g. in ARP but no source claims it, or claimed by a
            # source but not in ARP.
            "_seen_count": sum([in_wl, in_wd, infra]),
        })

    # Sort by IP (numeric) then MAC
    def ip_key(r):
        try:
            return tuple(int(p) for p in r["ip"].split(".")) if r["ip"] else (999,999,999,999)
        except Exception:
            return (999, 999, 999, 999)
    rows.sort(key=ip_key)

    # Mismatch categories
    arp_only = [r for r in rows if r["in_arp"] and not r["in_wireless"]
                and not r["in_wired"] and not r["is_infra"]]
    mist_not_arp = [r for r in rows if r["in_wireless"] and not r["in_arp"]]
    central_not_arp = [r for r in rows if r["in_wired"] and not r["in_arp"]]
    double = [r for r in rows if r["in_wireless"] and r["in_wired"]]

    summary = {
        "total_union": len(rows),
        "in_arp": sum(1 for r in rows if r["in_arp"]),
        "in_wireless": sum(1 for r in rows if r["in_wireless"]),
        "in_wired": sum(1 for r in rows if r["in_wired"]),
        "infra": sum(1 for r in rows if r["is_infra"]),
        # mismatches
        "arp_only": len(arp_only),               # in ARP, no source claims it (= the "gap")
        "mist_not_arp": len(mist_not_arp),        # Mist sees it, ARP didn't
        "central_not_arp": len(central_not_arp),  # Central sees it, ARP didn't
        "double_counted": len(double),            # claimed by BOTH wireless+wired
    }

    return {"rows": rows, "summary": summary,
            "mismatches": {
                "arp_only": arp_only,
                "mist_not_arp": mist_not_arp,
                "central_not_arp": central_not_arp,
                "double_counted": double,
            }}
