"""
Physical infrastructure topology builder.

Assembles a hierarchical tree from data the dashboard already polls:
  WAN/Internet (root)
    └─ OPNsense (router/firewall)
         └─ switches (Aruba Central)
              └─ APs (Mist, linked to switch via LLDP system_name/port_id)
                   └─ [optional] wireless clients (by ap_mac)

LLDP gives REAL discovered switch<->AP adjacency (ap.lldp_stat.system_name =
the switch the AP is cabled to, port_id = the port). Everything else (router
-> switch uplink, clients -> AP association) is logical inference.

Output: a nested dict the frontend renders as an SVG tree. Pure data assembly,
no rendering.
"""


def _norm(s):
    return (s or "").strip().lower()


# Manual switch-to-switch uplink hints, since Central may not expose switch
# LLDP neighbour data. Maps a downstream switch name (lower case) to text in
# its upstream switch's name. Set from inventory.switch_uplinks in config.yaml.
EXTRA_SWITCH_UPLINKS = {}

# Gateway names marked `type: primary` in opnsense.wans. Empty = the first
# gateway OPNsense reports is the primary one.
PRIMARY_GATEWAYS = set()


def build_topology(opnsense, switches, aps, clients=None, include_clients=False,
                   wired_clients=None, include_wired=False):
    """
    Returns a tree:
    {
      "id","label","type","status","meta":{...},
      "children":[ ... same shape ... ]
    }
    types: wan | router | switch | ap | client
    """
    clients = clients or []

    gateways = (opnsense or {}).get("gateways", [])

    # --- Router (OPNsense) — the convergence point for both WANs -------------
    router_node = {
        "id": "router",
        "label": "OPNsense",
        "type": "router",
        "status": "up",
        "meta": {"role": "Firewall / Router"},
        "children": [],
    }

    # --- WAN nodes (one per gateway) ----------------------------------------
    # Each WAN is its own node feeding into the firewall. Primary gateways
    # (from config, else the first one) are highlighted; backups are dimmed. All link
    # down into the single router node (handled as multi-parent in the renderer).
    wan_nodes = []
    for i, g in enumerate(gateways):
        primary = (g.get("name") in PRIMARY_GATEWAYS) if PRIMARY_GATEWAYS else i == 0
        status_raw = _norm(g.get("status"))
        up = status_raw in ("up", "online", "none")
        wan_nodes.append({
            "id": f"wan:{i}",
            "label": g.get("name", f"WAN{i+1}"),
            "type": "wan",
            "status": "up" if up else "down",
            "role": "primary" if primary else "backup",
            "meta": {
                "role": "Primary" if primary else "Backup",
                "status": g.get("status", ""),
                "latency": g.get("delay", ""),
                "loss": g.get("loss", ""),
            },
            # Each WAN node "owns" the router as its child so the tree walker
            # reaches it; the renderer de-dupes the router so it draws once with
            # links from every WAN.
            "children": [router_node],
        })

    # Fallback: if OPNsense returned no gateways, still show a generic root.
    if not wan_nodes:
        wan_nodes = [{
            "id": "wan:0", "label": "Internet", "type": "wan",
            "status": "up", "role": "primary",
            "meta": {"role": "WAN"}, "children": [router_node],
        }]

    # The synthetic root holds the WAN nodes side-by-side (stacked vertically in
    # the left-to-right layout). It's not drawn as a node itself.
    root = {
        "id": "__root__",
        "label": "",
        "type": "root",
        "status": "up",
        "meta": {},
        "children": wan_nodes,
    }

    # --- Switches -----------------------------------------------------------
    # Build all switch nodes first, then parent them (a downstream switch's
    # parent switch may appear later in the list).
    switch_nodes = {}          # norm(name) -> node
    for sw in (switches or []):
        name = sw.get("name", "") or sw.get("serial", "") or "switch"
        status = sw.get("status", "")
        node = {
            "id": f"sw:{sw.get('serial', name)}",
            "label": name,
            "type": "switch",
            "status": "up" if _norm(status) in ("up", "online") else "down",
            "meta": {
                "model": sw.get("model", ""),
                "serial": sw.get("serial", ""),
                "clients": sw.get("client_count", ""),
            },
            "children": [],
        }
        switch_nodes[_norm(name)] = node

    # Parent each switch: to its upstream switch if an uplink hint exists and
    # that upstream is known, otherwise directly to the router.
    for nname, node in switch_nodes.items():
        up_name = EXTRA_SWITCH_UPLINKS.get(nname)
        parent = switch_nodes.get(_norm(up_name)) if up_name else None
        if parent is not None:
            node["meta"]["uplink_switch"] = up_name
            parent["children"].append(node)
        else:
            router_node["children"].append(node)

    # A catch-all bucket for APs whose LLDP switch we can't match to a known
    # switch (e.g. LLDP empty, or connected to an unmanaged switch).
    unknown_switch = None

    def get_unknown_switch():
        nonlocal unknown_switch
        if unknown_switch is None:
            unknown_switch = {
                "id": "sw:unknown",
                "label": "Unknown / direct",
                "type": "switch",
                "status": "unknown",
                "meta": {"note": "AP uplink not resolved via LLDP"},
                "children": [],
            }
            router_node["children"].append(unknown_switch)
        return unknown_switch

    # --- APs (attached to switches via LLDP) --------------------------------
    ap_nodes = {}              # ap_mac(lower) -> node
    for ap in (aps or []):
        mac = ap.get("mac", "")
        lldp = ap.get("lldp_stat", {}) or {}
        sw_name = lldp.get("system_name", "")
        port = lldp.get("port_id", "")
        status = ap.get("status", "")

        node = {
            "id": f"ap:{mac}",
            "label": ap.get("name", "") or mac or "AP",
            "type": "ap",
            "status": "up" if _norm(status) in ("connected", "up", "online") else "down",
            "meta": {
                "mac": mac,
                "model": ap.get("model", ""),
                "uplink_switch": sw_name,
                "uplink_port": port,
            },
            "children": [],
        }
        ap_nodes[_norm(mac)] = node

        # Attach to the matching switch, or the unknown bucket
        parent = switch_nodes.get(_norm(sw_name))
        if parent is None:
            parent = get_unknown_switch()
        parent["children"].append(node)

    # --- Clients (optional) under their AP ----------------------------------
    if include_clients:
        for c in clients:
            ap_mac = _norm(c.get("ap_mac", ""))
            parent = ap_nodes.get(ap_mac)
            if parent is None:
                continue
            parent["children"].append({
                "id": f"cl:{c.get('mac','')}",
                "label": c.get("hostname") or c.get("mac", "") or "client",
                "type": "client",
                "status": "up",
                "meta": {
                    "ip": c.get("ip", ""),
                    "rssi": c.get("rssi", ""),
                    "band": c.get("band", ""),
                },
                "children": [],
            })

    # --- Wired clients (optional) under their switch ------------------------
    # Central wired clients carry associated_device = switch serial.
    if include_wired:
        # Index switch nodes by serial for wired-client attachment.
        sw_by_serial = {}
        for node in switch_nodes.values():
            ser = node["meta"].get("serial", "")
            if ser:
                sw_by_serial[_norm(ser)] = node
        for c in (wired_clients or []):
            serial = _norm(c.get("associated_device", ""))
            parent = sw_by_serial.get(serial)
            if parent is None:
                continue
            mac = c.get("macaddr", "")
            parent["children"].append({
                "id": f"wc:{mac}",
                "label": c.get("name") or c.get("hostname") or mac or "wired",
                "type": "wired",
                "status": "up",
                "meta": {
                    "ip": c.get("ip_address", "") or c.get("ip", ""),
                    "mac": mac,
                    "vlan": c.get("vlan", ""),
                },
                "children": [],
            })

    return root


def topology_stats(tree):
    """Count nodes by type for a quick summary."""
    counts = {}
    def walk(n):
        counts[n["type"]] = counts.get(n["type"], 0) + 1
        for ch in n.get("children", []):
            walk(ch)
    walk(tree)
    return counts
