"""
Top Talkers from ntopng's REST API.
Fetches top local hosts by traffic, each annotated with its dominant nDPI app.

Designed to be called once per poll cycle and cached (not per page render),
since it makes 1 + N API calls (host list + per-host app lookup).

ntopng REST API (v6.6):
  host list: /lua/rest/v2/get/host/active.lua?ifid=0&sortColumn=column_bytes&sortOrder=desc&perPage=N
             -> {"rsp":{"data":[{ip,name,bytes:{total},is_localhost,country,is_blacklisted,num_alerts},...]}}
  per-host:  /lua/rest/v2/get/host/l7/stats.lua?ifid=0&host=IP
             -> {"rsp":[{label,value,duration},...]}  (sorted by value desc; [0] = top app)
"""
import json
import urllib.request
import urllib.error


def _get(base_url, token, path, timeout=8):
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        headers={"Authorization": f"Token {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _fmt_bytes(n):
    """Human-readable bytes."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def fetch_top_talkers(base_url, token, ifid=0, top_n=5, local_only=True):
    """
    Returns {"talkers": [...], "error": None} or {"talkers": [], "error": str}.
    Each talker: {ip, name, bytes_total, bytes_hr, top_app, country,
                  blacklisted, alerts}
    """
    try:
        # 1. Top hosts by traffic (pull a few extra so local_only filtering
        #    still leaves us top_n)
        per_page = top_n * 3 if local_only else top_n
        host_path = (f"/lua/rest/v2/get/host/active.lua?ifid={ifid}"
                     f"&sortColumn=column_bytes&sortOrder=desc&perPage={per_page}")
        hdata = _get(base_url, token, host_path)
        rows = (hdata.get("rsp") or {}).get("data") or []
    except urllib.error.HTTPError as e:
        return {"talkers": [], "error": f"ntopng API {e.code}"}
    except Exception as e:
        return {"talkers": [], "error": f"ntopng unreachable: {e}"}

    talkers = []
    for h in rows:
        if local_only and not h.get("is_localhost"):
            continue
        ip = h.get("ip", "")
        # 2. Per-host top app (best-effort; don't fail the whole card if one errs)
        top_app = ""
        try:
            adata = _get(base_url, token,
                         f"/lua/rest/v2/get/host/l7/stats.lua?ifid={ifid}&host={ip}")
            apps = adata.get("rsp") or []
            if apps:
                top_app = apps[0].get("label", "")
        except Exception:
            top_app = ""

        bytes_total = (h.get("bytes") or {}).get("total", 0)
        talkers.append({
            "ip": ip,
            "name": h.get("name") or ip,
            "bytes_total": bytes_total,
            "bytes_hr": _fmt_bytes(bytes_total),
            "top_app": top_app,
            "country": h.get("country", ""),
            "blacklisted": bool(h.get("is_blacklisted")),
            "alerts": h.get("num_alerts", 0),
        })
        if len(talkers) >= top_n:
            break

    return {"talkers": talkers, "error": None}
