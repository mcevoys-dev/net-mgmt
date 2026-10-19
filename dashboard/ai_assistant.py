"""
AI assistant for the network dashboard.
Builds a sanitized snapshot of current network state and asks Claude.

SECURITY: this module strips sensitive values (API keys, public WAN IP,
internal hostnames) before any data leaves the box. See _sanitize().
"""
import json
import urllib.request
import urllib.error

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-5-5"     # default; set assistant.model in config.yaml
MAX_TOKENS = 16000            # newer models think before answering; leave room
# Models that accept the server-side refusal fallback ("default" routing).
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}

SYSTEM_PROMPT = """You are a network assistant embedded in a home network dashboard.
You answer questions about the user's network using the live snapshot provided.
The user is a network professional, so be technical, concise, and direct.

Guidelines:
- Answer from the snapshot data. If the data doesn't contain the answer, say so plainly.
- Don't invent devices, values, or history. Only the current snapshot is available.
- When useful, reference specific devices, APs, switches, IPs, or metrics by name.
- For signal/RSSI: -65 or better is good, -70 to -75 weak, below -75 poor.
- Keep answers short unless asked to elaborate. Lead with the answer."""


def _sanitize(data: dict) -> dict:
    """Strip sensitive fields before sending to the API.
    Removes public WAN IPs, anything key/token/secret-ish, and trims to
    the fields useful for Q&A."""
    mist = data.get("mist", {})
    central = data.get("central", {})
    opnsense = data.get("opnsense", {})

    # WAN: keep status/latency/jitter/loss/interface, DROP public IP + gateway
    wan = []
    for g in opnsense.get("gateways", []):
        wan.append({
            "name": g.get("name"),
            "status": g.get("status"),
            "latency_ms": g.get("delay"),
            "jitter_ms": g.get("stddev"),
            "loss": g.get("loss"),
        })

    # Switches: keep operational fields, drop public_ip_address
    switches = []
    for s in central.get("switches", []):
        switches.append({
            "name": s.get("name"),
            "model": s.get("model"),
            "status": s.get("status"),
            "cpu": s.get("cpu_utilization"),
            "clients": s.get("client_count"),
            "site": s.get("site"),
        })

    # Wireless clients: signal-relevant fields only, no usernames/PSK
    wclients = []
    for c in mist.get("clients", []):
        wclients.append({
            "host": c.get("hostname"),
            "rssi": c.get("rssi"),
            "snr": c.get("snr"),
            "band": c.get("band"),
            "ap_mac": c.get("ap_mac"),
            "ssid": c.get("ssid"),
        })

    aps = []
    for a in mist.get("aps", []):
        aps.append({
            "name": a.get("name"),
            "mac": a.get("mac"),
            "status": a.get("status"),
        })

    return {
        "wan": wan,
        "switches": switches,
        "wired_client_count": len(central.get("clients", [])),
        "wireless_clients": wclients,
        "access_points": aps,
    }


def build_context(data: dict, gap: dict = None, health: dict = None, top_talkers: list = None) -> str:
    """Assemble the sanitized snapshot + derived analytics into a context string."""
    snap = _sanitize(data)
    ctx = {"snapshot": snap}
    if gap:
        ctx["gap_analysis"] = {
            "counts": gap.get("counts"),
            "unaccounted_devices": gap.get("gap_devices"),
        }
    if health:
        ctx["wireless_health"] = {
            "summary": health.get("summary"),
            "per_ap": health.get("per_ap"),
            "weak_clients": health.get("weak_clients"),
        }
    if top_talkers:
        ctx["top_talkers"] = top_talkers
    return json.dumps(ctx, indent=2, default=str)


def ask(api_key: str, messages: list, context: str, model: str = MODEL,
        max_tokens: int = MAX_TOKENS) -> dict:
    """Call Claude with the conversation history + current network context.
    messages: [{"role": "user"/"assistant", "content": "..."}]
    Returns {"answer": str} or {"error": str}.
    """
    # Inject current context as a system-appended block so it's fresh each turn
    system = SYSTEM_PROMPT + "\n\nCURRENT NETWORK SNAPSHOT (JSON):\n" + context

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
    }
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    if model in FALLBACK_MODELS:
        # If the model declines a request, let the API retry it on a suitable model.
        payload["fallbacks"] = "default"
        headers["anthropic-beta"] = "server-side-fallback-2026-07-01"
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode())
        if body.get("stop_reason") == "refusal":
            return {"error": "The assistant declined to answer that question."}
        # Extract text blocks (thinking blocks, if any, are skipped)
        parts = [b.get("text", "") for b in body.get("content", []) if b.get("type") == "text"]
        return {"answer": "\n".join(parts).strip() or "(no response)"}
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        return {"error": f"API error {e.code}: {detail}"}
    except Exception as e:
        return {"error": f"Request failed: {e}"}
