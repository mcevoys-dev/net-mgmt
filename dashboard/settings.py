"""
Configuration for the network dashboard.

Settings come from a YAML file (config.yaml next to app.py by default, or the
path in --config / $NETDASH_CONFIG). Anything left out falls back to DEFAULTS
below, so a config only needs the integrations you actually use.

Credential files are never inlined in the config: each integration names a
file, resolved relative to `secrets_dir`.
"""
import copy
import ipaddress
import os
from pathlib import Path

import yaml

APP_DIR = Path(__file__).resolve().parent

DEFAULTS = {
    "site": {
        "name": "Home Network",
        "timezone": "UTC",
        "lan_subnets": ["192.168.1.0/24"],
    },
    "server": {"host": "0.0.0.0", "port": 5000},
    "poll_interval": 60,
    "secrets_dir": ".",
    "data_dir": ".",
    "mist": {
        "enabled": False,
        "api_base": "https://api.mist.com/api/v1",
        "portal": "https://manage.mist.com/admin",
        "org_id": "",
        "site_id": "",
        "site_name": "",
        "token_file": "mist_token.txt",
    },
    "central": {
        "enabled": False,
        "api_base": "",
        "site": "",
        "token_file": "central_token.json",
        "switch_poll_seconds": 300,
    },
    "opnsense": {
        "enabled": False,
        "url": "https://192.168.1.1",
        "key_file": "opnsense_apikey.txt",
        "verify_tls": False,
        "wans": [],
    },
    "arp_scan": {"enabled": True, "interval": 300, "interface": ""},
    "ntopng": {
        "enabled": False,
        "url": "http://localhost:3000",
        "public_url": "",
        "token_file": "ntopng_token.txt",
    },
    "home_assistant": {
        "enabled": False,
        "url": "http://homeassistant.local:8123",
        "token_file": "ha_token.txt",
    },
    "assistant": {
        "enabled": False,
        "key_file": "anthropic_key.txt",
        "model": "claude-opus-5-5",
        "max_tokens": 16000,
    },
    "inventory": {
        "extra_infrastructure_macs": [],
        "self_mac": "",
        "switch_uplinks": {},
        "quiet_switches": [],
    },
    "links": [],
}

WAN_DEFAULTS = {"gateway": "", "interface": "", "name": "", "type": "primary",
                "icon": "globe", "ha_slug": ""}
LINK_DEFAULTS = {"name": "", "url": "", "icon": "ext"}
ICONS = {"fiber", "cell", "globe"}
LINK_ICONS = {"fw", "cloud", "flow", "ext", "globe", "switch", "ap"}


class ConfigError(Exception):
    pass


def _merge(base, over, path=""):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        where = f"{path}{k}"
        if k not in base:
            raise ConfigError(f"unknown setting '{where}'")
        if isinstance(base[k], dict) and base[k] and not isinstance(v, dict):
            raise ConfigError(f"'{where}' should be a section (key: value pairs)")
        if isinstance(base[k], dict) and base[k]:
            out[k] = _merge(base[k], v, where + ".")
        else:
            out[k] = v
    return out


class Section(dict):
    """dict with attribute access, so code can say CFG.mist.api_base."""
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k) from None


def _wrap(v):
    if isinstance(v, dict):
        return Section({k: _wrap(x) for k, x in v.items()})
    if isinstance(v, list):
        return [_wrap(x) for x in v]
    return v


def _slug(s):
    return "".join(c if c.isalnum() else "_" for c in s.lower()).strip("_") or "wan"


def load(path=None):
    path = Path(path or os.environ.get("NETDASH_CONFIG") or APP_DIR / "config.yaml")
    raw = {}
    if path.exists():
        try:
            raw = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"{path}: not valid YAML ({e})") from None
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: expected key: value settings at the top level")
    cfg = _merge(DEFAULTS, raw)

    base = path.parent if path.exists() else APP_DIR
    cfg["config_path"] = str(path) if path.exists() else ""
    cfg["secrets_dir"] = str((base / cfg["secrets_dir"]).resolve())
    cfg["data_dir"] = str((base / cfg["data_dir"]).resolve())

    if isinstance(cfg["site"]["lan_subnets"], str):
        cfg["site"]["lan_subnets"] = [cfg["site"]["lan_subnets"]]
    try:
        cfg["site"]["lan_subnets"] = [str(ipaddress.ip_network(n, strict=False))
                                      for n in cfg["site"]["lan_subnets"]]
    except (ValueError, TypeError) as e:
        raise ConfigError(f"site.lan_subnets: {e}") from None

    wans = []
    for i, w in enumerate(cfg["opnsense"]["wans"] or []):
        if not isinstance(w, dict):
            raise ConfigError(f"opnsense.wans[{i}] should be a section")
        unknown = set(w) - set(WAN_DEFAULTS)
        if unknown:
            raise ConfigError(f"opnsense.wans[{i}]: unknown setting(s) {', '.join(sorted(unknown))}")
        w = {**WAN_DEFAULTS, **w}
        if not w["gateway"] and not w["interface"]:
            raise ConfigError(f"opnsense.wans[{i}] needs a gateway or an interface")
        if w["icon"] not in ICONS:
            raise ConfigError(f"opnsense.wans[{i}].icon must be one of {', '.join(sorted(ICONS))}")
        if w["type"] not in ("primary", "backup"):
            raise ConfigError(f"opnsense.wans[{i}].type must be primary or backup")
        w["name"] = w["name"] or w["gateway"].replace("_GW", "").replace("_gw", "") or w["interface"]
        w["ha_slug"] = w["ha_slug"] or _slug(w["name"])
        wans.append(w)
    cfg["opnsense"]["wans"] = wans

    links = []
    for i, ln in enumerate(cfg["links"] or []):
        ln = {**LINK_DEFAULTS, **(ln or {})}
        if not ln["name"] or not ln["url"]:
            raise ConfigError(f"links[{i}] needs a name and a url")
        if ln["icon"] not in LINK_ICONS:
            ln["icon"] = "ext"
        links.append(ln)
    cfg["links"] = links

    inv = cfg["inventory"]
    inv["extra_infrastructure_macs"] = [m.lower() for m in inv["extra_infrastructure_macs"] or []]
    inv["self_mac"] = (inv["self_mac"] or "").lower()
    inv["switch_uplinks"] = {str(k).lower(): str(v) for k, v in (inv["switch_uplinks"] or {}).items()}
    inv["quiet_switches"] = [str(s).lower() for s in inv["quiet_switches"] or []]

    for section in ("central",):
        if cfg[section]["enabled"] and not cfg[section]["api_base"]:
            raise ConfigError("central.api_base is required when Central is enabled "
                              "(your API gateway URL, shown in Central under API Gateway)")
    return _wrap(cfg)


def secret_path(cfg, name):
    p = Path(name)
    return p if p.is_absolute() else Path(cfg.secrets_dir) / p


def data_path(cfg, name):
    return Path(cfg.data_dir) / name
