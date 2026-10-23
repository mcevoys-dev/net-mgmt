# Configuration reference

The dashboard reads `config.yaml` next to `app.py`, or the file given with
`--config` or the `NETDASH_CONFIG` environment variable. Every setting is
optional; the defaults below apply to anything you leave out.
`dashboard/config.example.yaml` is a commented starting point.

Unknown settings, malformed values and missing required values stop the app
with a message naming the setting, so a typo never fails silently.

## site

| Setting | Default | Meaning |
|---|---|---|
| `name` | `Home Network` | Shown in the header, browser tab and Overview |
| `timezone` | `UTC` | IANA time zone for times on the pages (`America/New_York`, `Europe/London`…) |
| `lan_subnets` | `[192.168.1.0/24]` | Subnets the ARP scan covers. A single string is accepted too. |

## server

| Setting | Default | Meaning |
|---|---|---|
| `host` | `0.0.0.0` | Address to listen on. Use `127.0.0.1` behind a reverse proxy. |
| `port` | `5000` | |

## Top level

| Setting | Default | Meaning |
|---|---|---|
| `poll_interval` | `60` | Seconds between refreshes from the APIs |
| `secrets_dir` | `.` | Where credential files are looked up, relative to the config file unless absolute |
| `data_dir` | `.` | Where `event_log.jsonl` and `device_seen_history.json` are kept |

## mist

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `api_base` | `https://api.mist.com/api/v1` | API host for your Mist cloud (see [integrations.md](integrations.md#juniper-mist-wi-fi)) |
| `portal` | `https://manage.mist.com/admin` | For "Open in Mist" links |
| `org_id` | blank | Blank = read from the token |
| `site_id` | blank | Blank = choose by `site_name` |
| `site_name` | blank | Blank (and no `site_id`) = the first site in the organisation |
| `token_file` | `mist_token.txt` | |

## central

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `api_base` | blank | **Required** when enabled: your API gateway URL |
| `site` | blank | Site for wired clients; blank = all sites |
| `token_file` | `central_token.json` | JSON with access/refresh token and client ID/secret; must be writable |
| `switch_poll_seconds` | `300` | How often switch details and ports are read |

## opnsense

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `url` | `https://192.168.1.1` | Firewall web address, with port if not 443 |
| `key_file` | `opnsense_apikey.txt` | The `key=` / `secret=` file OPNsense downloads |
| `verify_tls` | `false` | Check the firewall's certificate |
| `wans` | `[]` | Optional list describing your WAN links, in display order (below) |
| `top_interfaces` | `[lan]` | OPNsense interface names (as in its config: `lan`, `opt1`…) whose busiest devices the Firewall page shows |
| `firewall_log_lines` | `1000` | How many recent firewall log entries the blocked-traffic summary reads (every 5 minutes) |

Each entry in `wans`:

| Setting | Default | Meaning |
|---|---|---|
| `gateway` | blank | Gateway name as in *System → Gateways* (e.g. `WAN_GW`) |
| `interface` | blank | Device name (`igb0`, `em0`, `vtnet0`…) for the traffic graph. At least one of `gateway` / `interface` is required. |
| `name` | gateway minus `_GW` | Display name |
| `type` | `primary` | `primary` or `backup` (backup links are drawn dimmer and their quality flaps are not logged) |
| `icon` | `globe` | `fiber`, `cell` or `globe` |
| `ha_slug` | name, lower case | Used in Home Assistant entity IDs; set it to keep existing entity IDs if you rename a link |

With no `wans` list, gateways are shown with the names OPNsense reports, and
traffic is tracked on every interface OPNsense reports.

## arp_scan

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `interval` | `300` | Seconds between scans |
| `interface` | blank | Passed to `arp-scan --interface` if set |

## ntopng

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `url` | `http://localhost:3000` | Used by the dashboard, and for the sidebar link on the LAN (`localhost` is replaced by the address you reached the dashboard on) |
| `public_url` | blank | Sidebar link used when the dashboard is reached by a public hostname |
| `token_file` | `ntopng_token.txt` | |

## home_assistant

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `url` | `http://homeassistant.local:8123` | |
| `token_file` | `ha_token.txt` | Long-lived access token |

## assistant

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Shows the **Ask** button |
| `key_file` | `anthropic_key.txt` | Claude API key |
| `model` | `claude-opus-5-5` | Any Claude model ID |
| `max_tokens` | `16000` | Upper limit per answer; newer models also spend part of it thinking |

## inventory

| Setting | Default | Meaning |
|---|---|---|
| `extra_infrastructure_macs` | `[]` | MACs to treat as infrastructure, not "unaccounted". Matched on the first five octets, so a base MAC also covers its sibling interfaces. |
| `self_mac` | blank | This machine's NIC, likewise |
| `switch_uplinks` | `{}` | `downstream switch name: text in upstream switch name`, for the Topology page when Central does not report switch-to-switch links |
| `quiet_switches` | `[]` | Switch names whose up/down changes are not logged |

## links

Extra sidebar links under **Tools**. Each needs `name` and `url`; `icon` is one
of `fw`, `cloud`, `flow`, `ext`, `globe`, `switch`, `ap`. Links to ntopng,
OPNsense and Mist are added automatically when those integrations are on.
