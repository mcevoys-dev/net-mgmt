# Integrations: keys, tokens and permissions

Each integration is switched on in `config.yaml` and reads its credential from
a file in `secrets_dir` (default: the folder `config.yaml` is in; the example
config uses `secrets/`). Give every credential the least access that works,
and `chmod 600` the files. After adding one, run `python3 app.py --check`.

## Juniper Mist (Wi-Fi)

What it provides: Wi-Fi clients, access points and their radios, Mist's
wireless service levels (SLEs) and client connection failures.

1. In the Mist portal, open your user menu → **My Profile** → **API Token** →
   **Create Token**. A token for an account with an **Observer** role on the
   organisation is enough; the dashboard only reads.
2. Save the token on one line as `secrets/mist_token.txt`.
3. Set `mist.api_base` for your cloud: take the address you log in at,
   `manage.<cloud>.mist.com`, and swap `manage` for `api`
   (`https://api.<cloud>.mist.com/api/v1`). Set `mist.portal` to the login
   address plus `/admin` for the "Open in Mist" links.
4. Pick the site: `site_name` as shown in Mist, or `site_id` (from the portal
   URL when the site is selected). `org_id` is read from the token if left
   blank. `--check` lists the sites the token can see.

## HPE Aruba Central (switches)

What it provides: switch status and health, per-port status, speed and PoE,
and wired clients with their switch port and VLAN.

1. In Central, go to **Organization → Platform Integration → API Gateway**.
   Note the gateway URL shown there (for example
   `https://apigw-prod2.central.arubanetworks.com`) and set it as
   `central.api_base`.
2. Under **System Apps & Tokens** add an app if you have none; note its
   **client ID** and **client secret**. Under **My Apps & Tokens**, generate a
   token for the **Network Operations** application and download it.
3. Save `secrets/central_token.json` in this format:

   ```json
   {
     "access_token": "…",
     "refresh_token": "…",
     "client_id": "…",
     "client_secret": "…"
   }
   ```

   Access tokens expire after two hours. The dashboard refreshes them with the
   refresh token and writes the new pair back to this file, so the file must
   be writable by the dashboard's user.
4. Set `central.site` to the Central site whose wired clients you want (blank
   for all).

## OPNsense (WAN links and DHCP)

What it provides: WAN gateway status, latency, jitter and loss, WAN traffic,
and DHCP leases (used to tell static from dynamic addresses).

1. Create a dedicated user (*System → Access → Users*) rather than using root,
   and give it only the privileges that cover the four read-only endpoints the
   dashboard calls (privilege names vary a little between OPNsense versions;
   search the privilege list for these areas):
   - gateway status: `GET /api/routes/gateway/status`
   - interfaces overview: `GET /api/interfaces/overview/export`
   - DHCPv4 leases: `GET /api/dhcpv4/leases/searchLease`
   - interface statistics: `GET /api/diagnostics/interface/getInterfaceStatistics`

   `python3 app.py --check` calls the gateway endpoint; if a page is missing
   DHCP or traffic data, a privilege for one of the others is missing.
2. On that user, under **API keys**, click **+**. OPNsense downloads a file
   containing `key=…` and `secret=…` lines; save it as
   `secrets/opnsense_apikey.txt`.
3. Set `opnsense.url` to the firewall's web address, including the port if it
   is not 443. Set `verify_tls: true` if the firewall has a certificate your
   machine trusts.
4. Optional: list your WAN links under `opnsense.wans` to name and order them
   and draw traffic graphs (see [configuration.md](configuration.md)).

## LAN discovery (arp-scan)

No credential. The dashboard runs `arp-scan <subnet>` for each entry in
`site.lan_subnets` every `arp_scan.interval` seconds. Grant the binary
raw-socket permission once: `sudo setcap cap_net_raw+ep "$(command -v arp-scan)"`.

## ntopng (optional)

What it provides: top talkers by traffic for the assistant, and a **Flows**
link in the sidebar. See [setup.md](setup.md#5-optional-flow-data-with-ntopng)
to run it. Generate an API token for your ntopng user (in ntopng's user
settings) and save it as `secrets/ntopng_token.txt`. If ntopng's data is ever
reset, the token stops working; the dashboard keeps running without flow data
and logs the error.

## Home Assistant (optional)

Publishes these sensors every poll:
`sensor.network_wifi_clients`, `sensor.network_wired_clients`,
`sensor.network_total_devices`, `sensor.network_aps_online`,
`sensor.network_switches_online`, and for each WAN in `opnsense.wans`
`sensor.network_wan_<slug>_status`, `_download` and `_upload` (Mbps), where
`<slug>` is the WAN's `ha_slug` (by default its name in lower case).

Create a **long-lived access token** (your profile → *Security*) and save it as
`secrets/ha_token.txt`; set `home_assistant.url`.

## Assistant (optional)

The **Ask** panel sends your question plus a trimmed snapshot of the current
network state to Claude and shows the answer. Before anything is sent, the
snapshot is stripped of credentials and your public WAN address (see
`ai_assistant.py`); device names and internal addresses are included so
answers can name devices.

1. Create an API key in the Claude Console (console.anthropic.com) and save
   it as `secrets/anthropic_key.txt`.
2. Set `assistant.enabled: true`. `assistant.model` defaults to
   `claude-opus-5-5`; `claude-sonnet-5-5` or `claude-haiku-5-5` cost less. With
   the newer models, a request the model declines is retried on another model
   automatically (Anthropic's server-side fallback).

Each question is one API call billed to that key.
