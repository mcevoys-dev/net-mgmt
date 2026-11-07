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

   For the **Firewall** page, also:
   - system status: `GET /api/diagnostics/system/system_time`, `system_resources`,
     `system_disk`, `system_information`, `system_temperature`, and
     `GET /api/diagnostics/activity/get_activity` (CPU)
   - firmware status: `GET /api/core/firmware/status` (read only; the dashboard
     never starts an update check)
   - services: `GET /api/core/service/search`
   - firewall log and state table: `GET /api/diagnostics/firewall/log`,
     `firewall/stats`, `firewall/pf_statistics/info`, `firewall/pf_states`
   - current bandwidth per device: `GET /api/diagnostics/traffic/top/<interface>`

   `python3 app.py --check` calls the gateway endpoint and the Firewall-page
   endpoints, and names any that are refused.
2. On that user, under **API keys**, click **+**. OPNsense downloads a file
   containing `key=…` and `secret=…` lines; save it as
   `secrets/opnsense_apikey.txt`.
3. Set `opnsense.url` to the firewall's web address, including the port if it
   is not 443. Set `verify_tls: true` if the firewall has a certificate your
   machine trusts.
4. Optional: list your WAN links under `opnsense.wans` to name and order them
   and draw traffic graphs (see [configuration.md](configuration.md)).

## Proxmox VE (optional)

What it provides: cluster quorum and node status (a node whose uptime resets
has restarted, which is how HA fencing shows up), HA state, every VM and
container with its replication and newest backup, storage use, backup jobs,
and failed tasks, plus Events for each change.

Create a read-only API token. On any Proxmox node, as root:

```bash
pveum user add netdash@pve --comment "Network dashboard (read-only)"
pveum acl modify / --users netdash@pve --roles PVEAuditor
pveum user token add netdash@pve dashboard --privsep 0
```

The last command prints the token's `full-tokenid` (`netdash@pve!dashboard`)
and its `value` (the secret, shown only once). Save them as one line in
`secrets/proxmox_token.txt`:

```
netdash@pve!dashboard=<value>
```

`PVEAuditor` can read everything the page shows but cannot start, stop,
change or migrate anything. Set `proxmox.hosts` to the addresses of
several nodes (`https://<node>:8006`); the dashboard uses the first that
answers, so the page keeps working while one node is down. The dashboard
cannot see why a node dropped (that is in the node's own kernel log); send
node logs to a syslog server for that.

## Proxmox Backup Server (optional)

What it provides, as a **Backup server** card on the Proxmox page: each
datastore's space and the date Proxmox estimates it fills up, how many
backups it holds and how many failed verification, whether a prune job
limits how long backups are kept, garbage collection, verify / prune / sync
jobs and failed tasks, plus Events when any of those change. This is the
part a Proxmox VE token cannot see.

Create a read-only token. In the Backup Server's shell (web UI → *Shell*):

```bash
proxmox-backup-manager user create netdash@pbs --comment "Network dashboard (read-only)"
proxmox-backup-manager acl update / Audit --auth-id netdash@pbs
proxmox-backup-manager user generate-token netdash@pbs dashboard
proxmox-backup-manager acl update / Audit --auth-id 'netdash@pbs!dashboard'
```

The third command prints the token's `tokenid` and `value` (shown only
once). A token gets only the rights given to both it and its user, which is
why the role is set twice. Save them as one line in `secrets/pbs_token.txt`,
or enter them under **Admin → Credentials**:

```
netdash@pbs!dashboard:<value>
```

The `Audit` role can read but cannot back up, restore, prune or delete
anything. Set `pbs.url` to `https://<backup server>:8007`.

## Synology NAS (optional)

What it provides, on the **NAS** page: each disk's health and temperature,
volumes (state and space), CPU, memory and system temperature, plus Events
when a disk or volume leaves the normal state, a volume fills up or a disk
runs hot. An administrator account also shows storage pools (RAID type,
rebuilds, scrubbing), the SMART result, bad sectors, SSD life, waiting DSM
updates and the UPS.

Create an account just for the dashboard (*Control Panel → User & Group →
Create*), with a long random password:

1. Groups: leave it in `users` only.
2. Shared folders: **No access** to all of them.
3. Applications: **Allow** for **DSM** only, deny everything else. DSM
   refuses the sign-in ("permission denied") without it.
4. Leave 2-step verification off for this account: the dashboard signs in
   unattended. If DSM enforces 2-step verification, exempt this account.
5. Select the user, then *Delegate → Delegated Administration* and tick
   only **System monitoring** (view Info Center and Resource Monitor). This
   lets the account read disk and volume health without being an
   administrator.

Save the sign-in in `secrets/synology_credentials.txt`, or enter it under
**Admin → Credentials**, whose test reports what the account can see:

```
username=netdash
password=<password>
```

DSM has no read-only role for Storage Manager, so the dashboard reads
Info Center's storage view instead and says so on the page. If you want the
pool, SMART and update details as well, add the account to the
`administrators` group; that is a full administrator, so weigh it against
having that password on the dashboard's machine.

Set `synology.url` to `https://<nas>:5001`. Requests are POSTs, so the
password never appears in a URL or a web server log.

## Services: websites and ports (optional)

No credential. Every `services.interval` seconds (5 minutes by default) the
dashboard fetches each URL in `services.sites` and connects to each entry in
`services.ports`, and reports response time, uptime over the last 24 hours
and days until the TLS certificate expires. A check must fail twice in a
row before it is reported down, so one slow answer does not raise an alarm.
Checks run from the dashboard's machine, so a site that only fails from
outside your network (DNS, a tunnel) will still show as up here.

For mail servers, check the ports with their TLS mode: `tls` for implicit
TLS (465, 993) and `starttls` for SMTP (25, 587). When you connect by IP
address, set `sni` to the name on the certificate.

## Mail server: Stalwart and Listmonk (optional)

`mail.stalwart_url` (e.g. `http://<mail server>:8080`): reads Stalwart's
`/healthz/live` and `/healthz/ready`, which need no credential.

`mail.listmonk_url` (e.g. `http://<mail server>:9000`): recent campaigns,
list sizes, bounces in the last 7 days, and for each list named in
`mail.watch_lists`, how long since it last got a finished send. A watched
list that goes longer than `mail.max_gap_hours` without one is flagged,
which catches a newsletter job that stopped sending without an error.

In Listmonk, create a read-only API user: *Admin → Users → User roles → New*
with only `campaigns:get_all`, `lists:get_all` and `bounces:get`, then
*Users → New*, type **API**, with that role. Save the user name and the
token it shows in `secrets/listmonk_credentials.txt`, or enter them under
**Admin → Credentials**:

```
api_user=netdash
token=<token>
```

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
