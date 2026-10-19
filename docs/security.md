# Security notes

The dashboard shows a detailed map of your network: device names, addresses,
MACs, switch ports and Wi-Fi problems. Treat it like the admin pages of your
firewall.

## Access

- **There is no login.** Anyone who can reach the port can see every page and
  use `/api/data`, which returns the raw data from every integration
  (including your public WAN address). Keep it on a trusted LAN, or set
  `server.host: 127.0.0.1` and put an authenticating proxy in front of it
  (for example Cloudflare Tunnel with Cloudflare Access, or a reverse proxy
  with single sign-on).
- If the **Ask** panel is on, anyone who can reach the dashboard can spend
  your Claude API credit. Put it behind authentication before exposing it.

## Credentials

- Keep credentials in `secrets_dir`, owned by the dashboard's user, with
  `chmod 700` on the folder and `600` on the files. Never put them in
  `config.yaml` or in the app folder you share or commit; `.gitignore`
  already excludes `config.yaml`, `secrets/` and `data/`.
- Use least-privilege accounts: a Mist observer, a dedicated OPNsense API user
  limited to the four read endpoints in [integrations.md](integrations.md),
  a Central token for monitoring.
- Replace any key that has been pasted into chat, email or a ticket.
- The repository's pre-commit hook (`git config core.hooksPath .githooks`)
  blocks commits containing strings that look like secrets.

## The machine

- Grant `arp-scan` `cap_net_raw` (see [setup.md](setup.md)) rather than
  running the dashboard as root or leaving `arp-scan` setuid.
- Run the service as its own unprivileged user (the example systemd unit does).
- If you run the optional ntopng stack, its containers use host networking;
  pin image versions you have tested, and recreate with
  `docker compose up -d --pull never` unless you mean to upgrade.

## What leaves your network

| Destination | What | When |
|---|---|---|
| Mist, Aruba Central | API reads with your tokens | Every poll |
| api.macvendors.com | MAC addresses, to look up the maker | When a page shows a device whose maker is not cached |
| Anthropic | Your question plus a snapshot without credentials or public IP | Only when someone uses **Ask** |
| Home Assistant | Summary counts and WAN status | Every poll, if enabled |
