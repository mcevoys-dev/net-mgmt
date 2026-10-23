# Setting up the dashboard

These steps assume a Debian or Ubuntu machine on the LAN you want to watch
(a small VM is ideal). Adjust package commands for other distributions.

## 1. Install

```bash
sudo apt install python3 python3-venv arp-scan git
sudo useradd --system --create-home --home-dir /opt/network-dashboard netdash
sudo -u netdash git clone <this repo> /tmp/netdash-src
sudo -u netdash cp -r /tmp/netdash-src/dashboard/. /opt/network-dashboard/
cd /opt/network-dashboard
sudo -u netdash python3 -m venv venv
sudo -u netdash venv/bin/pip install -r requirements.txt
sudo -u netdash mkdir -m 700 secrets data
```

`arp-scan` needs permission to send raw packets. Grant just that, instead of
running the dashboard as root:

```bash
sudo setcap cap_net_raw+ep "$(command -v arp-scan)"
```

The machine must be on (or bridged to) every subnet listed in
`site.lan_subnets`; ARP does not cross routers.

## 2. Configure

```bash
sudo -u netdash cp config.example.yaml config.yaml
sudo -u netdash nano config.yaml
```

Turn on the integrations you have and fill in their addresses. Then put each
credential in its own file in `secrets/` (file names are set in the config).
[integrations.md](integrations.md) explains how to create every key and token,
and which permissions each one needs.

```bash
sudo -u netdash chmod 600 secrets/*
```

## 3. Check

```bash
sudo -u netdash venv/bin/python3 app.py --check
```

This loads the config, then makes one API call per enabled integration and
prints `OK` or `FAIL` with the reason. A config mistake (unknown setting, bad
subnet, missing Central URL…) is reported by name before anything runs. Fix
anything marked `FAIL` before continuing.

## 3b. Optional: admin password for Settings → Credentials

To change API keys from the browser instead of editing files, set an admin
password (12+ characters; only a salted hash is stored in `secrets_dir`):

```bash
sudo -u netdash venv/bin/python3 app.py --set-admin-password
```

Then use **Admin → Credentials** in the sidebar. See
[security.md](security.md#the-credentials-page) before using it over plain HTTP.

## 4. Run as a service

```bash
sudo cp systemd/network-dashboard.service /etc/systemd/system/
sudo nano /etc/systemd/system/network-dashboard.service   # check User and paths
sudo systemctl daemon-reload
sudo systemctl enable --now network-dashboard
journalctl -u network-dashboard -f                         # watch the first polls
```

Open `http://<machine>:5000`. The first poll takes a few seconds; the ARP scan
fills in **All Devices** within a minute, and the trend charts need about 30
minutes of history.

## 5. Optional: flow data with ntopng

`ntopng/compose.yaml` runs ntopng plus netflow2ng, which receives NetFlow v9 from
OPNsense (*Reporting → NetFlow*, destination `<machine>:2055`) and feeds ntopng.

```bash
sudo mkdir -p /opt/ntopng/data /opt/ntopng/redis && sudo chown 101:102 /opt/ntopng/redis
sudo cp ntopng/compose.yaml /opt/ntopng/
printf 'LOCAL_NETWORKS=192.168.1.0/24\n' | sudo tee /opt/ntopng/.env
cd /opt/ntopng && sudo docker compose up -d
```

Log in at `http://<machine>:3000` (first login `admin`/`admin`, you will be asked
to change it), create an API token under your user settings, save it as
`secrets/ntopng_token.txt` and set `ntopng.enabled: true`.

## Updating

```bash
cd /tmp/netdash-src && git pull
sudo -u netdash cp -r dashboard/*.py dashboard/requirements.txt /opt/network-dashboard/
sudo -u netdash /opt/network-dashboard/venv/bin/pip install -r /opt/network-dashboard/requirements.txt
sudo -u netdash /opt/network-dashboard/venv/bin/python3 /opt/network-dashboard/app.py --check
sudo systemctl restart network-dashboard
```

Your `config.yaml`, `secrets/` and `data/` are never overwritten by an update.
Compare your config with the new `config.example.yaml` for any new settings.

## Troubleshooting

| Symptom | Look at |
|---|---|
| A red "Some data sources failed" banner | The message names the integration; run `app.py --check` |
| All Devices is empty | `arp-scan` permission (step 1) and `site.lan_subnets` |
| Wrong times | `site.timezone` (an IANA name such as `Europe/London`) |
| WAN cards have odd names or no traffic graph | `opnsense.wans`: gateway names must match *System → Gateways*; `interface` must be the device name (igb0, em0…) |
| Switch ports never load | `central.api_base`, and that the Central token can read monitoring data |
| Ask says it is not set up | `assistant.enabled` and the key file |
