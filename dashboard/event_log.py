"""
Event / change log.

Each poll cycle, compare new state against the previous snapshot and record
meaningful transitions. Persists to a JSONL file with 7-day retention so the
log survives restarts ("what happened overnight").

Design priorities:
- High signal, low noise. Switches listed in inventory.quiet_switches (ones
  whose status flaps in Central as a reporting artifact) are not logged.
- Device appear/vanish is debounced: a change must persist DEBOUNCE_CYCLES
  polls before it's logged, so a phone briefly dropping doesn't spam the log.
"""
import json
import os
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

RETENTION_DAYS = 7
DEBOUNCE_CYCLES = 2  # device appear/vanish must persist this many polls
# Client-failure seen-keys older than this are dropped from the .cfseen file.
# Mist's failure window is 24h; keys for anything still in the log are rebuilt
# from the log itself on load, so this only needs to cover the Mist window.
CF_SEEN_HOURS = 48

# Switches whose up/down should NOT be logged (known flaky reporting) come from
# inventory.quiet_switches in config.yaml and are passed to EventLog().

# Severity tiers for UI styling
SEV_INFO = "info"
SEV_WARN = "warn"
SEV_CRIT = "crit"


class EventLog:
    def __init__(self, path: Path, quiet_switches=(), primary_gateways=()):
        self.path = path
        # Gateway names marked primary in config; empty = the first gateway.
        self.primary_gateways = set(primary_gateways)
        self.quiet_switches = {s.lower() for s in quiet_switches}
        self.events = []          # in-memory, recent-first
        self._prev = None         # previous poll's derived state
        # debounce trackers: mac -> consecutive cycles in the candidate state
        self._appear_pending = {}
        self._vanish_pending = {}
        # Client-failure dedup: set of normalised "timestamp|mac|type" keys
        # already logged. Rebuilt from the log on load (so nothing in the log
        # can be logged twice) and persisted in .cfseen for the Mist window.
        self._cf_seen = set()
        self._cf_baselined = False
        self._cf_seen_path = path.with_suffix(".cfseen")
        self._load()
        self._load_cf_seen()

    # ── persistence ────────────────────────────────────────────────────────
    @staticmethod
    def _cf_key(ts, mac, ftype):
        """Normalised dedup key. ts may be Unix seconds or an ISO string."""
        try:
            if isinstance(ts, str) and not ts.replace(".", "", 1).isdigit():
                ts = datetime.fromisoformat(ts).timestamp()
            ts = f"{float(ts):.3f}"
        except Exception:
            ts = str(ts)
        return f"{ts}|{(mac or '').lower()}|{ftype or ''}"

    @classmethod
    def _event_cf_key(cls, e):
        if e.get("kind") != "client":
            return None
        d = e.get("detail") or {}
        if not d.get("mac") or not d.get("type"):
            return None
        return cls._cf_key(e.get("ts", ""), d["mac"], d["type"])

    def _load(self):
        try:
            if self.path.exists():
                lines = self.path.read_text().splitlines()
                bad = 0
                self.events = []
                for l in lines:
                    if not l.strip():
                        continue
                    try:
                        self.events.append(json.loads(l))
                    except ValueError:
                        bad += 1  # e.g. a write cut off by a restart
                if bad:
                    print(f"[EVENTS] skipped {bad} unreadable line(s) in {self.path.name}", flush=True)
                    if not self.events:
                        raise ValueError("no readable events")
                loaded = len(self.events) + bad
                self._prune()
                self.events.sort(key=lambda e: e["ts"], reverse=True)
                # Drop duplicate client-failure events (an earlier bug re-logged
                # the same failures many times) and seed the seen-set.
                kept = []
                for e in self.events:
                    k = self._event_cf_key(e)
                    if k is not None:
                        if k in self._cf_seen:
                            continue
                        self._cf_seen.add(k)
                    kept.append(e)
                self.events = kept
                if len(kept) != loaded:
                    print(f"[EVENTS] loaded {loaded} events, kept {len(kept)} "
                          f"(removed {loaded - len(kept)} duplicates/expired)", flush=True)
                    self._save()
        except Exception as e:
            print(f"[EVENTS] load failed: {e}")
            self.events = []
            # Keep the unreadable file instead of overwriting it on the next save.
            try:
                aside = self.path.with_name(
                    f"{self.path.name}.unreadable-{datetime.now():%Y%m%d-%H%M%S}")
                shutil.copy2(self.path, aside)
                print(f"[EVENTS] copied unreadable log to {aside.name}")
            except Exception:
                pass

    @staticmethod
    def _atomic_write(path, text):
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text)
        os.replace(tmp, path)

    def _save(self):
        try:
            # store oldest-first on disk (append-friendly), newest-first in memory
            ordered = sorted(self.events, key=lambda e: e["ts"])
            self._atomic_write(self.path, "\n".join(json.dumps(e) for e in ordered) + "\n")
        except Exception as e:
            print(f"[EVENTS] save failed: {e}")

    def _prune(self):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        self.events = [e for e in self.events if e["ts"] >= cutoff]

    # ── client-failure dedup persistence ─────────────────────────────────────
    def _load_cf_seen(self):
        try:
            if self._cf_seen_path.exists():
                obj = json.loads(self._cf_seen_path.read_text())
                # merge (the log already seeded keys) and normalise old-format keys
                for k in obj.get("seen", []):
                    parts = k.split("|")
                    if len(parts) == 3:
                        self._cf_seen.add(self._cf_key(*parts))
                self._cf_baselined = obj.get("baselined", False)
        except Exception as e:
            print(f"[EVENTS] cf-seen load failed: {e}")
            self._cf_baselined = False

    def _save_cf_seen(self):
        try:
            # Drop keys by age, never at random: a randomly trimmed set forgets
            # failures still in Mist's 24h window and they get logged again.
            cutoff = datetime.now(timezone.utc).timestamp() - CF_SEEN_HOURS * 3600

            def fresh(k):
                try:
                    return float(k.split("|", 1)[0]) >= cutoff
                except ValueError:
                    return False

            seen = sorted(k for k in self._cf_seen if fresh(k))
            self._atomic_write(self._cf_seen_path,
                               json.dumps({"seen": seen, "baselined": self._cf_baselined}))
        except Exception as e:
            print(f"[EVENTS] cf-seen save failed: {e}")

    # ── client failure events (from Mist client-event stream) ────────────────
    # Severity by category. Auth issues are the most notable; roaming/SA-query
    # timeouts are usually benign background noise.
    CF_SEVERITY = {
        "auth":  SEV_WARN,
        "dhcp":  SEV_WARN,
        "dns":   SEV_WARN,
        "arp":   SEV_WARN,
        "assoc": SEV_INFO,
        "roam":  SEV_INFO,
        "other": SEV_INFO,
    }

    def process_client_failures(self, failures):
        """
        Log NEW Mist client failures as events, deduped by (timestamp|mac|type).

        No baseline suppression: on first run, the failures currently in the
        window ARE logged (once) — that's legitimate recent history worth
        capturing, and the per-event dedup keeps them from being re-logged on
        subsequent polls. The seen-set persists across restarts.

        New events are added as one batch: the log file is written once per
        poll, not once per failure.
        """
        if not failures:
            return

        def key(f):
            return self._cf_key(f.get("timestamp", ""), f.get("mac", ""), f.get("type", ""))

        new_logged = 0
        by_label = {}
        # oldest-first so a batch reads chronologically in the log
        for f in sorted(failures, key=lambda x: x.get("timestamp", 0)):
            k = key(f)
            if k in self._cf_seen:
                continue
            self._cf_seen.add(k)
            sev = self.CF_SEVERITY.get(f.get("category", "other"), SEV_INFO)
            # Prefer hostname, then IP, then MAC for the identifier
            who = f.get("hostname") or f.get("ip") or f.get("mac", "")
            band = f.get("band", "")
            rssi = f.get("rssi")
            meta = []
            if band:
                meta.append(band)
            if rssi is not None:
                meta.append(f"{rssi} dBm")
            meta_str = f" ({', '.join(meta)})" if meta else ""
            # Use the failure's actual Mist timestamp, not log-time, so events
            # show when the failure really happened (Mist gives Unix seconds).
            try:
                ev_ts = datetime.fromtimestamp(
                    float(f.get("timestamp", 0)), tz=timezone.utc).isoformat()
            except Exception:
                ev_ts = None
            self.add(
                "client",
                sev,
                f"{f.get('label','Client issue')}: {who}{meta_str}",
                {"mac": f.get("mac", ""), "ip": f.get("ip", ""),
                 "hostname": f.get("hostname", ""), "type": f.get("type", ""),
                 "ap": f.get("ap", ""), "ssid": f.get("ssid", ""),
                 "category": f.get("category", "")},
                ts=ev_ts,
                save=False,
            )
            new_logged += 1
            label = f.get("label", "Client issue")
            by_label[label] = by_label.get(label, 0) + 1

        if new_logged:
            self._commit()
            self._save_cf_seen()
            summary = ", ".join(f"{n} {lbl}" for lbl, n in sorted(by_label.items(), key=lambda x: -x[1]))
            print(f"[EVENTS] logged {new_logged} new client failure(s): {summary}", flush=True)

    # ── recording ──────────────────────────────────────────────────────────
    def add(self, kind, severity, message, detail=None, ts=None, save=True):
        ev = {
            "ts": ts or datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "severity": severity,
            "message": message,
            "detail": detail or {},
        }
        self.events.insert(0, ev)   # newest first
        if save:
            self._commit()
            print(f"[EVENTS] {severity.upper()} {kind}: {message}", flush=True)

    def _commit(self):
        self.events.sort(key=lambda e: e["ts"], reverse=True)  # keep order when ts is backdated
        self._prune()
        self._save()

    def recent(self, n=5):
        return self.events[:n]

    def all(self):
        return self.events

    # ── derive comparable state from a poll ──────────────────────────────────
    @staticmethod
    def _derive(data, arp_hosts, gap_macs):
        mist = data.get("mist", {})
        central = data.get("central", {})
        opnsense = data.get("opnsense", {})

        gateways = {}
        for g in opnsense.get("gateways", []):
            raw = (g.get("status", "") or "").lower()
            # OPNsense gateway status: 'none'/'up' = healthy, 'down'/'force_down'
            # = offline, 'loss'/'delay' = degraded (transient quality issues).
            if raw in ("none", "up", ""):
                state = "online"
            elif raw in ("down", "force_down"):
                state = "down"
            else:  # loss, delay, loss+delay, etc.
                state = "degraded"
            gateways[g.get("name", "?")] = state

        aps = {}
        for a in mist.get("aps", []):
            aps[a.get("mac", "")] = {
                "name": a.get("name", ""),
                "up": (a.get("status", "") or "").lower() in ("connected", "up", "online"),
            }

        switches = {}
        for s in central.get("switches", []):
            name = s.get("name", "")
            switches[name] = {
                "up": (s.get("status", "") or "").lower() in ("up", "online"),
            }

        return {
            "gateways": gateways,
            "aps": aps,
            "switches": switches,
            "arp_macs": {h.get("mac", "").lower() for h in arp_hosts if h.get("mac")},
            "gap_macs": {m.lower() for m in gap_macs},
        }

    # ── the diff engine, called once per poll ───────────────────────────────
    def process_poll(self, data, arp_hosts, gap_devices):
        gap_macs = [g.get("mac", "") for g in gap_devices]
        cur = self._derive(data, arp_hosts, gap_macs)
        prev = self._prev

        if prev is None:
            # first poll after start: establish baseline, don't flood with events
            self._prev = cur
            return

        # WAN gateway state changes. States: online / degraded / down.
        # down is the critical failover signal; recovery is notable. We skip
        # degraded-quality flaps on BACKUP links (cellular jitter is normal and
        # not actionable while it isn't carrying traffic) but still log a backup
        # going fully down. Primary = marked primary in config, else the first.
        gw_names = list(cur["gateways"].keys())
        primary_name = gw_names[0] if gw_names else None
        primaries = self.primary_gateways or {primary_name}
        for name, state in cur["gateways"].items():
            old = prev["gateways"].get(name)
            if old is None or old == state:
                continue
            is_primary = name in primaries
            went_down = state == "down"
            recovered = old == "down" and state == "online"
            degraded = state == "degraded" and old == "online"
            improved = old == "degraded" and state == "online"

            if went_down:
                self.add("wan", SEV_CRIT,
                         f"WAN '{name}' went DOWN", {"gateway": name, "to": state})
            elif recovered:
                self.add("wan", SEV_INFO,
                         f"WAN '{name}' recovered (back online)", {"gateway": name})
            elif degraded and is_primary:
                self.add("wan", SEV_WARN,
                         f"WAN '{name}' degraded (packet loss / latency)",
                         {"gateway": name})
            elif improved and is_primary:
                self.add("wan", SEV_INFO,
                         f"WAN '{name}' quality recovered", {"gateway": name})
            # backup-link quality flaps and other transitions: silent

        # AP up/down
        for mac, info in cur["aps"].items():
            old = prev["aps"].get(mac)
            if old is not None and old["up"] != info["up"]:
                self.add(
                    "ap",
                    SEV_WARN if not info["up"] else SEV_INFO,
                    f"AP '{info['name'] or mac}' went {'up' if info['up'] else 'down'}",
                    {"mac": mac, "name": info["name"]},
                )

        # Switch up/down (suppressing known-flaky ones)
        for name, info in cur["switches"].items():
            if name.lower() in self.quiet_switches:
                continue
            old = prev["switches"].get(name)
            if old is not None and old["up"] != info["up"]:
                self.add(
                    "switch",
                    SEV_WARN if not info["up"] else SEV_INFO,
                    f"Switch '{name}' went {'up' if info['up'] else 'down'}",
                    {"name": name},
                )

        # New unaccounted device (debounced: must persist DEBOUNCE_CYCLES polls).
        # A device enters "pending" when it first appears in the gap set and
        # wasn't already known last poll. It increments each cycle it stays in
        # the gap set, and logs once it crosses the debounce threshold.
        known_prev = prev["gap_macs"]
        for mac in cur["gap_macs"]:
            if mac in known_prev and mac not in self._appear_pending:
                # already established before we started tracking; not "new"
                continue
            # it's either newly-appeared or already mid-debounce: count it
            self._appear_pending[mac] = self._appear_pending.get(mac, 0) + 1

        # drop pending devices that left the gap set before debounce completed
        for mac in list(self._appear_pending.keys()):
            if mac not in cur["gap_macs"]:
                self._appear_pending.pop(mac, None)
                continue
            if self._appear_pending[mac] >= DEBOUNCE_CYCLES:
                self._appear_pending.pop(mac, None)
                dev = next((g for g in gap_devices if g.get("mac", "").lower() == mac), {})
                self.add(
                    "unaccounted",
                    SEV_WARN,
                    f"New unaccounted device: {dev.get('ip', mac)}",
                    {"mac": mac, "ip": dev.get("ip", ""), "vendor": dev.get("vendor", "")},
                )

        self._prev = cur
