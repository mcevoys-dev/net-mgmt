"""
Views and templates for the Backup Server, NAS and Services pages.

Kept apart from ui.py, which is already long. ui.install() calls install()
here; the templates use the same shell (BASE_HTML) and CSS as every page.
"""
from markupsafe import Markup

import synology_mon

ORDER = {"danger": 0, "warn": 1, "info": 2}
DAY = 86400


def _sorted(notes):
    return sorted(notes, key=lambda x: ORDER[x[0]])


def _days(s):
    return int(s // DAY) if s is not None else None


def _ok(state):
    return state in (None, "", "OK", "ok") or str(state).startswith("OK")


def spark(values, w=120, h=22):
    """Inline SVG bars of response times; a failed check is a red stub."""
    if not values:
        return Markup("")
    slots = 48
    values = values[-slots:]
    top = max([v for v in values if v] or [1])
    bw = w / slots
    bars = []
    for i, v in enumerate(values, start=slots - len(values)):
        x = round(i * bw, 2)
        if v is None:
            bars.append(f'<rect x="{x}" y="{h - 6}" width="{max(bw - 1, 1):.2f}" height="6" fill="var(--danger-dot)"/>')
        else:
            bh = max(2, round(h * v / top, 1))
            bars.append(f'<rect x="{x}" y="{h - bh}" width="{max(bw - 1, 1):.2f}" height="{bh}" fill="var(--info)" opacity=".65"/>')
    return Markup(f'<svg class="svc-spark" viewBox="0 0 {w} {h}" preserveAspectRatio="none" aria-hidden="true">{"".join(bars)}</svg>')


# ── Proxmox Backup Server ────────────────────────────────────────────────────

def pbs_view(g):
    mon = g.get("PBS")
    if not mon:
        return None
    s = mon.snapshot()
    cfg = g["CFG"].pbs
    if not s.get("updated"):
        return {"pending": True, "error": s.get("error"), "url": cfg.url}
    notes = []
    if s.get("error"):
        notes.append(("danger", f"Last poll of the backup server failed: {s['error']}"))
    for st in s["stores"]:
        n = st["name"]
        sn = st["snapshots"] or {}
        if st["error"]:
            notes.append(("danger", f"Datastore {n} reports an error: {st['error']}"))
        if (st["used_pct"] or 0) >= cfg.storage_warn_pct:
            notes.append(("warn", f"Datastore {n} is {st['used_pct']}% full ({st['free_gb']} GB free)."))
        if st["full_in"] is not None and st["full_in"] < cfg.full_warn_days * DAY:
            from ui import local_time
            notes.append(("warn", f"At the current rate, datastore {n} fills up in about {_days(st['full_in'])} days "
                                  f"(around {local_time(st['full_date'], '%-d %b %Y')})."))
        if sn.get("failed"):
            notes.append(("danger", f"{sn['failed']} backup(s) on {n} failed verification and may not restore: "
                                    + ", ".join(sn["failed_list"][:6]) + "."))
        if not st["retention"]:
            notes.append(("warn", f"Datastore {n} has no prune job, so every backup is kept forever and it keeps "
                                  "growing. Add one under Datastore → Prune & GC Jobs (for example keep 7 daily, "
                                  "4 weekly, 6 monthly)."))
        gc = st["gc"]
        if gc["ended"] and not _ok(gc["state"]):
            notes.append(("danger", f"Last garbage collection on {n} failed: {gc['state']}"))
        elif st["retention"] and (gc["age"] is None or gc["age"] > cfg.gc_max_age_days * DAY):
            notes.append(("warn", f"Garbage collection has not run on {n} "
                                  + (f"in {_days(gc['age'])} days" if gc["age"] else "yet")
                                  + "; pruned backups only free space after it runs."))
        if sn and sn.get("count") and not st["verify_jobs"] and sn.get("unverified") == sn["count"]:
            notes.append(("info", f"No verify job on {n}: none of its {sn['count']} backups has been checked. "
                                  "A weekly verify job confirms they can be restored."))
    for j in s["jobs"]:
        if j["ended"] and not _ok(j["state"]) and j["enabled"]:
            notes.append(("danger", f"{j['kind'].title()} job {j['id']} last ended with: {str(j['state'])[:140]}"))
    if s["failed_tasks"]:
        notes.append(("warn", f"{len(s['failed_tasks'])} backup server task(s) failed in the last 24 hours."))
    if (s["node"].get("rootfs") or 0) >= cfg.storage_warn_pct:
        notes.append(("warn", f"The backup server's own system disk is {s['node']['rootfs']}% full."))
    return {**s, "pending": False, "notes": _sorted(notes), "url": cfg.url,
            "warn_pct": cfg.storage_warn_pct, "gc_max_days": cfg.gc_max_age_days}


def pbs_summary(g):
    v = pbs_view(g)
    if not v or v.get("pending"):
        return (1, 0, 0) if v and v.get("error") and "No credentials" not in v["error"] else None
    poor = fair = good = 0
    for st in v["stores"]:
        sn = st["snapshots"] or {}
        if st["error"] or sn.get("failed") or (st["used_pct"] or 0) >= 95 or not _ok(st["gc"]["state"]) or v.get("error"):
            poor += 1
        elif (st["used_pct"] or 0) >= v["warn_pct"] or not st["retention"] or \
                (st["full_in"] is not None and st["full_in"] < 90 * DAY):
            fair += 1
        else:
            good += 1
    return (poor, fair, good)


# ── Synology NAS ─────────────────────────────────────────────────────────────

def nas_view(g):
    mon = g.get("NAS")
    if not mon:
        return None
    s = mon.snapshot()
    cfg = g["CFG"].synology
    if not s.get("updated"):
        return {"pending": True, "error": s.get("error"), "url": cfg.url}
    notes = []
    if s.get("error"):
        notes.append(("danger", f"Last poll of the NAS failed: {s['error']}"))
    for part, why in (s.get("missing") or {}).items():
        notes.append(("info", f"Could not read {part}: {why}."
                      + (" Storage Manager needs an account in the administrators group." if part == "storage" else "")))
    for d in s["disks"]:
        if not synology_mon.disk_ok(d):
            notes.append(("danger", f"Disk {d['name']} ({d['model']}) reports {synology_mon.disk_problem(d)}."))
        if (d["temp"] or 0) >= cfg.disk_temp_warn:
            notes.append(("warn", f"Disk {d['name']} is at {d['temp']} °C (warning from {cfg.disk_temp_warn} °C)."))
        if d["life"] is not None and d["life"] < 10:
            notes.append(("warn", f"SSD {d['name']} has {d['life']}% of its rated life left."))
    for kind, label in (("pools", "Storage pool"), ("volumes", "Volume")):
        for x in s[kind]:
            if x["status"] not in synology_mon.NORMAL:
                sev = "danger" if x["status"] in ("degraded", "crashed", "attention", "error") else "warn"
                notes.append((sev, f"{label} {x['name']} is {x['status']}."))
            if x.get("progress"):
                notes.append(("info", f"{label} {x['name']}: {x['progress']}."))
    for x in s["volumes"]:
        if (x["used_pct"] or 0) >= cfg.volume_warn_pct:
            notes.append(("warn", f"Volume {x['name']} is {x['used_pct']}% full ({x['free_gb']} GB free)."))
    if s.get("temp_warn"):
        notes.append(("warn", f"The NAS reports a temperature warning ({s.get('temp')} °C)."))
    if (s.get("dsm_update") or {}).get("available"):
        notes.append(("info", f"A DSM update is available{': ' + str(s['dsm_update']['version']) if s['dsm_update'].get('version') else ''}. "
                              "Shut down the Backup Server VM first if it runs on this NAS."))
    ups = s.get("ups")
    if ups and ups.get("status") and str(ups["status"]).lower() not in ("ol", "online", "connected"):
        notes.append(("warn", f"UPS status: {ups['status']}."))
    return {**s, "pending": False, "notes": _sorted(notes), "url": cfg.url,
            "warn_pct": cfg.volume_warn_pct, "temp_limit": cfg.disk_temp_warn,
            "disk_ok": synology_mon.disk_ok, "normal": synology_mon.NORMAL}


def nas_summary(g):
    v = nas_view(g)
    if not v or v.get("pending"):
        return (1, 0, 0) if v and v.get("error") and "No credentials" not in v["error"] else None
    poor = fair = good = 0
    for d in v["disks"]:
        if not synology_mon.disk_ok(d):
            poor += 1
        elif (d["temp"] or 0) >= v["temp_limit"] or (d["life"] is not None and d["life"] < 10):
            fair += 1
        else:
            good += 1
    for x in v["volumes"] + v["pools"]:
        if x["status"] in ("degraded", "crashed", "attention", "error"):
            poor += 1
        elif x["status"] not in synology_mon.NORMAL or (x.get("used_pct") or 0) >= v["warn_pct"]:
            fair += 1
        else:
            good += 1
    return (poor, fair, good)


# ── Services (websites, ports, mail) ─────────────────────────────────────────

def services_view(g):
    chk, mail = g.get("SERVICES"), g.get("MAIL")
    if not chk and not mail:
        return None
    s = chk.snapshot() if chk else {"rows": [], "updated": None}
    m = mail.snapshot() if mail else None
    notes = []
    for r in s["rows"]:
        if r["level"] == "danger":
            notes.append(("danger", f"{r['name']} is down: {r['error']}."))
        elif r["level"] == "warn":
            if not r["ok"]:
                notes.append(("warn", f"{r['name']}: last check failed ({r['error']})."))
            if r["cert_days"] is not None and r["cert_days"] <= s.get("cert_warn", 21):
                notes.append(("warn" if r["cert_days"] > 7 else "danger",
                              f"Certificate for {r['name']} expires in {int(r['cert_days'])} day(s)."))
            if r["ok"] and (r["ms"] or 0) >= s.get("slow_ms", 3000):
                notes.append(("info", f"{r['name']} took {r['ms']} ms to answer."))
    if m and m.get("updated"):
        st = m.get("stalwart")
        if st and not st["ok"]:
            notes.append(("danger", "Mail server health check failing: "
                          + (st["error"] or f"live={st['live']}, ready={st['ready']}") + "."))
        lm = m.get("listmonk")
        if lm and lm.get("error"):
            notes.append(("info" if lm.get("no_creds") else "danger", f"Listmonk: {lm['error']}"))
        for w in (lm or {}).get("watched", []):
            if w["level"] == "good":
                continue
            if not w["known"]:
                why = "no such list in Listmonk (check mail.watch_lists)"
            elif w["problem"]:
                why = f"campaign “{w['problem']['name']}” is {w['problem']['status']}"
            elif w["age"] is None:
                why = "no finished send found"
            elif w["short"]:
                why = f"last send reached {w['last']['sent']} of {w['last']['to_send']} subscribers"
            else:
                why = f"no send in {_days(w['age'])}d {int(w['age'] % DAY // 3600)}h"
            notes.append((w["level"], f"Newsletter {w['name']}: {why}."))
        if lm and (lm.get("bounce_types") or {}).get("hard", 0) >= 5:
            notes.append(("warn", f"{lm['bounce_types']['hard']} hard bounces in the last 7 days."))
    groups = {}
    for r in s["rows"]:
        groups.setdefault((r["kind"], r["group"]), []).append(r)
    certs = [r for r in s["rows"] if r["cert_days"] is not None]
    soonest = min(certs, key=lambda r: r["cert_days"]) if certs else None
    return {"pending": not s.get("updated") and not (m and m.get("updated")),
            "checks": s, "mail": m, "notes": _sorted(notes), "soonest": soonest,
            "sites": [r for r in s["rows"] if r["kind"] == "site"],
            "ports": [r for r in s["rows"] if r["kind"] == "port"],
            "spark": spark, "max_gap_h": g["CFG"].mail.max_gap_hours}


def services_summary(g):
    v = services_view(g)
    if not v or v["pending"]:
        return None
    rows = v["checks"]["rows"]
    poor = sum(1 for r in rows if r["level"] == "danger")
    fair = sum(1 for r in rows if r["level"] == "warn")
    good = sum(1 for r in rows if r["level"] == "good")
    return (poor, fair, good) if rows else None


def mail_summary(g):
    v = services_view(g)
    m = v and v.get("mail")
    if not m or not m.get("updated"):
        return None
    poor = fair = good = 0
    st = m.get("stalwart")
    if st:
        poor, good = (poor, good + 1) if st["ok"] else (poor + 1, good)
    lm = m.get("listmonk")
    if lm:
        if lm.get("no_creds"):
            pass
        elif lm.get("error"):
            poor += 1
        else:
            good += 1
        for w in lm.get("watched", []):
            poor += w["level"] == "danger"
            fair += w["level"] == "warn"
            good += w["level"] == "good"
    return (poor, fair, good)


# ── registration ─────────────────────────────────────────────────────────────

def install(app, g, page):
    from flask import render_template_string
    cfg = g["CFG"]
    NAS_HTML = page(NAS_BODY)
    SERVICES_HTML = page(SERVICES_BODY)
    app.jinja_env.globals.update(
        ui_pbs_summary=lambda: pbs_summary(g),
        ui_nas_summary=lambda: nas_summary(g),
        ui_svc_summary=lambda: services_summary(g),
        ui_mail_summary=lambda: mail_summary(g),
    )

    def nas_page():
        return render_template_string(NAS_HTML, title="NAS", active="nas",
                                      last_updated=g["last_updated_str"](), v=nas_view(g))

    def services_page():
        return render_template_string(SERVICES_HTML, title="Services", active="services",
                                      last_updated=g["last_updated_str"](), v=services_view(g))

    if cfg.synology.enabled:
        app.add_url_rule("/nas", "nas_page", nas_page)
    if cfg.services.enabled or cfg.mail.enabled:
        app.add_url_rule("/services", "services_page", services_page)


NOTES = r"""
{% if v.notes %}
<section class="card" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('info') }} Worth a look</div></div></div>
  <div class="card-b" style="padding-top:.4rem"><ul class="notes">{% for sev, n in v.notes %}<li class="note-{{ sev }}">{{ n }}</li>{% endfor %}</ul></div>
</section>
{% endif %}
"""

# Rendered inside the Proxmox page (as `pb`), after the cluster's own backup card.
PBS_SECTION = r"""
{% if pb %}
<section class="card" id="backup-server" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('disk') }} Backup server</div>
    <div class="card-sub">{% if pb.pending %}Reading Proxmox Backup Server…{% else %}Proxmox Backup Server {{ pb.version or '' }}{% if pb.node.uptime %} · up {{ pb.node.uptime | duration }}{% endif %}{% if pb.node.cpu is not none %} · CPU {{ pb.node.cpu }}%{% endif %}{% if pb.node.mem is not none %} · memory {{ pb.node.mem }}%{% endif %}{% if pb.node.rootfs is not none %} · system disk {{ pb.node.rootfs }}%{% endif %}{% endif %}</div></div>
    <div class="card-x"><a class="card-link" href="{{ pb.url }}" target="_blank" rel="noopener">Open {{ ext() }}</a></div></div>
  {% if pb.pending %}
  <div class="card-b"><div class="info-banner">{{ icon('info') }}<span>Fills in within a few minutes of the dashboard starting.{% if pb.error %} Last error: {{ pb.error }}{% endif %}</span></div></div>
  {% else %}
  {% if pb.notes %}<div class="card-b" style="padding-bottom:0"><ul class="notes">{% for sev, n in pb.notes %}<li class="note-{{ sev }}">{{ n }}</li>{% endfor %}</ul></div>{% endif %}
  <div class="table-wrap">
    <table class="t">
      <thead><tr><th>Datastore</th><th style="min-width:180px">Space</th><th>Fills up</th><th class="r">Backups</th><th>Verified</th><th>Retention</th><th>Garbage collection</th></tr></thead>
      <tbody>
      {% for st in pb.stores %}
      {% set sn = st.snapshots or {} %}
      <tr>
        <td><span class="dev-name">{{ st.name }}</span>{% if st.error %} <span class="pill pill-danger">error</span>{% endif %}</td>
        <td><div class="mrow" style="grid-template-columns:1fr auto"><span class="mrow-s">{{ st.used_gb }} of {{ st.total_gb }} GB · {{ st.free_gb }} GB free</span>
            <span class="mrow-v {{ 'danger' if (st.used_pct or 0) >= 95 else ('warn' if (st.used_pct or 0) >= pb.warn_pct else '') }}">{{ st.used_pct }}%</span>
            <div class="mbar {{ 'bad' if (st.used_pct or 0) >= 95 else ('warn' if (st.used_pct or 0) >= pb.warn_pct else 'info') }}"><span style="width:{{ [st.used_pct or 0, 1] | max }}%"></span></div></div></td>
        <td style="white-space:nowrap">{% if st.full_date %}<span class="{{ 'warn' if st.full_in and st.full_in < 90*86400 }}">{{ st.full_date | local_time('%b %Y') }}</span><div class="dev-sub">in ~{{ (st.full_in / 86400) | int }} days</div>{% else %}<span class="muted">not growing</span>{% endif %}</td>
        <td class="r">{{ sn.count if sn else '—' }}<div class="dev-sub">{{ sn.groups | length if sn else 0 }} guests{% if sn.oldest_days %} · oldest {{ sn.oldest_days }}d{% endif %}</div></td>
        <td style="white-space:nowrap">{% if not sn %}<span class="muted">—</span>{% elif sn.failed %}<span class="pill pill-danger">{{ sn.failed }} failed</span>{% elif sn.verified %}<span class="status"><i class="dot good"></i>{{ sn.verified }} ok</span>{% else %}<span class="muted">none yet</span>{% endif %}{% if sn and sn.unverified %}<div class="dev-sub">{{ sn.unverified }} not verified</div>{% endif %}</td>
        <td>{% if st.retention %}{% for j in st.prune_jobs[:1] %}<span class="mono" style="font-size:.74rem">{% for k, val in j.keep | dictsort %}{{ k }} {{ val }}{{ ', ' if not loop.last }}{% endfor %}</span>{% endfor %}{% if not st.prune_jobs %}<span class="mono" style="font-size:.74rem">{% for k, val in st.keep | dictsort %}{{ k }} {{ val }}{{ ', ' if not loop.last }}{% endfor %}</span>{% endif %}{% else %}<span class="pill pill-warn">kept forever</span>{% endif %}</td>
        <td style="white-space:nowrap">{% set gc = st.gc %}{% if gc.ended %}<span class="status"><i class="dot {{ 'good' if not gc.state or gc.state.startswith('OK') else 'danger' }}"></i>{{ (gc.age | duration) ~ ' ago' if gc.age else '' }}</span>{% if gc.removed_gb %}<div class="dev-sub">freed {{ gc.removed_gb }} GB</div>{% endif %}{% else %}<span class="muted">never</span>{% endif %}{% if gc.schedule %}<div class="dev-sub mono">{{ gc.schedule }}</div>{% endif %}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% if pb.jobs %}
  <div class="table-wrap" style="border-top:1px solid var(--border)">
    <table class="t">
      <thead><tr><th>Job</th><th>Datastore</th><th>Schedule</th><th>Last run</th><th>Next</th></tr></thead>
      <tbody>{% for j in pb.jobs %}
      <tr><td><span class="pill pill-muted">{{ j.kind }}</span> <span class="dev-name">{{ j.id }}</span>{% if not j.enabled %} <span class="pill pill-warn">disabled</span>{% endif %}{% if j.remote %} <span class="muted">from {{ j.remote }}/{{ j.remote_store }}</span>{% endif %}</td>
          <td class="mono">{{ j.store }}</td><td class="mono muted">{{ j.schedule or '—' }}</td>
          <td style="white-space:nowrap">{% if j.ended %}<span class="status"><i class="dot {{ 'good' if not j.state or j.state.startswith('OK') else 'danger' }}"></i>{{ j.ended | local_time('%a %-d %b %H:%M') }}</span>{% if j.state and not j.state.startswith('OK') %}<div class="danger" style="font-size:.74rem">{{ j.state[:120] }}</div>{% endif %}{% else %}<span class="muted">never</span>{% endif %}</td>
          <td class="muted" style="white-space:nowrap">{{ j.next | local_time('%a %H:%M') if j.next else '—' }}</td></tr>
      {% endfor %}</tbody>
    </table>
  </div>
  {% endif %}
  {% for st in pb.stores if st.snapshots and st.snapshots.groups %}
  <details class="pbs-groups"><summary>Backups by guest on {{ st.name }} ({{ st.snapshots.groups | length }})</summary>
    <div class="table-wrap"><table class="t sortable">
      <thead><tr><th>Guest</th><th>Name</th><th class="r">Backups</th><th>Newest</th><th>Newest verified</th></tr></thead>
      <tbody>{% for gr in st.snapshots.groups %}
      <tr><td class="mono">{{ gr.type }}/{{ gr.id }}</td><td>{{ gr.comment or '' }}</td><td class="r">{{ gr.count }}</td>
          <td data-v="{{ gr.age or 0 }}" style="white-space:nowrap">{{ (gr.age | duration) ~ ' ago' if gr.age else '—' }}</td>
          <td>{% if gr.last_verify == 'ok' %}<span class="status"><i class="dot good"></i>ok</span>{% elif gr.last_verify == 'failed' %}<span class="pill pill-danger">failed</span>{% else %}<span class="muted">not yet</span>{% endif %}</td></tr>
      {% endfor %}</tbody>
    </table></div>
  </details>
  {% endfor %}
  {% if pb.failed_tasks %}
  <div class="table-wrap" style="border-top:1px solid var(--border)">
    <table class="t"><thead><tr><th>Failed task</th><th>When</th><th>Result</th></tr></thead><tbody>
      {% for t in pb.failed_tasks %}<tr><td>{{ t.type }} {{ t.id or '' }}</td><td class="mono muted" style="white-space:nowrap">{{ t.start | local_time('%a %H:%M') }}</td><td class="danger" style="font-size:.78rem">{{ t.status }}</td></tr>{% endfor %}
    </tbody></table>
  </div>
  {% endif %}
  {% endif %}
</section>
<style>.pbs-groups{border-top:1px solid var(--border)}.pbs-groups summary{cursor:pointer;padding:.65rem 1rem;font-size:.8rem;color:var(--text2)}</style>
{% endif %}
"""

NAS_BODY = r"""
{% if not v %}
<section class="card"><div class="empty">The Synology NAS is not enabled in config.yaml.</div></section>
{% elif v.pending %}
{% call page_head('NAS', 'Reading the NAS…') %}{% endcall %}
<div class="info-banner">{{ icon('info') }}<span>Reading the Synology NAS; this page fills in within a few minutes of the dashboard starting.{% if v.error %} Last error: {{ v.error }}{% endif %}</span></div>
{% else %}
{% call page_head('NAS', (v.model or 'Synology') ~ ' · ' ~ ((v.dsm or 'DSM ?') if (v.dsm or '').startswith('DSM') else 'DSM ' ~ v.dsm) ~ ((' · up ' ~ (v.uptime | duration)) if v.uptime else '')) %}<a class="btn btn-sm" href="{{ v.url }}" target="_blank" rel="noopener">Open DSM {{ ext() }}</a>{% endcall %}
{% set n_ok = namespace(d=0, hot=0) %}
{% for d in v.disks %}{% if v.disk_ok(d) %}{% set n_ok.d = n_ok.d + 1 %}{% endif %}{% if (d.temp or 0) > n_ok.hot %}{% set n_ok.hot = d.temp %}{% endif %}{% endfor %}
{% set vols_ok = v.volumes | selectattr('status', 'in', v.normal) | list | length %}
<div class="stats">
  <div class="stat"><div class="stat-l">{{ icon('disk') }} Disks</div>
    <div class="stat-v {{ 'v-good' if n_ok.d == v.disks | length else 'v-danger' }}">{{ n_ok.d }}<small>/{{ v.disks | length }}</small></div>
    <div class="stat-s">healthy (status and SMART)</div></div>
  <div class="stat"><div class="stat-l">{{ icon('server') }} Volumes</div>
    <div class="stat-v {{ 'v-good' if vols_ok == v.volumes | length else 'v-danger' }}">{{ vols_ok }}<small>/{{ v.volumes | length }}</small></div>
    <div class="stat-s">{% for p in v.pools %}{{ p.raid }}{{ ', ' if not loop.last }}{% else %}no pools read{% endfor %}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('pulse') }} Hottest disk</div>
    <div class="stat-v {{ 'v-warn' if n_ok.hot >= v.temp_limit }}">{{ n_ok.hot or '—' }}<small>{{ ' °C' if n_ok.hot }}</small></div>
    <div class="stat-s">{% if v.temp %}system {{ v.temp }} °C{% else %}warning at {{ v.temp_limit }} °C{% endif %}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('devices') }} CPU / memory</div>
    <div class="stat-v" style="font-size:1.2rem;margin-top:.55rem">{{ (v.cpu ~ '%') if v.cpu is not none else '—' }} · {{ (v.mem ~ '%') if v.mem is not none else '—' }}</div>
    <div class="stat-s">{% if v.ram_gb %}{{ v.ram_gb }} GB RAM{% else %}now{% endif %}</div></div>
  <div class="stat"><div class="stat-l">{{ icon('refresh') }} DSM update</div>
    {% set du = v.dsm_update %}
    <div class="stat-v {{ 'v-info' if du and du.available }}" style="font-size:1.2rem;margin-top:.55rem">{% if not du %}—{% elif du.available %}Available{% else %}Up to date{% endif %}</div>
    <div class="stat-s">{{ du.version if du and du.version else ('UPS: ' ~ v.ups.status if v.ups else 'no UPS reported') }}</div></div>
</div>
""" + NOTES + r"""
<div class="grid">
  <section class="card c6">
    <div class="card-h"><div><div class="card-t">{{ icon('server') }} Volumes</div><div class="card-sub">Space and state; warning at {{ v.warn_pct }}%</div></div></div>
    <div class="card-b"><div class="mlist" style="gap:.55rem">
      {% for x in v.volumes %}
      <div class="mrow"><span class="mrow-l" style="font-weight:500">{{ x.name }} <span class="muted mono" style="font-size:.72rem">{{ x.fs }}</span>{% if x.status not in v.normal %} <span class="pill {{ 'pill-danger' if x.status in ('degraded','crashed','attention','error') else 'pill-warn' }}">{{ x.status }}</span>{% endif %}{% if x.progress %} <span class="pill pill-info">{{ x.progress }}</span>{% endif %}</span>
        <span class="mrow-v {{ 'danger' if (x.used_pct or 0) >= 95 else ('warn' if (x.used_pct or 0) >= v.warn_pct else '') }}">{{ (x.used_pct ~ '%') if x.used_pct is not none else '—' }}</span>
        <div class="mbar {{ 'bad' if (x.used_pct or 0) >= 95 else ('warn' if (x.used_pct or 0) >= v.warn_pct else 'info') }}"><span style="width:{{ [x.used_pct or 0, 1] | max }}%"></span></div>
        {% if x.total_gb %}<span class="mrow-s">{{ x.free_gb }} GB free of {{ x.total_gb }} GB</span>{% endif %}</div>
      {% else %}<div class="muted">No volumes read{% if v.missing.storage %} ({{ v.missing.storage }}){% endif %}.</div>{% endfor %}
    </div></div>
  </section>
  <section class="card c6">
    <div class="card-h"><div><div class="card-t">{{ icon('topo') }} Storage pools</div><div class="card-sub">RAID type and state; rebuilds and scrubbing show here</div></div></div>
    <div class="card-b flush"><table class="t"><tbody>
      {% for p in v.pools %}
      <tr><td style="width:1%"><i class="dot {{ 'good' if p.status in v.normal else ('danger' if p.status in ('degraded','crashed','attention','error') else 'warn') }}"></i></td>
          <td style="padding-left:0"><span class="dev-name">{{ p.name }}</span> <span class="muted">{{ p.raid }} · {{ p.disks }} disk{{ 's' if p.disks != 1 }}</span>{% if p.progress %} <span class="pill pill-info">{{ p.progress }}</span>{% endif %}</td>
          <td class="r muted">{{ p.status or '—' }}</td></tr>
      {% else %}<tr><td class="muted">No storage pools read.</td></tr>{% endfor %}
    </tbody></table>
    {% if v.ups %}<div class="card-foot"><span>UPS {{ v.ups.model }}: {{ v.ups.status }}{% if v.ups.charge is not none %} · {{ v.ups.charge }}% charge{% endif %}</span></div>{% endif %}
    </div>
  </section>
</div>

<section class="card">
  <div class="card-h"><div><div class="card-t">{{ icon('disk') }} Disks</div><div class="card-sub">Status, SMART, temperature{% if v.disks | selectattr('life') | list %} and SSD life{% endif %}</div></div></div>
  <div class="table-wrap">
    <table class="t sortable">
      <thead><tr><th>Disk</th><th>Model</th><th class="r">Size</th><th>Status</th><th>SMART</th><th class="r">Temp</th><th class="r">Bad sectors</th><th class="r">SSD life</th></tr></thead>
      <tbody>
      {% for d in v.disks %}
      <tr>
        <td><span class="dev-name">{{ d.name }}</span><div class="dev-sub">{{ d.type }}{% if d.pool %} · {{ d.pool }}{% endif %}</div></td>
        <td class="mono" style="font-size:.76rem">{{ d.model }}<div class="dev-sub">{{ d.firmware }}</div></td>
        <td class="r" data-v="{{ d.size_gb or 0 }}">{{ ((d.size_gb / 1000) | round(1) ~ ' TB') if d.size_gb and d.size_gb >= 1000 else ((d.size_gb ~ ' GB') if d.size_gb else '—') }}</td>
        <td><span class="status"><i class="dot {{ 'good' if d.status in v.normal else 'danger' }}"></i>{{ d.status or '—' }}</span></td>
        <td>{% if d.smart %}<span class="{{ '' if d.smart in v.normal or d.smart in ('healthy','safe') else 'danger' }}">{{ d.smart }}</span>{% else %}<span class="muted">—</span>{% endif %}</td>
        <td class="r {{ 'warn' if (d.temp or 0) >= v.temp_limit }}">{{ (d.temp ~ ' °C') if d.temp else '—' }}</td>
        <td class="r {{ 'danger' if d.bad_sectors }}">{{ d.bad_sectors if d.bad_sectors is not none else '—' }}</td>
        <td class="r {{ 'warn' if d.life is not none and d.life < 10 }}">{{ (d.life ~ '%') if d.life is not none else '—' }}</td>
      </tr>
      {% else %}<tr><td colspan="8" class="muted">No disks read{% if v.missing.storage %} ({{ v.missing.storage }}){% endif %}.</td></tr>{% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endif %}
<style>.notes li.note-danger::before{background:var(--danger-dot)}.notes li.note-info::before{background:var(--info)}</style>
"""

SERVICES_BODY = r"""
{% if not v %}
<section class="card"><div class="empty">Neither services nor mail is enabled in config.yaml.</div></section>
{% elif v.pending %}
{% call page_head('Services', 'Running the first checks…') %}{% endcall %}
<div class="info-banner">{{ icon('info') }}<span>The first round of checks runs when the dashboard starts; refresh in a minute.</span></div>
{% else %}
{% set up_sites = v.sites | selectattr('ok') | list | length %}
{% set up_ports = v.ports | selectattr('ok') | list | length %}
{% set m = v.mail %}
{% call page_head('Services', 'Websites, ports and certificates checked every ' ~ ((v.checks.interval or 300) // 60) ~ ' minutes' ~ (' · mail and newsletters' if m else '')) %}{% endcall %}
<div class="stats">
  {% if v.sites %}<div class="stat"><div class="stat-l">{{ icon('globe') }} Websites</div>
    <div class="stat-v {{ 'v-good' if up_sites == v.sites | length else 'v-danger' }}">{{ up_sites }}<small>/{{ v.sites | length }}</small></div>
    <div class="stat-s">answering now</div></div>{% endif %}
  {% if v.ports %}<div class="stat"><div class="stat-l">{{ icon('plug') }} Ports</div>
    <div class="stat-v {{ 'v-good' if up_ports == v.ports | length else 'v-danger' }}">{{ up_ports }}<small>/{{ v.ports | length }}</small></div>
    <div class="stat-s">accepting connections</div></div>{% endif %}
  {% if v.soonest %}<div class="stat"><div class="stat-l">{{ icon('check') }} Next certificate expiry</div>
    <div class="stat-v {{ 'v-warn' if v.soonest.cert_days <= v.checks.cert_warn }}">{{ v.soonest.cert_days | int }}<small> days</small></div>
    <div class="stat-s">{{ v.soonest.name }}</div></div>{% endif %}
  {% if m and m.stalwart %}<div class="stat"><div class="stat-l">{{ icon('mail') }} Mail server</div>
    <div class="stat-v {{ 'v-good' if m.stalwart.ok else 'v-danger' }}" style="font-size:1.2rem;margin-top:.55rem">{{ 'Healthy' if m.stalwart.ok else 'Failing' }}</div>
    <div class="stat-s">Stalwart health checks</div></div>{% endif %}
  {% if m and m.listmonk and m.listmonk.watched %}{% set wok = m.listmonk.watched | selectattr('level', 'equalto', 'good') | list | length %}
  <div class="stat"><div class="stat-l">{{ icon('clock') }} Newsletters</div>
    <div class="stat-v {{ 'v-good' if wok == m.listmonk.watched | length else 'v-warn' }}">{{ wok }}<small>/{{ m.listmonk.watched | length }}</small></div>
    <div class="stat-s">sent within {{ v.max_gap_h }}h</div></div>{% endif %}
</div>
""" + NOTES + r"""
{% macro chk_table(rows, kind) %}
<div class="table-wrap">
  <table class="t sortable">
    <thead><tr><th>Name</th><th>Status</th><th class="r">Response</th><th>Last 4 hours</th><th class="r">Up 24h</th><th class="r">Certificate</th></tr></thead>
    <tbody>
    {% for r in rows %}
    <tr>
      <td><span class="dev-name">{{ r.name }}</span>{% if r.group %} <span class="pill pill-muted">{{ r.group }}</span>{% endif %}
          <div class="dev-sub mono">{% if kind == 'site' %}<a href="{{ r.target }}" target="_blank" rel="noopener">{{ r.target.split('://')[1].rstrip('/') }}</a>{% if r.final_url %} → {{ r.final_url.split('://')[1] }}{% endif %}{% else %}{{ r.target }}{% if r.tls and r.tls != 'none' %} · {{ r.tls }}{% endif %}{% endif %}</div></td>
      <td style="white-space:nowrap">{% if r.level == 'pending' %}<span class="muted">checking…</span>{% else %}<span class="status"><i class="dot {{ 'good' if r.ok else ('danger' if r.down else 'warn') }}"></i>{{ ('HTTP ' ~ r.status) if r.ok and r.status else ('Up' if r.ok else ('Down' if r.down else 'Failed once')) }}</span>{% if not r.ok %}<div class="danger" style="font-size:.74rem;white-space:normal">{{ r.error }}</div>{% elif r.since and 600 <= r.since < 86400 %}<div class="dev-sub">up {{ r.since | duration }}</div>{% endif %}{% endif %}</td>
      <td class="r {{ 'warn' if (r.ms or 0) >= v.checks.slow_ms }}" data-v="{{ r.ms or 999999 }}">{{ (r.ms ~ ' ms') if r.ms is not none else '—' }}{% if r.avg_ms %}<div class="dev-sub">avg {{ r.avg_ms }}</div>{% endif %}</td>
      <td>{{ v.spark(r.spark) }}</td>
      <td class="r {{ 'warn' if r.uptime_pct is not none and r.uptime_pct < 99 }}" data-v="{{ r.uptime_pct or 0 }}">{{ (r.uptime_pct ~ '%') if r.uptime_pct is not none else '—' }}</td>
      <td class="r {{ 'danger' if r.cert_days is not none and r.cert_days <= 7 else ('warn' if r.cert_days is not none and r.cert_days <= v.checks.cert_warn) }}" data-v="{{ r.cert_days if r.cert_days is not none else 9999 }}">{{ ((r.cert_days | int) ~ ' days') if r.cert_days is not none else '—' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endmacro %}

{% if v.sites %}
<section class="card" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('globe') }} Websites</div><div class="card-sub">Fetched from this server, following redirects; down after two failed checks in a row</div></div></div>
  {{ chk_table(v.sites, 'site') }}
</section>
{% endif %}

{% if v.ports %}
<section class="card" style="margin-bottom:1rem">
  <div class="card-h"><div><div class="card-t">{{ icon('plug') }} Ports</div><div class="card-sub">TCP connect, plus the TLS handshake and certificate where set</div></div></div>
  {{ chk_table(v.ports, 'port') }}
</section>
{% endif %}

{% if m and m.listmonk %}
{% set lm = m.listmonk %}
<div class="grid">
  <section class="card {{ 'c7' if lm.watched else 'c12' }}">
    <div class="card-h"><div><div class="card-t">{{ icon('mail') }} Recent campaigns</div><div class="card-sub">Listmonk{% if lm.bounces_7d is not none %} · {{ lm.bounces_7d }} bounce{{ 's' if lm.bounces_7d != 1 }} in 7 days{% for t, n in lm.bounce_types | dictsort %} ({{ n }} {{ t }}){% endfor %}{% endif %}</div></div>
      <div class="card-x"><a class="card-link" href="{{ lm.url }}/admin/campaigns" target="_blank" rel="noopener">Open {{ ext() }}</a></div></div>
    {% if lm.error %}<div class="card-b"><div class="danger">{{ lm.error }}</div></div>{% else %}
    <div class="table-wrap"><table class="t">
      <thead><tr><th>Campaign</th><th>Status</th><th class="r">Sent</th><th>When</th></tr></thead>
      <tbody>{% for c in lm.campaigns[:15] %}
      <tr><td><span class="dev-name">{{ c.name }}</span><div class="dev-sub">{{ c.lists | join(', ') }}</div></td>
          <td>{% if c.status == 'finished' %}<span class="status"><i class="dot good"></i>finished</span>{% elif c.status in ('cancelled', 'paused') %}<span class="pill pill-warn">{{ c.status }}</span>{% elif c.status == 'running' %}<span class="pill pill-info">sending</span>{% else %}<span class="muted">{{ c.status }}</span>{% endif %}</td>
          <td class="r {{ 'warn' if c.status == 'finished' and c.to_send and c.sent < c.to_send }}">{{ c.sent }}{% if c.to_send and c.to_send != c.sent %} / {{ c.to_send }}{% endif %}</td>
          <td class="muted" style="white-space:nowrap">{{ (c.started or c.created) | local_time('%a %-d %b %H:%M') }}</td></tr>
      {% endfor %}</tbody>
    </table></div>
    {% endif %}
  </section>
  {% if lm.watched %}
  <section class="card c5">
    <div class="card-h"><div><div class="card-t">{{ icon('clock') }} Newsletters</div><div class="card-sub">Flagged after {{ v.max_gap_h }} hours without a finished send</div></div></div>
    <div class="card-b flush"><table class="t"><tbody>
      {% for w in lm.watched %}
      <tr><td style="width:1%"><i class="dot {{ w.level }}"></i></td>
          <td style="padding-left:0"><span class="dev-name">{{ w.name }}</span><div class="dev-sub">{{ w.subscribers if w.subscribers is not none else '?' }} subscribers</div></td>
          <td class="r" style="white-space:nowrap">{% if w.age is not none %}<span class="{{ 'warn' if w.level != 'good' }}">{{ w.age | duration }} ago</span><div class="dev-sub">{{ w.last.sent }} sent</div>{% elif not w.known %}<span class="danger">list not found</span>{% else %}<span class="muted">never</span>{% endif %}</td></tr>
      {% endfor %}
    </tbody></table></div>
  </section>
  {% endif %}
</div>
{% endif %}
{% endif %}
<style>.notes li.note-danger::before{background:var(--danger-dot)}.notes li.note-info::before{background:var(--info)}
.svc-spark{width:120px;height:22px;display:block}</style>
"""
