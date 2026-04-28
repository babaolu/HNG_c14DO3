"""
dashboard.py — Flask web dashboard served at :8080.
Refreshes every 3 seconds via meta-refresh and /api/metrics JSON endpoint.

Shows: banned IPs, global req/s, top 10 source IPs,
       CPU/memory usage, effective mean/stddev, uptime.
"""
import time
import logging
import psutil
from flask import Flask, jsonify, render_template_string

log = logging.getLogger("dashboard")

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="3">
<title>HNG Anomaly Detection — Live Dashboard</title>
<style>
  :root { --bg:#0f1117; --card:#1a1d27; --accent:#7c3aed;
          --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
          --text:#e2e8f0; --muted:#94a3b8; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text);
         font-family:'Courier New',monospace; font-size:14px; padding:20px; }
  h1 { font-size:20px; color:var(--accent); margin-bottom:16px; letter-spacing:1px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
          gap:16px; margin-bottom:20px; }
  .card { background:var(--card); border-radius:8px; padding:16px;
          border:1px solid #2d3148; }
  .card h2 { font-size:12px; color:var(--muted); margin-bottom:8px;
             text-transform:uppercase; letter-spacing:1px; }
  .val { font-size:28px; font-weight:bold; }
  .val.green { color:var(--green); }
  .val.red   { color:var(--red); }
  .val.amber { color:var(--amber); }
  table { width:100%; border-collapse:collapse; }
  th { color:var(--muted); font-size:11px; text-align:left;
       padding:4px 8px; border-bottom:1px solid #2d3148; }
  td { padding:4px 8px; font-size:13px; }
  tr:hover td { background:#242840; }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px;
           font-size:11px; font-weight:bold; }
  .badge.ban { background:#7f1d1d; color:#fca5a5; }
  .badge.ok  { background:#14532d; color:#86efac; }
  .uptime { color:var(--muted); font-size:12px; margin-top:4px; }
  .ts { color:var(--muted); font-size:11px; margin-bottom:16px; }
</style>
</head>
<body>
<h1>&#9632; HNG Cloud.ng &mdash; Anomaly Detection Engine</h1>
<p class="ts">Last updated: {{ now }} &nbsp;|&nbsp; Auto-refresh: 3s</p>

<div class="grid">
  <div class="card">
    <h2>Global req/s</h2>
    <div class="val {{ 'red' if global_rps > mean * 3 else 'green' }}">
      {{ "%.2f"|format(global_rps) }}
    </div>
    <div class="uptime">
      Baseline mean: {{ "%.4f"|format(mean) }} &nbsp;|&nbsp;
      stddev: {{ "%.4f"|format(stddev) }}
    </div>
  </div>

  <div class="card">
    <h2>Banned IPs</h2>
    <div class="val {{ 'red' if banned_count > 0 else 'green' }}">
      {{ banned_count }}
    </div>
    <div class="uptime">Active iptables DROP rules</div>
  </div>

  <div class="card">
    <h2>System</h2>
    <div style="font-size:16px; margin-top:4px; font-weight:bold;">
      CPU: {{ cpu }}% &nbsp;&nbsp; MEM: {{ mem }}%
    </div>
    <div class="uptime">Uptime: {{ uptime }}</div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>Banned IPs detail</h2>
    <table>
      <tr>
        <th>IP</th>
        <th>Offense</th>
        <th>Condition</th>
        <th>Expires in</th>
      </tr>
      {% for ip, info in banned.items() %}
      <tr>
        <td><span class="badge ban">{{ ip }}</span></td>
        <td>{{ info.offense_count }}</td>
        <td style="font-size:11px; color:#94a3b8;">
          {{ info.condition[:45] }}
        </td>
        <td>
          {% if info.until == -1 %}
            <span style="color:#ef4444">permanent</span>
          {% else %}
            {{ [0, (info.until | int) - (now_ts | int)] | max }}s
          {% endif %}
        </td>
      </tr>
      {% else %}
      <tr>
        <td colspan="4" style="color:var(--muted); padding:12px 8px;">
          No banned IPs
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Top 10 source IPs (last 60s)</h2>
    <table>
      <tr><th>IP</th><th>Req/s</th><th>Status</th></tr>
      {% for ip, count in top_ips.items() %}
      <tr>
        <td>{{ ip }}</td>
        <td>{{ "%.2f"|format(count / 60.0) }}</td>
        <td>
          {% if ip in banned %}
            <span class="badge ban">BANNED</span>
          {% else %}
            <span class="badge ok">OK</span>
          {% endif %}
        </td>
      </tr>
      {% else %}
      <tr>
        <td colspan="3" style="color:var(--muted); padding:12px 8px;">
          No traffic yet
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
</div>
</body>
</html>"""


def run_dashboard(cfg, state, baseline):
    app = Flask(__name__)
    port = cfg["dashboard"]["port"]
    start_time = state["start_time"]

    def _uptime():
        secs = int(time.time() - start_time)
        h, r = divmod(secs, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    @app.route("/")
    def index():
        return render_template_string(
            _HTML,
            now=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            now_ts=time.time(),
            global_rps=state.get("global_rps", 0.0),
            mean=baseline.effective_mean,
            stddev=baseline.effective_stddev,
            banned=state.get("banned", {}),
            banned_count=len(state.get("banned", {})),
            top_ips=state.get("top_ips", {}),
            cpu=psutil.cpu_percent(interval=None),
            mem=psutil.virtual_memory().percent,
            uptime=_uptime(),
        )

    @app.route("/api/metrics")
    def metrics():
        return jsonify({
            "global_rps": state.get("global_rps", 0.0),
            "baseline_mean": baseline.effective_mean,
            "baseline_stddev": baseline.effective_stddev,
            "banned": {
                ip: {k: v for k, v in info.items()}
                for ip, info in state.get("banned", {}).items()
            },
            "top_ips": state.get("top_ips", {}),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": psutil.virtual_memory().percent,
            "uptime_seconds": int(time.time() - start_time),
        })

    log.info(f"Dashboard starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
