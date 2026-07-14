"""
Session Recorder (spec Component 13).

Pulls everything from Telemetry for a session and produces:
  reports/<session_id>.json  — full structured timeline + threat intel
  reports/<session_id>.html  — human-readable analyst report with dark theme
"""
import json
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Session Report — {session_id}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
    background: #0d1117; color: #c9d1d9;
    margin: 0; padding: 2rem;
  }}
  h1 {{ color: #58a6ff; font-size: 1.4rem; margin-bottom: 0.3rem; }}
  h2 {{ color: #79c0ff; font-size: 1.05rem; margin: 1.6rem 0 0.5rem; border-bottom: 1px solid #30363d; padding-bottom: 4px; }}
  .meta {{ color: #8b949e; font-size: 0.82rem; margin-bottom: 1.5rem; }}
  .score-badge {{
    display: inline-block; padding: 3px 12px; border-radius: 20px;
    font-weight: 600; font-size: 0.88rem;
  }}
  .high {{ background: #f85149; color: #fff; }}
  .medium {{ background: #d29922; color: #fff; }}
  .low {{ background: #238636; color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.2rem; font-size: 0.82rem; }}
  th {{ background: #161b22; color: #8b949e; text-align: left;
       padding: 6px 10px; border-bottom: 2px solid #30363d; }}
  td {{ padding: 5px 10px; border-bottom: 1px solid #21262d; vertical-align: top; word-break: break-word; }}
  tr:hover td {{ background: #161b22; }}
  .tag {{
    display: inline-block; padding: 1px 7px; border-radius: 4px;
    font-size: 0.75rem; font-weight: 600; margin: 1px;
  }}
  .tag-red   {{ background: #3d1f1f; color: #f85149; border: 1px solid #f8514930; }}
  .tag-amber {{ background: #2d2208; color: #d29922; border: 1px solid #d2992230; }}
  .tag-blue  {{ background: #0d2340; color: #58a6ff; border: 1px solid #58a6ff30; }}
  .mitre {{ font-family: monospace; font-size: 0.78rem; color: #8b949e; }}
  .event-nav      {{ color: #58a6ff; }}
  .event-threat   {{ color: #f85149; font-weight: 600; }}
  .event-decoy    {{ color: #d29922; font-weight: 600; }}
  .event-honeytoken {{ color: #f0883e; font-weight: 600; }}
  .event-screenshot {{ color: #3fb950; }}
  summary {{ cursor: pointer; color: #8b949e; font-size: 0.8rem; }}
</style>
</head>
<body>

<h1>Deception Platform &mdash; Session Report</h1>
<div class="meta">
  Session ID: <code>{session_id}</code> &nbsp;|&nbsp;
  Persona: <strong>{employee_name}</strong> ({department}) &nbsp;|&nbsp;
  UA: <code>{ua_short}</code>
</div>

<h2>Threat Summary</h2>
<p>
  Score: <span class="score-badge {score_class}">{score} / ∞</span>
  &nbsp;&nbsp;
  Decision: <span class="score-badge {decision_class}">{decision}</span>
</p>

{cluster_summary}

<table>
  <tr><th>Finding</th><th>MITRE Technique</th><th>Weight</th><th>Detail</th></tr>
  {findings_rows}
</table>

<h2>Attack Timeline</h2>
<table>
  <tr><th style="width:90px">Time (s)</th><th style="width:160px">Event</th><th>Data</th></tr>
  {timeline_rows}
</table>

<h2>Screenshots taken</h2>
<p style="color:#8b949e; font-size:0.82rem">{screenshot_list}</p>

<h2>Raw JSON</h2>
<details>
  <summary>Expand full JSON report</summary>
  <pre style="font-size:0.75rem; color:#8b949e; overflow-x:auto">{raw_json}</pre>
</details>

</body>
</html>"""


def _score_class(score):
    if score >= 60: return "high"
    if score >= 30: return "medium"
    return "low"


def _event_class(event_type):
    if "threat" in event_type: return "event-threat"
    if "decoy" in event_type:  return "event-decoy"
    if "honeytoken" in event_type: return "event-honeytoken"
    if "navigation" in event_type: return "event-nav"
    if "screenshot" in event_type: return "event-screenshot"
    return ""


def build_report(session_id: str, telemetry, threat_summary: dict, decision: dict, report_prefix: str = ""):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    events = telemetry.all_events()

    persona_meta = {}
    for e in events:
        if e["event_type"] == "session_start":
            persona_meta = e["data"]
            break

    report = {
        "session_id":     session_id,
        "persona":        persona_meta,
        "threat_summary": threat_summary,
        "decision":       decision,
        "event_count":    len(events),
        "timeline":       events,
    }

    file_base = f"{report_prefix}__{session_id}" if report_prefix else session_id
    json_path = REPORTS_DIR / f"{file_base}.json"
    json_str  = json.dumps(report, indent=2, default=str)
    json_path.write_text(json_str, encoding="utf-8")

    # ── findings table — clusters shown in amber, raw signals in red ──
    findings = threat_summary.get("findings", [])
    clusters = threat_summary.get("clusters", [])

    if findings:
        findings_rows = ""
        for f in findings:
            is_cluster = f["label"].startswith("[CLUSTER]")
            tag_cls    = "tag-amber" if is_cluster else "tag-red"
            findings_rows += (
                f"<tr>"
                f"<td><span class='tag {tag_cls}'>{f['label']}</span></td>"
                f"<td class='mitre'>{f['mitre']}</td>"
                f"<td>{f['weight']}</td>"
                f"<td style='color:#8b949e'>{f['detail'][:140]}</td>"
                f"</tr>"
            )
    else:
        findings_rows = "<tr><td colspan='4' style='color:#8b949e'>No findings — benign session</td></tr>"

    cluster_summary = ""
    if clusters:
        cluster_summary = (
            "<h2>Attack Clusters Fired</h2>"
            "<p style='font-size:0.82rem;color:#d29922'>"
            + " &nbsp;&bull;&nbsp; ".join(
                f"<span class='tag tag-amber'>{c}</span>" for c in clusters)
            + "</p>"
            "<p style='font-size:0.8rem;color:#8b949e'>"
            "These cluster matches are the primary diversion signal — each requires "
            "multiple correlated indicators to fire, eliminating single-signal false positives."
            "</p>"
        )

    t0 = events[0]["ts"] if events else 0
    shots = []
    timeline_rows = ""
    for e in events:
        rel_t = f"{e['ts'] - t0:.2f}"
        cls   = _event_class(e["event_type"])
        data  = json.dumps(e["data"], default=str)[:240]
        timeline_rows += (
            f"<tr>"
            f"<td>{rel_t}</td>"
            f"<td class='{cls}'>{e['event_type']}</td>"
            f"<td style='font-family:monospace;font-size:0.75rem'>{data}</td>"
            f"</tr>\n"
        )
        if e["event_type"] == "screenshot":
            shots.append(e["data"].get("path", ""))

    screenshot_list = " &nbsp;|&nbsp; ".join(
        f"<code>{p}</code>" for p in shots) or "none"

    d_action = decision.get("action", "unknown")
    d_class  = "high" if "decoy" in d_action else "low"
    score    = threat_summary.get("score", 0)

    html = HTML_TEMPLATE.format(
        session_id      = session_id,
        employee_name   = persona_meta.get("employee_name", "unknown"),
        department      = persona_meta.get("department", "unknown"),
        ua_short        = persona_meta.get("user_agent", "")[:60],
        score           = score,
        score_class     = _score_class(score),
        decision        = d_action,
        decision_class  = d_class,
        findings_rows   = findings_rows,
        cluster_summary = cluster_summary,
        timeline_rows   = timeline_rows,
        screenshot_list = screenshot_list,
        raw_json        = json_str[:8000],
    )

    html_path = REPORTS_DIR / f"{file_base}.html"
    html_path.write_text(html, encoding="utf-8")

    return json_path, html_path
