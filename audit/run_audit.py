#!/usr/bin/env python3
import hashlib, hmac, html, json, math, os, platform, re, socket, struct, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

REPORTS_DIR       = Path(os.getenv("AUDIT_REPORTS_DIR", "/reports"))
TARGET_HOST       = os.getenv("AUDIT_TARGET_HOST", "generator")
TARGET_TCP_PORT   = int(os.getenv("AUDIT_TARGET_TCP_PORT", "1420"))
TARGET_PREMIX_PORT = int(os.getenv("AUDIT_TARGET_PREMIX_PORT", "1421"))
TARGET_HTTP_URL   = os.getenv("AUDIT_TARGET_HTTP_URL", "http://generator:8080")
SAMPLE_SIZE       = int(os.getenv("AUDIT_SAMPLE_SIZE", str(20 * 1024 * 1024)))
PREMIX_SIZE       = int(os.getenv("AUDIT_PREMIX_SIZE", str(8 * 1024 * 1024)))
RNGTEST_BLOCKS    = int(os.getenv("AUDIT_RNGTEST_BLOCKS", "1000"))
CHAIN_SECRET      = os.getenv("AUDIT_CHAIN_SECRET", "")
DIEHARDER_TESTS   = [x.strip() for x in os.getenv("AUDIT_DIEHARDER_TESTS", "0,1,2,8,15,100").split(",") if x.strip()]
SHA512_ROUNDS     = int(os.getenv("AUDIT_SHA512_ROUNDS", "32"))
SOCKET_TIMEOUT    = float(os.getenv("AUDIT_SOCKET_TIMEOUT_SEC", "5"))
MAX_SESSIONS      = int(os.getenv("AUDIT_MAX_TCP_SESSIONS", "1024"))
PRACTRAND_ENABLED = os.getenv("AUDIT_PRACTRAND", "0") == "1"
PRACTRAND_TLMAX   = os.getenv("AUDIT_PRACTRAND_TLMAX", "256M")
PRACTRAND_MAX_BYTES = int(os.getenv("AUDIT_PRACTRAND_MAX_BYTES", str(32 * 1024 * 1024)))
THROUGHPUT_WARN   = float(os.getenv("AUDIT_THROUGHPUT_WARN_MIB", "0.5"))

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
CHAIN_PATH  = REPORTS_DIR / "chain.jsonl"
INDEX_PATH  = REPORTS_DIR / "index.html"
LATEST_PATH = REPORTS_DIR / "latest.json"

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_json(url):
    with urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())

# ---------------------------------------------------------------------------
# TCP sample fetch
# ---------------------------------------------------------------------------

def fetch_sample_via_tcp(target_bytes, port=None):
    chunks, total, sessions = [], 0, 0
    started = time.perf_counter()
    while total < target_bytes and sessions < MAX_SESSIONS:
        sessions += 1
        with socket.create_connection((TARGET_HOST, port or TARGET_TCP_PORT), timeout=SOCKET_TIMEOUT) as s:
            s.settimeout(SOCKET_TIMEOUT)
            part = bytearray()
            while True:
                try:
                    d = s.recv(65536)
                except socket.timeout:
                    break
                if not d:
                    break
                part.extend(d)
        if not part or part == b"Warming up...\n":
            if part == b"Warming up...\n":
                time.sleep(1.0)
            continue
        chunks.append(bytes(part))
        total += len(part)
    dur = max(time.perf_counter() - started, 1e-6)
    sample = b"".join(chunks)[:target_bytes]
    return {"bytes": len(sample), "duration_sec": round(dur, 3), "sessions": sessions,
            "throughput_mib_s": round((len(sample) / dur) / (1024*1024), 3), "data": sample}

# ---------------------------------------------------------------------------
# External tool helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd, stdin_bytes=None):
    t0 = time.perf_counter()
    r = subprocess.run(cmd, input=stdin_bytes, capture_output=True, check=False)
    return {"command": cmd, "returncode": r.returncode, "duration_sec": round(time.perf_counter()-t0, 3),
            "stdout": r.stdout.decode("utf-8", errors="replace"),
            "stderr": r.stderr.decode("utf-8", errors="replace")}

def parse_ent(stdout):
    res = {"entropy_bits_per_byte": None, "chi_square": None, "pi_error_pct": None, "serial_correlation": None}
    for line in stdout.splitlines():
        if "Entropy =" in line:
            m = re.search(r"Entropy =\s*([0-9.]+)", line)
            if m: res["entropy_bits_per_byte"] = float(m.group(1))
        elif "Chi square distribution" in line:
            m = re.search(r"is\s*([0-9.]+)", line)
            if m: res["chi_square"] = float(m.group(1))
        elif "Monte Carlo value for Pi" in line:
            m = re.search(r"error\s*([0-9.]+)\s*percent", line)
            if m: res["pi_error_pct"] = float(m.group(1))
        elif "Serial correlation coefficient" in line:
            m = re.search(r"coefficient is\s*([-0-9.e]+)", line)
            if m: res["serial_correlation"] = float(m.group(1))
    return res

def parse_rngtest(out, err):
    text = out + "\n" + err
    succ = fail = None
    for line in text.splitlines():
        if "successes" in line and "failures" in line:
            ms = re.search(r"successes:\s*(\d+)", line)
            mf = re.search(r"failures:\s*(\d+)", line)
            if ms: succ = int(ms.group(1))
            if mf: fail = int(mf.group(1))
    return {"successes": succ, "failures": fail}

def summarize_dieharder(stdout):
    return [l.strip() for l in stdout.splitlines() if any(m in l for m in ("PASSED","FAILED","WEAK"))]

# ---------------------------------------------------------------------------
# Pre-mix statistics (byte-level, no external tools)
# ---------------------------------------------------------------------------

def premix_stats(data: bytes):
    n = len(data)
    if n == 0:
        return None
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    # Shannon entropy
    entropy = -sum((c/n) * math.log2(c/n) for c in counts if c > 0)
    byte_mean = sum(i * counts[i] for i in range(256)) / n
    bits_set = sum(bin(b).count("1") for b in data)
    bit_balance = bits_set / (n * 8)
    # chi-square
    expected = n / 256
    chi_sq = sum((c - expected)**2 / expected for c in counts)
    # serial correlation
    if n > 1:
        mean = byte_mean
        num = sum((data[i] - mean)*(data[i+1] - mean) for i in range(n-1))
        den = sum((b - mean)**2 for b in data)
        sc = num / den if den != 0 else 0.0
    else:
        sc = 0.0
    return {
        "bytes": n,
        "entropy_bits_per_byte": round(entropy, 6),
        "chi_square": round(chi_sq, 3),
        "serial_correlation": round(sc, 6),
        "byte_mean": round(byte_mean, 4),
        "bit_balance": round(bit_balance, 6),
    }

# ---------------------------------------------------------------------------
# Node health
# ---------------------------------------------------------------------------

def evaluate_nodes(sources):
    nodes = []
    now = time.time()
    for item in sources:
        node_id = item.get("node") or item.get("node_id") or "unknown"
        last_seen = item.get("last_seen") or item.get("last_seen_ts")
        age = round(now - last_seen, 1) if isinstance(last_seen, (int, float)) else None
        bps = item.get("avg_bytes_per_sec") or item.get("throughput_bps") or 0
        packets = item.get("packets", 0)
        accepting_samples = item.get("accepting_samples", True)
        source_audit_status = item.get("source_audit_status")
        repeat_score = item.get("source_audit_repeat_score")
        if age is not None and age > 120:
            health = "FAIL"
        elif not accepting_samples:
            health = "WARN"
        elif source_audit_status in ("WARN", "STALE"):
            health = "WARN"
        elif age is not None and age > 30:
            health = "WARN"
        elif bps < 100:
            health = "WARN"
        else:
            health = "OK"
        nodes.append({"node_id": node_id, "last_seen_age_sec": age,
                      "avg_bytes_per_sec": bps, "packets": packets, "health": health,
                      "accepting_samples": accepting_samples,
                      "source_audit_status": source_audit_status,
                      "source_audit_repeat_score": repeat_score})
    return nodes

# ---------------------------------------------------------------------------
# Verdict (3-dimensional)
# ---------------------------------------------------------------------------

def build_verdict(ent_parsed, rng_parsed, dieharder_lines, node_health, premix):
    alerts = []

    # output_quality
    eb = ent_parsed.get("entropy_bits_per_byte")
    dh_fail = any("FAILED" in l for l in dieharder_lines)
    dh_weak = any("WEAK" in l for l in dieharder_lines)
    rf = rng_parsed.get("failures")

    if eb is None:
        oq = "FAIL"; alerts.append("ENT could not compute entropy — sample may be malformed.")
    elif eb > 7.999 and (rf == 0 or rf is None) and not dh_fail:
        oq = "GOOD" if not dh_weak else "WARN"
    elif eb > 7.99 and not dh_fail:
        oq = "WARN"
    else:
        oq = "FAIL"; alerts.append("Statistical tests indicate non-random output.")

    # source_health
    if not node_health:
        sh = "WARN"; alerts.append("No node health data available.")
    else:
        fail_nodes = [n for n in node_health if n["health"] == "FAIL"]
        warn_nodes = [n for n in node_health if n["health"] == "WARN"]
        if fail_nodes:
            sh = "FAIL"; alerts.append(f"{len(fail_nodes)} node(s) in FAIL state.")
        elif len(node_health) == 1:
            sh = "WARN"; alerts.append("Only 1 SDR node contributing — single point of failure.")
        elif warn_nodes:
            sh = "WARN"
        else:
            sh = "GOOD"

    # audit_confidence
    if premix is None:
        alerts.append("Pre-mix sample unavailable — source quality cannot be evaluated independently.")
        ac = "WARN"
    else:
        pe = premix.get("entropy_bits_per_byte", 0)
        if pe < 6.0:
            alerts.append(f"Pre-mix entropy low ({pe:.3f} bits/byte) — physical source may be degraded.")
            ac = "WARN"
        else:
            ac = "GOOD"

    if oq == "GOOD" and sh in ("WARN","FAIL"):
        alerts.append("Tests OK, but source health issues detected — output quality not fully confirmed.")

    return {
        "output_quality": oq,
        "source_health": sh,
        "audit_confidence": ac,
        "alerts": alerts,
        "note": ("Final output is tested after cryptographic conditioning. "
                 "Source quality is evaluated separately using pre-conditioning samples "
                 "and node health metrics.")
    }

# ---------------------------------------------------------------------------
# SHA-512 benchmark
# ---------------------------------------------------------------------------

def bench_sha512(data, rounds):
    t0 = time.perf_counter()
    d = None
    for _ in range(max(1, rounds)):
        d = hashlib.sha512(data).hexdigest()
    dur = max(time.perf_counter()-t0, 1e-6)
    tb = len(data) * max(1, rounds)
    return {"rounds": rounds, "duration_sec": round(dur,3),
            "throughput_mib_s": round((tb/dur)/(1024*1024),3), "last_digest": d}

# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

def sys_snapshot():
    cpu_model, mem_kib = "unknown", None
    for p, key in [("/proc/cpuinfo","model name"), ("/proc/meminfo","MemTotal")]:
        pp = Path(p)
        if pp.exists():
            for line in pp.read_text(errors="replace").splitlines():
                if line.lower().startswith(key.lower()):
                    if "cpuinfo" in p:
                        cpu_model = line.split(":",1)[1].strip()
                    else:
                        mem_kib = int(line.split()[1])
                    break
    return {"hostname": platform.node(), "platform": platform.platform(),
            "python": platform.python_version(), "cpu_count": os.cpu_count(),
            "cpu_model": cpu_model, "mem_total_kib": mem_kib}

# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

def read_prev_hash():
    if not CHAIN_PATH.exists(): return None
    last = None
    for line in CHAIN_PATH.read_text(errors="replace").splitlines():
        line = line.strip()
        if line: last = line
    if not last: return None
    try: return json.loads(last).get("chain_hash")
    except: return None


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def _badge(val):
    color = {"GOOD":"#22c55e","WARN":"#f59e0b","FAIL":"#ef4444"}.get(val,"#64748b")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em">{html.escape(val)}</span>'

def render_html(report):
    v = report["verdict"]
    alerts_html = "".join(f'<li style="color:#f59e0b">⚠ {html.escape(a)}</li>' for a in v.get("alerts",[]))
    alerts_block = f'<ul style="margin:8px 0;padding-left:20px">{alerts_html}</ul>' if alerts_html else '<p style="color:#22c55e">No alerts.</p>'

    # node health table
    node_rows = ""
    for n in report.get("node_health",[]):
        hc = {"OK":"#22c55e","WARN":"#f59e0b","FAIL":"#ef4444"}.get(n["health"],"#64748b")
        node_rows += (f'<tr><td>{html.escape(str(n["node_id"]))}</td>'
                      f'<td>{n.get("last_seen_age_sec","?")}</td>'
                      f'<td>{n.get("avg_bytes_per_sec","?")}</td>'
                      f'<td>{n.get("packets","?")}</td>'
                      f'<td>{html.escape(str(n.get("source_audit_status","?")))}</td>'
                      f'<td>{html.escape(str(n.get("source_audit_repeat_score","?")))}</td>'
                      f'<td style="color:{hc};font-weight:bold">{n["health"]}</td></tr>')
    if not node_rows:
        node_rows = '<tr><td colspan="7">No node data</td></tr>'

    source_audits = report.get("source_audits", [])
    source_audit_rows = ""
    for item in source_audits:
        accepting = "yes" if item.get("accepting_samples", True) else "no"
        source_audit_rows += (
            f'<tr><td>{html.escape(str(item.get("node","unknown")))}</td>'
            f'<td>{html.escape(str(item.get("status","?")))}</td>'
            f'<td>{html.escape(str(item.get("repeat_score","?")))}</td>'
            f'<td>{html.escape(str(item.get("spectral_flatness","?")))}</td>'
            f'<td>{html.escape(str(item.get("dominant_value_ratio","?")))}</td>'
            f'<td>{html.escape(str(item.get("consecutive_equal_ratio","?")))}</td>'
            f'<td>{html.escape(accepting)}</td></tr>'
        )
    if not source_audit_rows:
        source_audit_rows = '<tr><td colspan="7">No source audit data</td></tr>'

    # premix stats
    pm = report.get("premix_stats")
    if pm:
        pm_html = f"""<div class="card">
        <h2>Pre-mix sample <span class="stage-badge">pre-mix</span></h2>
        <p class="muted">Stage: after extractor, before SHA-512 conditioning ({pm['bytes']//1024} KiB sample)</p>
        <table><tbody>
        <tr><td>Entropy bits/byte</td><td><code>{pm['entropy_bits_per_byte']}</code></td></tr>
        <tr><td>Chi-square</td><td><code>{pm['chi_square']}</code></td></tr>
        <tr><td>Serial correlation</td><td><code>{pm['serial_correlation']}</code></td></tr>
        <tr><td>Byte mean</td><td><code>{pm['byte_mean']}</code> (ideal≈127.5)</td></tr>
        <tr><td>Bit balance</td><td><code>{pm['bit_balance']}</code> (ideal≈0.5)</td></tr>
        </tbody></table></div>"""
    else:
        pm_html = '<div class="card" style="border-color:#f59e0b"><h2>Pre-mix sample</h2><p style="color:#f59e0b">⚠ Pre-mix data not available from this endpoint.</p></div>'

    dh_items = "".join(f'<li><code>{html.escape(l)}</code></li>' for l in report["tests"]["dieharder"]["interesting_lines"]) or "<li>No PASSED/WEAK/FAILED lines</li>"

    pr_block = ""
    if "practrand" in report["tests"]:
        pr = report["tests"]["practrand"]
        pr_block = f"""<section class="card">
        <h2>PractRand</h2>
        <pre>{html.escape(pr.get("stdout","")[:2000])}</pre>
        </section>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Audit report {html.escape(report['timestamp'])}</title>
  <style>
    body{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#081018;color:#dbe8f7;margin:0;padding:32px;line-height:1.6}}
    h1,h2{{color:#fff}}h2{{font-size:1em;margin-bottom:6px}}
    a{{color:#85d9ff}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin:24px 0}}
    .card{{border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.03);padding:16px;border-radius:6px}}
    code,pre{{color:#ffe28a;white-space:pre-wrap;word-break:break-word}}
    table{{width:100%;border-collapse:collapse;margin-top:8px}}
    th,td{{border-bottom:1px solid rgba(255,255,255,0.1);padding:8px 6px;text-align:left;vertical-align:top}}
    .muted{{color:#9bb0c5;font-size:0.9em}}
    .stage-badge{{background:#1e3a5f;color:#85d9ff;padding:2px 7px;border-radius:4px;font-size:0.8em;margin-left:6px}}
    .note-box{{border:1px solid #334155;background:#0f1e2e;padding:14px;border-radius:6px;color:#94a3b8;font-size:0.9em;margin:16px 0}}
  </style>
</head>
<body>
  <p><a href="./index.html">← Report index</a></p>
  <h1>Cryptographic entropy audit report</h1>
  <p class="muted">Date: {html.escape(report['timestamp'])} | Source: <code>{html.escape(report['sample']['source'])}</code></p>
  <div class="note-box">ℹ {html.escape(v['note'])}</div>

  <div class="grid">
    <section class="card">
      <h2>Verdict</h2>
      <table><tbody>
      <tr><td>Output quality</td><td>{_badge(v['output_quality'])}</td></tr>
      <tr><td>Source health</td><td>{_badge(v['source_health'])}</td></tr>
      <tr><td>Audit confidence</td><td>{_badge(v['audit_confidence'])}</td></tr>
      </tbody></table>
      <p style="margin-top:10px;font-size:0.9em">Stage tested: <span class="stage-badge">final</span> (post SHA-512)</p>
    </section>
    <section class="card">
      <h2>Alerts</h2>
      {alerts_block}
    </section>
    <section class="card">
      <h2>Integrity chain</h2>
      <p>Prev hash: <code>{html.escape(str(report['integrity']['prev_chain_hash']))[:24]}…</code></p>
      <p>Report SHA-256: <code>{html.escape(report['integrity']['report_sha256'])[:24]}…</code></p>
      <p>Chain hash: <code>{html.escape(report['integrity']['chain_hash'])}</code></p>
      <p>HMAC: <code>{html.escape(str(report['integrity'].get('chain_hmac','none')))}</code></p>
    </section>
    <section class="card">
      <h2>Performance</h2>
      <p>Download: <code>{report['sample']['throughput_mib_s']} MiB/s</code></p>
      <p>TCP sessions: <code>{report['sample']['sessions']}</code></p>
      <p>SHA-512 bench: <code>{report['benchmarks']['sha512']['throughput_mib_s']} MiB/s</code></p>
      <p>ENT / RNGtest / Dieharder: <code>{report['tests']['ent']['duration_sec']}s / {report['tests']['rngtest']['duration_sec']}s / {report['tests']['dieharder']['duration_sec']}s</code></p>
    </section>
  </div>

  <h2>Data pipeline stages</h2>
  <div class="grid">
    <div class="card">
      <h2>Stage 1 – raw/input <span class="stage-badge">SDR</span></h2>
      <p class="muted">Physical RF noise captured by SDR nodes before any processing.</p>
      <p>Node count: <code>{len(report.get('node_health',[]))}</code></p>
    </div>
    <div class="card">
      <h2>Stage 2 – pre-mix <span class="stage-badge">pre-mix</span></h2>
      <p class="muted">After extractor / XOR-fold, before SHA-512 conditioning. Evaluated below.</p>
    </div>
    <div class="card">
      <h2>Stage 3 – final output <span class="stage-badge">final</span></h2>
      <p class="muted">After SHA-512 conditioning. This is what ENT / RNGtest / Dieharder test.</p>
      <p>Sample: <code>{report['sample']['bytes']//1024} KiB</code> | SHA-256: <code>{report['sample']['sha256'][:16]}…</code></p>
    </div>
  </div>

  <div class="grid">
    {pm_html}
  </div>

  <h2>Test statistics — final output <span class="stage-badge">final</span></h2>
  <div class="grid">
    <section class="card">
      <h2>ENT</h2>
      <pre>{html.escape(json.dumps(report['tests']['ent']['parsed'],indent=2))}</pre>
    </section>
    <section class="card">
      <h2>RNGtest (FIPS 140-2)</h2>
      <pre>{html.escape(json.dumps(report['tests']['rngtest']['parsed'],indent=2))}</pre>
    </section>
    <section class="card">
      <h2>Dieharder</h2>
      <p class="muted">Tests: {html.escape(", ".join(report['tests']['dieharder'].get('test_ids',[])))}</p>
      <ul>{dh_items}</ul>
    </section>
    {pr_block}
  </div>

  <h2>Node health — source <span class="stage-badge">SDR</span></h2>
  <table>
    <thead><tr><th>Node ID</th><th>Last seen (s ago)</th><th>Avg B/s</th><th>Packets</th><th>Source audit</th><th>Repeat score</th><th>Health</th></tr></thead>
    <tbody>{node_rows}</tbody>
  </table>

  <h2>Latest source audits — raw/input <span class="stage-badge">SDR</span></h2>
  <table>
    <thead><tr><th>Node ID</th><th>Status</th><th>Repeat score</th><th>Spectral flatness</th><th>Dominant value ratio</th><th>Consecutive equal ratio</th><th>Accepting samples</th></tr></thead>
    <tbody>{source_audit_rows}</tbody>
  </table>

  <h2>Generator parameters</h2>
  <pre>{html.escape(json.dumps(report['healthz'],indent=2,ensure_ascii=False))}</pre>

  <h2>Audit environment</h2>
  <pre>{html.escape(json.dumps(report['environment'],indent=2,ensure_ascii=False))}</pre>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------

def write_index(entries):
    rows = ""
    for e in sorted(entries, key=lambda x: x["timestamp"], reverse=True):
        v = e.get("verdict", {})
        oq = v.get("output_quality", v.get("label","?"))
        sh = v.get("source_health","?")
        ac = v.get("audit_confidence","?")
        rows += (f'<tr><td>{html.escape(e["timestamp"])}</td>'
                 f'<td><a href="{html.escape(e["html_file"])}">HTML</a></td>'
                 f'<td><a href="{html.escape(e["json_file"])}">JSON</a></td>'
                 f'<td><code>{html.escape(oq)}</code></td>'
                 f'<td><code>{html.escape(sh)}</code></td>'
                 f'<td><code>{html.escape(ac)}</code></td>'
                 f'<td><code>{html.escape(e["chain_hash"][:20])}…</code></td></tr>')
    INDEX_PATH.write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entropy audit reports</title>
<style>body{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#0a0f14;color:#d7e3f4;margin:0;padding:32px}}
h1{{margin-top:0}}a{{color:#8de1ff}}table{{width:100%;border-collapse:collapse;margin-top:24px}}
th,td{{border-bottom:1px solid rgba(255,255,255,0.12);padding:10px 8px;text-align:left;vertical-align:top}}
code{{color:#ffe28a}}.meta{{color:#9fb2c7;max-width:72ch}}</style></head>
<body><h1>Cryptographic audit reports</h1>
<p class="meta">Reports are generated periodically. Each entry is chained via SHA-256. See <a href="chain.jsonl">chain.jsonl</a>.</p>
<table><thead><tr><th>Date</th><th>HTML</th><th>JSON</th><th>Output Quality</th><th>Source Health</th><th>Audit Confidence</th><th>Chain hash</th></tr></thead>
<tbody>{''.join([rows]) if rows else '<tr><td colspan="7">No reports yet</td></tr>'}</tbody></table>
</body></html>""", encoding="utf-8")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    timestamp = datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat()
    slug = timestamp.replace(":", "-")
    alerts_early = []

    # fetch healthz / sources
    healthz = http_json(f"{TARGET_HTTP_URL}/healthz")
    sources_raw = []
    try:
        sources_raw = http_json(f"{TARGET_HTTP_URL}/sources")
    except Exception as e:
        alerts_early.append(f"Could not fetch /sources: {e}")
    source_audits = []
    try:
        source_audits = http_json(f"{TARGET_HTTP_URL}/source-audits")
    except Exception as e:
        alerts_early.append(f"Could not fetch /source-audits: {e}")

    node_health = evaluate_nodes(sources_raw)
    if len(node_health) == 1:
        alerts_early.append("Only 1 SDR node contributing — single point of failure.")
    if any(not item.get("accepting_samples", True) for item in source_audits):
        alerts_early.append("One or more SDR nodes are currently blocked by the raw source audit repeat threshold.")

    # fetch final sample (post SHA-512) — stage 3
    sample = fetch_sample_via_tcp(SAMPLE_SIZE, port=TARGET_TCP_PORT)
    if sample["bytes"] <= 0:
        raise RuntimeError("Failed to fetch sample from TCP 1420.")
    if sample["throughput_mib_s"] < THROUGHPUT_WARN:
        alerts_early.append(f"Throughput {sample['throughput_mib_s']} MiB/s below warning threshold {THROUGHPUT_WARN} MiB/s.")

    sample_sha256 = hashlib.sha256(sample["data"]).hexdigest()

    # fetch pre-mix sample — stage 2
    premix_data = None
    try:
        pm_sample = fetch_sample_via_tcp(PREMIX_SIZE, port=TARGET_PREMIX_PORT)
        if pm_sample["bytes"] > 0:
            premix_data = pm_sample["data"]
    except Exception as e:
        alerts_early.append(f"Pre-mix sample fetch failed: {e}")

    pm_stats = premix_stats(premix_data) if premix_data else None
    if pm_stats is None:
        alerts_early.append("Pre-mix sample unavailable — source quality cannot be evaluated independently.")

    with tempfile.NamedTemporaryFile(prefix="audit-final-", suffix=".bin", delete=False) as tmp:
        tmp.write(sample["data"])
        sample_path = Path(tmp.name)

    try:
        ent_r   = run_cmd(["ent", str(sample_path)])
        rng_r   = run_cmd(["rngtest", "-c", str(RNGTEST_BLOCKS)], stdin_bytes=sample["data"])

        dh_raw, dh_dur, dh_rc = [], 0.0, 0
        for tid in DIEHARDER_TESTS:
            r = run_cmd(["dieharder", "-g", "201", "-f", str(sample_path), "-d", tid])
            dh_raw.append({"test_id": tid, "returncode": r["returncode"],
                           "stdout": r["stdout"], "stderr": r["stderr"], "duration_sec": r["duration_sec"]})
            dh_dur += r["duration_sec"]
            dh_rc = max(dh_rc, r["returncode"])

        pr_result = None
        if PRACTRAND_ENABLED:
            pr_input = sample["data"][:min(len(sample["data"]), max(1, PRACTRAND_MAX_BYTES))]
            try:
                pr_result = run_cmd(["RNG_test", "stdin", "-tlmax", PRACTRAND_TLMAX], stdin_bytes=pr_input)
            except FileNotFoundError:
                alerts_early.append("PractRand enabled, but RNG_test binary is not installed in the audit environment.")

    finally:
        sample_path.unlink(missing_ok=True)

    sha512_bench = bench_sha512(sample["data"], SHA512_ROUNDS)
    ent_parsed = parse_ent(ent_r["stdout"])
    rng_parsed = parse_rngtest(rng_r["stdout"], rng_r["stderr"])
    dh_lines = []
    for item in dh_raw:
        dh_lines.extend(summarize_dieharder(item["stdout"]))

    verdict = build_verdict(ent_parsed, rng_parsed, dh_lines, node_health, pm_stats)
    verdict["alerts"] = alerts_early + verdict["alerts"]

    tests = {
        "ent":       {"duration_sec": ent_r["duration_sec"], "returncode": ent_r["returncode"],
                      "parsed": ent_parsed, "stdout": ent_r["stdout"], "stderr": ent_r["stderr"],
                      "stage": "final"},
        "rngtest":   {"duration_sec": rng_r["duration_sec"], "returncode": rng_r["returncode"],
                      "parsed": rng_parsed, "stdout": rng_r["stdout"], "stderr": rng_r["stderr"],
                      "stage": "final"},
        "dieharder": {"duration_sec": round(dh_dur,3), "returncode": dh_rc,
                      "interesting_lines": dh_lines, "test_ids": DIEHARDER_TESTS,
                      "raw": dh_raw, "stage": "final"},
    }
    if pr_result:
        tests["practrand"] = {"duration_sec": pr_result["duration_sec"],
                               "returncode": pr_result["returncode"],
                               "stdout": pr_result["stdout"], "stderr": pr_result["stderr"],
                               "stage": "final"}

    report = {
        "timestamp": timestamp,
        "pipeline_stages": {
            "raw_sdr":   "Physical RF noise from SDR nodes, before any processing",
            "pre_mix":   "After XOR-fold extractor, before SHA-512 conditioning — evaluated via premix_stats",
            "final":     "After SHA-512 conditioning — evaluated via ENT / RNGtest / Dieharder",
        },
        "sample": {
            "source": f"tcp://{TARGET_HOST}:{TARGET_TCP_PORT}",
            "stage": "final",
            "target_size_bytes": SAMPLE_SIZE,
            "bytes": sample["bytes"],
            "duration_sec": sample["duration_sec"],
            "sessions": sample["sessions"],
            "throughput_mib_s": sample["throughput_mib_s"],
            "sha256": sample_sha256,
        },
        "premix_stats": pm_stats,
        "node_health": node_health,
        "source_audits": source_audits,
        "healthz": healthz,
        "sources": sources_raw,
        "environment": sys_snapshot(),
        "benchmarks": {"sha512": sha512_bench},
        "tests": tests,
        "verdict": verdict,
    }

    # integrity chain
    rjb = json.dumps(report, indent=2, ensure_ascii=False).encode()
    report_sha256 = hashlib.sha256(rjb).hexdigest()
    prev_hash = read_prev_hash()
    ch = hashlib.sha256()
    if prev_hash: ch.update(prev_hash.encode())
    ch.update(report_sha256.encode())
    chain_hash = ch.hexdigest()
    chain_hmac = None
    if CHAIN_SECRET:
        chain_hmac = hmac.new(CHAIN_SECRET.encode(), chain_hash.encode(), hashlib.sha256).hexdigest()

    report["integrity"] = {"prev_chain_hash": prev_hash, "report_sha256": report_sha256,
                           "chain_hash": chain_hash, "chain_hmac": chain_hmac}

    rjp = REPORTS_DIR / f"{slug}-report.json"
    rhp = REPORTS_DIR / f"{slug}-report.html"
    rjp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    rhp.write_text(render_html(report), encoding="utf-8")
    (REPORTS_DIR / f"{slug}-report.sha256").write_text(f"{report_sha256}  {rjp.name}\n", encoding="utf-8")
    (REPORTS_DIR / f"{slug}-sample.sha256").write_text(f"{sample_sha256}  sample.bin\n", encoding="utf-8")

    chain_entry = {"timestamp": timestamp, "html_file": rhp.name, "json_file": rjp.name,
                   "sample_sha256": sample_sha256, "report_sha256": report_sha256,
                   "prev_chain_hash": prev_hash, "chain_hash": chain_hash,
                   "chain_hmac": chain_hmac, "verdict": verdict}
    with CHAIN_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(chain_entry, ensure_ascii=False) + "\n")

    entries = []
    for line in CHAIN_PATH.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line: continue
        try: entries.append(json.loads(line))
        except: continue
    write_index(entries)
    LATEST_PATH.write_text(json.dumps(chain_entry, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({"status":"ok","report":rjp.name,"html":rhp.name,"chain_hash":chain_hash}, ensure_ascii=False))

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status":"error","error":str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise
