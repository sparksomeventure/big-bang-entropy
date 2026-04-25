#!/usr/bin/env python3
import hashlib
import hmac
import html
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

REPORTS_DIR = Path(os.getenv("AUDIT_REPORTS_DIR", "/reports"))
TARGET_HOST = os.getenv("AUDIT_TARGET_HOST", "generator")
TARGET_TCP_PORT = int(os.getenv("AUDIT_TARGET_TCP_PORT", "1420"))
TARGET_HTTP_URL = os.getenv("AUDIT_TARGET_HTTP_URL", "http://generator:8080")
SAMPLE_SIZE = int(os.getenv("AUDIT_SAMPLE_SIZE", str(20 * 1024 * 1024)))
RNGTEST_BLOCKS = int(os.getenv("AUDIT_RNGTEST_BLOCKS", "1000"))
CHAIN_SECRET = os.getenv("AUDIT_CHAIN_SECRET", "")
DIEHARDER_TESTS = [item.strip() for item in os.getenv("AUDIT_DIEHARDER_TESTS", "0").split(",") if item.strip()]
SHA512_ROUNDS = int(os.getenv("AUDIT_SHA512_ROUNDS", "32"))
SOCKET_TIMEOUT = float(os.getenv("AUDIT_SOCKET_TIMEOUT_SEC", "5"))
MAX_SESSIONS = int(os.getenv("AUDIT_MAX_TCP_SESSIONS", "1024"))

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
CHAIN_PATH = REPORTS_DIR / "chain.jsonl"
INDEX_PATH = REPORTS_DIR / "index.html"
LATEST_PATH = REPORTS_DIR / "latest.json"


def http_json(url: str):
    with urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_sample_via_tcp(target_bytes: int):
    chunks = []
    total = 0
    sessions = 0
    started = time.perf_counter()

    while total < target_bytes and sessions < MAX_SESSIONS:
        sessions += 1
        with socket.create_connection((TARGET_HOST, TARGET_TCP_PORT), timeout=SOCKET_TIMEOUT) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            part = bytearray()
            while True:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                part.extend(data)

        if not part:
            continue

        if part == b"Warming up...\n":
            time.sleep(1.0)
            continue

        chunks.append(bytes(part))
        total += len(part)

    duration = max(time.perf_counter() - started, 0.000001)
    sample = b"".join(chunks)[:target_bytes]
    return {
        "bytes": len(sample),
        "duration_sec": round(duration, 3),
        "sessions": sessions,
        "throughput_mib_s": round((len(sample) / duration) / (1024 * 1024), 3),
        "data": sample,
    }


def run_command(command, stdin_bytes=None):
    started = time.perf_counter()
    result = subprocess.run(
        command,
        input=stdin_bytes,
        capture_output=True,
        check=False,
    )
    duration = max(time.perf_counter() - started, 0.000001)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.decode("utf-8", errors="replace"),
        "stderr": result.stderr.decode("utf-8", errors="replace"),
        "duration_sec": round(duration, 3),
    }


def parse_ent(stdout: str):
    entropy = None
    chi_square = None
    pi_error_pct = None
    serial_correlation = None
    for line in stdout.splitlines():
        if "Entropy =" in line:
            match = re.search(r"Entropy =\s*([0-9.]+)", line)
            if match:
                entropy = float(match.group(1))
        elif "Chi square distribution" in line:
            match = re.search(r"Chi square distribution for .*? is\s*([0-9.]+)", line)
            if match:
                chi_square = float(match.group(1))
        elif "Monte Carlo value for Pi" in line:
            match = re.search(r"error\s*([0-9.]+)\s*percent", line)
            if match:
                pi_error_pct = float(match.group(1))
        elif "Serial correlation coefficient" in line:
            match = re.search(r"Serial correlation coefficient is\s*([-0-9.]+)", line)
            if match:
                serial_correlation = float(match.group(1))
    return {
        "entropy_bits_per_byte": entropy,
        "chi_square": chi_square,
        "pi_error_pct": pi_error_pct,
        "serial_correlation": serial_correlation,
    }


def parse_rngtest(stdout: str, stderr: str):
    text = "\n".join([stdout, stderr])
    successes = failures = None
    for line in text.splitlines():
        if "successes" in line and "failures" in line:
            success_match = re.search(r"successes:\s*(\d+)", line)
            failure_match = re.search(r"failures:\s*(\d+)", line)
            if success_match:
                successes = int(success_match.group(1))
            if failure_match:
                failures = int(failure_match.group(1))
    return {
        "successes": successes,
        "failures": failures,
    }


def summarize_dieharder(stdout: str):
    interesting = []
    for line in stdout.splitlines():
        if any(marker in line for marker in ("PASSED", "FAILED", "WEAK")):
            interesting.append(line.strip())
    return interesting


def benchmark_sha512(sample: bytes, rounds: int):
    started = time.perf_counter()
    digest = None
    for _ in range(max(1, rounds)):
        digest = hashlib.sha512(sample).hexdigest()
    duration = max(time.perf_counter() - started, 0.000001)
    total_bytes = len(sample) * max(1, rounds)
    return {
        "rounds": max(1, rounds),
        "duration_sec": round(duration, 3),
        "throughput_mib_s": round((total_bytes / duration) / (1024 * 1024), 3),
        "last_digest": digest,
    }


def get_system_snapshot():
    cpu_model = "unknown"
    mem_total_kib = None

    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line and line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2:
                    mem_total_kib = int(parts[1])
                break

    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "cpu_model": cpu_model,
        "mem_total_kib": mem_total_kib,
    }


def build_verdict(entropy_bits, rng_successes, rng_failures, dieharder_lines):
    if entropy_bits is None:
        return {
            "label": "AUDIT_ERROR",
            "summary": "The basic ENT statistics could not be calculated.",
        }

    dieharder_failed = any("FAILED" in line for line in dieharder_lines)
    if entropy_bits > 7.999 and rng_successes == RNGTEST_BLOCKS and not dieharder_failed:
        return {
            "label": "CRYPTOGRAPHICALLY_VERY_STRONG",
            "summary": "The sample passed the quick statistical checks and shows no obvious red flags.",
        }

    if entropy_bits > 7.99 and (rng_failures in (0, None)) and not dieharder_failed:
        return {
            "label": "GOOD",
            "summary": "Quality looks good, but weekly results and environmental trends should still be monitored.",
        }

    return {
        "label": "NEEDS_ATTENTION",
        "summary": "The result is not automatically alarming, but it needs a manual review of source and sampling parameters.",
    }


def read_previous_chain_hash():
    if not CHAIN_PATH.exists():
        return None
    last = None
    for line in CHAIN_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            last = line
    if not last:
        return None
    try:
        payload = json.loads(last)
    except Exception:
        return None
    return payload.get("chain_hash")


def write_index(entries):
    rows = []
    for entry in sorted(entries, key=lambda item: item["timestamp"], reverse=True):
        rows.append(
            "<tr>"
            f"<td>{html.escape(entry['timestamp'])}</td>"
            f"<td><a href=\"{html.escape(entry['html_file'])}\">HTML</a></td>"
            f"<td><a href=\"{html.escape(entry['json_file'])}\">JSON</a></td>"
            f"<td><code>{html.escape(entry['verdict']['label'])}</code></td>"
            f"<td><code>{html.escape(entry['chain_hash'][:20])}...</code></td>"
            "</tr>"
        )

    page = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Entropy audit reports</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0a0f14; color:#d7e3f4; margin:0; padding:32px; }}
    h1 {{ margin-top:0; }}
    a {{ color:#8de1ff; }}
    table {{ width:100%; border-collapse:collapse; margin-top:24px; }}
    th, td {{ border-bottom:1px solid rgba(255,255,255,0.12); padding:12px 8px; text-align:left; vertical-align:top; }}
    code {{ color:#ffe28a; }}
    .meta {{ color:#9fb2c7; max-width:72ch; }}
  </style>
</head>
<body>
  <h1>Cryptographic audit reports</h1>
  <p class=\"meta\">Reports are generated periodically by the audit service. Each entry is appended to the integrity chain stored in <a href=\"chain.jsonl\">chain.jsonl</a>. If an environment secret is configured, entries also include an HMAC.</p>
  <table>
    <thead>
      <tr>
        <th>Date</th>
        <th>HTML</th>
        <th>JSON</th>
        <th>Verdict</th>
        <th>Chain hash</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="5">No reports yet</td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""
    INDEX_PATH.write_text(page, encoding="utf-8")


def render_report_html(report):
    dieharder_items = "".join(
        f"<li><code>{html.escape(line)}</code></li>" for line in report["tests"]["dieharder"]["interesting_lines"]
    ) or "<li>Brak linii PASSED/WEAK/FAILED</li>"

    source_rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['node'])}</td>"
        f"<td>{item['packets']}</td>"
        f"<td>{item['raw_bytes']}</td>"
        f"<td>{item['avg_bytes_per_sec']}</td>"
        "</tr>"
        for item in report.get("sources", [])
    ) or '<tr><td colspan="4">No source data available</td></tr>'

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Audit report {html.escape(report['timestamp'])}</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#081018; color:#dbe8f7; margin:0; padding:32px; line-height:1.55; }}
    h1, h2 {{ color:#ffffff; }}
    a {{ color:#85d9ff; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; margin:24px 0; }}
    .card {{ border:1px solid rgba(255,255,255,0.12); background:rgba(255,255,255,0.03); padding:16px; }}
    code, pre {{ color:#ffe28a; white-space:pre-wrap; word-break:break-word; }}
    table {{ width:100%; border-collapse:collapse; margin-top:16px; }}
    th, td {{ border-bottom:1px solid rgba(255,255,255,0.12); padding:10px 8px; text-align:left; vertical-align:top; }}
    .muted {{ color:#9bb0c5; }}
  </style>
</head>
<body>
  <p><a href=\"./index.html\">Back to report index</a></p>
  <h1>Cryptographic audit report</h1>
  <p class=\"muted\">Date: {html.escape(report['timestamp'])} | Sample source: <code>{html.escape(report['sample']['source'])}</code></p>

  <div class=\"grid\">
    <section class=\"card\">
      <h2>Verdict</h2>
      <p><code>{html.escape(report['verdict']['label'])}</code></p>
      <p>{html.escape(report['verdict']['summary'])}</p>
    </section>
    <section class=\"card\">
      <h2>Integrity</h2>
      <p>Previous hash: <code>{html.escape(str(report['integrity']['prev_chain_hash']))}</code></p>
      <p>Report hash: <code>{html.escape(report['integrity']['report_sha256'])}</code></p>
      <p>Chain hash: <code>{html.escape(report['integrity']['chain_hash'])}</code></p>
      <p>HMAC: <code>{html.escape(str(report['integrity'].get('chain_hmac')))}</code></p>
    </section>
    <section class=\"card\">
      <h2>Performance</h2>
      <p>Sample download: <code>{report['sample']['throughput_mib_s']} MiB/s</code></p>
      <p>TCP sessions: <code>{report['sample']['sessions']}</code></p>
      <p>SHA-512: <code>{report['benchmarks']['sha512']['throughput_mib_s']} MiB/s</code></p>
      <p>ENT / RNG / Dieharder time: <code>{report['tests']['ent']['duration_sec']} / {report['tests']['rngtest']['duration_sec']} / {report['tests']['dieharder']['duration_sec']} s</code></p>
    </section>
  </div>

  <h2>Source parameters</h2>
  <pre>{html.escape(json.dumps(report['healthz'], indent=2, ensure_ascii=False))}</pre>

  <h2>Test statistics</h2>
  <div class=\"grid\">
    <section class=\"card\">
      <h2>ENT</h2>
      <pre>{html.escape(json.dumps(report['tests']['ent']['parsed'], indent=2, ensure_ascii=False))}</pre>
    </section>
    <section class=\"card\">
      <h2>RNGTEST</h2>
      <pre>{html.escape(json.dumps(report['tests']['rngtest']['parsed'], indent=2, ensure_ascii=False))}</pre>
    </section>
    <section class=\"card\">
      <h2>Dieharder</h2>
      <ul>{dieharder_items}</ul>
    </section>
  </div>

  <h2>Audit container environment</h2>
  <pre>{html.escape(json.dumps(report['environment'], indent=2, ensure_ascii=False))}</pre>

  <h2>Source nodes</h2>
  <table>
    <thead>
      <tr><th>Node</th><th>Packets</th><th>Raw bytes</th><th>Avg B/s</th></tr>
    </thead>
    <tbody>
      {source_rows}
    </tbody>
  </table>
</body>
</html>
"""


def main():
    timestamp = datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat()
    slug = timestamp.replace(":", "-")

    healthz = http_json(f"{TARGET_HTTP_URL}/healthz")
    sources = http_json(f"{TARGET_HTTP_URL}/sources")

    sample = fetch_sample_via_tcp(SAMPLE_SIZE)
    if sample["bytes"] <= 0:
        raise RuntimeError("Failed to fetch a sample from the generator over TCP 1420.")

    with tempfile.NamedTemporaryFile(prefix="entropy-audit-", suffix=".bin", delete=False) as tmp:
        tmp.write(sample["data"])
        sample_path = Path(tmp.name)
    sample_sha256 = hashlib.sha256(sample["data"]).hexdigest()
    try:
        ent_result = run_command(["ent", str(sample_path)])
        rng_result = run_command(["rngtest", "-c", str(RNGTEST_BLOCKS)], stdin_bytes=sample["data"])

        dieharder_raw = []
        dieharder_duration = 0.0
        dieharder_returncode = 0
        for test_id in DIEHARDER_TESTS:
            result = run_command(["dieharder", "-g", "201", "-f", str(sample_path), "-d", test_id])
            dieharder_raw.append({
                "test_id": test_id,
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "duration_sec": result["duration_sec"],
            })
            dieharder_duration += result["duration_sec"]
            dieharder_returncode = max(dieharder_returncode, result["returncode"])
    finally:
        try:
            sample_path.unlink(missing_ok=True)
        except Exception:
            pass

    sha512_benchmark = benchmark_sha512(sample["data"], SHA512_ROUNDS)

    ent_parsed = parse_ent(ent_result["stdout"])
    rng_parsed = parse_rngtest(rng_result["stdout"], rng_result["stderr"])
    dieharder_lines = []
    for item in dieharder_raw:
        dieharder_lines.extend(summarize_dieharder(item["stdout"]))

    verdict = build_verdict(
        ent_parsed["entropy_bits_per_byte"],
        rng_parsed["successes"],
        rng_parsed["failures"],
        dieharder_lines,
    )

    report = {
        "timestamp": timestamp,
        "sample": {
            "source": f"tcp://{TARGET_HOST}:{TARGET_TCP_PORT}",
            "target_size_bytes": SAMPLE_SIZE,
            "bytes": sample["bytes"],
            "duration_sec": sample["duration_sec"],
            "sessions": sample["sessions"],
            "throughput_mib_s": sample["throughput_mib_s"],
            "sha256": sample_sha256,
        },
        "healthz": healthz,
        "sources": sources,
        "environment": get_system_snapshot(),
        "benchmarks": {
            "sha512": sha512_benchmark,
        },
        "tests": {
            "ent": {
                "duration_sec": ent_result["duration_sec"],
                "returncode": ent_result["returncode"],
                "parsed": ent_parsed,
                "stdout": ent_result["stdout"],
                "stderr": ent_result["stderr"],
            },
            "rngtest": {
                "duration_sec": rng_result["duration_sec"],
                "returncode": rng_result["returncode"],
                "parsed": rng_parsed,
                "stdout": rng_result["stdout"],
                "stderr": rng_result["stderr"],
            },
            "dieharder": {
                "duration_sec": round(dieharder_duration, 3),
                "returncode": dieharder_returncode,
                "interesting_lines": dieharder_lines,
                "raw": dieharder_raw,
            },
        },
        "verdict": verdict,
    }

    report_json_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    report_sha256 = hashlib.sha256(report_json_bytes).hexdigest()
    prev_chain_hash = read_previous_chain_hash()
    chain_hasher = hashlib.sha256()
    if prev_chain_hash:
        chain_hasher.update(prev_chain_hash.encode("utf-8"))
    chain_hasher.update(report_sha256.encode("utf-8"))
    chain_hash = chain_hasher.hexdigest()

    chain_hmac = None
    if CHAIN_SECRET:
        chain_hmac = hmac.new(CHAIN_SECRET.encode("utf-8"), chain_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    report["integrity"] = {
        "prev_chain_hash": prev_chain_hash,
        "report_sha256": report_sha256,
        "chain_hash": chain_hash,
        "chain_hmac": chain_hmac,
    }

    report_json_path = REPORTS_DIR / f"{slug}-report.json"
    report_html_path = REPORTS_DIR / f"{slug}-report.html"
    report_json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report_html_path.write_text(render_report_html(report), encoding="utf-8")
    (REPORTS_DIR / f"{slug}-report.sha256").write_text(f"{report_sha256}  {report_json_path.name}\n", encoding="utf-8")
    (REPORTS_DIR / f"{slug}-sample.sha256").write_text(f"{sample_sha256}  {sample_path.name}\n", encoding="utf-8")

    chain_entry = {
        "timestamp": timestamp,
        "html_file": report_html_path.name,
        "json_file": report_json_path.name,
        "sample_sha256": sample_sha256,
        "report_sha256": report_sha256,
        "prev_chain_hash": prev_chain_hash,
        "chain_hash": chain_hash,
        "chain_hmac": chain_hmac,
        "verdict": verdict,
    }
    with CHAIN_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(chain_entry, ensure_ascii=False) + "\n")

    entries = []
    for line in CHAIN_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    write_index(entries)
    LATEST_PATH.write_text(json.dumps(chain_entry, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "report": report_json_path.name,
        "html": report_html_path.name,
        "chain_hash": chain_hash,
    }, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise
