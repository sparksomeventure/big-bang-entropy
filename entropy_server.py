import base64
import hashlib
import json
import os
import socket
import string
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from flask import Flask, Response, jsonify, request, stream_with_context
from werkzeug.middleware.proxy_fix import ProxyFix

UDP_HOST = os.getenv("UDP_HOST", "0.0.0.0")
UDP_PORT = int(os.getenv("UDP_PORT", "5005"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))
TELNET_PORT = int(os.getenv("TELNET_PORT", "1420"))
RAW_TELNET_PORT = int(os.getenv("RAW_TELNET_PORT", "1421"))
RAW_HTTP_CHUNK = int(os.getenv("RAW_HTTP_CHUNK", "65536"))
TELNET_SESSION_BYTES = int(os.getenv("TELNET_SESSION_BYTES", str(RAW_HTTP_CHUNK)))
TELNET_MAX_BYTES_PER_SESSION = int(os.getenv("TELNET_MAX_BYTES_PER_SESSION", str(1024 * 1024)))
STREAM_CHUNK_BYTES = int(os.getenv("STREAM_CHUNK_BYTES", str(64 * 1024)))
STREAM_WAIT_TIMEOUT_SEC = float(os.getenv("STREAM_WAIT_TIMEOUT_SEC", "2.0"))
STREAM_WAIT_INTERVAL_SEC = float(os.getenv("STREAM_WAIT_INTERVAL_SEC", "0.05"))
POOL_SIZE_MB = int(os.getenv("POOL_SIZE_MB", "128"))
POOL_MAX_BYTES = POOL_SIZE_MB * 1024 * 1024
RAW_POOL_SIZE_MB = int(os.getenv("RAW_POOL_SIZE_MB", "64"))
RAW_POOL_MAX_BYTES = RAW_POOL_SIZE_MB * 1024 * 1024
IMAGE_ASSEMBLY_TTL_SEC = int(os.getenv("IMAGE_ASSEMBLY_TTL_SEC", "60"))
WATERFALL_HISTORY_FRAMES = int(os.getenv("WATERFALL_HISTORY_FRAMES", "5"))
NODE_TTL_SEC = int(os.getenv("NODE_TTL_SEC", str(6 * 60 * 60)))
SOURCE_AUDIT_STATE_PATH = Path(
    os.getenv("SOURCE_AUDIT_STATE_PATH", "/tmp/bbe-source-audits.json")
)
SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD = float(
    os.getenv("SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD", "0.9")
)
SOURCE_AUDIT_MAX_AGE_SEC = int(
    os.getenv("SOURCE_AUDIT_MAX_AGE_SEC", str(36 * 60 * 60))
)
MIX_BLOCK_BYTES = int(os.getenv("MIX_BLOCK_BYTES", "64"))
LOG_EVERY_SEC = int(os.getenv("LOG_EVERY_SEC", "30"))
LOW_POOL_THRESHOLD_PCT = float(os.getenv("LOW_POOL_THRESHOLD_PCT", "10"))
THROTTLE_BYTES_PER_SEC = int(os.getenv("THROTTLE_BYTES_PER_SEC", str(1024 * 1024)))
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "1"))
TCP_PROXY_PROTOCOL_ENABLED = os.getenv("TCP_PROXY_PROTOCOL_ENABLED", "0").lower() in (
    "1",
    "true",
    "yes",
)
TCP_PROXY_PROTOCOL_TIMEOUT_SEC = float(os.getenv("TCP_PROXY_PROTOCOL_TIMEOUT_SEC", "0.2"))
TCP_PROXY_PROTOCOL_MAX_HEADER_BYTES = int(
    os.getenv("TCP_PROXY_PROTOCOL_MAX_HEADER_BYTES", "256")
)
AUTOSTART_THREADS = os.getenv("ENTROPY_SERVER_AUTOSTART_THREADS", "1").lower() in (
    "1",
    "true",
    "yes",
)

entropy_pool = bytearray()
pool_lock = threading.Lock()

raw_pool = bytearray()
raw_pool_lock = threading.Lock()

waterfalls: Dict[str, Dict[str, object]] = {}
waterfalls_lock = threading.Lock()

image_fragments: Dict[str, Dict[str, object]] = {}
image_fragments_lock = threading.Lock()

generator_state = hashlib.sha512(os.urandom(64)).digest()
generator_state_lock = threading.Lock()

node_stats: Dict[str, Dict[str, object]] = {}
node_stats_lock = threading.Lock()

source_audits: Dict[str, Dict[str, object]] = {}
source_audits_lock = threading.Lock()


def log(message: str):
    print(message, flush=True)


def _clamp_pool():
    global entropy_pool
    margin = 10 * 1024 * 1024
    if len(entropy_pool) > POOL_MAX_BYTES + margin:
        excess = len(entropy_pool) - POOL_MAX_BYTES
        del entropy_pool[:excess]

def _clamp_raw_pool():
    global raw_pool
    margin = 5 * 1024 * 1024
    if len(raw_pool) > RAW_POOL_MAX_BYTES + margin:
        excess = len(raw_pool) - RAW_POOL_MAX_BYTES
        del raw_pool[:excess]


def _store_entropy(payload: bytes):
    global entropy_pool
    with pool_lock:
        entropy_pool.extend(payload)
        _clamp_pool()


def _persist_source_audits():
    try:
        SOURCE_AUDIT_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with source_audits_lock:
            snapshot = {
                "generated_at": time.time(),
                "repeat_score_threshold": SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD,
                "max_age_sec": SOURCE_AUDIT_MAX_AGE_SEC,
                "nodes": {
                    node_name: dict(state)
                    for node_name, state in sorted(source_audits.items())
                },
            }
        SOURCE_AUDIT_STATE_PATH.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        log(f"[!] Could not persist source audits to {SOURCE_AUDIT_STATE_PATH}: {exc}")


def _source_audit_summary(audit: Optional[Dict[str, object]], now: Optional[float] = None):
    now = time.time() if now is None else now
    if not audit:
        return {
            "status": "MISSING",
            "accepting_samples": False,
            "repeat_score": None,
            "age_sec": None,
        }

    updated_at = float(audit.get("updated_at", 0.0) or 0.0)
    age_sec = round(now - updated_at, 1) if updated_at else None
    repeat_score = audit.get("repeat_score")
    if age_sec is not None and age_sec > SOURCE_AUDIT_MAX_AGE_SEC:
        status = "STALE"
        accepting = False
    elif isinstance(repeat_score, (int, float)) and repeat_score >= SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD:
        status = "WARN"
        accepting = False
    else:
        status = "OK"
        accepting = True

    return {
        "status": status,
        "accepting_samples": accepting,
        "repeat_score": repeat_score,
        "age_sec": age_sec,
    }


def _update_source_audit(node_name: str, audit_payload: Dict[str, object]):
    with source_audits_lock:
        source_audits[node_name] = audit_payload
    _persist_source_audits()


def _node_accepts_samples(node_name: str) -> bool:
    with source_audits_lock:
        audit = source_audits.get(node_name)
    return _source_audit_summary(audit)["accepting_samples"]


def _pop_entropy_chunk(chunk_size: int) -> Optional[bytes]:
    global entropy_pool
    with pool_lock:
        if len(entropy_pool) < chunk_size:
            return None
        data = bytes(entropy_pool[-chunk_size:])
        del entropy_pool[-chunk_size:]
        return data


def _pop_entropy_chunk_up_to(chunk_size: int) -> Optional[bytes]:
    global entropy_pool
    with pool_lock:
        if not entropy_pool:
            return None
        actual_size = min(len(entropy_pool), chunk_size)
        data = bytes(entropy_pool[-actual_size:])
        del entropy_pool[-actual_size:]
        return data

def _pop_raw_chunk(chunk_size: int) -> Optional[bytes]:
    global raw_pool
    with raw_pool_lock:
        if len(raw_pool) < chunk_size:
            return None
        data = bytes(raw_pool[-chunk_size:])
        del raw_pool[-chunk_size:]
        return data


def _stream_entropy(total_bytes: int):
    remaining = total_bytes
    started_at = time.time()
    chunk_count = 0

    while remaining > 0:
        target_size = min(STREAM_CHUNK_BYTES, remaining)
        chunk = _pop_entropy_chunk_up_to(target_size)

        if chunk is None:
            if time.time() - started_at >= STREAM_WAIT_TIMEOUT_SEC:
                break
            time.sleep(STREAM_WAIT_INTERVAL_SEC)
            continue

        started_at = time.time()
        remaining -= len(chunk)
        chunk_count += 1
        yield chunk

        if _is_low_pool():
            time.sleep(len(chunk) / max(1, THROTTLE_BYTES_PER_SEC))

    delivered = total_bytes - remaining
    log(
        f"[*] HTTP entropy stream finished requested={total_bytes} "
        f"delivered={delivered} chunks={chunk_count}"
    )


def _parse_requested_bytes(default_bytes: int) -> int:
    requested = request.args.get("bytes")
    if requested is None:
        return default_bytes
    try:
        parsed = int(requested)
    except ValueError:
        return default_bytes
    return max(1, parsed)


def _pool_bytes() -> int:
    with pool_lock:
        return len(entropy_pool)


def _pool_fill_pct() -> float:
    if POOL_MAX_BYTES <= 0:
        return 0.0
    return (_pool_bytes() / POOL_MAX_BYTES) * 100.0


def _is_low_pool() -> bool:
    return _pool_fill_pct() < LOW_POOL_THRESHOLD_PCT


def _effective_telnet_session_bytes() -> int:
    return min(max(1, TELNET_SESSION_BYTES), TELNET_MAX_BYTES_PER_SESSION)


def _store_waterfall(node_name: str, frame_id: str, image_format: str, image_bytes: bytes):
    if image_format not in ("png", "webp"):
        return

    with waterfalls_lock:
        state = waterfalls.setdefault(
            node_name,
            {
                "frames": [],
                "updated_at": 0.0,
            },
        )

        frame = next(
            (item for item in state["frames"] if item["frame_id"] == frame_id),
            None,
        )
        if frame is None:
            frame = {
                "frame_id": frame_id,
                "formats": {},
                "updated_at": time.time(),
            }
            state["frames"].append(frame)

        frame["formats"][image_format] = image_bytes
        frame["updated_at"] = time.time()
        state["updated_at"] = frame["updated_at"]
        state["frames"] = sorted(state["frames"], key=lambda item: item["updated_at"])[
            -max(1, WATERFALL_HISTORY_FRAMES) :
        ]

    log(
        f"[*] Waterfall updated from node={node_name}, frame_id={frame_id}, "
        f"format={image_format}, bytes={len(image_bytes)}"
    )


def _update_node_stats(node_name: str, raw_bytes: int, payload_bytes: int, rejected: bool = False):
    with node_stats_lock:
        state = node_stats.setdefault(
            node_name,
            {
                "first_seen": time.time(),
                "raw_bytes": 0,
                "payload_bytes": 0,
                "packets": 0,
                "rejected_packets": 0,
                "rejected_bytes": 0,
                "last_seen": 0.0,
            },
        )
        if rejected:
            state["rejected_packets"] += 1
            state["rejected_bytes"] += raw_bytes
        else:
            state["raw_bytes"] += raw_bytes
            state["payload_bytes"] += payload_bytes
            state["packets"] += 1
        state["last_seen"] = time.time()


def _cleanup_stale_nodes(now: Optional[float] = None):
    now = time.time() if now is None else now
    cutoff = now - NODE_TTL_SEC

    with node_stats_lock:
        stale_nodes = [
            node_name
            for node_name, state in node_stats.items()
            if state["last_seen"] and state["last_seen"] < cutoff
        ]
        for node_name in stale_nodes:
            del node_stats[node_name]

    source_audits_changed = False
    with source_audits_lock:
        stale_audits = [
            node_name
            for node_name, state in source_audits.items()
            if state.get("updated_at", 0.0) < cutoff
        ]
        for node_name in stale_audits:
            del source_audits[node_name]
            source_audits_changed = True

    with waterfalls_lock:
        stale_waterfalls = [
            node_name
            for node_name, state in waterfalls.items()
            if state["updated_at"] < cutoff
        ]
        for node_name in stale_waterfalls:
            del waterfalls[node_name]

    if source_audits_changed:
        _persist_source_audits()


def _snapshot_sources():
    _cleanup_stale_nodes()
    now = time.time()
    with source_audits_lock:
        audit_snapshot = {
            node_name: dict(state) for node_name, state in source_audits.items()
        }
    with node_stats_lock:
        payload = []
        for node_name, state in sorted(node_stats.items()):
            active_for = max(now - state["first_seen"], 1.0)
            audit_info = audit_snapshot.get(node_name)
            audit_summary = _source_audit_summary(audit_info, now=now)
            payload.append(
                {
                    "node": node_name,
                    "raw_bytes": state["raw_bytes"],
                    "payload_bytes": state["payload_bytes"],
                    "packets": state["packets"],
                    "rejected_packets": state.get("rejected_packets", 0),
                    "rejected_bytes": state.get("rejected_bytes", 0),
                    "first_seen": state["first_seen"],
                    "last_seen": state["last_seen"],
                    "last_seen_age_sec": round(now - state["last_seen"], 1)
                    if state["last_seen"]
                    else None,
                    "avg_bytes_per_sec": round(state["raw_bytes"] / active_for, 1),
                    "source_audit_status": audit_summary["status"],
                    "source_audit_repeat_score": audit_summary["repeat_score"],
                    "source_audit_age_sec": audit_summary["age_sec"],
                    "accepting_samples": audit_summary["accepting_samples"],
                }
            )
    return payload


def _mix_samples_into_entropy(node_name: str, raw_samples: bytes, source_timestamp: float):
    global generator_state

    if not raw_samples:
        return

    processed_output = bytearray()
    with generator_state_lock:
        local_state = generator_state
        for offset in range(0, len(raw_samples), MIX_BLOCK_BYTES):
            block = raw_samples[offset : offset + MIX_BLOCK_BYTES]
            hasher = hashlib.sha512(local_state)
            hasher.update(node_name.encode("utf-8"))
            hasher.update(str(source_timestamp).encode("utf-8"))
            hasher.update(block)
            hasher.update(str(time.time_ns()).encode("utf-8"))
            local_state = hasher.digest()
            processed_output.extend(local_state)
        generator_state = local_state

    _store_entropy(processed_output)
    
    # Store raw samples for auditing (Stage 2)
    with raw_pool_lock:
        raw_pool.extend(raw_samples)
        _clamp_raw_pool()


def cleanup_incomplete_images_worker():
    while True:
        cutoff = time.time() - IMAGE_ASSEMBLY_TTL_SEC
        with image_fragments_lock:
            stale_keys = [
                message_id
                for message_id, state in image_fragments.items()
                if state["updated_at"] < cutoff
            ]
            for message_id in stale_keys:
                del image_fragments[message_id]
        _cleanup_stale_nodes()
        time.sleep(5)


def _handle_waterfall_part(message: dict):
    node_name = message.get("node")
    frame_id = message.get("frame_id")
    image_format = message.get("format", "png")
    message_id = message.get("message_id")
    part_index = int(message.get("part_index", -1))
    total_parts = int(message.get("total_parts", 0))
    payload_b64 = message.get("payload_b64")

    if not node_name or not frame_id or not message_id or not payload_b64:
        return
    if total_parts <= 0 or part_index < 0 or part_index >= total_parts:
        return
    if image_format not in ("png", "webp"):
        return

    try:
        payload = base64.b64decode(payload_b64)
    except Exception:
        return

    completed_image: Optional[bytes] = None
    completed_format: Optional[str] = None
    completed_frame_id: Optional[str] = None
    with image_fragments_lock:
        state = image_fragments.setdefault(
            message_id,
            {
                "node": node_name,
                "frame_id": frame_id,
                "format": image_format,
                "total_parts": total_parts,
                "parts": {},
                "updated_at": time.time(),
            },
        )

        if (
            state["node"] != node_name
            or state["frame_id"] != frame_id
            or state["format"] != image_format
            or state["total_parts"] != total_parts
        ):
            image_fragments[message_id] = {
                "node": node_name,
                "frame_id": frame_id,
                "format": image_format,
                "total_parts": total_parts,
                "parts": {part_index: payload},
                "updated_at": time.time(),
            }
            return

        state["parts"][part_index] = payload
        state["updated_at"] = time.time()

        if len(state["parts"]) == state["total_parts"]:
            ordered_parts = [state["parts"][idx] for idx in range(state["total_parts"])]
            completed_image = b"".join(ordered_parts)
            completed_format = state["format"]
            completed_frame_id = state["frame_id"]
            del image_fragments[message_id]

    if completed_image is not None and completed_format and completed_frame_id:
        _store_waterfall(node_name, completed_frame_id, completed_format, completed_image)


def _handle_source_audit(message: dict):
    node_name = message.get("node")
    metrics = message.get("metrics")
    if not node_name or not isinstance(metrics, dict):
        return

    updated_at = time.time()
    audit_payload = {
        "node": node_name,
        "captured_at": float(message.get("timestamp", updated_at)),
        "updated_at": updated_at,
        "sample_bytes": int(metrics.get("sample_bytes", 0) or 0),
        "sample_count": int(metrics.get("sample_count", 0) or 0),
        "mean": float(metrics.get("mean", 0.0) or 0.0),
        "stddev": float(metrics.get("stddev", 0.0) or 0.0),
        "dominant_value_ratio": float(metrics.get("dominant_value_ratio", 0.0) or 0.0),
        "consecutive_equal_ratio": float(metrics.get("consecutive_equal_ratio", 0.0) or 0.0),
        "spectral_flatness": float(metrics.get("spectral_flatness", 0.0) or 0.0),
        "repeat_score": float(metrics.get("repeat_score", 0.0) or 0.0),
        "min_value": int(metrics.get("min_value", 0) or 0),
        "max_value": int(metrics.get("max_value", 0) or 0),
    }
    summary = _source_audit_summary(audit_payload, now=updated_at)
    audit_payload["status"] = summary["status"]
    audit_payload["accepting_samples"] = summary["accepting_samples"]
    audit_payload["repeat_score_threshold"] = SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD
    _update_source_audit(node_name, audit_payload)
    log(
        f"[*] Source audit updated for node={node_name} "
        f"(repeat_score={audit_payload['repeat_score']:.4f}, "
        f"accepting_samples={audit_payload['accepting_samples']})"
    )


def udp_receiver_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, UDP_PORT))
    log(f"[*] UDP receiver listening on {UDP_HOST}:{UDP_PORT}")

    while True:
        packet, address = sock.recvfrom(65535)
        try:
            message = json.loads(packet.decode("utf-8"))
        except Exception:
            log(f"[!] Ignoring invalid UDP packet from {address}")
            continue

        msg_type = message.get("type")
        if msg_type == "samples":
            node_name = message.get("node")
            payload_b64 = message.get("payload_b64")
            if not node_name or not payload_b64:
                continue
            try:
                raw_payload = base64.b64decode(payload_b64)
            except Exception:
                continue
            source_timestamp = float(message.get("timestamp", time.time()))
            if not _node_accepts_samples(node_name):
                _update_node_stats(node_name, len(raw_payload), 0, rejected=True)
                log(f"[!] Rejecting samples from node={node_name} due to source audit repeat threshold.")
                continue
            _update_node_stats(node_name, len(raw_payload), len(raw_payload))
            _mix_samples_into_entropy(node_name, raw_payload, source_timestamp)
        elif msg_type == "waterfall":
            _handle_waterfall_part(message)
        elif msg_type == "source_audit":
            _handle_source_audit(message)


def telnet_client_worker(conn: socket.socket, address):
    try:
        client_address = _resolve_tcp_client_address(conn, address)
        log(f"[*] TCP entropy client connected from {client_address} via peer={address}")
        session_bytes = _effective_telnet_session_bytes()
        data = _pop_entropy_chunk(session_bytes)
        if data is None:
            conn.sendall(b"Warming up...\n")
            log(f"[*] TCP entropy client {client_address} got warmup response")
            return

        conn.sendall(data)
        log(
            f"[*] TCP entropy client {client_address} served {len(data)} bytes "
            f"(session_limit={session_bytes})"
        )
    except Exception as exc:
        log(f"[!] TCP entropy client error from {address}: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def raw_telnet_client_worker(conn: socket.socket, address):
    try:
        log(f"[*] TCP RAW client connected from {address}")
        session_bytes = _effective_telnet_session_bytes()
        data = _pop_raw_chunk(session_bytes)
        if data is None:
            conn.sendall(b"Warming up raw pool...\n")
            return
        conn.sendall(data)
        log(f"[*] TCP RAW client {address} served {len(data)} bytes")
    except Exception as exc:
        log(f"[!] TCP RAW client error from {address}: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def telnet_server_worker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", TELNET_PORT))
    server.listen()
    log(f"[*] TCP entropy server listening on 0.0.0.0:{TELNET_PORT}")

    while True:
        conn, address = server.accept()
        threading.Thread(
            target=telnet_client_worker,
            args=(conn, address),
            daemon=True,
        ).start()


def raw_telnet_server_worker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", RAW_TELNET_PORT))
    server.listen()
    log(f"[*] TCP RAW entropy server listening on 0.0.0.0:{RAW_TELNET_PORT} (Internal)")

    while True:
        conn, address = server.accept()
        threading.Thread(
            target=raw_telnet_client_worker,
            args=(conn, address),
            daemon=True,
        ).start()


def _parse_proxy_protocol_line(line: bytes, fallback_address):
    try:
        decoded = line.decode("ascii").strip()
    except UnicodeDecodeError:
        return fallback_address

    parts = decoded.split()
    if len(parts) < 2 or parts[0] != "PROXY":
        return fallback_address
    if parts[1] == "UNKNOWN":
        return fallback_address
    if len(parts) < 6:
        return fallback_address

    source_host = parts[2]
    try:
        source_port = int(parts[4])
    except ValueError:
        return fallback_address
    return (source_host, source_port)


def _resolve_tcp_client_address(conn: socket.socket, fallback_address):
    if not TCP_PROXY_PROTOCOL_ENABLED:
        return fallback_address

    original_timeout = conn.gettimeout()
    try:
        conn.settimeout(TCP_PROXY_PROTOCOL_TIMEOUT_SEC)
        peek = conn.recv(TCP_PROXY_PROTOCOL_MAX_HEADER_BYTES, socket.MSG_PEEK)
        if not peek.startswith(b"PROXY "):
            return fallback_address

        line = bytearray()
        while len(line) < TCP_PROXY_PROTOCOL_MAX_HEADER_BYTES:
            chunk = conn.recv(1)
            if not chunk:
                break
            line.extend(chunk)
            if line.endswith(b"\r\n"):
                return _parse_proxy_protocol_line(bytes(line), fallback_address)
    except (BlockingIOError, TimeoutError, socket.timeout):
        return fallback_address
    finally:
        conn.settimeout(original_timeout)

    return fallback_address


app = Flask(__name__)
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=max(1, TRUSTED_PROXY_HOPS),
    x_proto=1,
    x_host=1,
)


@app.route("/healthz")
def healthz():
    _cleanup_stale_nodes()
    with pool_lock:
        pool_bytes = len(entropy_pool)
    with waterfalls_lock:
        node_count = len(waterfalls)
    with node_stats_lock:
        source_nodes = len(node_stats)
    with source_audits_lock:
        rejecting_nodes = sum(
            1 for audit in source_audits.values() if not _source_audit_summary(audit)["accepting_samples"]
        )
    return jsonify(
        {
            "status": "ok",
            "pool_bytes": pool_bytes,
            "pool_fill_pct": round(_pool_fill_pct(), 2),
            "pool_size_mb": POOL_SIZE_MB,
            "raw_http_chunk": RAW_HTTP_CHUNK,
            "telnet_session_bytes": _effective_telnet_session_bytes(),
            "telnet_max_bytes_per_session": TELNET_MAX_BYTES_PER_SESSION,
            "mix_block_bytes": MIX_BLOCK_BYTES,
            "stream_chunk_bytes": STREAM_CHUNK_BYTES,
            "low_pool_threshold_pct": LOW_POOL_THRESHOLD_PCT,
            "throttle_bytes_per_sec": THROTTLE_BYTES_PER_SEC,
            "telnet_port": TELNET_PORT,
            "udp_port": UDP_PORT,
            "nodes_with_waterfall": node_count,
            "source_nodes": source_nodes,
            "rejecting_source_nodes": rejecting_nodes,
            "source_audit_repeat_score_threshold": SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD,
            "source_audit_state_path": str(SOURCE_AUDIT_STATE_PATH),
        }
    )


@app.route("/raw")
def get_raw():
    data = _pop_entropy_chunk(RAW_HTTP_CHUNK)
    if data is None:
        return "Warming up...", 503
    return Response(data, mimetype="application/octet-stream")


@app.route("/raw/stream")
def stream_raw():
    requested_bytes = _parse_requested_bytes(STREAM_CHUNK_BYTES * 16)
    return Response(
        stream_with_context(_stream_entropy(requested_bytes)),
        mimetype="application/octet-stream",
    )


@app.route("/download/entropy")
def download_entropy():
    requested_bytes = _parse_requested_bytes(STREAM_CHUNK_BYTES * 16)
    return Response(
        stream_with_context(_stream_entropy(requested_bytes)),
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="entropy-{int(time.time())}.bin"',
            "X-Entropy-Requested-Bytes": str(requested_bytes),
        },
    )


@app.route("/waterfalls")
def list_waterfalls():
    _cleanup_stale_nodes()
    with waterfalls_lock:
        payload = [
            {
                "node": node_name,
                "updated_at": state["updated_at"],
                "frame_count": len(state["frames"]),
                "frames": [
                    {
                        "frame_id": frame["frame_id"],
                        "updated_at": frame["updated_at"],
                        "formats": sorted(frame["formats"].keys()),
                    }
                    for frame in state["frames"]
                ],
                "url": f"/waterfall/{node_name}",
            }
            for node_name, state in sorted(waterfalls.items())
            if state["frames"]
        ]
    return jsonify(payload)


@app.route("/sources")
def list_sources():
    return jsonify(_snapshot_sources())


@app.route("/source-audits")
def list_source_audits():
    _cleanup_stale_nodes()
    now = time.time()
    with source_audits_lock:
        payload = []
        for node_name, state in sorted(source_audits.items()):
            item = dict(state)
            item["age_sec"] = round(now - state["updated_at"], 1) if state.get("updated_at") else None
            payload.append(item)
    return jsonify(payload)


@app.route("/waterfall")
def get_default_waterfall():
    _cleanup_stale_nodes()
    node_name = request.args.get("node")
    if not node_name:
        with waterfalls_lock:
            if not waterfalls:
                return "No waterfall yet", 503
            node_name = sorted(waterfalls.keys())[0]
    return get_waterfall(node_name)


@app.route("/waterfall/<node_name>.<ext>")
def get_waterfall(node_name: str, ext: str):
    _cleanup_stale_nodes()
    if ext not in ("png", "webp"):
        return "Invalid extension", 400

    with waterfalls_lock:
        state = waterfalls.get(node_name)
        if state is None:
            return "No waterfall for this node yet", 404
        frames = state["frames"]
        if not frames:
            return "No waterfall for this node yet", 404

        requested_frame_id = request.args.get("frame")
        frame = None
        if requested_frame_id:
            frame = next((item for item in frames if item["frame_id"] == requested_frame_id), None)
            if frame is None:
                return "Requested waterfall frame not found", 404
        else:
            frame = frames[-1]

        image_bytes = frame["formats"].get(ext)
        if image_bytes is None:
            return "Requested format not available for this frame", 404

    return Response(image_bytes, mimetype=f"image/{ext}")


class EntropyRNG:
    def __init__(self):
        self.buffer = bytearray()

    def get_byte(self) -> int:
        if not self.buffer:
            chunk = _pop_entropy_chunk(256)
            if chunk is None:
                raise ValueError("Warming up...")
            self.buffer.extend(chunk)
        return self.buffer.pop(0)

    def choice(self, seq):
        n = len(seq)
        limit = 256 - (256 % n)
        while True:
            val = self.get_byte()
            if val < limit:
                return seq[val % n]

    def sample(self, seq, k):
        pool = list(seq)
        result = []
        for _ in range(k):
            n = len(pool)
            limit = 256 - (256 % n)
            while True:
                val = self.get_byte()
                if val < limit:
                    idx = val % n
                    result.append(pool.pop(idx))
                    break
        return result


@app.route("/api/password")
def api_password():
    length = int(request.args.get("length", 16))
    use_lowercase = request.args.get("lowercase", "1").lower() in ("1", "true", "yes")
    use_special = request.args.get("special", "1").lower() in ("1", "true", "yes")
    use_numbers = request.args.get("numbers", "1").lower() in ("1", "true", "yes")
    use_uppercase = request.args.get("uppercase", "1").lower() in ("1", "true", "yes")
    count = int(request.args.get("count", 1))

    if length <= 0 or length > 1024 or count <= 0 or count > 1000:
        return jsonify({"error": "Invalid parameters"}), 400

    alphabet = ""
    if use_lowercase:
        alphabet += string.ascii_lowercase
    if use_uppercase:
        alphabet += string.ascii_uppercase
    if use_numbers:
        alphabet += string.digits
    if use_special:
        alphabet += "!@#$%^&*()_+=-[]{}|;:,.<>?"

    if not alphabet:
        return jsonify({"error": "Empty alphabet"}), 400

    rng = EntropyRNG()
    passwords = []
    try:
        for _ in range(count):
            pwd = "".join(rng.choice(alphabet) for _ in range(length))
            passwords.append(pwd)
    except ValueError as e:
        return str(e), 503

    return jsonify({"passwords": passwords})


@app.route("/api/pin")
def api_pin():
    length = int(request.args.get("length", 4))
    count = int(request.args.get("count", 1))

    if length not in (4, 6) or count <= 0 or count > 1000:
        return jsonify({"error": "Invalid parameters"}), 400

    rng = EntropyRNG()
    pins = []
    try:
        for _ in range(count):
            pin = "".join(rng.choice(string.digits) for _ in range(length))
            pins.append(pin)
    except ValueError as e:
        return str(e), 503

    return jsonify({"pins": pins})


@app.route("/api/lotto")
def api_lotto():
    count = int(request.args.get("count", 1))

    if count <= 0 or count > 1000:
        return jsonify({"error": "Invalid parameters"}), 400

    rng = EntropyRNG()
    results = []
    base_pool = list(range(1, 50))
    try:
        for _ in range(count):
            draw = sorted(rng.sample(base_pool, 6))
            results.append(draw)
    except ValueError as e:
        return str(e), 503

    return jsonify({"lotto": results})


def stats_logger_worker():
    while True:
        time.sleep(LOG_EVERY_SEC)
        _cleanup_stale_nodes()

        with pool_lock:
            pool_bytes = len(entropy_pool)
        with node_stats_lock:
            sources = {
                node_name: {
                    "packets": state["packets"],
                    "rejected_packets": state.get("rejected_packets", 0),
                    "raw_bytes": state["raw_bytes"],
                    "last_seen": round(time.time() - state["last_seen"], 1)
                    if state["last_seen"]
                    else None,
                }
                for node_name, state in sorted(node_stats.items())
            }
        with waterfalls_lock:
            waterfall_nodes = sorted(waterfalls.keys())
        with source_audits_lock:
            audit_states = {
                node_name: _source_audit_summary(audit)
                for node_name, audit in sorted(source_audits.items())
            }

        log(
            "[*] Generator stats: "
            f"pool_bytes={pool_bytes}, "
            f"source_nodes={len(sources)}, "
            f"waterfalls={waterfall_nodes}, "
            f"sources={sources}, "
            f"source_audits={audit_states}"
        )


def _start_background_threads():
    log(
        "[*] Entropy generator starting "
        f"(http_port={HTTP_PORT}, telnet_port={TELNET_PORT}, "
        f"udp_host={UDP_HOST}, udp_port={UDP_PORT}, "
        f"pool_size_mb={POOL_SIZE_MB}, mix_block_bytes={MIX_BLOCK_BYTES}, "
        f"telnet_session_bytes={_effective_telnet_session_bytes()}, "
        f"stream_chunk_bytes={STREAM_CHUNK_BYTES}, "
        f"low_pool_threshold_pct={LOW_POOL_THRESHOLD_PCT}, "
        f"throttle_bytes_per_sec={THROTTLE_BYTES_PER_SEC}, "
        f"source_audit_repeat_score_threshold={SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD})"
    )
    threading.Thread(target=udp_receiver_worker, daemon=True).start()
    threading.Thread(target=telnet_server_worker, daemon=True).start()
    threading.Thread(target=raw_telnet_server_worker, daemon=True).start()
    threading.Thread(target=cleanup_incomplete_images_worker, daemon=True).start()
    threading.Thread(target=stats_logger_worker, daemon=True).start()
    log("[*] Entropy generator background threads online")


if AUTOSTART_THREADS:
    _start_background_threads()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)
