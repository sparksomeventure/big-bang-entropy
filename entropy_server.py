import base64
import atexit
import hmac
import hashlib
import json
import os
import socket
import sqlite3
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
ENTROPY_PERSIST_MAX_BYTES = int(
    os.getenv("ENTROPY_PERSIST_MAX_BYTES", str(64 * 1024 * 1024))
)
IMAGE_ASSEMBLY_TTL_SEC = int(os.getenv("IMAGE_ASSEMBLY_TTL_SEC", "60"))
WATERFALL_HISTORY_FRAMES = int(os.getenv("WATERFALL_HISTORY_FRAMES", "5"))
NODE_TTL_SEC = int(os.getenv("NODE_TTL_SEC", str(6 * 60 * 60)))
SOURCE_AUDIT_STATE_PATH = Path(
    os.getenv("SOURCE_AUDIT_STATE_PATH", "/tmp/bbe-source-audits.json")
)
ENTROPY_PERSIST_PATH_VALUE = os.getenv("ENTROPY_PERSIST_PATH", "")
ENTROPY_PERSIST_PATH = (
    Path(ENTROPY_PERSIST_PATH_VALUE).expanduser() if ENTROPY_PERSIST_PATH_VALUE else None
)
ENTROPY_PERSIST_KEY = os.getenv("ENTROPY_PERSIST_KEY", "")
ENTROPY_PERSIST_KEY_FILE_VALUE = os.getenv("ENTROPY_PERSIST_KEY_FILE", "")
ENTROPY_PERSIST_KEY_FILE = (
    Path(ENTROPY_PERSIST_KEY_FILE_VALUE).expanduser()
    if ENTROPY_PERSIST_KEY_FILE_VALUE
    else None
)
ENTROPY_PERSIST_INTERVAL_SEC = float(os.getenv("ENTROPY_PERSIST_INTERVAL_SEC", "5.0"))
ENTROPY_PERSIST_ON_CONSUME = os.getenv("ENTROPY_PERSIST_ON_CONSUME", "0").lower() in (
    "1",
    "true",
    "yes",
)
ENTROPY_REKEY_RESTORED_POOL = os.getenv("ENTROPY_REKEY_RESTORED_POOL", "1").lower() in (
    "1",
    "true",
    "yes",
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
METRICS_ENABLED = os.getenv("METRICS_ENABLED", "1").lower() in (
    "1",
    "true",
    "yes",
)
METRICS_DB_PATH_VALUE = os.getenv("METRICS_DB_PATH", "/tmp/bbe-metrics.sqlite3")
METRICS_DB_PATH = (
    Path(METRICS_DB_PATH_VALUE).expanduser() if METRICS_DB_PATH_VALUE else None
)
METRICS_BUCKET_SEC = max(60, int(os.getenv("METRICS_BUCKET_SEC", "300")))
METRICS_FLUSH_INTERVAL_SEC = max(
    1.0, float(os.getenv("METRICS_FLUSH_INTERVAL_SEC", "15.0"))
)
METRICS_RETENTION_DAYS = max(1, int(os.getenv("METRICS_RETENTION_DAYS", "90")))
METRICS_DEFAULT_RANGE_SEC = int(os.getenv("METRICS_DEFAULT_RANGE_SEC", str(24 * 60 * 60)))

entropy_pool = bytearray()
pool_lock = threading.Lock()
entropy_checkpoint_lock = threading.RLock()
entropy_checkpoint_event = threading.Event()
entropy_checkpoint_loaded = False
last_entropy_checkpoint_at = 0.0

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
node_runtime_stats: Dict[str, Dict[str, object]] = {}
node_runtime_stats_lock = threading.Lock()

source_audits: Dict[str, Dict[str, object]] = {}
source_audits_lock = threading.Lock()

metrics_node_buckets: Dict[tuple[int, str], Dict[str, object]] = {}
metrics_system_buckets: Dict[int, Dict[str, object]] = {}
metrics_lock = threading.Lock()
metrics_db_lock = threading.Lock()
metrics_db_initialized_path: Optional[str] = None


def log(message: str):
    print(message, flush=True)


def _metrics_enabled() -> bool:
    return METRICS_ENABLED and METRICS_DB_PATH is not None


def _metrics_bucket_start(timestamp: Optional[float] = None) -> int:
    timestamp = time.time() if timestamp is None else float(timestamp)
    return int(timestamp // METRICS_BUCKET_SEC * METRICS_BUCKET_SEC)


def _empty_node_metric_bucket(bucket_start: int, node_name: str) -> Dict[str, object]:
    return {
        "bucket_start": bucket_start,
        "node": node_name,
        "sample_packets": 0,
        "sample_bytes": 0,
        "rejected_packets": 0,
        "rejected_bytes": 0,
        "signal_mean_sum": 0.0,
        "signal_mean_weight": 0.0,
        "signal_abs_mean_sum": 0.0,
        "signal_abs_mean_weight": 0.0,
        "signal_stddev_sum": 0.0,
        "signal_stddev_weight": 0.0,
        "audit_repeat_score_sum": 0.0,
        "audit_repeat_score_count": 0,
        "updated_at": time.time(),
    }


def _empty_system_metric_bucket(bucket_start: int) -> Dict[str, object]:
    return {
        "bucket_start": bucket_start,
        "pool_bytes_sum": 0.0,
        "pool_fill_pct_sum": 0.0,
        "source_nodes_sum": 0.0,
        "rejecting_nodes_sum": 0.0,
        "waterfall_nodes_sum": 0.0,
        "sample_count": 0,
        "updated_at": time.time(),
    }


def _optional_float(value) -> Optional[float]:
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed != parsed:
        return None
    return parsed


def _optional_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_node_metric(
    node_name: str,
    *,
    timestamp: Optional[float] = None,
    sample_packets: int = 0,
    sample_bytes: int = 0,
    rejected_packets: int = 0,
    rejected_bytes: int = 0,
    signal_mean: Optional[float] = None,
    signal_abs_mean: Optional[float] = None,
    signal_stddev: Optional[float] = None,
    signal_sample_count: Optional[int] = None,
    audit_repeat_score: Optional[float] = None,
):
    if not _metrics_enabled() or not node_name:
        return

    safe_node = str(node_name)[:128]
    bucket_start = _metrics_bucket_start(timestamp)
    key = (bucket_start, safe_node)
    signal_weight = max(float(signal_sample_count or 1), 1.0)

    with metrics_lock:
        bucket = metrics_node_buckets.setdefault(
            key,
            _empty_node_metric_bucket(bucket_start, safe_node),
        )
        bucket["sample_packets"] += max(0, int(sample_packets))
        bucket["sample_bytes"] += max(0, int(sample_bytes))
        bucket["rejected_packets"] += max(0, int(rejected_packets))
        bucket["rejected_bytes"] += max(0, int(rejected_bytes))

        parsed_signal_mean = _optional_float(signal_mean)
        if parsed_signal_mean is not None:
            bucket["signal_mean_sum"] += parsed_signal_mean * signal_weight
            bucket["signal_mean_weight"] += signal_weight

        parsed_signal_abs_mean = _optional_float(signal_abs_mean)
        if parsed_signal_abs_mean is not None:
            bucket["signal_abs_mean_sum"] += parsed_signal_abs_mean * signal_weight
            bucket["signal_abs_mean_weight"] += signal_weight

        parsed_signal_stddev = _optional_float(signal_stddev)
        if parsed_signal_stddev is not None:
            bucket["signal_stddev_sum"] += parsed_signal_stddev * signal_weight
            bucket["signal_stddev_weight"] += signal_weight

        parsed_repeat_score = _optional_float(audit_repeat_score)
        if parsed_repeat_score is not None:
            bucket["audit_repeat_score_sum"] += parsed_repeat_score
            bucket["audit_repeat_score_count"] += 1

        bucket["updated_at"] = time.time()


def _record_system_metrics_snapshot(timestamp: Optional[float] = None):
    if not _metrics_enabled():
        return

    _cleanup_stale_nodes()
    now = time.time() if timestamp is None else float(timestamp)
    bucket_start = _metrics_bucket_start(now)
    with pool_lock:
        pool_bytes = len(entropy_pool)
    pool_fill_pct = (pool_bytes / POOL_MAX_BYTES * 100.0) if POOL_MAX_BYTES else 0.0
    with node_stats_lock:
        source_nodes = len(node_stats)
    with waterfalls_lock:
        waterfall_nodes = len(waterfalls)
    with source_audits_lock:
        audit_snapshot = [dict(state) for state in source_audits.values()]
    rejecting_nodes = sum(
        1
        for audit in audit_snapshot
        if not _source_audit_summary(audit, now=now)["accepting_samples"]
    )

    with metrics_lock:
        bucket = metrics_system_buckets.setdefault(
            bucket_start,
            _empty_system_metric_bucket(bucket_start),
        )
        bucket["pool_bytes_sum"] += pool_bytes
        bucket["pool_fill_pct_sum"] += pool_fill_pct
        bucket["source_nodes_sum"] += source_nodes
        bucket["rejecting_nodes_sum"] += rejecting_nodes
        bucket["waterfall_nodes_sum"] += waterfall_nodes
        bucket["sample_count"] += 1
        bucket["updated_at"] = time.time()


def _connect_metrics_db():
    if METRICS_DB_PATH is None:
        raise RuntimeError("metrics DB path is not configured")
    METRICS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(METRICS_DB_PATH), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _init_metrics_db() -> bool:
    global metrics_db_initialized_path
    if not _metrics_enabled():
        return False

    path_key = str(METRICS_DB_PATH)
    with metrics_db_lock:
        if metrics_db_initialized_path == path_key:
            return True
        try:
            with _connect_metrics_db() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS node_metric_buckets (
                        bucket_start INTEGER NOT NULL,
                        node TEXT NOT NULL,
                        sample_packets INTEGER NOT NULL DEFAULT 0,
                        sample_bytes INTEGER NOT NULL DEFAULT 0,
                        rejected_packets INTEGER NOT NULL DEFAULT 0,
                        rejected_bytes INTEGER NOT NULL DEFAULT 0,
                        signal_mean_sum REAL NOT NULL DEFAULT 0,
                        signal_mean_weight REAL NOT NULL DEFAULT 0,
                        signal_abs_mean_sum REAL NOT NULL DEFAULT 0,
                        signal_abs_mean_weight REAL NOT NULL DEFAULT 0,
                        signal_stddev_sum REAL NOT NULL DEFAULT 0,
                        signal_stddev_weight REAL NOT NULL DEFAULT 0,
                        audit_repeat_score_sum REAL NOT NULL DEFAULT 0,
                        audit_repeat_score_count INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (bucket_start, node)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS system_metric_buckets (
                        bucket_start INTEGER PRIMARY KEY,
                        pool_bytes_sum REAL NOT NULL DEFAULT 0,
                        pool_fill_pct_sum REAL NOT NULL DEFAULT 0,
                        source_nodes_sum REAL NOT NULL DEFAULT 0,
                        rejecting_nodes_sum REAL NOT NULL DEFAULT 0,
                        waterfall_nodes_sum REAL NOT NULL DEFAULT 0,
                        sample_count INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_node_metric_buckets_node_time "
                    "ON node_metric_buckets(node, bucket_start)"
                )
            metrics_db_initialized_path = path_key
            return True
        except Exception as exc:
            log(f"[!] Could not initialize metrics DB at {METRICS_DB_PATH}: {exc}")
            return False


def _flush_metrics_to_db() -> bool:
    if not _metrics_enabled():
        return False

    _record_system_metrics_snapshot()

    with metrics_lock:
        node_rows = [dict(row) for row in metrics_node_buckets.values()]
        system_rows = [dict(row) for row in metrics_system_buckets.values()]
        metrics_node_buckets.clear()
        metrics_system_buckets.clear()

    if not node_rows and not system_rows:
        return True
    if not _init_metrics_db():
        return False

    now = time.time()
    cutoff_bucket = _metrics_bucket_start(now - (METRICS_RETENTION_DAYS * 24 * 60 * 60))
    try:
        with metrics_db_lock:
            with _connect_metrics_db() as conn:
                conn.executemany(
                    """
                    INSERT INTO node_metric_buckets (
                        bucket_start,
                        node,
                        sample_packets,
                        sample_bytes,
                        rejected_packets,
                        rejected_bytes,
                        signal_mean_sum,
                        signal_mean_weight,
                        signal_abs_mean_sum,
                        signal_abs_mean_weight,
                        signal_stddev_sum,
                        signal_stddev_weight,
                        audit_repeat_score_sum,
                        audit_repeat_score_count,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_start, node) DO UPDATE SET
                        sample_packets = sample_packets + excluded.sample_packets,
                        sample_bytes = sample_bytes + excluded.sample_bytes,
                        rejected_packets = rejected_packets + excluded.rejected_packets,
                        rejected_bytes = rejected_bytes + excluded.rejected_bytes,
                        signal_mean_sum = signal_mean_sum + excluded.signal_mean_sum,
                        signal_mean_weight = signal_mean_weight + excluded.signal_mean_weight,
                        signal_abs_mean_sum = signal_abs_mean_sum + excluded.signal_abs_mean_sum,
                        signal_abs_mean_weight = signal_abs_mean_weight + excluded.signal_abs_mean_weight,
                        signal_stddev_sum = signal_stddev_sum + excluded.signal_stddev_sum,
                        signal_stddev_weight = signal_stddev_weight + excluded.signal_stddev_weight,
                        audit_repeat_score_sum = audit_repeat_score_sum + excluded.audit_repeat_score_sum,
                        audit_repeat_score_count = audit_repeat_score_count + excluded.audit_repeat_score_count,
                        updated_at = excluded.updated_at
                    """,
                    [
                        (
                            row["bucket_start"],
                            row["node"],
                            row["sample_packets"],
                            row["sample_bytes"],
                            row["rejected_packets"],
                            row["rejected_bytes"],
                            row["signal_mean_sum"],
                            row["signal_mean_weight"],
                            row["signal_abs_mean_sum"],
                            row["signal_abs_mean_weight"],
                            row["signal_stddev_sum"],
                            row["signal_stddev_weight"],
                            row["audit_repeat_score_sum"],
                            row["audit_repeat_score_count"],
                            now,
                            row["updated_at"],
                        )
                        for row in node_rows
                    ],
                )
                conn.executemany(
                    """
                    INSERT INTO system_metric_buckets (
                        bucket_start,
                        pool_bytes_sum,
                        pool_fill_pct_sum,
                        source_nodes_sum,
                        rejecting_nodes_sum,
                        waterfall_nodes_sum,
                        sample_count,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bucket_start) DO UPDATE SET
                        pool_bytes_sum = pool_bytes_sum + excluded.pool_bytes_sum,
                        pool_fill_pct_sum = pool_fill_pct_sum + excluded.pool_fill_pct_sum,
                        source_nodes_sum = source_nodes_sum + excluded.source_nodes_sum,
                        rejecting_nodes_sum = rejecting_nodes_sum + excluded.rejecting_nodes_sum,
                        waterfall_nodes_sum = waterfall_nodes_sum + excluded.waterfall_nodes_sum,
                        sample_count = sample_count + excluded.sample_count,
                        updated_at = excluded.updated_at
                    """,
                    [
                        (
                            row["bucket_start"],
                            row["pool_bytes_sum"],
                            row["pool_fill_pct_sum"],
                            row["source_nodes_sum"],
                            row["rejecting_nodes_sum"],
                            row["waterfall_nodes_sum"],
                            row["sample_count"],
                            now,
                            row["updated_at"],
                        )
                        for row in system_rows
                    ],
                )
                conn.execute(
                    "DELETE FROM node_metric_buckets WHERE bucket_start < ?",
                    (cutoff_bucket,),
                )
                conn.execute(
                    "DELETE FROM system_metric_buckets WHERE bucket_start < ?",
                    (cutoff_bucket,),
                )
            return True
    except Exception as exc:
        log(f"[!] Could not flush metrics DB at {METRICS_DB_PATH}: {exc}")
        return False


def _parse_statistics_range_seconds(value: Optional[str]) -> int:
    if not value:
        return METRICS_DEFAULT_RANGE_SEC

    raw = str(value).strip().lower()
    units = {"m": 60, "h": 60 * 60, "d": 24 * 60 * 60}
    if raw[-1:] in units:
        try:
            seconds = int(float(raw[:-1]) * units[raw[-1]])
        except ValueError:
            return METRICS_DEFAULT_RANGE_SEC
    else:
        try:
            seconds = int(raw)
        except ValueError:
            return METRICS_DEFAULT_RANGE_SEC

    max_seconds = METRICS_RETENTION_DAYS * 24 * 60 * 60
    return max(METRICS_BUCKET_SEC, min(seconds, max_seconds))


def _safe_average(total: float, weight: float) -> Optional[float]:
    if not weight:
        return None
    return round(float(total) / float(weight), 4)


def _build_node_metric_point(row, bucket_step: int) -> Dict[str, object]:
    sample_packets = int(row["sample_packets"] or 0)
    sample_bytes = int(row["sample_bytes"] or 0)
    rejected_packets = int(row["rejected_packets"] or 0)
    rejected_bytes = int(row["rejected_bytes"] or 0)
    return {
        "sample_packets": sample_packets,
        "sample_bytes": sample_bytes,
        "rejected_packets": rejected_packets,
        "rejected_bytes": rejected_bytes,
        "throughput_bytes_per_sec": round(sample_bytes / max(1, bucket_step), 2),
        "avg_signal": _safe_average(
            row["signal_mean_sum"] or 0.0,
            row["signal_mean_weight"] or 0.0,
        ),
        "avg_abs_signal": _safe_average(
            row["signal_abs_mean_sum"] or 0.0,
            row["signal_abs_mean_weight"] or 0.0,
        ),
        "avg_signal_stddev": _safe_average(
            row["signal_stddev_sum"] or 0.0,
            row["signal_stddev_weight"] or 0.0,
        ),
        "avg_repeat_score": _safe_average(
            row["audit_repeat_score_sum"] or 0.0,
            row["audit_repeat_score_count"] or 0.0,
        ),
    }


def _entropy_persistence_enabled() -> bool:
    return ENTROPY_PERSIST_PATH is not None and (
        bool(ENTROPY_PERSIST_KEY) or ENTROPY_PERSIST_KEY_FILE is not None
    )


def _read_entropy_persist_key() -> bytes:
    if ENTROPY_PERSIST_KEY_FILE is not None:
        key_text = ENTROPY_PERSIST_KEY_FILE.read_text(encoding="utf-8").strip()
    else:
        key_text = ENTROPY_PERSIST_KEY.strip()

    if not key_text:
        raise ValueError("empty entropy persistence key")

    try:
        decoded = base64.b64decode(key_text, validate=True)
        if len(decoded) >= 32:
            return decoded
    except Exception:
        pass

    return key_text.encode("utf-8")


def _derive_entropy_checkpoint_keys(salt: bytes) -> tuple[bytes, bytes]:
    master_key = _read_entropy_persist_key()
    material = hashlib.pbkdf2_hmac("sha512", master_key, salt, 210_000, dklen=128)
    return material[:64], material[64:]


def _checkpoint_keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        stream.extend(
            hmac.new(
                enc_key,
                nonce + counter.to_bytes(8, "big"),
                hashlib.sha512,
            ).digest()
        )
        counter += 1
    return bytes(stream[:length])


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _pack_entropy_checkpoint(pool_snapshot: bytes) -> bytes:
    salt = os.urandom(32)
    nonce = os.urandom(24)
    enc_key, mac_key = _derive_entropy_checkpoint_keys(salt)
    ciphertext = _xor_bytes(
        pool_snapshot,
        _checkpoint_keystream(enc_key, nonce, len(pool_snapshot)),
    )
    payload = {
        "version": 1,
        "created_at": time.time(),
        "pool_size": len(pool_snapshot),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    mac_body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["hmac_b64"] = base64.b64encode(
        hmac.new(mac_key, mac_body, hashlib.sha512).digest()
    ).decode("ascii")
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unpack_entropy_checkpoint(checkpoint_bytes: bytes) -> bytes:
    payload = json.loads(checkpoint_bytes.decode("utf-8"))
    if payload.get("version") != 1:
        raise ValueError("unsupported entropy checkpoint version")

    hmac_b64 = payload.pop("hmac_b64", "")
    salt = base64.b64decode(payload["salt_b64"], validate=True)
    nonce = base64.b64decode(payload["nonce_b64"], validate=True)
    ciphertext = base64.b64decode(payload["ciphertext_b64"], validate=True)
    enc_key, mac_key = _derive_entropy_checkpoint_keys(salt)

    mac_body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_mac = hmac.new(mac_key, mac_body, hashlib.sha512).digest()
    supplied_mac = base64.b64decode(hmac_b64, validate=True)
    if not hmac.compare_digest(expected_mac, supplied_mac):
        raise ValueError("entropy checkpoint authentication failed")

    pool_snapshot = _xor_bytes(ciphertext, _checkpoint_keystream(enc_key, nonce, len(ciphertext)))
    declared_size = int(payload.get("pool_size", -1))
    if declared_size != len(pool_snapshot):
        raise ValueError("entropy checkpoint size mismatch")
    return pool_snapshot


def _rekey_restored_entropy(restored_pool: bytes) -> bytes:
    if not ENTROPY_REKEY_RESTORED_POOL or not restored_pool:
        return restored_pool

    restored_seed = os.urandom(64)
    output = bytearray()
    local_state = hashlib.sha512(
        restored_seed + hashlib.sha512(restored_pool).digest()
    ).digest()
    for offset in range(0, len(restored_pool), MIX_BLOCK_BYTES):
        block = restored_pool[offset : offset + MIX_BLOCK_BYTES]
        local_state = hashlib.sha512(local_state + block + os.urandom(32)).digest()
        output.extend(local_state)
    return bytes(output[: len(restored_pool)])


def _load_entropy_checkpoint():
    global entropy_checkpoint_loaded, generator_state
    if not _entropy_persistence_enabled():
        return
    if not ENTROPY_PERSIST_PATH.exists():
        entropy_checkpoint_loaded = True
        return

    try:
        restored_pool = _unpack_entropy_checkpoint(ENTROPY_PERSIST_PATH.read_bytes())
        restored_pool = _rekey_restored_entropy(restored_pool)
        with pool_lock:
            entropy_pool.clear()
            entropy_pool.extend(restored_pool[-POOL_MAX_BYTES:])
        with generator_state_lock:
            generator_state = hashlib.sha512(
                generator_state + hashlib.sha512(restored_pool).digest() + os.urandom(64)
            ).digest()
        entropy_checkpoint_loaded = True
        log(
            f"[*] Restored encrypted entropy checkpoint "
            f"bytes={len(restored_pool)} path={ENTROPY_PERSIST_PATH}"
        )
    except Exception as exc:
        entropy_checkpoint_loaded = False
        log(f"[!] Ignoring invalid entropy checkpoint {ENTROPY_PERSIST_PATH}: {exc}")


def _write_entropy_checkpoint(snapshot: Optional[bytes] = None) -> bool:
    global last_entropy_checkpoint_at
    if not _entropy_persistence_enabled():
        return True

    with entropy_checkpoint_lock:
        if snapshot is None:
            with pool_lock:
                snapshot = _entropy_checkpoint_snapshot_locked()
        try:
            ENTROPY_PERSIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            checkpoint_bytes = _pack_entropy_checkpoint(snapshot)
            tmp_path = ENTROPY_PERSIST_PATH.with_name(f".{ENTROPY_PERSIST_PATH.name}.tmp")
            tmp_path.write_bytes(checkpoint_bytes)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, ENTROPY_PERSIST_PATH)
            last_entropy_checkpoint_at = time.time()
            return True
        except Exception as exc:
            log(f"[!] Could not persist entropy checkpoint to {ENTROPY_PERSIST_PATH}: {exc}")
            return False


def _request_entropy_checkpoint():
    if _entropy_persistence_enabled():
        entropy_checkpoint_event.set()


def _persist_after_consume_if_needed(snapshot: bytes):
    if _entropy_persistence_enabled() and ENTROPY_PERSIST_ON_CONSUME:
        return _write_entropy_checkpoint(snapshot)
    else:
        _request_entropy_checkpoint()
        return True


def _entropy_checkpoint_snapshot_locked() -> bytes:
    max_bytes = max(1, min(ENTROPY_PERSIST_MAX_BYTES, POOL_MAX_BYTES))
    return bytes(entropy_pool[-max_bytes:])


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
    _request_entropy_checkpoint()


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
    snapshot = None
    if _entropy_persistence_enabled() and ENTROPY_PERSIST_ON_CONSUME:
        with entropy_checkpoint_lock:
            with pool_lock:
                if len(entropy_pool) < chunk_size:
                    return None
                data = bytes(entropy_pool[-chunk_size:])
                del entropy_pool[-chunk_size:]
                snapshot = _entropy_checkpoint_snapshot_locked()
            if not _write_entropy_checkpoint(snapshot):
                with pool_lock:
                    entropy_pool.extend(data)
                    _clamp_pool()
                return None
            return data

    with pool_lock:
        if len(entropy_pool) < chunk_size:
            return None
        data = bytes(entropy_pool[-chunk_size:])
        del entropy_pool[-chunk_size:]
        snapshot = _entropy_checkpoint_snapshot_locked()
    _persist_after_consume_if_needed(snapshot)
    return data


def _pop_entropy_chunk_up_to(chunk_size: int) -> Optional[bytes]:
    global entropy_pool
    snapshot = None
    if _entropy_persistence_enabled() and ENTROPY_PERSIST_ON_CONSUME:
        with entropy_checkpoint_lock:
            with pool_lock:
                if not entropy_pool:
                    return None
                actual_size = min(len(entropy_pool), chunk_size)
                data = bytes(entropy_pool[-actual_size:])
                del entropy_pool[-actual_size:]
                snapshot = _entropy_checkpoint_snapshot_locked()
            if not _write_entropy_checkpoint(snapshot):
                with pool_lock:
                    entropy_pool.extend(data)
                    _clamp_pool()
                return None
            return data

    with pool_lock:
        if not entropy_pool:
            return None
        actual_size = min(len(entropy_pool), chunk_size)
        data = bytes(entropy_pool[-actual_size:])
        del entropy_pool[-actual_size:]
        snapshot = _entropy_checkpoint_snapshot_locked()
    _persist_after_consume_if_needed(snapshot)
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
    if rejected:
        _record_node_metric(
            node_name,
            rejected_packets=1,
            rejected_bytes=max(0, int(raw_bytes)),
        )
    else:
        _record_node_metric(
            node_name,
            sample_packets=1,
            sample_bytes=max(0, int(raw_bytes)),
        )


def _touch_node_stats(node_name: str):
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
    _record_node_metric(
        node_name,
        timestamp=updated_at,
        signal_mean=audit_payload["mean"],
        signal_abs_mean=abs(audit_payload["mean"]),
        signal_stddev=audit_payload["stddev"],
        signal_sample_count=audit_payload["sample_count"],
        audit_repeat_score=audit_payload["repeat_score"],
    )
    log(
        f"[*] Source audit updated for node={node_name} "
        f"(repeat_score={audit_payload['repeat_score']:.4f}, "
        f"accepting_samples={audit_payload['accepting_samples']})"
    )


def _counter_delta(current_value, previous_value) -> int:
    current = _optional_int(current_value) or 0
    previous = _optional_int(previous_value)
    if previous is None:
        return 0
    if current < previous:
        return max(0, current)
    return max(0, current - previous)


def _handle_node_metrics(message: dict):
    node_name = message.get("node")
    if not node_name:
        return

    stats = message.get("stats") if isinstance(message.get("stats"), dict) else {}
    signal = message.get("signal") if isinstance(message.get("signal"), dict) else {}
    timestamp = _optional_float(message.get("timestamp")) or time.time()
    _touch_node_stats(node_name)

    with node_runtime_stats_lock:
        previous = node_runtime_stats.setdefault(node_name, {})
        health_rejected_delta = _counter_delta(
            stats.get("health_rejected_packets"),
            previous.get("health_rejected_packets"),
        )
        previous.update(
            {
                "updated_at": time.time(),
                "sample_packets_sent": _optional_int(stats.get("sample_packets_sent")) or 0,
                "sample_bytes_sent": _optional_int(stats.get("sample_bytes_sent")) or 0,
                "waterfalls_sent": _optional_int(stats.get("waterfalls_sent")) or 0,
                "source_audits_sent": _optional_int(stats.get("source_audits_sent")) or 0,
                "health_rejected_packets": _optional_int(stats.get("health_rejected_packets")) or 0,
                "rct_rejected_packets": _optional_int(stats.get("rct_rejected_packets")) or 0,
                "apt_rejected_packets": _optional_int(stats.get("apt_rejected_packets")) or 0,
            }
        )

    if health_rejected_delta:
        _record_node_metric(
            node_name,
            timestamp=timestamp,
            rejected_packets=health_rejected_delta,
        )

    if signal:
        _record_node_metric(
            node_name,
            timestamp=timestamp,
            signal_mean=_optional_float(signal.get("mean")),
            signal_abs_mean=_optional_float(signal.get("abs_mean")),
            signal_stddev=_optional_float(signal.get("stddev")),
            signal_sample_count=_optional_int(signal.get("sample_count")),
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
        elif msg_type == "node_metrics":
            _handle_node_metrics(message)


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
    sources_snapshot = _snapshot_sources()
    with pool_lock:
        pool_bytes = len(entropy_pool)
    with waterfalls_lock:
        node_count = len(waterfalls)
    source_nodes = len(sources_snapshot)
    rejecting_nodes = sum(
        1 for source in sources_snapshot if not source.get("accepting_samples", True)
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
            "entropy_persistence_enabled": _entropy_persistence_enabled(),
            "entropy_persist_path": str(ENTROPY_PERSIST_PATH)
            if ENTROPY_PERSIST_PATH is not None
            else None,
            "entropy_persist_on_consume": ENTROPY_PERSIST_ON_CONSUME,
            "entropy_rekey_restored_pool": ENTROPY_REKEY_RESTORED_POOL,
            "last_entropy_checkpoint_at": last_entropy_checkpoint_at or None,
            "metrics_enabled": _metrics_enabled(),
            "metrics_bucket_seconds": METRICS_BUCKET_SEC,
            "metrics_retention_days": METRICS_RETENTION_DAYS,
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


@app.route("/api/node-status/<node_name>")
def get_node_status(node_name: str):
    _cleanup_stale_nodes()
    now = time.time()
    
    with source_audits_lock:
        audit_info = source_audits.get(node_name)
        
    summary = _source_audit_summary(audit_info, now=now)
    
    with node_stats_lock:
        stats = node_stats.get(node_name, {})
        last_seen = stats.get("last_seen", 0.0)
        rejected_packets = stats.get("rejected_packets", 0)

    return jsonify({
        "node": node_name,
        "status": summary["status"],
        "accepting_samples": summary["accepting_samples"],
        "repeat_score": summary["repeat_score"],
        "repeat_score_threshold": SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD,
        "age_sec": summary["age_sec"],
        "max_age_sec": SOURCE_AUDIT_MAX_AGE_SEC,
        "last_seen_age_sec": round(now - last_seen, 1) if last_seen else None,
        "rejected_packets": rejected_packets
    })


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


def _statistics_node_filter():
    node = (request.args.get("node") or "").strip()
    if not node or node.lower() == "all":
        return None
    return node[:128]


def _query_metric_nodes(start_bucket: int):
    if not _init_metrics_db():
        return []
    try:
        with metrics_db_lock:
            with _connect_metrics_db() as conn:
                rows = conn.execute(
                    """
                    SELECT DISTINCT node
                    FROM node_metric_buckets
                    WHERE bucket_start >= ?
                    ORDER BY node
                    """,
                    (start_bucket,),
                ).fetchall()
        return [row[0] for row in rows]
    except Exception as exc:
        log(f"[!] Could not query metric nodes: {exc}")
        return []


def _query_statistics_points(range_seconds: int, node_filter: Optional[str]):
    _flush_metrics_to_db()

    now = time.time()
    end_bucket = _metrics_bucket_start(now)
    start_bucket = _metrics_bucket_start(now - range_seconds)
    bucket_step = METRICS_BUCKET_SEC

    node_where = "bucket_start BETWEEN ? AND ?"
    params = [start_bucket, end_bucket]
    if node_filter:
        node_where += " AND node = ?"
        params.append(node_filter)

    node_rows = {}
    per_node_rows: Dict[int, Dict[str, Dict[str, object]]] = {}
    system_rows = {}
    if _init_metrics_db():
        try:
            with metrics_db_lock:
                with _connect_metrics_db() as conn:
                    conn.row_factory = sqlite3.Row
                    for row in conn.execute(
                        f"""
                        SELECT
                            bucket_start,
                            SUM(sample_packets) AS sample_packets,
                            SUM(sample_bytes) AS sample_bytes,
                            SUM(rejected_packets) AS rejected_packets,
                            SUM(rejected_bytes) AS rejected_bytes,
                            SUM(signal_mean_sum) AS signal_mean_sum,
                            SUM(signal_mean_weight) AS signal_mean_weight,
                            SUM(signal_abs_mean_sum) AS signal_abs_mean_sum,
                            SUM(signal_abs_mean_weight) AS signal_abs_mean_weight,
                            SUM(signal_stddev_sum) AS signal_stddev_sum,
                            SUM(signal_stddev_weight) AS signal_stddev_weight,
                            SUM(audit_repeat_score_sum) AS audit_repeat_score_sum,
                            SUM(audit_repeat_score_count) AS audit_repeat_score_count
                        FROM node_metric_buckets
                        WHERE {node_where}
                        GROUP BY bucket_start
                        ORDER BY bucket_start
                        """,
                        params,
                    ):
                        node_rows[int(row[0])] = row

                    for row in conn.execute(
                        f"""
                        SELECT
                            bucket_start,
                            node,
                            sample_packets,
                            sample_bytes,
                            rejected_packets,
                            rejected_bytes,
                            signal_mean_sum,
                            signal_mean_weight,
                            signal_abs_mean_sum,
                            signal_abs_mean_weight,
                            signal_stddev_sum,
                            signal_stddev_weight,
                            audit_repeat_score_sum,
                            audit_repeat_score_count
                        FROM node_metric_buckets
                        WHERE {node_where}
                        ORDER BY bucket_start, node
                        """,
                        params,
                    ):
                        bucket_nodes = per_node_rows.setdefault(int(row["bucket_start"]), {})
                        bucket_nodes[str(row["node"])] = _build_node_metric_point(row, bucket_step)

                    for row in conn.execute(
                        """
                        SELECT
                            bucket_start,
                            pool_bytes_sum,
                            pool_fill_pct_sum,
                            source_nodes_sum,
                            rejecting_nodes_sum,
                            waterfall_nodes_sum,
                            sample_count
                        FROM system_metric_buckets
                        WHERE bucket_start BETWEEN ? AND ?
                        ORDER BY bucket_start
                        """,
                        (start_bucket, end_bucket),
                    ):
                        system_rows[int(row[0])] = row
        except Exception as exc:
            log(f"[!] Could not query statistics points: {exc}")

    points = []
    bucket = start_bucket
    while bucket <= end_bucket:
        node_row = node_rows.get(bucket)
        system_row = system_rows.get(bucket)

        sample_packets = int(node_row[1] or 0) if node_row else 0
        sample_bytes = int(node_row[2] or 0) if node_row else 0
        rejected_packets = int(node_row[3] or 0) if node_row else 0
        rejected_bytes = int(node_row[4] or 0) if node_row else 0

        point = {
            "ts": bucket,
            "sample_packets": sample_packets,
            "sample_bytes": sample_bytes,
            "rejected_packets": rejected_packets,
            "rejected_bytes": rejected_bytes,
            "throughput_bytes_per_sec": round(sample_bytes / max(1, bucket_step), 2),
            "avg_signal": None,
            "avg_abs_signal": None,
            "avg_signal_stddev": None,
            "avg_repeat_score": None,
            "nodes": per_node_rows.get(bucket, {}),
            "pool_bytes_avg": None,
            "pool_fill_pct_avg": None,
            "source_nodes_avg": None,
            "rejecting_nodes_avg": None,
            "waterfall_nodes_avg": None,
        }

        if node_row:
            point["avg_signal"] = _safe_average(node_row[5] or 0.0, node_row[6] or 0.0)
            point["avg_abs_signal"] = _safe_average(node_row[7] or 0.0, node_row[8] or 0.0)
            point["avg_signal_stddev"] = _safe_average(node_row[9] or 0.0, node_row[10] or 0.0)
            point["avg_repeat_score"] = _safe_average(node_row[11] or 0.0, node_row[12] or 0.0)

        if system_row and system_row[6]:
            count = float(system_row[6])
            point["pool_bytes_avg"] = round(float(system_row[1] or 0.0) / count, 2)
            point["pool_fill_pct_avg"] = round(float(system_row[2] or 0.0) / count, 4)
            point["source_nodes_avg"] = round(float(system_row[3] or 0.0) / count, 2)
            point["rejecting_nodes_avg"] = round(float(system_row[4] or 0.0) / count, 2)
            point["waterfall_nodes_avg"] = round(float(system_row[5] or 0.0) / count, 2)

        points.append(point)
        bucket += bucket_step

    return {
        "bucket_seconds": bucket_step,
        "range_seconds": range_seconds,
        "generated_at": now,
        "node": node_filter or "all",
        "nodes": _query_metric_nodes(start_bucket),
        "points": points,
    }


def _query_statistics_summary(range_seconds: int, node_filter: Optional[str]):
    _flush_metrics_to_db()

    now = time.time()
    start_bucket = _metrics_bucket_start(now - range_seconds)
    end_bucket = _metrics_bucket_start(now)
    node_where = "bucket_start BETWEEN ? AND ?"
    params = [start_bucket, end_bucket]
    if node_filter:
        node_where += " AND node = ?"
        params.append(node_filter)

    totals = {
        "sample_packets": 0,
        "sample_bytes": 0,
        "rejected_packets": 0,
        "rejected_bytes": 0,
        "avg_signal": None,
        "avg_abs_signal": None,
        "avg_signal_stddev": None,
        "avg_repeat_score": None,
        "avg_throughput_bytes_per_sec": 0.0,
    }
    if _init_metrics_db():
        try:
            with metrics_db_lock:
                with _connect_metrics_db() as conn:
                    row = conn.execute(
                        f"""
                        SELECT
                            SUM(sample_packets),
                            SUM(sample_bytes),
                            SUM(rejected_packets),
                            SUM(rejected_bytes),
                            SUM(signal_mean_sum),
                            SUM(signal_mean_weight),
                            SUM(signal_abs_mean_sum),
                            SUM(signal_abs_mean_weight),
                            SUM(signal_stddev_sum),
                            SUM(signal_stddev_weight),
                            SUM(audit_repeat_score_sum),
                            SUM(audit_repeat_score_count)
                        FROM node_metric_buckets
                        WHERE {node_where}
                        """,
                        params,
                    ).fetchone()
            if row:
                totals["sample_packets"] = int(row[0] or 0)
                totals["sample_bytes"] = int(row[1] or 0)
                totals["rejected_packets"] = int(row[2] or 0)
                totals["rejected_bytes"] = int(row[3] or 0)
                totals["avg_signal"] = _safe_average(row[4] or 0.0, row[5] or 0.0)
                totals["avg_abs_signal"] = _safe_average(row[6] or 0.0, row[7] or 0.0)
                totals["avg_signal_stddev"] = _safe_average(row[8] or 0.0, row[9] or 0.0)
                totals["avg_repeat_score"] = _safe_average(row[10] or 0.0, row[11] or 0.0)
                totals["avg_throughput_bytes_per_sec"] = round(
                    totals["sample_bytes"] / max(1, range_seconds),
                    2,
                )
        except Exception as exc:
            log(f"[!] Could not query statistics summary: {exc}")

    sources_snapshot = _snapshot_sources()
    with pool_lock:
        pool_bytes = len(entropy_pool)
    with waterfalls_lock:
        waterfall_nodes = len(waterfalls)
    return {
        "generated_at": now,
        "range_seconds": range_seconds,
        "node": node_filter or "all",
        "metrics_enabled": _metrics_enabled(),
        "metrics_bucket_seconds": METRICS_BUCKET_SEC,
        "metrics_retention_days": METRICS_RETENTION_DAYS,
        "current": {
            "pool_bytes": pool_bytes,
            "pool_fill_pct": round(_pool_fill_pct(), 2),
            "source_nodes": len(sources_snapshot),
            "rejecting_source_nodes": sum(
                1 for source in sources_snapshot if not source.get("accepting_samples", True)
            ),
            "waterfall_nodes": waterfall_nodes,
        },
        "totals": totals,
    }


@app.route("/api/statistics/timeseries")
def api_statistics_timeseries():
    range_seconds = _parse_statistics_range_seconds(request.args.get("range"))
    return jsonify(_query_statistics_points(range_seconds, _statistics_node_filter()))


@app.route("/api/statistics/summary")
def api_statistics_summary():
    range_seconds = _parse_statistics_range_seconds(request.args.get("range"))
    return jsonify(_query_statistics_summary(range_seconds, _statistics_node_filter()))


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


def _meets_password_requirements(password: str, required_charsets):
    return all(any(ch in charset for ch in password) for charset in required_charsets)


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
    required_charsets = []
    if use_lowercase:
        charset = string.ascii_lowercase
        alphabet += charset
        required_charsets.append(charset)
    if use_uppercase:
        charset = string.ascii_uppercase
        alphabet += charset
        required_charsets.append(charset)
    if use_numbers:
        charset = string.digits
        alphabet += charset
        required_charsets.append(charset)
    if use_special:
        charset = "!@#$%^&*()_+=-[]{}|;:,.<>?"
        alphabet += charset
        required_charsets.append(charset)

    if not alphabet:
        return jsonify({"error": "Empty alphabet"}), 400
    if length < len(required_charsets):
        return jsonify({"error": "Length is too short for selected character classes"}), 400

    rng = EntropyRNG()
    passwords = []
    try:
        for _ in range(count):
            while True:
                pwd = "".join(rng.choice(alphabet) for _ in range(length))
                if _meets_password_requirements(pwd, required_charsets):
                    break
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


def entropy_checkpoint_worker():
    if not _entropy_persistence_enabled():
        return

    while True:
        entropy_checkpoint_event.wait(ENTROPY_PERSIST_INTERVAL_SEC)
        entropy_checkpoint_event.clear()

        if time.time() - last_entropy_checkpoint_at < ENTROPY_PERSIST_INTERVAL_SEC:
            continue

        _write_entropy_checkpoint()


def metrics_flush_worker():
    if not _metrics_enabled():
        return

    while True:
        time.sleep(METRICS_FLUSH_INTERVAL_SEC)
        _flush_metrics_to_db()


def _start_background_threads():
    _load_entropy_checkpoint()
    if _entropy_persistence_enabled():
        atexit.register(_write_entropy_checkpoint)
    if _metrics_enabled():
        atexit.register(_flush_metrics_to_db)

    log(
        "[*] Entropy generator starting "
        f"(http_port={HTTP_PORT}, telnet_port={TELNET_PORT}, "
        f"udp_host={UDP_HOST}, udp_port={UDP_PORT}, "
        f"pool_size_mb={POOL_SIZE_MB}, mix_block_bytes={MIX_BLOCK_BYTES}, "
        f"telnet_session_bytes={_effective_telnet_session_bytes()}, "
        f"stream_chunk_bytes={STREAM_CHUNK_BYTES}, "
        f"low_pool_threshold_pct={LOW_POOL_THRESHOLD_PCT}, "
        f"throttle_bytes_per_sec={THROTTLE_BYTES_PER_SEC}, "
        f"source_audit_repeat_score_threshold={SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD}, "
        f"entropy_persistence_enabled={_entropy_persistence_enabled()}, "
        f"entropy_persist_path={ENTROPY_PERSIST_PATH}, "
        f"entropy_persist_max_bytes={ENTROPY_PERSIST_MAX_BYTES}, "
        f"entropy_persist_on_consume={ENTROPY_PERSIST_ON_CONSUME}, "
        f"metrics_enabled={_metrics_enabled()}, "
        f"metrics_db_path={METRICS_DB_PATH}, "
        f"metrics_bucket_sec={METRICS_BUCKET_SEC})"
    )
    threading.Thread(target=udp_receiver_worker, daemon=True).start()
    threading.Thread(target=telnet_server_worker, daemon=True).start()
    threading.Thread(target=raw_telnet_server_worker, daemon=True).start()
    threading.Thread(target=cleanup_incomplete_images_worker, daemon=True).start()
    threading.Thread(target=stats_logger_worker, daemon=True).start()
    threading.Thread(target=entropy_checkpoint_worker, daemon=True).start()
    threading.Thread(target=metrics_flush_worker, daemon=True).start()
    log("[*] Entropy generator background threads online")


if AUTOSTART_THREADS:
    _start_background_threads()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)
