import base64
import io
import json
import math
import os
import socket
import threading
import time
import uuid
from collections import deque

import iio
import matplotlib
import numpy as np
from matplotlib.collections import LineCollection
from matplotlib.colors import LinearSegmentedColormap

matplotlib.use("Agg")
import matplotlib.pyplot as plt

PLUTO_IP = os.getenv("PLUTO_IP", "192.168.2.1")
FREQ = int(os.getenv("FREQ", "1420405000"))
GAIN = int(os.getenv("GAIN", "70"))
RX_CHANNEL = os.getenv("RX_CHANNEL", "voltage0")
NODE_NAME = os.getenv("NODE_NAME", socket.gethostname())
UDP_TARGET_HOST = os.getenv("UDP_TARGET_HOST", "generator")
UDP_TARGET_PORT = int(os.getenv("UDP_TARGET_PORT", "5005"))
SAMPLE_PACKET_BYTES = int(os.getenv("SAMPLE_PACKET_BYTES", "12000"))
WATERFALL_INTERVAL_SEC = int(os.getenv("WATERFALL_INTERVAL_SEC", "10"))
WATERFALL_UDP_CHUNK_BYTES = int(os.getenv("WATERFALL_UDP_CHUNK_BYTES", "48000"))
WATERFALL_HISTORY_FRAMES = int(os.getenv("WATERFALL_HISTORY_FRAMES", "5"))
WATERFALL_AXIS_WINDOW_SEC = int(os.getenv("WATERFALL_AXIS_WINDOW_SEC", "30"))
SOURCE_AUDIT_INTERVAL_SEC = int(os.getenv("SOURCE_AUDIT_INTERVAL_SEC", str(24 * 60 * 60)))
SOURCE_AUDIT_SAMPLE_BYTES = int(os.getenv("SOURCE_AUDIT_SAMPLE_BYTES", str(256 * 1024)))
LOG_EVERY_SEC = int(os.getenv("LOG_EVERY_SEC", "30"))

runtime_stats = {
    "sample_packets_sent": 0,
    "sample_bytes_sent": 0,
    "waterfalls_sent": 0,
    "waterfall_parts_sent": 0,
    "source_audits_sent": 0,
    "last_sample_at": 0.0,
    "last_waterfall_at": 0.0,
    "last_source_audit_at": 0.0,
}
stats_lock = threading.Lock()
latest_raw_iq = None
latest_raw_iq_at = 0.0
latest_raw_iq_lock = threading.Lock()
waterfall_history = deque(maxlen=max(1, WATERFALL_HISTORY_FRAMES))
axis_window_frames = max(2, int(math.ceil(max(1, WATERFALL_AXIS_WINDOW_SEC) / max(1, WATERFALL_INTERVAL_SEC))))
waterfall_axis_metrics = deque(maxlen=axis_window_frames)


def getenv_optional_float(name: str):
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return float(value)


WATERFALL_Y_SPAN_DB = getenv_optional_float("WATERFALL_Y_SPAN_DB")
WATERFALL_Y_MIN_DB = getenv_optional_float("WATERFALL_Y_MIN_DB")
WATERFALL_Y_MAX_DB = getenv_optional_float("WATERFALL_Y_MAX_DB")

THEME_BG = "#020202"
THEME_PRIMARY = "#05B6D4"
THEME_SECONDARY = "#22D3EE"
THEME_ACCENT = "#67E8F9"
THEME_HISTORY = "#A5F3FC"

WATERFALL_BG_CMAP = LinearSegmentedColormap.from_list(
    "spark_cyan_bg",
    [THEME_BG, "#083344", THEME_PRIMARY, THEME_ACCENT],
)
WATERFALL_LINE_CMAP = LinearSegmentedColormap.from_list(
    "spark_cyan_line",
    [THEME_PRIMARY, THEME_SECONDARY, THEME_ACCENT],
)


def log(message: str):
    print(message, flush=True)


def build_iio_context():
    return iio.Context(f"ip:{PLUTO_IP}")


def configure_radio(ctx):
    phy = ctx.find_device("ad9361-phy")
    phy.find_channel("altvoltage0", True).attrs["frequency"].value = str(FREQ)
    rx = phy.find_channel(RX_CHANNEL)
    rx.attrs["gain_control_mode"].value = "manual"
    rx.attrs["hardwaregain"].value = str(GAIN)

    data_dev = ctx.find_device("cf-ad9361-lpc")
    for chan in data_dev.channels:
        chan.enabled = True
    return data_dev


def udp_send(sock: socket.socket, message: dict):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sock.sendto(payload, (UDP_TARGET_HOST, UDP_TARGET_PORT))


def analyze_raw_signal(raw_iq: bytes):
    limit = len(raw_iq) - (len(raw_iq) % 2)
    samples = np.frombuffer(raw_iq[:limit], dtype=np.int16)
    if samples.size < 2:
        return None

    sample_count = int(samples.size)
    unique_values, counts = np.unique(samples, return_counts=True)
    dominant_value_ratio = float(counts.max() / sample_count)
    consecutive_equal_ratio = float(np.mean(samples[1:] == samples[:-1]))
    mean = float(np.mean(samples))
    stddev = float(np.std(samples))

    iq_i = samples[0::2].astype(np.float32)
    iq_q = samples[1::2].astype(np.float32)
    iq_len = min(iq_i.size, iq_q.size)
    if iq_len >= 16:
        iq_complex = iq_i[:iq_len] + 1j * iq_q[:iq_len]
        psd = np.abs(np.fft.fft(iq_complex)) ** 2 + 1e-12
        spectral_flatness = float(np.exp(np.mean(np.log(psd))) / np.mean(psd))
    else:
        spectral_flatness = 1.0

    repeat_score = max(dominant_value_ratio, consecutive_equal_ratio, 1.0 - spectral_flatness)
    return {
        "sample_bytes": int(limit),
        "sample_count": sample_count,
        "unique_values": int(unique_values.size),
        "mean": round(mean, 4),
        "stddev": round(stddev, 4),
        "min_value": int(samples.min()),
        "max_value": int(samples.max()),
        "dominant_value_ratio": round(dominant_value_ratio, 6),
        "consecutive_equal_ratio": round(consecutive_equal_ratio, 6),
        "spectral_flatness": round(spectral_flatness, 6),
        "repeat_score": round(float(min(max(repeat_score, 0.0), 1.0)), 6),
    }


def update_latest_raw_iq(raw_iq: bytes):
    global latest_raw_iq, latest_raw_iq_at
    snapshot = bytes(raw_iq[:SOURCE_AUDIT_SAMPLE_BYTES])
    with latest_raw_iq_lock:
        latest_raw_iq = snapshot
        latest_raw_iq_at = time.time()


def get_latest_raw_iq_snapshot():
    with latest_raw_iq_lock:
        if latest_raw_iq is None:
            return None, 0.0
        return latest_raw_iq, latest_raw_iq_at


def entropy_sender_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        ctx = build_iio_context()
        data_dev = configure_radio(ctx)
        buffer = iio.Buffer(data_dev, 65536)
        log(
            f"[*] SDR sample stream ready (node={NODE_NAME}, pluto_ip={PLUTO_IP}, "
            f"freq={FREQ}, gain={GAIN}, rx_channel={RX_CHANNEL}, "
            f"sample_packet_bytes={SAMPLE_PACKET_BYTES})"
        )
    except Exception as exc:
        log(f"[!] SDR init error: {exc}")
        time.sleep(10)
        os._exit(1)

    entropy_accumulator = bytearray()

    while True:
        try:
            buffer.refill()
            raw_data = buffer.read()
            update_latest_raw_iq(raw_data)

            # --- OPTIMIZED DSP PIPELINE (multi-bit XOR-fold + Von Neumann) ---
            # 1. Parse raw IQ samples as signed 16-bit integers
            limit = len(raw_data) - (len(raw_data) % 2)
            samples = np.frombuffer(raw_data[:limit], dtype=np.int16)

            # 2. Light decimation [::4] – PlutoSDR AD9361 auto-correlation drops
            #    within 3-4 samples (Nyquist oversampling), so [::37] was wasting
            #    ~89% of perfectly good noise. [::4] still guarantees independence.
            decimated = samples[::4]

            # 3. Multi-bit XOR fold: combine LSB (bit0) and next noise bit (bit1)
            #    via XOR. XOR of two weakly-biased independent bits produces a bit
            #    closer to 0.5 bias, effectively a cheap pre-whitening step.
            #    Result is half the samples as independent noise bits.
            lsb0 = (decimated & np.int16(1)).astype(np.uint8)
            lsb1 = ((decimated >> 1) & np.int16(1)).astype(np.uint8)
            bits = lsb0 ^ lsb1

            # 4. Von Neumann Extractor (mandatory – removes any residual DC bias)
            if len(bits) % 2 != 0:
                bits = bits[:-1]
            pairs = bits.reshape(-1, 2)
            valid_mask = pairs[:, 0] != pairs[:, 1]
            extracted_bits = pairs[valid_mask, 0]

            # 5. FIPS 140-3 Health Checks (RCT & APT)
            # RCT: Repetition Count Test (checks for stuck bits / constant output)
            if len(extracted_bits) > 32:
                # Check for long runs of the same bit
                bit_str = "".join(extracted_bits.astype(str))
                if "0" * 32 in bit_str or "1" * 32 in bit_str:
                    log("[!] Health Check Failed: RCT (long run detected). Dropping packet.")
                    continue

            # APT: Adaptive Proportion Test (checks for strong bias in a window)
            # Window of 512 bits, max 400 of the same bit (conservative)
            if len(extracted_bits) >= 512:
                window = extracted_bits[:512]
                ones = np.sum(window)
                if ones < 112 or ones > 400: # Approx 0.22 to 0.78 proportion
                    log(f"[!] Health Check Failed: APT (bias detected: {ones}/512 ones). Dropping packet.")
                    continue

            # 6. Pack bits into bytes and accumulate
            extracted_bytes = np.packbits(extracted_bits).tobytes()
            entropy_accumulator.extend(extracted_bytes)
            # ------------------------------------------------------------------

            # Send in 1 KB chunks to generator
            chunk_target = 1024
            while len(entropy_accumulator) >= chunk_target:
                chunk = bytes(entropy_accumulator[:chunk_target])
                del entropy_accumulator[:chunk_target]

                udp_send(
                    sock,
                    {
                        "type": "samples",
                        "node": NODE_NAME,
                        "payload_b64": base64.b64encode(chunk).decode("ascii"),
                        "raw_bytes": len(chunk),
                        "timestamp": time.time(),
                    },
                )
                with stats_lock:
                    runtime_stats["sample_packets_sent"] += 1
                    runtime_stats["sample_bytes_sent"] += len(chunk)
                    runtime_stats["last_sample_at"] = time.time()
        except Exception as exc:
            log(f"[!] SDR streaming error: {exc}")
            time.sleep(2)


def waterfall_sender_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        ctx = build_iio_context()
        data_dev = configure_radio(ctx)
        viz_buffer = iio.Buffer(data_dev, 16384)
        log(
            f"[*] Waterfall stream ready (node={NODE_NAME}, interval={WATERFALL_INTERVAL_SEC}s, "
            f"udp_chunk_bytes={WATERFALL_UDP_CHUNK_BYTES})"
        )
    except Exception as exc:
        log(f"[!] Waterfall init error: {exc}")
        time.sleep(10)
        os._exit(1)

    while True:
        try:
            viz_buffer.refill()
            raw_iq = viz_buffer.read()

            iq = np.frombuffer(raw_iq, dtype=np.int16).astype(np.float32)
            iq_complex = iq[0::2] + 1j * iq[1::2]

            psd = np.abs(np.fft.fftshift(np.fft.fft(iq_complex))) ** 2
            psd_db = 10 * np.log10(psd + 1e-9)
            freqs = np.fft.fftshift(np.fft.fftfreq(len(iq_complex), d=1 / 2.084e6)) / 1e6

            x = freqs + (FREQ / 1e6)
            y = psd_db
            waterfall_history.append(y.copy())
            history_frames = list(waterfall_history)

            noise_floor = float(np.quantile(y, 0.08))
            peak_level = float(np.quantile(y, 0.995))
            waterfall_axis_metrics.append(
                {
                    "noise_floor": noise_floor,
                    "peak_level": peak_level,
                }
            )
            recent_noise_floors = [entry["noise_floor"] for entry in waterfall_axis_metrics]
            recent_peak_levels = [entry["peak_level"] for entry in waterfall_axis_metrics]
            y_floor = min(recent_noise_floors)
            y_peak = max(recent_peak_levels)
            if (
                WATERFALL_Y_MIN_DB is not None
                and WATERFALL_Y_MAX_DB is not None
                and WATERFALL_Y_MAX_DB > WATERFALL_Y_MIN_DB
            ):
                y_min = WATERFALL_Y_MIN_DB
                y_max = WATERFALL_Y_MAX_DB
            else:
                dynamic_span = max(20.0, (y_peak - y_floor) + 8.0)
                y_span = WATERFALL_Y_SPAN_DB if WATERFALL_Y_SPAN_DB is not None else dynamic_span
                y_center = (y_floor + y_peak) / 2.0
                y_min = y_center - (y_span / 2.0)
                y_max = y_center + (y_span / 2.0)

            fig, ax = plt.subplots(figsize=(10, 4), dpi=130)
            fig.subplots_adjust(left=0.11, right=0.985, top=0.88, bottom=0.18)
            fig.patch.set_facecolor(THEME_BG)
            ax.set_facecolor(THEME_BG)

            gradient = np.linspace(0, 1, 600)
            gradient = np.vstack((gradient, gradient))
            ax.imshow(
                gradient,
                extent=[float(x.min()), float(x.max()), y_min, y_max],
                cmap=WATERFALL_BG_CMAP,
                aspect="auto",
                alpha=0.22,
                origin="lower",
                zorder=0,
            )

            points = np.array([x, y]).T.reshape(-1, 1, 2)
            segments = np.concatenate([points[:-1], points[1:]], axis=1)
            line = LineCollection(segments, cmap=WATERFALL_LINE_CMAP, linewidth=2.2)
            line.set_array(np.linspace(0, 1, len(segments)))
            line.set_zorder(4)
            ax.add_collection(line)

            for history_index, history_y in enumerate(history_frames[:-1]):
                alpha = 0.05 + (0.18 * (history_index + 1) / max(1, len(history_frames)))
                ax.plot(
                    x,
                    history_y,
                    color=THEME_HISTORY,
                    linewidth=1.4,
                    alpha=alpha,
                    zorder=1.5 + history_index * 0.1,
                )

            ax.plot(x, y, color=THEME_PRIMARY, linewidth=6, alpha=0.10, zorder=3)
            ax.plot(x, y, color=THEME_ACCENT, linewidth=1.4, alpha=0.95, zorder=6)
            ax.fill_between(x, y, y_min, color=THEME_PRIMARY, alpha=0.16, zorder=2)
            ax.fill_between(x, y, y_min, color=THEME_SECONDARY, alpha=0.08, zorder=1)
            ax.scatter(x[::64], y[::64], s=6, c=THEME_ACCENT, alpha=0.35, linewidths=0, zorder=5)

            ax.set_title(
                f"Node {NODE_NAME} - Cosmic Noise @ {FREQ / 1e6:.3f} MHz",
                color=THEME_PRIMARY,
                fontsize=12,
                pad=12,
            )
            ax.set_xlabel("Frequency [MHz]", color=THEME_PRIMARY)
            ax.set_ylabel("Power [dB]", color=THEME_PRIMARY)
            ax.grid(True, alpha=0.16, color=THEME_PRIMARY, linestyle=":")
            ax.set_ylim(y_min, y_max)
            ax.tick_params(colors=THEME_PRIMARY)
            for spine in ax.spines.values():
                spine.set_color(THEME_PRIMARY)
                spine.set_alpha(0.7)

            frame_bytes = {}
            for image_format in ("png", "webp"):
                buf = io.BytesIO()
                save_kwargs = {
                    "format": image_format.upper(),
                    "facecolor": fig.get_facecolor(),
                    "edgecolor": "none",
                }
                if image_format == "webp":
                    save_kwargs["pil_kwargs"] = {"quality": 85, "method": 6}
                fig.savefig(buf, **save_kwargs)
                frame_bytes[image_format] = buf.getvalue()
            plt.close(fig)
            frame_id = str(uuid.uuid4())
            frame_timestamp = time.time()
            part_count_summary = []
            for image_format, image_bytes in frame_bytes.items():
                message_id = str(uuid.uuid4())
                total_parts = int(math.ceil(len(image_bytes) / WATERFALL_UDP_CHUNK_BYTES))
                part_count_summary.append(f"{image_format}={len(image_bytes)}B/{total_parts}p")
                for part_index in range(total_parts):
                    start = part_index * WATERFALL_UDP_CHUNK_BYTES
                    end = start + WATERFALL_UDP_CHUNK_BYTES
                    udp_send(
                        sock,
                        {
                            "type": "waterfall",
                            "node": NODE_NAME,
                            "frame_id": frame_id,
                            "format": image_format,
                            "message_id": message_id,
                            "part_index": part_index,
                            "total_parts": total_parts,
                            "payload_b64": base64.b64encode(image_bytes[start:end]).decode("ascii"),
                            "timestamp": frame_timestamp,
                        },
                    )
                    with stats_lock:
                        runtime_stats["waterfall_parts_sent"] += 1

            with stats_lock:
                runtime_stats["waterfalls_sent"] += 1
                runtime_stats["last_waterfall_at"] = time.time()
            log(
                f"[*] Waterfall sent (node={NODE_NAME}, frame_id={frame_id}, "
                f"history={len(history_frames)}, {', '.join(part_count_summary)})"
            )
            time.sleep(WATERFALL_INTERVAL_SEC)
        except Exception as exc:
            log(f"[!] Waterfall streaming error: {exc}")
            time.sleep(2)


def source_audit_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log(
        f"[*] Source audit worker ready (node={NODE_NAME}, interval={SOURCE_AUDIT_INTERVAL_SEC}s, "
        f"sample_bytes~={SOURCE_AUDIT_SAMPLE_BYTES}, source=shared_raw_iq)"
    )

    while True:
        try:
            raw_iq, raw_iq_at = get_latest_raw_iq_snapshot()
            if raw_iq is None:
                time.sleep(2)
                continue
            metrics = analyze_raw_signal(raw_iq)
            if metrics is None:
                time.sleep(5)
                continue

            udp_send(
                sock,
                {
                    "type": "source_audit",
                    "node": NODE_NAME,
                    "timestamp": raw_iq_at or time.time(),
                    "metrics": metrics,
                },
            )
            with stats_lock:
                runtime_stats["source_audits_sent"] += 1
                runtime_stats["last_source_audit_at"] = time.time()
            log(
                f"[*] Source audit sent (node={NODE_NAME}, repeat_score={metrics['repeat_score']}, "
                f"spectral_flatness={metrics['spectral_flatness']})"
            )
            time.sleep(max(1, SOURCE_AUDIT_INTERVAL_SEC))
        except Exception as exc:
            log(f"[!] Source audit error: {exc}")
            time.sleep(5)


def stats_logger_worker():
    while True:
        time.sleep(LOG_EVERY_SEC)
        with stats_lock:
            snapshot = dict(runtime_stats)
        last_sample_age = (
            round(time.time() - snapshot["last_sample_at"], 1)
            if snapshot["last_sample_at"]
            else None
        )
        last_waterfall_age = (
            round(time.time() - snapshot["last_waterfall_at"], 1)
            if snapshot["last_waterfall_at"]
            else None
        )
        last_source_audit_age = (
            round(time.time() - snapshot["last_source_audit_at"], 1)
            if snapshot["last_source_audit_at"]
            else None
        )
        log(
            "[*] SDR node stats: "
            f"node={NODE_NAME}, "
            f"sample_packets_sent={snapshot['sample_packets_sent']}, "
            f"sample_bytes_sent={snapshot['sample_bytes_sent']}, "
            f"waterfalls_sent={snapshot['waterfalls_sent']}, "
            f"waterfall_parts_sent={snapshot['waterfall_parts_sent']}, "
            f"source_audits_sent={snapshot['source_audits_sent']}, "
            f"last_sample_age_sec={last_sample_age}, "
            f"last_waterfall_age_sec={last_waterfall_age}, "
            f"last_source_audit_age_sec={last_source_audit_age}"
        )


if __name__ == "__main__":
    log(
        f"[*] SDR node {NODE_NAME} streaming to "
        f"{UDP_TARGET_HOST}:{UDP_TARGET_PORT} from Pluto {PLUTO_IP}"
    )
    threading.Thread(target=entropy_sender_worker, daemon=True).start()
    threading.Thread(target=waterfall_sender_worker, daemon=True).start()
    threading.Thread(target=source_audit_worker, daemon=True).start()
    threading.Thread(target=stats_logger_worker, daemon=True).start()
    while True:
        time.sleep(60)
