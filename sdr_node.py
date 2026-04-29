import base64
import ctypes
import io
import json
import math
import os
import socket
import threading
import time
import uuid
import urllib.request
import urllib.parse
import ssl
from collections import deque

import iio
import matplotlib
import numpy as np
from matplotlib.collections import LineCollection
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.ticker import FuncFormatter

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
SDR_TYPE = os.getenv("SDR_TYPE", "pluto").lower()
RTL_SDR_INDEX = int(os.getenv("RTL_SDR_INDEX", "0"))
SAMPLE_RATE = float(os.getenv("SAMPLE_RATE", "2.048e6"))
PLUTO_BUFFER_SAMPLES = int(os.getenv("PLUTO_BUFFER_SAMPLES", "65536"))
RTL_READ_BYTES = int(os.getenv("RTL_READ_BYTES", "262144"))
ENTROPY_DECIMATION_FACTOR = max(1, int(os.getenv("ENTROPY_DECIMATION_FACTOR", "4")))
HTTP_TARGET_PORT = os.getenv("HTTP_TARGET_PORT", "8080")
HTTP_TARGET_PROTOCOL = os.getenv("HTTP_TARGET_PROTOCOL", "http")
HTTP_TARGET_VERIFY_SSL = os.getenv("HTTP_TARGET_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
CONVERTER_MODE = os.getenv("CONVERTER_MODE", "none").strip().lower()

audit_trigger_event = threading.Event()

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
latest_raw_iq_error_logged = False
waterfall_history = deque(maxlen=max(1, WATERFALL_HISTORY_FRAMES))
axis_window_frames = max(2, int(math.ceil(max(1, WATERFALL_AXIS_WINDOW_SEC) / max(1, WATERFALL_INTERVAL_SEC))))
waterfall_axis_metrics = deque(maxlen=axis_window_frames)
MAX_SHARED_RAW_IQ_AGE_SEC = max(10, WATERFALL_INTERVAL_SEC * 3)


def getenv_optional_float(name: str):
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return float(value)


def getenv_optional_int(name: str):
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return int(value)


WATERFALL_Y_SPAN_DB = getenv_optional_float("WATERFALL_Y_SPAN_DB")
WATERFALL_Y_MIN_DB = getenv_optional_float("WATERFALL_Y_MIN_DB")
WATERFALL_Y_MAX_DB = getenv_optional_float("WATERFALL_Y_MAX_DB")
CONVERTER_LO_HZ = getenv_optional_int("CONVERTER_LO_HZ")
CONVERTER_LO_LOW_HZ = int(os.getenv("CONVERTER_LO_LOW_HZ", "9750000000"))
CONVERTER_LO_HIGH_HZ = int(os.getenv("CONVERTER_LO_HIGH_HZ", "10600000000"))
CONVERTER_RF_LOW_MIN_HZ = int(os.getenv("CONVERTER_RF_LOW_MIN_HZ", "10700000000"))
CONVERTER_RF_LOW_MAX_HZ = int(os.getenv("CONVERTER_RF_LOW_MAX_HZ", "11700000000"))
CONVERTER_RF_HIGH_MIN_HZ = int(os.getenv("CONVERTER_RF_HIGH_MIN_HZ", "11700000000"))
CONVERTER_RF_HIGH_MAX_HZ = int(os.getenv("CONVERTER_RF_HIGH_MAX_HZ", "12750000000"))

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


class SDRSourceHandle:
    def __init__(self, source, ctx=None, dev=None):
        self.source = source
        self.ctx = ctx
        self.dev = dev


class CompatRtlSdr:
    _library = None

    def __init__(self, device_index=0):
        self.device_index = int(device_index)
        self._dev = ctypes.c_void_p()
        self._sample_rate = 0
        self._center_freq = 0
        self._gain = None
        lib = self._get_library()
        result = lib.rtlsdr_open(ctypes.byref(self._dev), self.device_index)
        if result != 0:
            raise RuntimeError(f"rtlsdr_open(index={self.device_index}) failed with code {result}")

    @classmethod
    def _get_library(cls):
        if cls._library is not None:
            return cls._library

        lib = ctypes.CDLL("librtlsdr.so")
        lib.rtlsdr_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32]
        lib.rtlsdr_open.restype = ctypes.c_int
        lib.rtlsdr_close.argtypes = [ctypes.c_void_p]
        lib.rtlsdr_close.restype = ctypes.c_int
        lib.rtlsdr_set_center_freq.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        lib.rtlsdr_set_center_freq.restype = ctypes.c_int
        lib.rtlsdr_set_sample_rate.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        lib.rtlsdr_set_sample_rate.restype = ctypes.c_int
        lib.rtlsdr_set_tuner_gain_mode.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.rtlsdr_set_tuner_gain_mode.restype = ctypes.c_int
        lib.rtlsdr_set_tuner_gain.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.rtlsdr_set_tuner_gain.restype = ctypes.c_int
        lib.rtlsdr_reset_buffer.argtypes = [ctypes.c_void_p]
        lib.rtlsdr_reset_buffer.restype = ctypes.c_int
        lib.rtlsdr_read_sync.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int),
        ]
        lib.rtlsdr_read_sync.restype = ctypes.c_int
        cls._library = lib
        return lib

    def _require_ok(self, result, operation):
        if result != 0:
            raise RuntimeError(f"{operation} failed with code {result}")

    @property
    def sample_rate(self):
        return self._sample_rate

    @sample_rate.setter
    def sample_rate(self, value):
        value = int(float(value))
        self._require_ok(
            self._get_library().rtlsdr_set_sample_rate(self._dev, value),
            f"rtlsdr_set_sample_rate({value})",
        )
        self._sample_rate = value

    @property
    def center_freq(self):
        return self._center_freq

    @center_freq.setter
    def center_freq(self, value):
        value = int(float(value))
        self._require_ok(
            self._get_library().rtlsdr_set_center_freq(self._dev, value),
            f"rtlsdr_set_center_freq({value})",
        )
        self._center_freq = value

    @property
    def gain(self):
        return self._gain

    @gain.setter
    def gain(self, value):
        lib = self._get_library()
        if value in (None, "auto"):
            self._require_ok(lib.rtlsdr_set_tuner_gain_mode(self._dev, 0), "rtlsdr_set_tuner_gain_mode(auto)")
            self._gain = value
            return

        gain_db = float(value)
        gain_tenths_db = int(round(gain_db * 10))
        self._require_ok(lib.rtlsdr_set_tuner_gain_mode(self._dev, 1), "rtlsdr_set_tuner_gain_mode(manual)")
        self._require_ok(
            lib.rtlsdr_set_tuner_gain(self._dev, gain_tenths_db),
            f"rtlsdr_set_tuner_gain({gain_tenths_db})",
        )
        self._gain = gain_db

    def read_bytes(self, num_bytes):
        num_bytes = int(num_bytes)
        if num_bytes <= 0:
            return b""

        lib = self._get_library()
        buffer = ctypes.create_string_buffer(num_bytes)
        bytes_read = ctypes.c_int()
        self._require_ok(
            lib.rtlsdr_read_sync(self._dev, buffer, num_bytes, ctypes.byref(bytes_read)),
            f"rtlsdr_read_sync({num_bytes})",
        )
        return buffer.raw[: bytes_read.value]

    def reset_buffer(self):
        self._require_ok(self._get_library().rtlsdr_reset_buffer(self._dev), "rtlsdr_reset_buffer")

    def cancel(self):
        return None

    def close(self):
        if not self._dev:
            return
        try:
            self._require_ok(self._get_library().rtlsdr_close(self._dev), "rtlsdr_close")
        finally:
            self._dev = ctypes.c_void_p()

    def __repr__(self):
        gain_repr = "auto" if self._gain in (None, "auto") else f"{self._gain:.1f} dB"
        return (
            f"CompatRtlSdr(index={self.device_index}, "
            f"sample_rate={self._sample_rate}, center_freq={self._center_freq}, gain={gain_repr})"
        )


def get_display_frequency_axis():
    if DISPLAY_FREQ_HZ >= 1_000_000_000:
        return 1_000_000_000.0, "GHz"
    return 1_000_000.0, "MHz"


def resolve_radio_frequencies():
    mode = CONVERTER_MODE or "none"
    rf_freq_hz = FREQ

    if mode == "none":
        return {
            "mode": "none",
            "rf_freq_hz": rf_freq_hz,
            "tuner_freq_hz": rf_freq_hz,
            "display_freq_hz": rf_freq_hz,
            "converter_lo_hz": None,
            "converter_path": "direct",
        }

    if mode == "up":
        if CONVERTER_LO_HZ is None or CONVERTER_LO_HZ <= 0:
            raise ValueError("CONVERTER_LO_HZ must be set for CONVERTER_MODE=up")
        return {
            "mode": "up",
            "rf_freq_hz": rf_freq_hz,
            "tuner_freq_hz": rf_freq_hz + CONVERTER_LO_HZ,
            "display_freq_hz": rf_freq_hz,
            "converter_lo_hz": CONVERTER_LO_HZ,
            "converter_path": "upconverter",
        }

    if mode == "down":
        selected_lo_hz = CONVERTER_LO_HZ
        converter_path = "downconverter-manual"

        if selected_lo_hz is None:
            if CONVERTER_RF_LOW_MIN_HZ <= rf_freq_hz < CONVERTER_RF_LOW_MAX_HZ:
                selected_lo_hz = CONVERTER_LO_LOW_HZ
                converter_path = "downconverter-low-band"
            elif CONVERTER_RF_HIGH_MIN_HZ <= rf_freq_hz <= CONVERTER_RF_HIGH_MAX_HZ:
                selected_lo_hz = CONVERTER_LO_HIGH_HZ
                converter_path = "downconverter-high-band"
            else:
                raise ValueError(
                    f"FREQ={rf_freq_hz} Hz is outside configured downconverter RF ranges "
                    f"({CONVERTER_RF_LOW_MIN_HZ}-{CONVERTER_RF_LOW_MAX_HZ - 1} / "
                    f"{CONVERTER_RF_HIGH_MIN_HZ}-{CONVERTER_RF_HIGH_MAX_HZ})"
                )

        tuner_freq_hz = abs(rf_freq_hz - selected_lo_hz)
        if tuner_freq_hz <= 0:
            raise ValueError(
                f"Computed downconverter IF is invalid for FREQ={rf_freq_hz} Hz and LO={selected_lo_hz} Hz"
            )
        return {
            "mode": "down",
            "rf_freq_hz": rf_freq_hz,
            "tuner_freq_hz": tuner_freq_hz,
            "display_freq_hz": rf_freq_hz,
            "converter_lo_hz": selected_lo_hz,
            "converter_path": converter_path,
        }

    raise ValueError(f"Unsupported CONVERTER_MODE={CONVERTER_MODE!r}. Use none, down, or up.")


RADIO_FREQ_PLAN = resolve_radio_frequencies()
TUNER_FREQ_HZ = RADIO_FREQ_PLAN["tuner_freq_hz"]
DISPLAY_FREQ_HZ = RADIO_FREQ_PLAN["display_freq_hz"]


def build_iio_context():
    if not PLUTO_IP or PLUTO_IP.lower() in ("local", "auto"):
        log("[*] Searching for local/USB IIO context (auto-discovery)...")
        return iio.Context()

    if PLUTO_IP.lower() == "usb":
        log("[*] Attempting to connect to IIO context: usb:")
        return iio.Context("usb:")

    uri = PLUTO_IP
    if ":" not in uri:
        # Default to IP if only an address/hostname is provided
        uri = f"ip:{PLUTO_IP}"

    log(f"[*] Attempting to connect to IIO context: {uri}")
    return iio.Context(uri)


def configure_radio(ctx):
    phy = ctx.find_device("ad9361-phy")
    phy.find_channel("altvoltage0", True).attrs["frequency"].value = str(TUNER_FREQ_HZ)
    rx = phy.find_channel(RX_CHANNEL)
    rx.attrs["sampling_frequency"].value = str(int(SAMPLE_RATE))
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
    global latest_raw_iq_error_logged
    with latest_raw_iq_lock:
        if latest_raw_iq is None:
            return None, 0.0
        sample_age = time.time() - latest_raw_iq_at
        if sample_age > MAX_SHARED_RAW_IQ_AGE_SEC:
            if not latest_raw_iq_error_logged:
                log(
                    f"[!] Shared raw IQ is stale ({sample_age:.1f}s old). "
                    "Waiting for fresh SDR samples before sending waterfall/audit."
                )
                latest_raw_iq_error_logged = True
            return None, latest_raw_iq_at
        latest_raw_iq_error_logged = False
        return latest_raw_iq, latest_raw_iq_at


def cleanup_sdr_source(source):
    if source is None:
        return
    source_obj = source.source if isinstance(source, SDRSourceHandle) else source
    for method_name in ("cancel", "close", "destroy"):
        method = getattr(source_obj, method_name, None)
        if callable(method):
            try:
                method()
            except Exception:
                pass


def initialize_sdr_source():
    if SDR_TYPE == "rtlsdr":
        sdr_obj = CompatRtlSdr(device_index=RTL_SDR_INDEX)
        sdr_obj.sample_rate = SAMPLE_RATE
        sdr_obj.center_freq = TUNER_FREQ_HZ
        sdr_obj.gain = GAIN
        sdr_obj.reset_buffer()
        log(f"[*] RTL-SDR successfully initialized: {sdr_obj}")
        return SDRSourceHandle(sdr_obj)

    sdr_ctx = build_iio_context()
    sdr_dev = configure_radio(sdr_ctx)
    sdr_buffer = iio.Buffer(sdr_dev, PLUTO_BUFFER_SAMPLES)
    log(f"[*] PlutoSDR successfully initialized. Context: {sdr_ctx.name}")
    return SDRSourceHandle(sdr_buffer, ctx=sdr_ctx, dev=sdr_dev)


def has_repetition_run(bits: np.ndarray, max_run_length: int) -> bool:
    if bits.size < max_run_length:
        return False
    change_points = np.flatnonzero(np.diff(bits)) + 1
    run_lengths = np.diff(np.concatenate(([0], change_points, [bits.size])))
    return bool(run_lengths.max(initial=0) >= max_run_length)


def reconnect_sdr_source(previous_source, reason):
    cleanup_sdr_source(previous_source)
    for attempt in range(1, 11):
        try:
            log(f"[!] Reinitializing SDR after streaming failure ({reason}), attempt {attempt}/10...")
            return initialize_sdr_source()
        except Exception as exc:
            log(f"[!] SDR reinit attempt {attempt}/10 failed: {exc}")
            time.sleep(min(30, attempt * 2))
    log("[!] Fatal: Could not recover SDR stream after repeated reinit failures. Exiting.")
    os._exit(1)


def entropy_sender_worker(source):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    entropy_accumulator = bytearray()

    log(f"[*] Entropy sender worker active (node={NODE_NAME}, type={SDR_TYPE})")

    while True:
        try:
            if SDR_TYPE == "rtlsdr":
                # read_bytes(n) returns bytes/bytearray for RTL-SDR
                raw_data = source.source.read_bytes(RTL_READ_BYTES)
            else:
                # buffer.refill() for PlutoSDR
                source.source.refill()
                raw_data = source.source.read()

            update_latest_raw_iq(raw_data)

            # --- OPTIMIZED DSP PIPELINE (multi-bit XOR-fold + Von Neumann) ---
            # 1. Parse raw IQ samples
            dtype = np.uint8 if SDR_TYPE == "rtlsdr" else np.int16
            # Ensure we have a multiple of sample size (2 bytes for RTL, 4 for Pluto)
            limit = len(raw_data) - (len(raw_data) % (2 if SDR_TYPE == "rtlsdr" else 4))
            samples = np.frombuffer(raw_data[:limit], dtype=dtype)

            # 2. Light decimation – configurable so weak nodes can be tuned
            #    conservatively without touching the extractor implementation.
            decimated = samples[::ENTROPY_DECIMATION_FACTOR]

            # 3. Multi-bit XOR fold: combine LSB (bit0) and next noise bit (bit1)
            #    via XOR. XOR of two weakly-biased independent bits produces a bit
            #    closer to 0.5 bias, effectively a cheap pre-whitening step.
            #    Result is half the samples as independent noise bits.
            lsb0 = np.bitwise_and(decimated, 1).astype(np.uint8, copy=False)
            lsb1 = np.bitwise_and(np.right_shift(decimated, 1), 1).astype(np.uint8, copy=False)
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
                if has_repetition_run(extracted_bits, 32):
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

            # Respect configured packet size to avoid wasting throughput on
            # base64+JSON+UDP overhead per tiny payload.
            chunk_target = max(256, SAMPLE_PACKET_BYTES)
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
            entropy_accumulator.clear()
            source = reconnect_sdr_source(source, str(exc))
            time.sleep(1)


def waterfall_sender_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    log(
        f"[*] Waterfall worker ready (node={NODE_NAME}, interval={WATERFALL_INTERVAL_SEC}s, "
        f"udp_chunk_bytes={WATERFALL_UDP_CHUNK_BYTES}, source=shared_raw_iq)"
    )

    while True:
        try:
            raw_iq, raw_iq_at = get_latest_raw_iq_snapshot()
            if raw_iq is None:
                time.sleep(2)
                continue

            dtype = np.uint8 if SDR_TYPE == "rtlsdr" else np.int16
            iq = np.frombuffer(raw_iq, dtype=dtype).astype(np.float32)
            if SDR_TYPE == "rtlsdr":
                # Center 8-bit unsigned (0..255) to avoid huge DC spike in FFT
                iq = iq - 127.5

            iq_complex = iq[0::2] + 1j * iq[1::2]

            psd = np.abs(np.fft.fftshift(np.fft.fft(iq_complex))) ** 2
            psd_db = 10 * np.log10(psd + 1e-9)
            freqs = np.fft.fftshift(np.fft.fftfreq(len(iq_complex), d=1 / 2.084e6)) / 1e6

            axis_scale_hz, axis_unit = get_display_frequency_axis()
            axis_center = DISPLAY_FREQ_HZ / axis_scale_hz
            axis_span = freqs / (axis_scale_hz / 1e6)
            x = axis_span + axis_center
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
                f"Node {NODE_NAME} - Cosmic Noise @ {DISPLAY_FREQ_HZ / axis_scale_hz:.3f} {axis_unit}",
                color=THEME_PRIMARY,
                fontsize=12,
                pad=12,
            )
            ax.set_xlabel(f"Frequency [{axis_unit}]", color=THEME_PRIMARY)
            ax.set_ylabel("Power [dB]", color=THEME_PRIMARY)
            ax.grid(True, alpha=0.16, color=THEME_PRIMARY, linestyle=":")
            ax.set_ylim(y_min, y_max)
            ax.tick_params(colors=THEME_PRIMARY)
            ax.xaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.3f}"))
            ax.xaxis.offsetText.set_visible(False)
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
            # Wait for event or interval
            triggered = audit_trigger_event.wait(timeout=max(1, SOURCE_AUDIT_INTERVAL_SEC))
            if triggered:
                log("[*] Source audit triggered by status poller (STALE or WARN status).")
                audit_trigger_event.clear()

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
        except Exception as exc:
            log(f"[!] Source audit error: {exc}")
            time.sleep(5)


def status_poller_worker():
    safe_node_name = urllib.parse.quote(NODE_NAME)
    
    # Construct URL. If port is empty, don't append it.
    if HTTP_TARGET_PORT:
        url = f"{HTTP_TARGET_PROTOCOL}://{UDP_TARGET_HOST}:{HTTP_TARGET_PORT}/api/node-status/{safe_node_name}"
    else:
        url = f"{HTTP_TARGET_PROTOCOL}://{UDP_TARGET_HOST}/api/node-status/{safe_node_name}"
        
    log(f"[*] Status poller worker active (polling {url} every 60s, verify_ssl={HTTP_TARGET_VERIFY_SSL})")
    
    # Create SSL context if we need to skip verification
    ctx = None
    if HTTP_TARGET_PROTOCOL == "https" and not HTTP_TARGET_VERIFY_SSL:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    while True:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    status = data.get("status")
                    accepting = data.get("accepting_samples", True)
                    
                    if not accepting or status in ("STALE", "WARN"):
                        log(f"[!] Generator status: {status} (accepting={accepting}). Requesting fresh audit...")
                        audit_trigger_event.set()
                    elif status == "OK":
                        # All good
                        pass
                else:
                    log(f"[!] Status poller: Unexpected response {response.status}")
        except Exception as exc:
            # This is expected if generator is down or network issues
            # log(f"[!] Status poller error: {exc}")
            pass
        
        time.sleep(60)


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
        f"[*] SDR node {NODE_NAME} starting. Target: "
        f"{UDP_TARGET_HOST}:{UDP_TARGET_PORT}, Source: Pluto {PLUTO_IP}"
    )
    log(
        f"[*] Frequency plan: mode={RADIO_FREQ_PLAN['mode']}, "
        f"path={RADIO_FREQ_PLAN['converter_path']}, "
        f"rf={RADIO_FREQ_PLAN['rf_freq_hz'] / 1e6:.3f} MHz, "
        f"tuner={RADIO_FREQ_PLAN['tuner_freq_hz'] / 1e6:.3f} MHz"
        + (
            f", lo={RADIO_FREQ_PLAN['converter_lo_hz'] / 1e6:.3f} MHz"
            if RADIO_FREQ_PLAN["converter_lo_hz"] is not None
            else ""
        )
    )

    # Give Pluto a moment to breathe after previous container restart
    time.sleep(5)

    # Main initialization loop - process won't start workers until hardware is ready
    sdr_source = None
    for attempt in range(1, 11):
        try:
            log(f"[*] SDR init attempt {attempt}/10 (Type: {SDR_TYPE})...")
            sdr_source = initialize_sdr_source()
            break
        except Exception as exc:
            log(f"[!] SDR init failed: {exc}")
            time.sleep(10)
    else:
        log("[!] Fatal: Could not initialize SDR after 10 attempts. Exiting.")
        os._exit(1)

    # Start workers - pass the initialized source to the sampler thread
    threading.Thread(target=entropy_sender_worker, args=(sdr_source,), daemon=True).start()
    threading.Thread(target=waterfall_sender_worker, daemon=True).start()
    threading.Thread(target=source_audit_worker, daemon=True).start()
    threading.Thread(target=status_poller_worker, daemon=True).start()
    threading.Thread(target=stats_logger_worker, daemon=True).start()

    while True:
        time.sleep(60)
