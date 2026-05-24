import base64
import binascii
import ctypes
import argparse
import gc
import io
import json
import math
import os
import socket
import struct
import threading
import time
import uuid
import urllib.request
import urllib.parse
import ssl
import zlib
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
PLUTO_RX_CHANNEL_MODE = os.getenv("PLUTO_RX_CHANNEL_MODE", "iq").strip().lower()
PLUTO_ALLOW_USB = os.getenv("PLUTO_ALLOW_USB", "0").lower() in ("1", "true", "yes")
PLUTO_INIT_ATTEMPTS = max(1, int(os.getenv("PLUTO_INIT_ATTEMPTS", "3")))
PLUTO_REINIT_ATTEMPTS = max(1, int(os.getenv("PLUTO_REINIT_ATTEMPTS", "3")))
PLUTO_INIT_BACKOFF_BASE_SEC = float(os.getenv("PLUTO_INIT_BACKOFF_BASE_SEC", "5"))
PLUTO_INIT_BACKOFF_MAX_SEC = float(os.getenv("PLUTO_INIT_BACKOFF_MAX_SEC", "45"))
PLUTO_FAILURE_COOLDOWN_SEC = float(os.getenv("PLUTO_FAILURE_COOLDOWN_SEC", "90"))
PLUTO_SOCKET_TIMEOUT_SEC = float(os.getenv("PLUTO_SOCKET_TIMEOUT_SEC", "3"))
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
NODE_METRICS_INTERVAL_SEC = int(os.getenv("NODE_METRICS_INTERVAL_SEC", "30"))
LOG_EVERY_SEC = int(os.getenv("LOG_EVERY_SEC", "30"))
SDR_TYPE = os.getenv("SDR_TYPE", "pluto").lower()
RTL_SDR_INDEX = int(os.getenv("RTL_SDR_INDEX", "0"))
SAMPLE_RATE = float(os.getenv("SAMPLE_RATE", "3840000"))
PLUTO_BUFFER_SAMPLES = int(os.getenv("PLUTO_BUFFER_SAMPLES", "2048"))
PLUTO_MAX_INITIAL_BUFFER_SAMPLES = int(os.getenv("PLUTO_MAX_INITIAL_BUFFER_SAMPLES", "2048"))
PLUTO_BUFFER_FALLBACK_SAMPLES = os.getenv("PLUTO_BUFFER_FALLBACK_SAMPLES", "1024,512,256")
PLUTO_SAFE_SAMPLE_RATE_HZ = int(os.getenv("PLUTO_SAFE_SAMPLE_RATE_HZ", "2400000"))
PLUTO_RF_BANDWIDTH_HZ = int(os.getenv("PLUTO_RF_BANDWIDTH_HZ", "0"))
RTL_READ_BYTES = int(os.getenv("RTL_READ_BYTES", "262144"))
DUMMY_READ_BYTES = int(os.getenv("DUMMY_READ_BYTES", str(32768 * 4)))
DUMMY_SIGNAL_HZ = float(os.getenv("DUMMY_SIGNAL_HZ", "142000"))
DUMMY_NOISE_STDDEV = float(os.getenv("DUMMY_NOISE_STDDEV", "9000"))
DUMMY_SIGNAL_AMPLITUDE = float(os.getenv("DUMMY_SIGNAL_AMPLITUDE", "12000"))
DUMMY_READ_SLEEP_SEC = float(os.getenv("DUMMY_READ_SLEEP_SEC", "0.02"))
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
    "health_rejected_packets": 0,
    "rct_rejected_packets": 0,
    "apt_rejected_packets": 0,
    "last_sample_at": 0.0,
    "last_waterfall_at": 0.0,
    "last_source_audit_at": 0.0,
    "last_health_rejected_at": 0.0,
    "last_signal_at": 0.0,
}
stats_lock = threading.Lock()
latest_raw_iq = None
latest_raw_iq_at = 0.0
latest_raw_iq_lock = threading.Lock()
latest_raw_iq_error_logged = False
latest_signal_metrics = None
latest_signal_metrics_lock = threading.Lock()
waterfall_history = deque(maxlen=max(1, WATERFALL_HISTORY_FRAMES))
axis_window_frames = max(2, int(math.ceil(max(1, WATERFALL_AXIS_WINDOW_SEC) / max(1, WATERFALL_INTERVAL_SEC))))
waterfall_axis_metrics = deque(maxlen=axis_window_frames)
MAX_SHARED_RAW_IQ_AGE_SEC = max(10, WATERFALL_INTERVAL_SEC * 3)
MAX_SAFE_SAMPLE_PACKET_BYTES = 48000


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


def effective_sample_packet_bytes() -> int:
    requested = max(256, int(SAMPLE_PACKET_BYTES))
    if requested > MAX_SAFE_SAMPLE_PACKET_BYTES:
        log(
            f"[!] SAMPLE_PACKET_BYTES={requested} is too large for JSON+base64 over one UDP datagram. "
            f"Clamping to {MAX_SAFE_SAMPLE_PACKET_BYTES}."
        )
    return min(requested, MAX_SAFE_SAMPLE_PACKET_BYTES)


class SDRSourceHandle:
    def __init__(self, source, ctx=None, dev=None):
        self.source = source
        self.ctx = ctx
        self.dev = dev


class PlutoInitError(RuntimeError):
    pass


def pluto_step(step_name: str):
    log(f"[*] Pluto init: {step_name}")


def format_iio_error(exc: Exception) -> str:
    message = str(exc)
    errno_value = getattr(exc, "errno", None)
    if errno_value is not None and f"[Errno {errno_value}]" not in message:
        message = f"[Errno {exc.errno}] {message}"
    return message


def pluto_init_delay(attempt: int) -> float:
    return min(PLUTO_INIT_BACKOFF_MAX_SEC, PLUTO_INIT_BACKOFF_BASE_SEC * (2 ** max(0, attempt - 1)))


def parse_iio_available_numbers(value: str):
    if not value:
        return []
    cleaned = value.replace("[", " ").replace("]", " ").replace(",", " ")
    numbers = []
    for part in cleaned.split():
        try:
            numbers.append(float(part))
        except ValueError:
            continue
    return numbers


def read_available_min(channel, attr_name: str):
    available = channel.attrs.get(f"{attr_name}_available")
    if available is None:
        return None
    try:
        raw_value = available.value
        numbers = parse_iio_available_numbers(raw_value)
    except Exception as exc:
        log(f"[!] Pluto init: could not read {attr_name}_available: {exc}")
        return None
    if raw_value.strip().startswith("[") and len(numbers) >= 3:
        return int(numbers[0])
    return int(min(numbers)) if numbers else None


def choose_pluto_sample_rate(rx_channel):
    requested = int(float(SAMPLE_RATE))
    min_rate = read_available_min(rx_channel, "sampling_frequency")
    if min_rate is None or requested >= min_rate:
        return requested

    adjusted = max(min_rate, PLUTO_SAFE_SAMPLE_RATE_HZ, requested)
    log(
        f"[!] SAMPLE_RATE={requested} is below Pluto minimum {min_rate}; "
        f"using {adjusted} Hz instead."
    )
    return adjusted


def parse_positive_int_list(value: str):
    result = []
    for part in value.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            parsed = int(part)
        except ValueError:
            continue
        if parsed > 0:
            result.append(parsed)
    return result


def pluto_buffer_candidates():
    requested = max(128, int(PLUTO_BUFFER_SAMPLES))
    initial_limit = max(128, int(PLUTO_MAX_INITIAL_BUFFER_SAMPLES))
    first = min(requested, initial_limit)
    candidates = [first]
    for value in parse_positive_int_list(PLUTO_BUFFER_FALLBACK_SAMPLES):
        value = max(128, min(int(value), initial_limit, requested))
        if value not in candidates:
            candidates.append(value)
    return candidates


def effective_pluto_buffer_samples(attempt=1):
    candidates = pluto_buffer_candidates()
    selected = candidates[min(max(1, int(attempt)) - 1, len(candidates) - 1)]
    requested = max(128, int(PLUTO_BUFFER_SAMPLES))
    if selected != requested:
        log(
            f"[!] PLUTO_BUFFER_SAMPLES={requested} requested; using "
            f"{selected} samples to reduce libiio/Pluto transport stress."
        )
    if selected > 8192:
        log(
            f"[!] Pluto RX buffer {selected} samples is larger than the conservative "
            "clone-safe range. Prefer 2048 or 4096 if transport errors continue."
        )
    return selected


def resolve_iio_uri():
    pluto_uri = PLUTO_IP.strip()
    if not pluto_uri or pluto_uri.lower() in ("local", "auto"):
        raise PlutoInitError(
            "PLUTO_IP=auto/local would trigger libiio auto-discovery. "
            "Set PLUTO_IP=192.168.2.1 or PLUTO_ALLOW_USB=1 if you really need USB."
        )
    if pluto_uri.lower() in ("usb", "usb:"):
        if not PLUTO_ALLOW_USB:
            raise PlutoInitError("USB backend disabled; set PLUTO_IP=192.168.2.1 or PLUTO_ALLOW_USB=1")
        return "usb:"
    if "://" in pluto_uri:
        return pluto_uri
    if ":" not in pluto_uri:
        return f"ip:{pluto_uri}"
    return pluto_uri


def iio_uri_host(uri: str):
    if not uri.startswith("ip:"):
        return None
    host = uri[3:]
    if ":" in host:
        host = host.rsplit(":", 1)[0]
    return host or None


def pluto_socket_test(uri: str):
    host = iio_uri_host(uri)
    if host is None:
        log(f"[*] Pluto diagnose: socket test skipped for non-IP URI {uri}")
        return
    pluto_step(f"socket test {host}:30431")
    with socket.create_connection((host, 30431), timeout=PLUTO_SOCKET_TIMEOUT_SEC):
        pass


def pluto_enabled_rx_channels():
    if PLUTO_RX_CHANNEL_MODE in ("i", "i_only", "single", "mono"):
        return {RX_CHANNEL}
    if RX_CHANNEL == "voltage1":
        return {"voltage1"}
    return {"voltage0", "voltage1"}


def pluto_sample_frame_bytes():
    return 2 if len(pluto_enabled_rx_channels()) == 1 else 4


class DummySdr:
    def __init__(
        self,
        sample_rate,
        read_bytes,
        signal_hz,
        noise_stddev,
        signal_amplitude,
    ):
        self.sample_rate = float(sample_rate)
        self.read_bytes = int(read_bytes)
        self.signal_hz = float(signal_hz)
        self.noise_stddev = float(noise_stddev)
        self.signal_amplitude = float(signal_amplitude)
        self.sample_index = 0
        self.rng = np.random.default_rng()

    def read(self):
        iq_pairs = max(2, self.read_bytes // 4)
        idx = np.arange(iq_pairs, dtype=np.float64) + self.sample_index
        self.sample_index += iq_pairs

        phase = 2.0 * np.pi * self.signal_hz * idx / self.sample_rate
        slow_phase = 2.0 * np.pi * idx / max(1.0, self.sample_rate * 0.7)
        envelope = 0.65 + 0.35 * np.sin(slow_phase)
        signal_i = np.cos(phase) * self.signal_amplitude * envelope
        signal_q = np.sin(phase) * self.signal_amplitude * envelope
        noise_i = self.rng.normal(0.0, self.noise_stddev, iq_pairs)
        noise_q = self.rng.normal(0.0, self.noise_stddev, iq_pairs)

        interleaved = np.empty(iq_pairs * 2, dtype=np.int16)
        interleaved[0::2] = np.clip(signal_i + noise_i, -32768, 32767).astype(np.int16)
        interleaved[1::2] = np.clip(signal_q + noise_q, -32768, 32767).astype(np.int16)
        return interleaved.tobytes()


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
    uri = resolve_iio_uri()
    pluto_step(f"create context {uri}")
    return iio.Context(uri)


def configure_radio(ctx):
    pluto_step("find ad9361-phy")
    phy = ctx.find_device("ad9361-phy")
    if phy is None:
        raise PlutoInitError("IIO device ad9361-phy not found")

    pluto_step("set LO frequency")
    lo = phy.find_channel("altvoltage0", True)
    if lo is None:
        raise PlutoInitError("IIO output channel altvoltage0 not found on ad9361-phy")
    lo.attrs["frequency"].value = str(TUNER_FREQ_HZ)

    pluto_step(f"select RX channel {RX_CHANNEL}")
    rx = phy.find_channel(RX_CHANNEL)
    if rx is None:
        raise PlutoInitError(f"IIO RX channel {RX_CHANNEL} not found on ad9361-phy")

    sample_rate = choose_pluto_sample_rate(rx)
    pluto_step(f"set sample rate {sample_rate}")
    rx.attrs["sampling_frequency"].value = str(sample_rate)

    if PLUTO_RF_BANDWIDTH_HZ > 0 and "rf_bandwidth" in rx.attrs:
        rf_bandwidth = PLUTO_RF_BANDWIDTH_HZ
    else:
        rf_bandwidth = int(max(200000, min(sample_rate, sample_rate * 0.8)))
    if "rf_bandwidth" in rx.attrs:
        pluto_step(f"set RF bandwidth {rf_bandwidth}")
        rx.attrs["rf_bandwidth"].value = str(rf_bandwidth)
    else:
        log("[!] Pluto init: RX channel has no rf_bandwidth attribute; leaving unchanged.")

    pluto_step(f"set gain {GAIN}")
    if "gain_control_mode" in rx.attrs:
        rx.attrs["gain_control_mode"].value = "manual"
    if "hardwaregain" in rx.attrs:
        rx.attrs["hardwaregain"].value = str(GAIN)
    else:
        log("[!] Pluto init: RX channel has no hardwaregain attribute; leaving gain unchanged.")

    pluto_step("find buffer device cf-ad9361-lpc")
    data_dev = ctx.find_device("cf-ad9361-lpc")
    if data_dev is None:
        raise PlutoInitError("IIO buffer-capable device cf-ad9361-lpc not found")
    enabled_channels = pluto_enabled_rx_channels()
    pluto_step(f"enable RX buffer channels {','.join(sorted(enabled_channels))}")
    for chan in data_dev.channels:
        chan.enabled = chan.id in enabled_channels
    return data_dev


def udp_send(sock: socket.socket, message: dict):
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sock.sendto(payload, (UDP_TARGET_HOST, UDP_TARGET_PORT))


def raw_signal_samples(raw_iq: bytes):
    dtype = np.uint8 if SDR_TYPE == "rtlsdr" else np.int16
    itemsize = np.dtype(dtype).itemsize
    limit = len(raw_iq) - (len(raw_iq) % itemsize)
    if limit <= 0:
        return None, 0

    samples = np.frombuffer(raw_iq[:limit], dtype=dtype).astype(np.float32)
    if SDR_TYPE == "rtlsdr":
        samples = samples - 127.5
    return samples, limit


def summarize_raw_signal(raw_iq: bytes):
    samples, limit = raw_signal_samples(raw_iq)
    if samples is None or samples.size < 2:
        return None

    return {
        "sample_bytes": int(limit),
        "sample_count": int(samples.size),
        "mean": round(float(np.mean(samples)), 4),
        "abs_mean": round(float(np.mean(np.abs(samples))), 4),
        "stddev": round(float(np.std(samples)), 4),
        "min_value": round(float(samples.min()), 4),
        "max_value": round(float(samples.max()), 4),
    }


def update_latest_signal_metrics(raw_iq: bytes):
    global latest_signal_metrics
    metrics = summarize_raw_signal(raw_iq)
    if metrics is None:
        return
    metrics["captured_at"] = time.time()
    with latest_signal_metrics_lock:
        latest_signal_metrics = metrics
    with stats_lock:
        runtime_stats["last_signal_at"] = metrics["captured_at"]


def get_latest_signal_metrics():
    with latest_signal_metrics_lock:
        if latest_signal_metrics is None:
            return None
        return dict(latest_signal_metrics)


def analyze_raw_signal(raw_iq: bytes):
    samples, limit = raw_signal_samples(raw_iq)
    if samples is None or samples.size < 2:
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
    cleanup_targets = [source_obj]
    if isinstance(source, SDRSourceHandle):
        cleanup_targets.extend([source.dev, source.ctx])

    for target in cleanup_targets:
        if target is None:
            continue
        for method_name in ("cancel", "close", "destroy"):
            method = getattr(target, method_name, None)
            if callable(method):
                try:
                    method()
                except Exception:
                    pass
    if isinstance(source, SDRSourceHandle):
        source.source = None
        source.dev = None
        source.ctx = None
    gc.collect()


def initialize_sdr_source(init_attempt=1):
    if SDR_TYPE == "dummy":
        dummy = DummySdr(
            sample_rate=SAMPLE_RATE,
            read_bytes=DUMMY_READ_BYTES,
            signal_hz=DUMMY_SIGNAL_HZ,
            noise_stddev=DUMMY_NOISE_STDDEV,
            signal_amplitude=DUMMY_SIGNAL_AMPLITUDE,
        )
        log(
            "[*] Dummy SDR initialized "
            f"(sample_rate={SAMPLE_RATE}, read_bytes={DUMMY_READ_BYTES}, "
            f"signal_hz={DUMMY_SIGNAL_HZ}, noise_stddev={DUMMY_NOISE_STDDEV})"
        )
        return SDRSourceHandle(dummy)

    if SDR_TYPE == "rtlsdr":
        sdr_obj = CompatRtlSdr(device_index=RTL_SDR_INDEX)
        sdr_obj.sample_rate = SAMPLE_RATE
        sdr_obj.center_freq = TUNER_FREQ_HZ
        sdr_obj.gain = GAIN
        sdr_obj.reset_buffer()
        log(f"[*] RTL-SDR successfully initialized: {sdr_obj}")
        return SDRSourceHandle(sdr_obj)

    sdr_ctx = None
    sdr_dev = None
    try:
        sdr_ctx = build_iio_context()
        sdr_dev = configure_radio(sdr_ctx)
        buffer_samples = effective_pluto_buffer_samples(init_attempt)
        pluto_step(f"create RX buffer {buffer_samples} samples")
        sdr_buffer = iio.Buffer(sdr_dev, buffer_samples)
        log(f"[*] PlutoSDR successfully initialized. Context: {sdr_ctx.name}")
        return SDRSourceHandle(sdr_buffer, ctx=sdr_ctx, dev=sdr_dev)
    except Exception:
        cleanup_sdr_source(SDRSourceHandle(None, ctx=sdr_ctx, dev=sdr_dev))
        raise


def has_repetition_run(bits: np.ndarray, max_run_length: int) -> bool:
    if bits.size < max_run_length:
        return False
    change_points = np.flatnonzero(np.diff(bits)) + 1
    run_lengths = np.diff(np.concatenate(([0], change_points, [bits.size])))
    return bool(run_lengths.max(initial=0) >= max_run_length)


def reconnect_sdr_source(previous_source, reason):
    cleanup_sdr_source(previous_source)
    for attempt in range(1, PLUTO_REINIT_ATTEMPTS + 1):
        try:
            log(
                f"[!] Reinitializing SDR after streaming failure ({reason}), "
                f"attempt {attempt}/{PLUTO_REINIT_ATTEMPTS}..."
            )
            return initialize_sdr_source(init_attempt=attempt)
        except Exception as exc:
            cleanup_sdr_source(None)
            log(f"[!] SDR reinit attempt {attempt}/{PLUTO_REINIT_ATTEMPTS} failed: {format_iio_error(exc)}")
            delay = pluto_init_delay(attempt)
            log(f"[*] Waiting {delay:.1f}s before next SDR reinit attempt.")
            time.sleep(delay)
    log(
        f"[!] Fatal: Could not recover SDR stream after {PLUTO_REINIT_ATTEMPTS} attempts. "
        f"Cooling down for {PLUTO_FAILURE_COOLDOWN_SEC:.0f}s, then exiting."
    )
    time.sleep(PLUTO_FAILURE_COOLDOWN_SEC)
    os._exit(1)


def entropy_sender_worker(source):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    entropy_accumulator = bytearray()
    chunk_target = effective_sample_packet_bytes()

    log(
        f"[*] Entropy sender worker active (node={NODE_NAME}, type={SDR_TYPE}, "
        f"sample_packet_bytes={chunk_target}, decimation={ENTROPY_DECIMATION_FACTOR})"
    )

    pluto_read_logged = False
    while True:
        read_stage = "idle"
        try:
            if SDR_TYPE == "rtlsdr":
                # read_bytes(n) returns bytes/bytearray for RTL-SDR
                read_stage = "rtlsdr_read_sync"
                raw_data = source.source.read_bytes(RTL_READ_BYTES)
            elif SDR_TYPE == "dummy":
                read_stage = "dummy_read"
                raw_data = source.source.read()
                if DUMMY_READ_SLEEP_SEC > 0:
                    time.sleep(DUMMY_READ_SLEEP_SEC)
            else:
                # buffer.refill() for PlutoSDR
                if not pluto_read_logged:
                    log("[*] Pluto stream: refill/read RX buffer")
                    pluto_read_logged = True
                read_stage = "pluto_buffer_refill"
                source.source.refill()
                read_stage = "pluto_buffer_read"
                raw_data = source.source.read()

            update_latest_raw_iq(raw_data)
            update_latest_signal_metrics(raw_data)

            # --- OPTIMIZED DSP PIPELINE (multi-bit XOR-fold + Von Neumann) ---
            # 1. Parse raw IQ samples
            dtype = np.uint8 if SDR_TYPE == "rtlsdr" else np.int16
            # Ensure we have a multiple of sample size (2 bytes for RTL, 4 for Pluto)
            limit = len(raw_data) - (len(raw_data) % (2 if SDR_TYPE == "rtlsdr" else pluto_sample_frame_bytes()))
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
                    with stats_lock:
                        runtime_stats["health_rejected_packets"] += 1
                        runtime_stats["rct_rejected_packets"] += 1
                        runtime_stats["last_health_rejected_at"] = time.time()
                    continue

            # APT: Adaptive Proportion Test (checks for strong bias in a window)
            # Window of 512 bits, max 400 of the same bit (conservative)
            if len(extracted_bits) >= 512:
                window = extracted_bits[:512]
                ones = np.sum(window)
                if ones < 112 or ones > 400: # Approx 0.22 to 0.78 proportion
                    log(f"[!] Health Check Failed: APT (bias detected: {ones}/512 ones). Dropping packet.")
                    with stats_lock:
                        runtime_stats["health_rejected_packets"] += 1
                        runtime_stats["apt_rejected_packets"] += 1
                        runtime_stats["last_health_rejected_at"] = time.time()
                    continue

            # 6. Pack bits into bytes and accumulate
            extracted_bytes = np.packbits(extracted_bits).tobytes()
            entropy_accumulator.extend(extracted_bytes)
            # ------------------------------------------------------------------

            # Respect configured packet size to avoid wasting throughput on
            # base64+JSON+UDP overhead per tiny payload.
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
            log(f"[!] SDR streaming error during {read_stage}: {format_iio_error(exc)}")
            entropy_accumulator.clear()
            source = reconnect_sdr_source(source, str(exc))
            pluto_read_logged = False
            time.sleep(1)


def encode_rgb_png(rgb: np.ndarray) -> bytes:
    height, width, channels = rgb.shape
    if channels != 3:
        raise ValueError("PNG encoder expects RGB data")

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        checksum = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)

    rows = [b"\x00" + np.ascontiguousarray(rgb[row]).tobytes() for row in range(height)]
    payload = b"".join(rows)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(payload, 6))
        + chunk(b"IEND", b"")
    )


def render_lightweight_waterfall_png(
    current_power: np.ndarray,
    y_min: float,
    y_max: float,
    history_frames,
) -> bytes:
    width = 960
    height = 360
    top = 30
    bottom = 32
    plot_h = height - top - bottom

    image = np.zeros((height, width, 3), dtype=np.uint8)
    image[:, :, 0] = 2
    image[:, :, 1] = 8
    image[:, :, 2] = 10

    for x_pos in range(0, width, 80):
        image[top : height - bottom, x_pos : x_pos + 1] = (5, 42, 48)
    for y_pos in range(top, height - bottom, 48):
        image[y_pos : y_pos + 1, :] = (5, 42, 48)

    xs_src = np.linspace(0, current_power.size - 1, current_power.size)
    xs_dst = np.linspace(0, current_power.size - 1, width)
    span = max(1e-6, y_max - y_min)

    def draw_trace(values: np.ndarray, color, glow=False):
        resampled = np.interp(xs_dst, xs_src, values)
        norm = np.clip((resampled - y_min) / span, 0.0, 1.0)
        ys = (height - bottom - 1 - norm * (plot_h - 1)).astype(np.int32)
        for x_pos, y_pos in enumerate(ys):
            image[y_pos : min(height - bottom, y_pos + 2), x_pos] = color
            if glow:
                y0 = max(top, y_pos - 2)
                y1 = min(height - bottom, y_pos + 3)
                image[y0:y1, x_pos, 1] = np.maximum(image[y0:y1, x_pos, 1], 75)
                image[y0:y1, x_pos, 2] = np.maximum(image[y0:y1, x_pos, 2], 90)
                image[y_pos : height - bottom, x_pos, 1] = np.maximum(
                    image[y_pos : height - bottom, x_pos, 1],
                    22,
                )

    for frame_index, history in enumerate(history_frames[:-1]):
        fade = 50 + int(60 * (frame_index + 1) / max(1, len(history_frames)))
        draw_trace(history, (8, fade, fade + 20), glow=False)
    draw_trace(current_power, (103, 232, 249), glow=True)

    title = f"{NODE_NAME}  {DISPLAY_FREQ_HZ / 1e6:.3f} MHz"
    draw_ascii_label(image, title[:80], 24, 14, (103, 232, 249))
    draw_ascii_label(image, "DUMMY SDR WATERFALL", 24, height - 24, (34, 211, 238))
    return encode_rgb_png(image)


def draw_ascii_label(image: np.ndarray, text: str, x: int, y: int, color):
    glyph_w = 5
    glyph_h = 7
    cursor = x
    for char in text.upper():
        if cursor + glyph_w >= image.shape[1]:
            break
        pattern = SIMPLE_FONT.get(char, SIMPLE_FONT.get(" "))
        for row, bits in enumerate(pattern):
            for col, bit in enumerate(bits):
                if bit == "1":
                    y0 = y + row * 2
                    x0 = cursor + col * 2
                    image[y0 : y0 + 2, x0 : x0 + 2] = color
        cursor += (glyph_w + 1) * 2


SIMPLE_FONT = {
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "10000", "11110", "00001", "00001", "11110"],
    "6": ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01110", "10001", "10000", "10111", "10001", "10001", "01110"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
}


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

            if SDR_TYPE == "pluto" and pluto_sample_frame_bytes() == 2:
                iq_complex = iq.astype(np.complex64)
            else:
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

            if SDR_TYPE == "dummy":
                frame_bytes = {"png": render_lightweight_waterfall_png(y, y_min, y_max, history_frames)}
            else:
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
                    try:
                        fig.savefig(buf, **save_kwargs)
                        frame_bytes[image_format] = buf.getvalue()
                    except Exception as exc:
                        log(f"[!] Could not render {image_format} waterfall frame: {exc}")
                plt.close(fig)
            if not frame_bytes:
                time.sleep(2)
                continue
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

    first_run = True
    while True:
        try:
            triggered = False
            if first_run:
                pass
            else:
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
            first_run = False
            log(
                f"[*] Source audit sent (node={NODE_NAME}, repeat_score={metrics['repeat_score']}, "
                f"spectral_flatness={metrics['spectral_flatness']})"
            )
        except Exception as exc:
            log(f"[!] Source audit error: {exc}")
            time.sleep(5)


def node_metrics_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log(
        f"[*] Node metrics worker ready (node={NODE_NAME}, interval={NODE_METRICS_INTERVAL_SEC}s)"
    )

    while True:
        try:
            time.sleep(max(1, NODE_METRICS_INTERVAL_SEC))
            with stats_lock:
                snapshot = dict(runtime_stats)
            signal = get_latest_signal_metrics()
            message = {
                "type": "node_metrics",
                "node": NODE_NAME,
                "timestamp": time.time(),
                "stats": snapshot,
            }
            if signal is not None:
                message["signal"] = signal
            udp_send(sock, message)
        except Exception as exc:
            log(f"[!] Node metrics send error: {exc}")
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
        last_signal_age = (
            round(time.time() - snapshot["last_signal_at"], 1)
            if snapshot["last_signal_at"]
            else None
        )
        log(
            "[*] SDR node stats: "
            f"node={NODE_NAME}, "
            f"sample_packets_sent={snapshot['sample_packets_sent']}, "
            f"sample_bytes_sent={snapshot['sample_bytes_sent']}, "
            f"health_rejected_packets={snapshot['health_rejected_packets']}, "
            f"waterfalls_sent={snapshot['waterfalls_sent']}, "
            f"waterfall_parts_sent={snapshot['waterfall_parts_sent']}, "
            f"source_audits_sent={snapshot['source_audits_sent']}, "
            f"last_sample_age_sec={last_sample_age}, "
            f"last_waterfall_age_sec={last_waterfall_age}, "
            f"last_source_audit_age_sec={last_source_audit_age}, "
            f"last_signal_age_sec={last_signal_age}"
        )


def diagnose_pluto():
    if SDR_TYPE != "pluto":
        log(f"[!] --diagnose-pluto is intended for SDR_TYPE=pluto, current SDR_TYPE={SDR_TYPE}")
    source = None
    try:
        uri = resolve_iio_uri()
        pluto_socket_test(uri)
        pluto_step(f"create context {uri}")
        ctx = iio.Context(uri)
        log(f"[*] Pluto diagnose: context created ({ctx.name})")
        device_names = [dev.name or dev.id for dev in ctx.devices]
        log(f"[*] Pluto diagnose: devices={', '.join(device_names)}")

        dev = configure_radio(ctx)
        buffer_samples = min(effective_pluto_buffer_samples(), 2048)
        pluto_step(f"create RX buffer {buffer_samples} samples")
        buf = iio.Buffer(dev, buffer_samples)
        source = SDRSourceHandle(buf, ctx=ctx, dev=dev)

        pluto_step("refill/read buffer")
        buf.refill()
        raw = buf.read()
        log(f"[*] Pluto diagnose: read {len(raw)} bytes from RX buffer")
        metrics = analyze_raw_signal(raw)
        if metrics:
            log(
                "[*] Pluto diagnose: "
                f"stddev={metrics['stddev']}, min={metrics['min_value']}, "
                f"max={metrics['max_value']}, repeat_score={metrics['repeat_score']}"
            )
        log("[*] Pluto diagnose: OK")
        return 0
    except Exception as exc:
        log(f"[!] Pluto diagnose failed: {format_iio_error(exc)}")
        return 1
    finally:
        cleanup_sdr_source(source)


def run_sdr_node():
    log(
        f"[*] SDR node {NODE_NAME} starting. Target: "
        f"{UDP_TARGET_HOST}:{UDP_TARGET_PORT}, Source type: {SDR_TYPE}"
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
    if SDR_TYPE == "pluto":
        time.sleep(5)

    # Main initialization loop - process won't start workers until hardware is ready
    sdr_source = None
    for attempt in range(1, PLUTO_INIT_ATTEMPTS + 1):
        try:
            log(f"[*] SDR init attempt {attempt}/{PLUTO_INIT_ATTEMPTS} (Type: {SDR_TYPE})...")
            sdr_source = initialize_sdr_source(init_attempt=attempt)
            break
        except Exception as exc:
            cleanup_sdr_source(sdr_source)
            sdr_source = None
            log(f"[!] SDR init failed: {format_iio_error(exc)}")
            if attempt < PLUTO_INIT_ATTEMPTS:
                delay = pluto_init_delay(attempt)
                log(f"[*] Waiting {delay:.1f}s before next SDR init attempt.")
                time.sleep(delay)
    else:
        log(
            f"[!] Fatal: Could not initialize SDR after {PLUTO_INIT_ATTEMPTS} attempts. "
            f"Cooling down for {PLUTO_FAILURE_COOLDOWN_SEC:.0f}s, then exiting."
        )
        if SDR_TYPE == "pluto":
            time.sleep(PLUTO_FAILURE_COOLDOWN_SEC)
        os._exit(1)

    # Start workers - pass the initialized source to the sampler thread
    threading.Thread(target=entropy_sender_worker, args=(sdr_source,), daemon=True).start()
    threading.Thread(target=waterfall_sender_worker, daemon=True).start()
    threading.Thread(target=source_audit_worker, daemon=True).start()
    threading.Thread(target=node_metrics_worker, daemon=True).start()
    threading.Thread(target=status_poller_worker, daemon=True).start()
    threading.Thread(target=stats_logger_worker, daemon=True).start()

    while True:
        time.sleep(60)


def parse_args():
    parser = argparse.ArgumentParser(description="Big Bang Entropy SDR node")
    parser.add_argument(
        "--diagnose-pluto",
        action="store_true",
        help="run a one-shot PlutoSDR IIO connectivity and small-buffer read test without UDP",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.diagnose_pluto:
        raise SystemExit(diagnose_pluto())
    run_sdr_node()
