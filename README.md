# Big Bang Entropy Open-Source Starter

This directory contains the files needed to package and run a minimal self-hosted edition of Big Bang Entropy.

If you are looking for the full project description, public service details, or broader architecture notes, use the main repository README:

- [Main project README](https://github.com/sparksomeventure/big-bang-entropy/blob/main/README.md)

This document is intentionally focused on the starter package itself: what goes into it, how to assemble it, and how to run it locally or on your own infrastructure.

The intended package consists of:

- `entropy_server.py`
- `sdr_node.py`
- `audit/run_audit.py`
- the files from this `opensource-elements` directory, copied with structure preserved

## What Is Included Here

- `docker-compose.yml`
- `Dockerfile.generator`
- `Dockerfile.sdr`
- `Dockerfile.audit`
- `Dockerfile.nginx`
- `nginx.conf`
- `static/favicon.png`
- `templates/dashboard.html`
- `audit/entrypoint.sh`
- `LICENSE`

## Suggested Packaging Layout

After copying the core source files and this directory's contents into a clean repository, the result should look like this:

```text
.
├── Dockerfile.audit
├── Dockerfile.generator
├── Dockerfile.nginx
├── Dockerfile.sdr
├── LICENSE
├── README.md
├── docker-compose.yml
├── entropy_server.py
├── nginx.conf
├── sdr_node.py
├── static
│   └── favicon.png
├── audit
│   ├── entrypoint.sh
│   └── run_audit.py
└── templates
    └── dashboard.html
```

## Quick Start

1. Connect a PlutoSDR device for the SDR node.
2. Copy `entropy_server.py`, `sdr_node.py`, and `audit/run_audit.py` into the structure shown above.
3. Copy the contents of this directory into the same repository root.
4. Run:

```bash
docker compose up --build
```

Services:

- Dashboard: `http://localhost:8080`
- TCP entropy stream: `localhost:1420`
- UDP SDR ingest: `localhost:5005/udp`

## Architecture Overview

The starter package is split into a few clearly separated components:

- `generator` - central entropy server; receives SDR input, mixes it, stores it in a consumable pool, and exposes public endpoints
- `sdr-node` - local SDR worker connected to PlutoSDR; captures raw radio samples, extracts random material, and sends it to the generator over UDP
- `nginx` - serves the static dashboard and proxies HTTP requests to the generator
- `audit` - periodically checks generator output quality and writes public audit reports to `/reports/`

High-level data flow:

```text
antenna -> PlutoSDR -> sdr-node -> UDP -> generator -> entropy pool -> HTTP/TCP clients
```

The architecture is ready for more than one SDR node. Multiple nodes can send entropy to the same central generator in parallel.

## SDR Node Naming

SDR nodes use a compact naming convention:

```text
<country>-<city>-<technology>-<hardware>-<antenna><id>
```

Example:

```text
pl-lub-sdr-ad9363-omni01
```

Meaning:

- `pl` - country code (ISO 3166-1 alpha-2)
- `lub` - city or location shorthand
- `sdr` - node technology
- `ad9363` - SDR hardware or chipset
- `omni` - antenna type
- `01` - node identifier within that hardware and antenna group

Additional deployment details such as `indoor/outdoor`, OS, or image version should stay in metadata rather than in the node name.

## Configuration Notes

The most important settings for a node deployment are:

- `NODE_NAME` - logical name of the SDR node, for example `pl-lub-sdr-ad9363-omni01`
- `RECEIVER_ID` - optional ID of one physical receiver/RF chain on the same host
- `PHYSICAL_HOST_ID` - optional physical host ID used to group several receivers on one box
- `NODE_ID` - optional compatibility override; when empty, the stream ID is `NODE_NAME`
- `UDP_TARGET_HOST` - hostname or IP address of the central generator

For multiple receivers on one physical host, run one container per receiver with a unique
`NODE_NAME`, the same `PHYSICAL_HOST_ID`, and a different `RECEIVER_ID` plus the right
hardware selector, such as `RTL_SDR_INDEX`, `PLUTO_IP`, or `RX_CHANNEL`. The generator uses
`NODE_NAME` as the unique key by default, while host and receiver details stay available as
metadata.

Keep `NODE_NAME` in the `country-location-technology-radio-antennaNumber` convention, for
example `pl-lub-sdr-ad9363-omni01`, `pl-lub-sdr-rtlsdr-loop01`, or
`de-ber-sdr-hackrf-omni03`. Frequency bands belong in `FREQ`, not in the node name.

`RECEIVER_ID` is a human-assigned stable label, not necessarily a hardware serial. To see
what the node will use, run:

```bash
docker compose run --rm sdr-node-1 python3 sdr_node.py --print-identity
docker compose run --rm sdr-node-1 python3 sdr_node.py --list-devices
```

For a multi-host setup, the SDR node does not need a local generator container. It can send UDP packets to any reachable generator instance.

## Local Interfaces And Ports

The starter package exposes a few important local interfaces:

- `http://localhost:8080/` - dashboard
- `localhost:1420` - raw TCP entropy stream
- `localhost:5005/udp` - UDP ingest for SDR node packets

Common generator endpoints:

- `/raw` - returns a single raw entropy chunk
- `/raw/stream` - streams a requested number of bytes
- `/download/entropy` - returns entropy as a downloadable file
- `/healthz` - basic service health and pool state
- `/sources` - active SDR sources
- `/source-audits` - latest raw-signal audits reported by SDR nodes
- `/waterfalls` - available waterfall frames

## Local API Reference

The starter package exposes the same application endpoints, but in your own local or self-hosted environment.

### Output formats

- Raw entropy endpoints return `application/octet-stream`
- Diagnostic and generator endpoints return JSON
- Waterfall image endpoints return `image/png` or `image/webp`

### Core entropy endpoints

#### `GET /raw`

Returns a single binary chunk of raw entropy.

- Response: `200 OK` with `application/octet-stream`
- Warm-up behavior: `503 Warming up...` when the pool is not ready
- Chunk size: controlled by local server configuration, currently exposed by `/healthz` as `raw_http_chunk`

Example:

```bash
curl http://localhost:8080/raw --output entropy.bin
```

#### `GET /raw/stream?bytes=<n>`

Streams up to the requested number of bytes from the local entropy pool.

- Query parameter: `bytes` optional, positive integer
- Default request size: `STREAM_CHUNK_BYTES * 16`, exposed operationally by the local service
- Response: `200 OK` with streamed `application/octet-stream`
- Partial delivery is possible when the pool is still warming up or temporarily low

Example:

```bash
curl "http://localhost:8080/raw/stream?bytes=1048576" --output 1mb.bin
```

#### `GET /download/entropy?bytes=<n>`

Same entropy stream as `/raw/stream`, but returned with a download-oriented filename header.

- Query parameter: `bytes` optional, positive integer
- Response header: `Content-Disposition: attachment; filename="entropy-<timestamp>.bin"`
- Response header: `X-Entropy-Requested-Bytes`

Example:

```bash
curl -OJ "http://localhost:8080/download/entropy?bytes=65536"
```

### Diagnostics and monitoring endpoints

#### `GET /healthz`

Returns the current high-level status of the local service, including:

- pool size in bytes
- pool fill percentage
- configured public chunk sizes
- TCP session size
- active SDR source counts
- source-audit thresholds

Example:

```bash
curl http://localhost:8080/healthz
```

#### `GET /sources`

Returns the current snapshot of source nodes and their latest activity and audit state.

Example:

```bash
curl http://localhost:8080/sources
```

#### `GET /source-audits`

Returns the latest raw-signal audit payloads reported by SDR nodes.

Example:

```bash
curl http://localhost:8080/source-audits
```

#### `GET /waterfalls`

Returns a JSON list of available waterfall previews and frame metadata.

Example:

```bash
curl http://localhost:8080/waterfalls
```

#### `GET /waterfall`

Returns the latest waterfall image for the default or selected node.

- Optional query parameter: `node`
- Returns `503` when no waterfall is available yet

#### `GET /waterfall/<node>.<png|webp>?frame=<frame_id>`

Returns a specific waterfall image format for a node.

- Supported formats: `png`, `webp`
- Optional query parameter: `frame`
- Returns `404` if the node, frame, or image format is unavailable

### Utility generator endpoints

These endpoints consume entropy from the same local pool and return JSON.

#### `GET /api/password`

Query parameters:

- `length` default `16`, allowed `1..1024`
- `count` default `1`, allowed `1..1000`
- `lowercase` default `1`
- `uppercase` default `1`
- `numbers` default `1`
- `special` default `1`

Errors:

- `400 {"error":"Invalid parameters"}`
- `400 {"error":"Empty alphabet"}`
- `503 Warming up...`

Example:

```bash
curl "http://localhost:8080/api/password?length=24&count=3"
```

#### `GET /api/pin`

Query parameters:

- `length` default `4`, allowed values: `4` or `6`
- `count` default `1`, allowed `1..1000`

Errors:

- `400 {"error":"Invalid parameters"}`
- `503 Warming up...`

Example:

```bash
curl "http://localhost:8080/api/pin?length=6&count=5"
```

#### `GET /api/lotto`

Query parameters:

- `count` default `1`, allowed `1..1000`

Response:

- JSON with `lotto`, where each item is a sorted draw of 6 unique integers from `1..49`

Errors:

- `400 {"error":"Invalid parameters"}`
- `503 Warming up...`

Example:

```bash
curl "http://localhost:8080/api/lotto?count=3"
```

## Intended Use

This starter is meant for:

- local evaluation
- self-hosted deployments
- SDR node experiments
- integration into your own infrastructure

It is not a separate commercial SLA document and it is not the primary place for describing the public hosted service. For project-wide positioning and hosted-service context, refer to the main repository README.

## Audit Reports

The `audit` container periodically downloads a sample from the generator and runs statistical checks against it.

Reports are written to the shared `/reports/` directory and can be published directly by `nginx`. A typical audit run produces:

- an `HTML` report for quick inspection
- a `JSON` report for automation
- `SHA-256` checksum files
- an integrity-chain record

By default the daily audit stack runs a light set of representative `Dieharder` tests
(`0,1,8,15,100`) instead of a single subtest. It intentionally skips `rank_32x32`
(`-d 2`) because a 20 MiB daily sample can make Dieharder rewind the input file and
produce low-confidence results. `PractRand` is supported as an optional heavier stage and
can be enabled with `AUDIT_PRACTRAND=1`.

The compose stack also defines `audit-weekly`, which writes to the same `/reports` volume
and is intended for a deeper weekly run:

```env
AUDIT_WEEKLY_CRON=23 3 * * 0
AUDIT_WEEKLY_SAMPLE_SIZE=335544320
AUDIT_WEEKLY_PREMIX_SIZE=67108864
AUDIT_WEEKLY_DIEHARDER_TESTS=0,1,2,8,15,100
AUDIT_WEEKLY_PRACTRAND=1
AUDIT_WEEKLY_PRACTRAND_TLMAX=1G
AUDIT_WEEKLY_PRACTRAND_MAX_BYTES=268435456
```

If `RNG_test` is not installed in the audit image, the audit report will add an alert instead of
failing the whole run.

## Raw SDR Signal Audits

Each `sdr-node` also performs a separate audit of the raw SDR input before entropy extraction:

- once immediately after container startup
- then periodically, by default every `86400` seconds

The node sends this diagnostic report to the generator as a separate UDP message
`type: "source_audit"`, similar in spirit to the waterfall diagnostic stream.

The generator keeps the latest raw-signal audit per node, exposes it through `/source-audits`,
and also enriches `/sources` with the latest source-audit status so the main audit report can
show source-level warnings.

The raw-signal audit computes a `repeat_score`. When the latest score for a node exceeds
`SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD`, or when the node has not sent any raw-signal audit yet,
the generator will:

- stop accepting entropy packets from that node
- keep the node visible in status output
- mark the node as `WARN` rather than healthy

Useful related settings:

```env
SOURCE_AUDIT_INTERVAL_SEC=86400
SOURCE_AUDIT_SAMPLE_BYTES=262144
SOURCE_AUDIT_REPEAT_SCORE_THRESHOLD=0.9
SOURCE_AUDIT_MAX_AGE_SEC=129600
SOURCE_AUDIT_STATE_PATH=/tmp/bbe-source-audits.json
```

## How Randomness Is Produced

The system does not rely on software pseudo-randomness alone.

At the node level, PlutoSDR captures physical radio noise and ADC-level instability from the real RF chain. The SDR worker selects the most useful noisy bits, reduces bias and correlation, and forwards that material to the generator.

At the generator level, data from one or more nodes is mixed with a SHA-512-based mechanism before it enters the public consumable pool. This adds cryptographic resilience and helps separate public output from the raw internal state.

## Algorithm Notes

The entropy path has two layers:

- a signal-processing extractor inside `sdr_node.py`
- a cryptographic mixer inside `entropy_server.py`

### SDR node extractor

The SDR node reads signed 16-bit IQ samples from PlutoSDR. In simplified form:

```python
samples = np.frombuffer(raw_data, dtype=np.int16)
```

The extractor then applies four main steps.

1. Decimation for decorrelation

```python
decimated = samples[::4]
```

Adjacent ADC samples are not fully independent because the SDR front-end and digital filters introduce short-range memory. Taking every fourth sample reduces local correlation before bit extraction.

2. Low-bit extraction

```python
lsb0 = (decimated & np.int16(1)).astype(np.uint8)
lsb1 = ((decimated >> 1) & np.int16(1)).astype(np.uint8)
bits = lsb0 ^ lsb1
```

The least significant bits carry most of the quantization-level noise. Higher bits are influenced more strongly by deterministic signal amplitude. XOR-ing bit 0 and bit 1 acts as a very cheap pre-whitening step.

If:

```text
P(lsb0 = 1) = 0.5 + e0
P(lsb1 = 1) = 0.5 + e1
```

then:

```text
P(lsb0 XOR lsb1 = 1) ≈ 0.5 - 2*e0*e1
```

So the resulting bias is of second order in the original small biases.

3. Von Neumann extraction

The bitstream is grouped into pairs:

```python
pairs = bits.reshape(-1, 2)
valid_mask = pairs[:, 0] != pairs[:, 1]
extracted_bits = pairs[valid_mask, 0]
```

The rule is:

- `00` -> discard
- `11` -> discard
- `01` -> output `0`
- `10` -> output `1`

For an input bit with bias `P(b = 1) = p`, the useful pairs occur with equal probability:

```text
P(01) = p(1 - p)
P(10) = (1 - p)p
```

Therefore the output of the accepted pairs is unbiased, provided the input pairs are sufficiently independent. That is why the decimation step matters.

4. Packing and transport

The accepted bits are packed into bytes and sent in fixed UDP chunks to the generator.

Typical order of magnitude for one SDR cycle:

- `65536` raw samples
- about `16384` samples after decimation
- about `16384` XOR-fold bits
- about `4096-5000` bits after Von Neumann extraction
- about `512-625` output bytes before buffering into 1024-byte UDP packets

### Generator mixer

The generator maintains an internal 64-byte state and processes incoming entropy in fixed-size blocks.

In simplified form:

```python
state_next = SHA512(state_prev || node_name || source_timestamp || block || local_time_ns)
```

where:

- `state_prev` is the previous internal generator state
- `node_name` binds the source identity
- `source_timestamp` binds source timing
- `block` is the current raw entropy block from the node
- `local_time_ns` adds local arrival-time variation

Each digest becomes both:

- the next internal state
- material appended to the public entropy pool

This gives the mixer two important properties:

- chaining: every new output depends on all previous internal state transitions
- one-way protection: public output does not reveal the internal state needed to predict future output

In engineering terms, the SDR node is responsible for extracting physical unpredictability, and the generator is responsible for cryptographic whitening, state isolation, and aggregation across many nodes.

## Scope

This starter intentionally ships a minimal dashboard and container setup only. It avoids the current production-facing branding, public-service messaging, CI/CD details, and the larger website layer.

## License

This starter is intended to be published under the MIT License. See `LICENSE`.

## Authors

- SparkSome Ventrue Sp. z o.o.
- Tomasz Siroń
- Bartłomiej Pałka
