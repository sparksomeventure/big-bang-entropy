# Big Bang Entropy Core Starter

This directory contains the supporting files for a minimal open-source package of the project.

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

- `generator` - central entropy server; receives SDR input, mixes it, stores it in a FIFO pool, and exposes public endpoints
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
- `UDP_TARGET_HOST` - hostname or IP address of the central generator

For a multi-host setup, the SDR node does not need a local generator container. It can send UDP packets to any reachable generator instance.

## API And Ports

The minimal package exposes a few important interfaces:

- `http://localhost:8080/` - dashboard
- `localhost:1420` - raw TCP entropy stream
- `localhost:5005/udp` - UDP ingest for SDR node packets

Common generator endpoints:

- `/raw` - returns a single raw entropy chunk
- `/raw/stream` - streams a requested number of bytes
- `/download/entropy` - returns entropy as a downloadable file
- `/healthz` - basic service health and pool state
- `/sources` - active SDR sources
- `/waterfalls` - available waterfall frames

## Audit Reports

The `audit` container periodically downloads a sample from the generator and runs statistical checks against it.

Reports are written to the shared `/reports/` directory and can be published directly by `nginx`. A typical audit run produces:

- an `HTML` report for quick inspection
- a `JSON` report for automation
- `SHA-256` checksum files
- an integrity-chain record

## How Randomness Is Produced

The system does not rely on software pseudo-randomness alone.

At the node level, PlutoSDR captures physical radio noise and ADC-level instability from the real RF chain. The SDR worker selects the most useful noisy bits, reduces bias and correlation, and forwards that material to the generator.

At the generator level, data from one or more nodes is mixed with a SHA-512-based mechanism before it enters the public FIFO pool. This adds cryptographic resilience and helps separate public output from the raw internal state.

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
