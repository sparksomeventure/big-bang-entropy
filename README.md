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

## Scope

This starter intentionally ships a minimal dashboard and container setup only. It avoids the current production-facing branding, public-service messaging, CI/CD details, and the larger website layer.

## License

This starter is intended to be published under the MIT License. See `LICENSE`.

## Authors

- SparkSome Ventrue Sp. z o.o.
- Tomasz Siroń
- Bartłomiej Pałka
