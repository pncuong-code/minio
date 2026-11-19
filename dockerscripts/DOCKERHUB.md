# MinIO — pncuong-code hardened fork

> **Unofficial fork — not affiliated with, authorized, or endorsed by MinIO, Inc.**
> This image recompiles the AGPL v3.0 MinIO community edition from source with
> backported security fixes. "MinIO" is a trademark of MinIO, Inc., used here only
> to identify the upstream software. Official software and support: https://min.io

High Performance, Kubernetes-native, **S3-compatible** object storage.

This image is a **community MinIO fork with backported security hardening**. The
upstream community edition is no longer maintained; this fork recompiles MinIO
from source (not a repackaged upstream binary) with fixes from an internal
security re-audit (ANBM): path-traversal, authentication/identity confusion,
and resource-limit issues that remain unpatched in the public upstream.

It is a **drop-in replacement** for `minio/minio` — same binary, entrypoint,
command, ports and volumes.

## Tags

- `latest` — most recent build from `master`
- `sha-<shortsha>` — pinned to an exact commit (recommended for production)
- `RELEASE.<timestamp>.hotfix.<shortsha>` — the embedded release tag

Multi-arch: `linux/amd64`, `linux/arm64`.

## Quick start

```bash
docker run -d --name minio \
  -p 9000:9000 -p 9001:9001 \
  -v minio-data:/data \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=change-me-please \
  ghcr.io/pncuong-code/minio:latest \
  server /data --console-address ":9001"
```

- S3 API: `:9000` · Console: `:9001`
- Set strong `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` (never leave defaults in production).

## Verify the build

```bash
docker run --rm ghcr.io/pncuong-code/minio:latest --version
```

Source, Dockerfile and the exact commit each image was built from:
<https://github.com/pncuong-code/minio>

## License

GNU AGPL v3.0 — see `/licenses/LICENSE` inside the image.
