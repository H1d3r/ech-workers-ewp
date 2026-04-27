# EWP v2 — example configurations

All configs in this directory drive the unified `cmd/ewp` binary:

```
ewp -config <file>.yaml
```

| File | Role |
|---|---|
| `client-socks5.yaml` | Local SOCKS5 proxy → ewpclient (WebSocket+ECH+ML-KEM) |
| `client-http.yaml` | Local HTTP CONNECT proxy → ewpclient |
| `client-tun.yaml` | OS-level TUN interface (TODO: still needs platform setup) |
| `server.yaml` | EWP-WebSocket listener + direct outbound (typical VPS deployment) |
| `relay.yaml` | EWP listener + ewpclient outbound (chain through another node) |

Replace placeholder values (`UUID`, `URL`, certificate paths) before running.

## UUID

Generate with `uuidgen` or any UUID v4 tool. The same UUID must be present on
both client (in `outbounds[].uuid`) and server (in `inbounds[].uuids`).

## TLS

Server-side TLS uses standard PEM cert/key. Get them from Let's Encrypt
(`certbot`) or any other CA. Client-side TLS uses the embedded Mozilla CA
bundle by default; no system trust store dependency.

## ECH

To enable ECH, point `ech: true` and ensure your server's domain has an
HTTPS resource record advertising the ECH config. The bootstrap DoH (in the
`ech.bootstrap_doh` block) fetches that record at startup.
