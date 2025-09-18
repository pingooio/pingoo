---
date: 2025-09-16T06:00:00Z
title: "Pingoo listeners"
type: "page"
url: "/docs/listeners"
---

# Listeners

Listeners are the addresses, ports and protcols that Pingoo listen to.

**pingoo.yml**
```yml
listeners:
  http:
    address: http://0.0.0.0:8080
  https:
    address: http://0.0.0.0:8080
    services: ["api"]
```

Valid protocols:
- `http`
- `https`
- `tcp`
- `tcp+tls`

Pingoo only support HTTP/2 (and QUIC with HTTP/3 soon) on `https` listeners, on purpose. HTTP/2 was introduced in 2015 and is supported by virtually all browsers and client libraries: https://caniuse.com/http2. Only abandonned bots don't support HTTP/2. Clients are informed of this via the ALPN TLS field.

## Graceful shutdown

When receiving a `Ctrl+C` / `terminate` signal, listeners initiate the graceful shutdown process. They first stop accepting new connections / requests and then wait up to 20 seconds (may change in the future) for in-flight connections / request to finish.

## Zero-downtime upgrades

Pingoo uses the `SO_REUSEPORT` option on sockets to enable zero-downtime upgrades

If you are using docker you will need to use the `--network host` CLI argument to use zer-downtime upgrade with `SO_REUSEPORT`.

```bash
$ docker run -d --network host ghcr.io/pingooio/pingoo
```
