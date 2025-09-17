---
date: 2025-09-16T06:00:00Z
title: "Pingoo listeners"
type: "page"
url: "/docs/listeners"
---

# Listeners

Listeners are the entrypoints of

**pingoo.yml**
```yml
listeners:
  http:
    address: http://0.0.0.0:8080
  https:
    address: http://0.0.0.0:8080
    services: ["api"]
```

## Zero-downtime upgrades

Pingoo uses the `SO_REUSEPORT` flag on sockets to enable zero-downtime upgrades

If you are using docker you will need to use the `--network host` CLI argument.
