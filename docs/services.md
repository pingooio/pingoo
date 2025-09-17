---
date: 2025-09-16T06:00:00Z
title: "Pingoo services"
type: "page"
url: "/docs/services"
---


# Services


## Routing


## HTTP Proxy

### HTTP headers


pingoo adds a few HTTP headers


`x-forwarded-host`

`x-forwarded-for`

`x-forwarded-proto`

`pingoo-client-ip`

`pingoo-client-country`

`pingoo-client-asn`


## Service Discovery

### DNS

### Docker

pingoo automagically discovers containers that are tagged with the `pingoo.service` label.

```yml
services:
  api:
    http_proxy:
```

```bash
docker run --label pingoo.service=api my_api_image:latest
```

pingoo requires that your containers expose a single port (e.g. `EXPOSE 8080`). If you containers don't expose any port or expost multiple ports, you will need to tag them with the `pingoo.port` label.


```bash
docker run --label pingoo.service=api --label pingoo.port=8080 my_api_image:latest
```


In order to enabled docker service discovery pingoo needs access to the docker socket, so if you are running pingoo inside a docker container you need to bind it:
```bash
docker run -d -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/pingooio/pingoo
```
