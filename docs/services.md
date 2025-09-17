---
date: 2025-09-16T06:00:00Z
title: "Pingoo services"
type: "page"
url: "/docs/services"
---


# Services


## Routing


```yml
services:
  api:
    route: host.starts_with("api")
    http_proxy: ["http://127.0.0.1"]
```

## HTTP Proxy

```yml
listeners:
  http:
    address: http://0.0.0.0:8080

services:
  api:
    route: host.starts_with("api")
    http_proxy: ["http://api.myservice.internal"]
```

### HTTP headers

Ppingoo the following HTTP headers to requests to upstream servers when used in HTTP proxy mode:


`x-forwarded-host`: The original `Host` header. e.g. `example.com`

`x-forwarded-for`:

`x-forwarded-proto`: `http` or `https`

`pingoo-client-ip`: The IP address of the client. e.g. `1.2.3.4`


The following headers are available **only** if [geoip](/docs/geoip) is enabled:

`pingoo-client-country`: The 2-letters codes of the country, inferred from the IP address. e.g. `FR`

`pingoo-client-asn`: The [Autonomous System Number](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)), inferred from the IP address. e.g. `123`


## TCP proxy

**pingoo.yml**
```yml
listeners:
  tcp:
    address: tcp://0.0.0.0:25

services:
  smtp_plaintest:
    tcp_proxy: ["tcp://1.2.3.4:25", "tcp://4.3.2.1:25"]
```

## Static

```yml
listeners:
  http:
    address: http://0.0.0.0:8080

services:
  webapp:
    static:
      root: /var/www
```


## Service Discovery

### DNS

Pingoo automatically resolves domains in upstreams.

### Docker

Pingoo automagically discovers containers that are tagged with the `pingoo.service` label.

```yml
listeners:
  http:
    address: http://0.0.0.0:8080

services:
  api:
    http_proxy: []
```

```bash
docker run --label pingoo.service=api my_api_image:latest
```

Pingoo requires that your containers expose a single port (e.g. `EXPOSE 8080`). If you containers don't expose any port or expost multiple ports, you will need to tag them with the `pingoo.port` label.


```bash
docker run --label pingoo.service=api --label pingoo.port=8080 my_api_image:latest
```


In order to enabled docker service discovery Pingoo needs access to the docker socket, so if you are running Pingoo inside a docker container you need to bind it:
```bash
docker run -d -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/pingooio/pingoo
```
