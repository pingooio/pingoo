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

See the [rules page](/docs/rules) to learn Pingoo's expression language and what variables and function are available.


## HTTP Proxy

```yml
listeners:
  http:
    address: http://0.0.0.0:8080

services:
  api:
    route: host.starts_with("api")
    http_proxy: ["http://api1.myservice.internal", "http://api2.myservice.internal"]
```


### HTTP headers

Pingoo adds the following HTTP headers to requests to upstream servers when used in HTTP proxy mode:


`x-forwarded-host`: The original `Host` header. e.g. `example.com`. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-Host

`X-Forwarded-For`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For

`X-Forwarded-Proto`: `http` or `https`. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-Proto

`Pingoo-Client-Ip`: The IP address of the client. e.g. `1.2.3.4`.


The following headers are available **only** if [geoip](/docs/geoip) is enabled:

`Pingoo-Client-Country`: The 2-letters codes of the country inferred from the IP address. e.g. `FR`

`Pingoo-Client-Asn`: The [Autonomous System Number (ASN)](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)) inferred from the IP address. e.g. `123`


## Static

Pingoo can directly serve static content such as static sites, single page applications and assets.

```yml
listeners:
  http:
    address: http://0.0.0.0:8080

services:
  webapp:
    static:
      root: /var/www
```


## TCP proxy

**pingoo.yml**
```yml
listeners:
  smtp:
    address: tcp://0.0.0.0:25

services:
  smtp_backends:
    tcp_proxy: ["tcp://1.2.3.4:25", "tcp://4.3.2.1:25"]
```


## Service Discovery

### DNS

Pingoo automatically resolves domains in upstreams.

### Docker

Pingoo automagically discovers containers that are tagged with the `pingoo.service` label:

```yml
listeners:
  http:
    address: http://0.0.0.0:8080

services:
  api:
    http_proxy: [] # leave the upstream list empty whehn using Docker service discovery
```

```bash
docker run -d --label pingoo.service=api my_api_image:latest
```
Note that `--label pingoo.service=api` match the service name: `api`.


Pingoo requires that your containers expose a single port (e.g. `EXPOSE 8080`). If you containers don't expose any port or expose multiple ports, you will need to tag the port to forward traffic to with the `pingoo.port` label.


```bash
docker run -d --label pingoo.service=api --label pingoo.port=8080 my_api_image:latest
```


In order to enable docker service discovery Pingoo needs access to the docker socket. If you are running Pingoo inside a docker container you need to bind the docker socket:

```bash
docker run -d -v /var/run/docker.sock:/var/run/docker.sock pingooio/pingoo
```


## Load balancing

Pingoo currently load balance requests and connections between upstreams using the state of the art `random` algorithm.
