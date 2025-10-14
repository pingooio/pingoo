---
date: 2025-09-16T06:00:00Z
title: "Getting started with Pingoo"
type: "page"
url: "/docs/getting-started"
---

# Getting Started

Here is an example of using Pingoo:
- For TLS termination
- To serve a static web app
- As a load balancer for Docker containers serving an API
- As a WAF to block requests from some countries

```bash
$ ls
pingoo/
  pingoo.yml
  certificates/
    example.com.key
    example.com.pem
www/
  index.html
  index.css
  assets/
    ...
```

**pingoo.yml**
```yml
listeners:
  https:
    address: https://localhost:443

services:
  api:
    route: http_request.host.starts_with("api.")
    http_proxy: [] # leave upstreams empty when using Docker service discovery

  webapp:
    static:
      root: /var/www

rules:
  block_some_countries:
    expression: |
      ["XX"].contains(client.country)
    actions:
      - action: block
```


We need to bind the docker socket so Pingoo can list the containers with the `pingoo.service` label.

```bash
$ docker run -d --label pingoo.service=api your_api_image:latest
$ docker run -d --network host -v `pwd`/www:/var/www:ro -v `pwd`/pingoo:/etc/pingoo -v /var/run/docker.sock:/var/run/docker.sock pingooio/pingoo:latest
```
