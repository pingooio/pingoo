---
date: 2025-09-16T06:00:00Z
title: "Pingoo configuration"
type: "page"
url: "/docs/configuration"
---

# Configuration


## Configuration directory

Pingoo uses the `/etc/pingoo` directory to load and store its configuration files.

Pingoo needs **read and write** permission to the configuration directory.

Pingoo uses the `/etc/pingoo/tls` directory to load and store TLS certificates. Visit the [TLS page](/docs/tls) to learn more about TLS configuration.


## Configuration File

Pingoo's configuration file is located at `/etc/pingoo/pingoo.yml`



## pingoo.yml reference

> You may find non-documented configuration field by reading Pingoo's source code. Please refrain from using them as we provide no guarantees about their stability.

```yml
# Listeners are the port that Pingoo exposes and listen to.
listeners:
  http: # name of the listener
    # valid protocols are: http, https, tcp, tcp+tls
    address: http://0.0.0.0:8080
    # optional list of service to match for this listener.
    # By default (if the service field is not provided) Pingoo will use all the compatible services:
    # - http_proxy and static for http / https listeners
    # - tcp_proxy for tcp / tcp+tls listeners
    services: ["api"]

# (optional)
tls:
  # Automatic Certificate Management Environment (ACME)
  acme:
    domains: ["pingoo.io"]

# services are the applications that listeners route traffic to
services:
  api: # name of the service
    # (optional) expression to filter requests
    # match any request / connection if left empty
    route: http_request.starts_with("/api")
    http_proxy: [] # list of upstreams. Can be left empty if using Docker service discovery

  webapp:
    # static site
    static:
      # root folder to serve the static site / assets
      root: /var/www

# (optional)
rules:
  captcha_bots: # name of the rule
    # (optional) Expression to match requests to apply the rule.
    # If expression is empty, then the rule matches all the requests.
    expression: |
      !http_request.user_agent.starts_with("Mozilla/") && !http_request.user_agent.contains("curl/")
    actions:
      - action: captcha

# (optional) Lists can be used in rule expressions to match against a large number of values
lists:
  blocked_ips: # name of the list
    type: Ip # type of the individual items of the list. Valid values are: int, ip, string
    file: /etc/pingoo/lists/blocked_ip.csv # path to the list
```
