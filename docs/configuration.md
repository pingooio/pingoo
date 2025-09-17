---
date: 2025-09-16T06:00:00Z
title: "Pingoo configuration"
type: "page"
url: "/docs/configuration"
---

## Configuration File

pingoo checks for its configuration file in the following locations (in this order):
- `pingoo.yml`
- `/etc/pingoo/pingoo.yml`


## pingoo.yml reference

> You may find non-documented configuration field by reading pingoo's source code. Please refrain from using them as we provide no guarantees about their stability.

```yml
# Listeners are the port that pingoo exposes and listen to.
listeners:
  http: # name of the listener
    # valid protocols are: http, https, tcp, tcp+tls
    address: http://0.0.0.0:8080

# services are your upstream servers where connections and requests are forwarded to.
services:
  api: # name of the service
    http_proxy: []

# (optional)
rules:
  captcha_ bots: # name of the rule
    # (optional) Expression to match requests to apply the rule.
    # If expression is empty, then the rule matches all the requests.
    expression: |
      !request.user_agent.starts_with("Mozilla/") && !request.user_agent.contains("curl/")
    actions:
      - action: captcha
        parameters: {}

# (optional) Lists can be used in rule expressions to match against a large number of values
lists:
  blocked_ips: # name of the list
    type: ip # type of the individual items of the list. Valid values are: int, ip, string
    file: /etc/pingoo/lists/blocked_ip.csv # path to the list
```
