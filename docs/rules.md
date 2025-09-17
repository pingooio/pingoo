---
date: 2025-09-16T06:00:00Z
title: "Pingoo rules & lists"
type: "page"
url: "/docs/rules"
---


# Rules

## Types

`String`

`Int`


## Actions

Pingoo currently supports the following actions:

`captcha`: Serve a CAPTCHA to the client that must be solved to access the service.


`block`: Serve a 403 permission denied page.



## Functions


## Lists

You can provide lists to use in your rules and routes.

List must be formatted as CSV with at least 1 column for the values, and 1 optional column for the description.

For example:

**blocked_ips.csv**
```csv
127.0.0.1,"really bad person"
1.2.3.4,"bad bot"
```

Valid lists types:
- `Int`
- `String`
- `Ip`


For example if you have the following configuration file:

```yml
lists:
  blocked_ips:
    type: Ip
    file: blocked_ips.csv
```

You can then use the following expression in your rules and routes:

```yml
rules:
  block_blocked_ips:
    expression: |
      lists["blocked_ips"].contains(client.ip)
    actions:
      - action: block
        parameters: {}
```
