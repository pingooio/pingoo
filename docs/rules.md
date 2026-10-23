---
date: 2025-09-16T06:00:00Z
title: "Pingoo rules & lists"
type: "page"
url: "/docs/rules"
---

# Rules

Rules are the main way to modify requests / responses and to configure services.

Rules are loaded from both the `/etc/pingoo/pingoo.yml` file and all the `.yml` files in the `/etc/pingoo/rules` folder.

For example in **pingoo.yml**:
```yml
# ...

rules:
  block: # name of the rule
    expression: http_request.path == "/blocked"
    actions:
      - action: block
```

Or, in **/etc/pingoo/rules/blocked.yml**:
```yml
block: # name of the rule
  expression: http_request.path == "/blocked"
  actions:
    - action: block
```



## Expression Language

Pingoo uses a subset of the [Common Expression Language (CEL)](https://cel.dev) with all the inconsistencies and "surprising" things trimmed off.

## Types

- `Bool`
- `String`
- `Int`
- `Float`
- `Ip`
- `Regex`
- `Array<Type>`
- `Map<Key, Type>`


## Variables

```rust
http_request {
    host: String
    url: String
    path: String
    method: String
    user_agent: String
}

client {
    ip: Ip
    remote_port: Int
    asn: Int
    country: String
}
```


## Functions

- `contains`
- `length`
- `starts_with`
- `ends_with`


## Actions

Pingoo currently supports the following actions:

- `captcha`: Serve a CAPTCHA to the client that must be solved to proceed.
- `block`: Serve a 403 permission denied page.


## Lists

You can provide lists to use in your rules and routes expressions.

List must be formatted as CSV with at least 1 column for the values, and 1 optional column for the description.

For example:

**blocked_ips.csv**
```csv
127.0.0.1,"really bad person"
1.2.3.4,"bad bot"
```

**pingoo.yml**
```yml
lists:
  blocked_ips:
    type: Ip
    file: blocked_ips.csv

rules:
  block_blocked_ips:
    expression: lists["blocked_ips"].contains(client.ip)
    actions:
      - action: block
```


Valid lists types:
- `Int`
- `String`
- `Ip`

## Rate limiting

Algorithm used is the [sliding window](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)
that uses request count from both current and previous period.

`max` (u16) number of requests in given `period` (u16) denominated in seconds.
Rate limiters have finite `capacity` that should be a power of 2 (otherwise
next power of 2 will be allocated). E.g. `capacity: 1024` can store no more
than 1024 entries in a `period`.

For a case when `max` threshold is crossed Pingoo responds with [HTTP 429 Too
Many
Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/429).
For a case where `capacity` bucket is full Pingoo responds with [HTTP 503
Service
Unavailable](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/503).

**pingoo.yml**
```yml
rules:
  rate_limit_api_routes:
    expression: http_request.path.starts_with("/api/")
    actions:
      - action: limit
    limit:
      max: 10
      period: 60
      capacity: 1024
```

In this example Pingoo:
* protects resources under `/api` route
* allows no more than 10 requests per ONE minute
* starts returning HTTP 429 to the specific client, when number of incoming
  requests from IP address of that client crossed the threshold of 10 in
  sampling period of ONE minute
* can count requests for 1024 (2^10) unique IP addresses on every minute
* starts returning HTTP 503 to new clients if bucket is full and their IP is not in the bucket
