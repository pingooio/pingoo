---
date: 2025-09-16T06:00:00Z
title: "Pingoo geoip"
type: "page"
url: "/docs/geoip"
---


# GeoIP

pingoo natively supports resolving GeoIP information using `.mmdb` files. A default `geoip.mmdb` database is provided in pingoo's Docker image.

When geoip is enabled, pingoo will add the `X-Pingoo-Country` and `X-Pingoo-Asn` HTTP headers to upstream requests. Visit the [HTTP headers](/docs/http-headers) page to learn more about the HTTP headers added by pingoo.


## GeoIP Databases

GeoIP database records must have at least two fields:
- `country` a 2-letters `String`
- `asn` an `uint32`


You can download the latest GeoIP database that we provide for free here: [https://downloads.pingoo.io/geoip.mmdb.zst](https://downloads.pingoo.io/geoip.mmdb.zst)

> Free geoip databases are updated once a month. Please feel free to [contact us](/contact) if you need a database updated daily.


## Database compression

pingoo supports geoip databases compressed with zstd.

Compressed geoip databases must have the `.zst` extension e.g. `geoip.mmdb.zst`
