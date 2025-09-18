---
date: 2025-09-16T06:00:00Z
title: "Pingoo geoip"
type: "page"
url: "/docs/geoip"
---


# GeoIP

Pingoo natively supports resolving GeoIP information using `.mmdb` files. A default `geoip.mmdb` database is provided in Pingoo's Docker image.

When geoip is enabled, Pingoo will add the `Pingoo-Client-Country` and `Pingoo-Client-Asn` HTTP headers to upstream requests. Visit the [HTTP headers](/docs/http-headers) page to learn more about the HTTP headers added by Pingoo.


## GeoIP Databases

Pingoo tries to load the GeoIP database from the following paths (in this order):
- `/etc/pingoo/geoip.mmdb(.zst)`
- `/etc/pingoo_data/geoip.mmdb(.zst)`

If no GeoIP database is found, then GeoIP is disabled and a warning message is displayed.

GeoIP database records must have at least two fields:
- `country` a 2-letters `String`
- `asn` an `uint32`


You can download the latest GeoIP database that we provide for free here: [https://downloads.pingoo.io/geoip.mmdb.zst](https://downloads.pingoo.io/geoip.mmdb.zst)

> Free geoip databases are roughly updated once a month. Please feel free to [contact us](/contact) if you need a database updated daily.


## Database compression

Pingoo supports geoip databases compressed with [zstd](https://github.com/facebook/zstd).

Compressed geoip databases must have the `.zst` extension e.g. `geoip.mmdb.zst`



## Acknowledgment

Some of our GeoIP data are kindly provided by ipinfo.io under the [Create Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/) license.
