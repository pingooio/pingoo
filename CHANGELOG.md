# Pingoo Changelog

## v0.12.0 - 2025-09-26

* **minor breaking change**: Pingoo now errors if GeoIP database is not found.


## v0.11.0 - 2025-09-22

- **Breaking change**: the default geoip database is now located at `/usr/share/pingoo/geoip.mmdb(.zst)` in the Docker image instead of `/etc/pingoo_data/geoip.mmdb(.zst)` to follow the Filesystem Hierarchy Standard.
- Add support for `HS512`, `ES256` and `ES512` JSON Web Tokens.

## v0.10.0 - 2025-09-20

- **Breaking change**: Pingoo no longer try to read the configuration file from the current directory. Now Pingoo only loads its configuration file from `/etc/pingoo/pingoo.yml`.
- Rules are now also loaded from the `/etc/pingoo/rules` folder.
