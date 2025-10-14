# Pingoo Changelog

## v0.14.0 - 2025-10-14

* **minor breaking change**: logs are now formatted in JSON
* Improved configuration: rules' actios no longer need the `parameters` field.
* Docker hub image is now the recommended way to use Pingoo.
* Pingoo no longer errors if no Geoip database is found and print a warning message instead

## v0.13.0 - 2025-10-04

* **Breaking change**: the `/etc/pingoo/certificates` folder has moved to `/etc/pingoo/tls`.
* Add support for automatic TLS (ACME protocol) 🎉
* HTTPS listeners now also support HTTP/1.1 alongside HTTP/2


## v0.12.0 - 2025-09-26

* **minor breaking change**: Pingoo now errors if GeoIP database is not found.


## v0.11.0 - 2025-09-22

- **Breaking change**: the default geoip database is now located at `/usr/share/pingoo/geoip.mmdb(.zst)` in the Docker image instead of `/etc/pingoo_data/geoip.mmdb(.zst)` to follow the Filesystem Hierarchy Standard.
- Add support for `HS512`, `ES256` and `ES512` JSON Web Tokens.


## v0.10.0 - 2025-09-20

- **Breaking change**: Pingoo no longer try to read the configuration file from the current directory. Now Pingoo only loads its configuration file from `/etc/pingoo/pingoo.yml`.
- Rules are now also loaded from the `/etc/pingoo/rules` folder.
