---
date: 2025-09-16T06:00:00Z
title: "Pingoo TLS"
type: "page"
url: "/docs/tls"
---

# TLS


TLS certificates are stored and read from the `/etc/pingoo/certificates` folder.

Private keys must have the `.key` extension and public certificates / certificate chains must have the `.pem` extension.

For example:
```bash
$ ls /etc/pingoo/certificates
pingoo.io.key
pingoo.io.pem
```

Pingoo automatically parses TLS certificates and match the hostname provided in the Server Name Indication (SNI) of the TLS protocol with the Subject Alternative Names (SANs) of the certificates to know which one to use when serving `https` / `tcp+tls`.

If no certificate is found for the requested domain, a default self-signed certificate is used.



## TLS version support

By design, Pingoo only supports TLS 1.3 (and up in the future).

TLS 1.3 was introduced in 2018 and is supported by virtually all browsers and client libraries: https://caniuse.com/tls1-3. Only abandonned bots don't support TLS 1.3, therefore it makes no sense to reduce the security of everybody to support these bots.


## Security

Pingoo uses AWS' [aws-lc-rs](https://github.com/aws/aws-lc-rs) cryptographic library under the hood, which is formally verified and provide an FIPS mode, to ensure the best security without making any compromise on performance.
