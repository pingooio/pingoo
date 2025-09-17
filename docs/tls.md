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

Pingoo automatically parses TLS certificates and use the Subject Alternative Names (SANs) to know which certificate to use.

If no certificate is found for the requested domain, a default self-signed certificate is used.



## TLS version support

By design, pingoo only supports TLS 1.3 (and up in the future).

TLS 1.3 was introduced in 2018 and is supported by virtually all browsers and client libraries: https://caniuse.com/tls1-3. Only abandonned bots gone rogue don't support TLS 1.3, therefore it makes not sense to reduce the security of users only to support these bots.


## Security

Pingoo uses AWS' [aws-lc-rs](https://github.com/aws/aws-lc-rs) cryptographic library under the hood, which is formally verified and provide an FIPS mode, to ensure the best security without making compromises on performance.
