---
date: 2025-09-16T06:00:00Z
title: "Pingoo TLS"
type: "page"
url: "/docs/tls"
---

# TLS


TLS certificates are stored and read from the `/etc/pingoo/tls` folder.

Private keys must have the `.key` extension and public certificates / certificate chains must have the `.pem` extension.

For example:
```bash
$ ls /etc/pingoo/tls
pingoo.io.key
pingoo.io.pem
```

Pingoo automatically parses TLS certificates and match the hostname provided in the Server Name Indication (SNI) of the TLS protocol with the Subject Alternative Names (SANs) of the certificates to know which one to use when serving `https` / `tcp+tls` connections.

If no certificate is found for the requested domain, a default self-signed certificate is used.


## Automatic HTTPS / TLS (ACME)

Pingoo supports the Automatic Certificate Management Environment (ACME) protocol in order to provide fully-automated certificate management.

**pingoo.yml**
```yml
listeners:
  https:
    address: https://0.0.0.0

tls:
  acme:
    domains: ["pingoo.io"]
```

Pingoo currently doesn't support wildcard certificates when using ACME.

Pingoo currently only supports the [tls-alpn-01](https://letsencrypt.org/docs/challenge-types/#tls-alpn-01) challenge. It means that one of your TLS listeners must be publicly accessible on the port `443`.



## TLS versions support

By design, Pingoo only supports TLS 1.3 (and up in the future).

TLS 1.3 was introduced in 2018 and is supported by virtually all browsers and client libraries: https://caniuse.com/tls1-3. Only abandonned bots don't support TLS 1.3, therefore it makes no sense to reduce the security of everybody to support these bots.


## Post-Quantum TLS

Pingoo supports post-quantum cryptography (also known as quantum-resistant cryptography), specifically the `X25519MLKEM768` hybrid key agreement. See [IETF's draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) for more information.


## Security

Pingoo uses AWS' [aws-lc-rs](https://github.com/aws/aws-lc-rs) cryptographic library under the hood, which is formally verified and provide an FIPS mode, to ensure the best security without making any compromise on performance.
