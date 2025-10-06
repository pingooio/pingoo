<p align="center">
  <a href="https://pingoo.io" target="_blank" rel="noopener"><img alt="Pingoo logo" src="https://pingoo.io/icon-256.png" height="128" /></a>
  <h1 align="center">Pingoo</h1>
  <h3 align="center">The fast and secure Load Balancer / API Gateway / Reverse Proxy with built-in service discovery, GeoIP, WAF, bot protection and much more</h3>
  <h3 align="center">
    <a href="https://pingoo.io">Documentation</a> | <a href="https://kerkour.com/announcing-pingoo">Read the launch post</a>
  </h3>
</p>

Open Source load balancers and reverse proxies are stuck in the past century with a very slow pace of development and most of the important features reserved for "Enterprise Editions" which lead developers to use third-party cloud services, exposing their users' traffic to legal, security and reliability risks.

Pingoo is a modern Load Balancer / API Gateway / Reverse Proxy that run on your own servers and already have (or will have soon) all the features you expect from managed services and even more. All of that with a huge boost in performance and security thanks to reduced latency and, of course, Rust ;)

* Automatic and Post-Quantum HTTPS / TLS
* Service Discovery (Docker, DNS...)
* Web Application Firewall (WAF)
* Easy compliance because the data never leaves your servers
* Bot protection and management
* TCP proxying
* GeoIP (country, ASN)
* Static sites
* And much more


## Quickstart

```bash
# You have a static site in the www folder
$ ls www
index.html
$ docker run --rm -ti --network host -v `pwd`/www:/var/wwww ghcr.io/pingooio/pingoo
# Pingoo is now listenning on http://0.0.0.0
```

## Documentation

See https://pingoo.io


## Updates

[Click Here](https://kerkour.com/blog) to visit the blog and [subscribe](https://kerkour.com/subscribe) by RSS or email to get weekly / monthly updates. No spam ever, only technical deep dives.


## Contributing

Please open an issue to discuss your idea before submitting a Pull Request.


## Support

Do you have custom needs? Do you want your features to be prioritized? Are you under attack and need help? Do you need support for deploying and self-hosting Pingoo?

Feel free to reach our team of experts to see how we can help: https://pingoo.io/contact


## Security

We are committed to make Pingoo the most secure Load Balancer / Reverse Proxy in the universe and beyond. If you've found a security issue in Pingoo, we appreciate your help in disclosing it to us in a responsible manner by contacting us: https://pingoo.io/contact


## License

MIT. See `LICENSE.txt`

Forever Open Source. No Open Core or "Enterprise Edition".
