---
date: 2025-09-16T06:00:00Z
title: "Pingoo"
description: "Performance and Security for everyone"
type: "page"
url: "/"
---

# Pingoo Overview

99.9999 % of the web uses some kind of reverse proxy or gateway, trillions of requests per day, whether it is to balance load between different services / machines, terminate TLS, apply security rules or block unwarranted traffic. And yet, this fundamental piece of infrastructure has seen very little love and innovation over the years, especially since the beginning of the AI <s>bubble</s> boom.

Existing load balancers and proxies are either stuck in the last century, or all the interesting features are reserved for "Enterprise Editions".

Pingoo is our attempt at bringing technical excellence and innovation to this forgotten corner of infrastructure.

We are not only committed to building the best Load Balancer / API Gateway / Reverse proxy, we are also committed to making it forever Open Source, no strings attached.

Our mission? Security and Performance for everyone.


## Deployment Patterns

There are three principal ways to deploy Pingoo:
- As a traditionnal load balancer / reverse proxy
- As a sidecar inside a Docker container, which is particularly handy if you are using a Platform as a Service (PaaS) such as Fly, Render or Heroku to deploy your projects.
- In hybrid mode, where an instance of Pingoo is used for load balancing, and sidecar instances are used as firewalls.

![Pingoo deployment modes](/assets/pingoo_deployment_modes.png)


### Load Balancer / Reverse Proxy

Visit the [services](/docs/services) page to learn how to configure Pingoo as a Load balancer / reverse proxy.


### Sidecar

Pingoo can also be deployed inside your own docker images and spawn your server as a child process.

You may like this approach if you are using a Platform as a Service (PaaS) such as Fly, Render or Heroku to deploy your projects and need a WAF or bot management solution.


**server.js**
```javascript
const http = require('http');

const ADDRESS = '127.0.0.1'
const PORT = 3000;

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!\n');
});

server.listen(PORT, ADDRESS, () => {
  console.log(`Server running at http://${ADDRESS}:${PORT}`);
});
```

**pingoo.yml**
```yml
child_process:
  # the command is executed from the current working directory. NOT relatively from pingoo.yml
  command: ["node", "server.js"]

listeners:
  http:
    address: http://0.0.0.0:8080

services:
  api:
    http_proxy: ["http://127.0.0.1:3000"]
```

**Dockerfile**
```dockerfile
FROM pingooio/pingoo:latest AS pingoo
FROM node:latest

# setup pingoo
RUN mkdir -p /etc/pingoo
COPY ./pingoo.yml /etc/pingoo/
COPY --from=pingoo /bin/pingoo /bin/pingoo

# setup server
WORKDIR /server
COPY ./server.js ./

CMD ["/bin/pingoo"]

EXPOSE 8080
```

```bash
$ docker build -t myimage:latest -f Dockerfile .
$ docker run --rm -ti -p 8080:8080 myimage:latest
```
