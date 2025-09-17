---
date: 2025-09-16T06:00:00Z
title: "Pingoo"
description: "Performance and Security for everyone"
type: "page"
url: "/"
---


## Deployment Patterns

There are two principal ways to deploy pingoo:
- As a traditionnal load balancer / reverse proxy
- As a sidecar inside a Docker container, which is particularly handy if you are using a Platform as a Service (PaaS) such as Fly, Render or Heroku to deploy your projects.
- In hybrid mode, where an instance of pingoo is used for load balancing, and sidecar instances are used as firewalls.

![Pingoo deployment modes](/assets/pingoo_deployment_modes.png)


### Load Balancer / Reverse Proxy

Visit the [services](/docs/services) page to learn how to configure Pingoo as a Load balancer / reverse proxy.


### Sidecar

Pingoo can also be deployed inside your own docker images and spawn your server as a child process.

You may like this approach if you are using a Platform as a Service (PaaS) such as Fly, Render or Heroku to deploy your projects.



**server.js**
```javascript
const http = require('http');

const PORT = 3000;

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!\n');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://localhost:${PORT}`);
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
FROM ghcr.io/pingooio/pingoo:latest AS pingoo
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
