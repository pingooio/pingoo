const http = require('http');

const PORT = parseInt(process.env.PORT, 10) || 8080;

function sendPlainText(res, status, text) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(text);
}

function handleSSE(req, res) {
  if (req.method !== 'GET') {
    res.writeHead(405, { Allow: 'GET' });
    return res.end();
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
  });

  res.write(': connected\n\n');

  const sendTime = () => {
    const now = new Date().toISOString();
    res.write(`data: ${now}\n\n`);
  };

  sendTime();
  const interval = setInterval(sendTime, 1000);

  req.on('close', () => {
    clearInterval(interval);
  });
}

const server = http.createServer((req, res) => {
  if (req.url === '/sse') {
    return handleSSE(req, res);
  }

  if (req.url === '/' && req.method === 'GET') {
    return sendPlainText(res, 200, `Hello World!`);
  }

  return sendPlainText(res, 404, `Not Found`);
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

server.on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
});
