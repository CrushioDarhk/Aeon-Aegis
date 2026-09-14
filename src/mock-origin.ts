import net from 'node:net';

/**
 * Aeon Aegis - Mock Protected Origin Server
 * 
 * Simulates an internal, non-public validator or RPC node listening on 127.0.0.1:8080.
 * In a production zero-trust topology, this service has no public IP and only accepts
 * traffic forwarded locally by the Aeon Aegis relay node.
 */

const HOST = process.env.ORIGIN_HOST || '127.0.0.1';
const PORT = parseInt(process.env.ORIGIN_PORT || '8080', 10);
const NODE_ID = process.env.ORIGIN_NODE_ID || 'aeon-origin-01';

const RESPONSE_PAYLOAD = JSON.stringify({
  status: 'protected',
  node_id: NODE_ID,
  timestamp: new Date().toISOString()
}) + '\n';

let totalRequestsHandled = 0;
let activeConnections = 0;

const server = net.createServer((socket) => {
  activeConnections++;
  const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;

  // Log incoming local socket connection (always 127.0.0.1, proving client origin isolation)
  console.log(JSON.stringify({
    level: 'info',
    timestamp: new Date().toISOString(),
    event: 'origin_connection_accepted',
    remote_address: remoteAddr,
    active_connections: activeConnections
  }));

  socket.on('data', (data) => {
    totalRequestsHandled++;
    const payloadStr = data.toString('utf-8');

    // Check if the payload is an HTTP request
    const isHttp = payloadStr.startsWith('GET ') || payloadStr.startsWith('POST ');
    
    if (isHttp) {
      const httpResponse = [
        'HTTP/1.1 200 OK',
        'Content-Type: application/json',
        `Content-Length: ${Buffer.byteLength(RESPONSE_PAYLOAD)}`,
        'Connection: close',
        '',
        RESPONSE_PAYLOAD
      ].join('\r\n');
      socket.write(httpResponse);
    } else {
      // Raw TCP stream response
      socket.write(RESPONSE_PAYLOAD);
    }
  });

  socket.on('error', (err) => {
    // Avoid unhandled socket resets during rapid benchmarking disconnects
    if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
      console.error(JSON.stringify({
        level: 'error',
        timestamp: new Date().toISOString(),
        event: 'origin_socket_error',
        error: err.message
      }));
    }
  });

  socket.on('close', () => {
    activeConnections--;
  });
});

server.listen(PORT, HOST, () => {
  console.log(JSON.stringify({
    level: 'info',
    timestamp: new Date().toISOString(),
    event: 'origin_server_started',
    host: HOST,
    port: PORT,
    node_id: NODE_ID,
    message: `Mock protected origin node listening on ${HOST}:${PORT}`
  }));
});

// Graceful shutdown handling
const shutdown = () => {
  console.log(JSON.stringify({
    level: 'info',
    timestamp: new Date().toISOString(),
    event: 'origin_server_stopping',
    total_requests: totalRequestsHandled
  }));
  server.close(() => {
    process.exit(0);
  });
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
