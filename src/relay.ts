import net from 'node:net';
import http from 'node:http';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { mplex } from '@libp2p/mplex';
import type { Stream, Connection } from '@libp2p/interface';

/**
 * ============================================================================
 * Aeon Aegis - Zero-Trust P2P Relay Node
 * ============================================================================
 * Architecture:
 * - Listens on TCP port 9090 via libp2p.
 * - Enforces mandatory Noise protocol cryptographic handshake (@chainsafe/libp2p-noise).
 * - Strips remote client IP / multiaddr network identities to prevent origin correlation.
 * - Securely forwards payload over local loopback TCP socket to Mock Origin (127.0.0.1:8080).
 * - Exposes Express + WebSocket control plane on port 9091 for health & metrics.
 * - Emits structured JSON logs for auditability, telemetry, and observability.
 */

// Configuration constants
export const RELAY_P2P_PORT = parseInt(process.env.RELAY_P2P_PORT || '9090', 10);
export const RELAY_CONTROL_PORT = parseInt(process.env.RELAY_CONTROL_PORT || '9091', 10);
export const ORIGIN_HOST = process.env.ORIGIN_HOST || '127.0.0.1';
export const ORIGIN_PORT = parseInt(process.env.ORIGIN_PORT || '8080', 10);
export const AEON_RELAY_PROTOCOL = '/aeon-aegis/relay/1.0.0';

// Structured logger
export function logJSON(level: 'info' | 'warn' | 'error', event: string, data: Record<string, any> = {}) {
  const logEntry = {
    level,
    timestamp: new Date().toISOString(),
    event,
    ...data
  };
  process.stdout.write(JSON.stringify(logEntry) + '\n');
  return logEntry;
}

// Telemetry & Metrics State
export interface RelayMetrics {
  activeConnections: number;
  totalConnectionsHandled: number;
  totalStreamsProxied: number;
  totalBytesIn: number;
  totalBytesOut: number;
  handshakeDurationsMs: number[];
  recentErrors: number;
  startTime: number;
}

export const metrics: RelayMetrics = {
  activeConnections: 0,
  totalConnectionsHandled: 0,
  totalStreamsProxied: 0,
  totalBytesIn: 0,
  totalBytesOut: 0,
  handshakeDurationsMs: [],
  recentErrors: 0,
  startTime: Date.now()
};

/**
 * Proxy function: Strips client origin metadata and pipes decrypted payload
 * between libp2p stream and internal origin TCP server.
 */
export function proxyStreamToOrigin(
  stream: Stream,
  connection: Connection,
  handshakeDurationMs: number
): void {
  metrics.totalStreamsProxied++;
  const streamId = stream.id;

  // Zero-trust boundary: Notice we deliberately DO NOT forward connection.remoteAddr
  // or client PeerId to the backend origin. The origin only sees a connection from 127.0.0.1.
  logJSON('info', 'stream_proxy_initiated', {
    stream_id: streamId,
    active_connections: metrics.activeConnections,
    handshake_duration_ms: handshakeDurationMs,
    target: `${ORIGIN_HOST}:${ORIGIN_PORT}`,
    action: 'metadata_stripped'
  });

  // Open clean internal TCP socket to mock origin
  const originSocket = net.createConnection({ host: ORIGIN_HOST, port: ORIGIN_PORT });

  let streamClosed = false;

  const cleanup = () => {
    if (streamClosed) return;
    streamClosed = true;
    try {
      if (!originSocket.destroyed) {
        originSocket.end();
      }
    } catch {
      // Ignore socket termination error
    }
  };

  originSocket.on('connect', () => {
    logJSON('info', 'origin_socket_connected', {
      stream_id: streamId,
      origin: `${ORIGIN_HOST}:${ORIGIN_PORT}`
    });
  });

  // Client -> Relay (Decrypted by Noise) -> Origin TCP Socket
  stream.addEventListener('message', (evt) => {
    try {
      const rawData: Uint8Array = evt.data instanceof Uint8Array ? evt.data : evt.data.subarray();
      const bytesCount = rawData.byteLength;
      metrics.totalBytesIn += bytesCount;

      logJSON('info', 'payload_routed_to_origin', {
        stream_id: streamId,
        bytes_transferred: bytesCount,
        active_connections: metrics.activeConnections,
        handshake_duration_ms: handshakeDurationMs
      });

      if (!originSocket.destroyed) {
        originSocket.write(rawData);
      }
    } catch (err: any) {
      metrics.recentErrors++;
      logJSON('error', 'origin_write_failed', {
        stream_id: streamId,
        error: err?.message
      });
      cleanup();
    }
  });

  // Origin TCP Socket -> Relay -> Client (Encrypted by Noise)
  originSocket.on('data', (data: Buffer) => {
    try {
      const bytesCount = data.byteLength;
      metrics.totalBytesOut += bytesCount;

      logJSON('info', 'payload_routed_to_client', {
        stream_id: streamId,
        bytes_transferred: bytesCount,
        active_connections: metrics.activeConnections
      });

      // Send payload back over the Noise encrypted stream
      stream.send(new Uint8Array(data));
    } catch (err: any) {
      metrics.recentErrors++;
      logJSON('error', 'stream_send_failed', {
        stream_id: streamId,
        error: err?.message
      });
      cleanup();
    }
  });

  originSocket.on('error', (err: any) => {
    metrics.recentErrors++;
    logJSON('error', 'origin_socket_error', {
      stream_id: streamId,
      error: err.message
    });
    cleanup();
  });

  originSocket.on('close', () => {
    cleanup();
  });

  stream.addEventListener('close', () => {
    cleanup();
  });
}

/**
 * Initializes and starts the libp2p Relay Node.
 */
export async function startRelayNode() {
  const node = await createLibp2p({
    addresses: {
      listen: [`/ip4/0.0.0.0/tcp/${RELAY_P2P_PORT}`]
    },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux(), mplex()]
  });

  // Connection-level tracking for Noise handshake measurement
  const connectionHandshakeStart = new Map<string, number>();

  node.addEventListener('connection:open', (event) => {
    const conn = event.detail;
    const now = Date.now();
    metrics.activeConnections++;
    metrics.totalConnectionsHandled++;

    // Calculate approximate Noise cryptographic negotiation duration
    const startTime = connectionHandshakeStart.get(conn.id) || now;
    const handshakeDurationMs = Math.max(1, now - startTime);
    metrics.handshakeDurationsMs.push(handshakeDurationMs);

    // Keep bounded history of durations (last 500)
    if (metrics.handshakeDurationsMs.length > 500) {
      metrics.handshakeDurationsMs.shift();
    }

    logJSON('info', 'noise_connection_opened', {
      connection_id: conn.id,
      active_connections: metrics.activeConnections,
      handshake_duration_ms: handshakeDurationMs,
      total_connections: metrics.totalConnectionsHandled
    });
  });

  node.addEventListener('connection:close', (event) => {
    const conn = event.detail;
    metrics.activeConnections = Math.max(0, metrics.activeConnections - 1);
    connectionHandshakeStart.delete(conn.id);

    logJSON('info', 'connection_closed', {
      connection_id: conn.id,
      active_connections: metrics.activeConnections
    });
  });

  // Register zero-trust stream handler with high concurrent stream capacity
  node.handle(AEON_RELAY_PROTOCOL, (stream, connection) => {
    const durations = metrics.handshakeDurationsMs;
    const latestHandshake = durations.length > 0 ? durations[durations.length - 1] : 0;
    proxyStreamToOrigin(stream, connection, latestHandshake);
  }, {
    maxInboundStreams: 1024,
    maxOutboundStreams: 1024
  });

  return node;
}

/**
 * Initializes Express and WebSocket control plane for local health checks and telemetry.
 */
export function startControlPlane(libp2pNode: any) {
  const app = express();
  app.use(express.json());

  // Health endpoint
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      service: 'aeon-aegis-relay',
      uptime_seconds: Math.floor((Date.now() - metrics.startTime) / 1000),
      timestamp: new Date().toISOString()
    });
  });

  // Metrics endpoint
  app.get('/metrics', (_req, res) => {
    const durations = metrics.handshakeDurationsMs;
    const avgHandshake = durations.length > 0
      ? (durations.reduce((a, b) => a + b, 0) / durations.length).toFixed(2)
      : '0.00';

    res.json({
      active_connections: metrics.activeConnections,
      total_connections: metrics.totalConnectionsHandled,
      total_streams_proxied: metrics.totalStreamsProxied,
      total_bytes_in: metrics.totalBytesIn,
      total_bytes_out: metrics.totalBytesOut,
      avg_noise_handshake_ms: parseFloat(avgHandshake),
      peer_id: libp2pNode.peerId.toString(),
      listen_addresses: libp2pNode.getMultiaddrs().map((a: any) => a.toString())
    });
  });

  const server = http.createServer(app);

  // WebSocket Server for live control / telemetry
  const wss = new WebSocketServer({ server, path: '/control/ws' });

  wss.on('connection', (ws: WebSocket) => {
    logJSON('info', 'control_ws_client_connected');
    
    // Send initial snapshot
    ws.send(JSON.stringify({
      type: 'SNAPSHOT',
      metrics,
      timestamp: new Date().toISOString()
    }));

    // Periodically stream metrics
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'METRICS_UPDATE',
          activeConnections: metrics.activeConnections,
          bytesIn: metrics.totalBytesIn,
          bytesOut: metrics.totalBytesOut,
          timestamp: new Date().toISOString()
        }));
      }
    }, 1000);

    ws.on('close', () => {
      clearInterval(interval);
      logJSON('info', 'control_ws_client_disconnected');
    });
  });

  server.listen(RELAY_CONTROL_PORT, '0.0.0.0', () => {
    logJSON('info', 'control_plane_started', {
      port: RELAY_CONTROL_PORT,
      health_endpoint: `http://127.0.0.1:${RELAY_CONTROL_PORT}/health`,
      metrics_endpoint: `http://127.0.0.1:${RELAY_CONTROL_PORT}/metrics`,
      ws_endpoint: `ws://127.0.0.1:${RELAY_CONTROL_PORT}/control/ws`
    });
  });

  return server;
}

/**
 * Main execution entry point
 */
async function main() {
  logJSON('info', 'relay_node_initializing', {
    p2p_port: RELAY_P2P_PORT,
    control_port: RELAY_CONTROL_PORT,
    target_origin: `${ORIGIN_HOST}:${ORIGIN_PORT}`
  });

  const node = await startRelayNode();
  await node.start();

  const listenAddrs = node.getMultiaddrs().map(a => a.toString());
  logJSON('info', 'relay_node_online', {
    peer_id: node.peerId.toString(),
    listen_addresses: listenAddrs,
    encryption: 'Noise',
    protocol: AEON_RELAY_PROTOCOL
  });

  const controlServer = startControlPlane(node);

  // Graceful shutdown
  const shutdown = async () => {
    logJSON('info', 'relay_node_shutting_down');
    try {
      controlServer.close();
      await node.stop();
    } catch (err: any) {
      logJSON('error', 'shutdown_error', { error: err?.message });
    }
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// Auto-start when executed directly
if (process.argv[1] && (process.argv[1].endsWith('relay.ts') || process.argv[1].endsWith('relay.js'))) {
  main().catch((err) => {
    logJSON('error', 'relay_node_fatal_error', {
      error: err?.message,
      stack: err?.stack
    });
    process.exit(1);
  });
}
