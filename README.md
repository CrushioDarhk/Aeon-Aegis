# Aeon Aegis 🛡️

**Zero-Trust P2P Relay Infrastructure & Security SDK**

Aeon Aegis is a high-performance, open-source zero-trust relay layer built with `libp2p` and Noise protocol encryption. It masks origin IP addresses and shields validator/RPC endpoints from direct exposure, surveillance, and DDoS attacks.

---

## 🏛️ Architecture

```
                               +-----------------------------------------------+
                               |            AEON AEGIS RELAY NODE              |
                               |               (libp2p + Noise)                |
 [ Client / Consumer ]         |                                               |     [ Internal Origin ]
(Web3 RPC / Validator)         |  1. TCP / Noise Handshake (Port 9090)         |   (Mock Protected Node)
         |                     |  2. Yamux Stream Muxer                        |             |
         |=== Noise TCP ======>|  3. Origin Metadata Stripping (No Client IP)  |             |
         |   (Port 9090)       |  4. Local Loopback Socket Pipe                |== Local ==> |
         |                     |     to 127.0.0.1:8080 ------------------------|   TCP       | (127.0.0.1:8080)
         |                     |                                               | (Port 8080) |
         |                     |  Control Plane (Express + WS on Port 9091)    |             |
         |                     +-----------------------------------------------+             |
         |                                             |                                     |
         +<================ Decrypted Response <-------+<====================================+
```
---

## ⚡ Verified Benchmark Metrics

Tested under local automated load testing harness (`100` concurrent requests over Noise TCP):

| Metric | Result | Status |
| :--- | :--- | :--- |
| **Total Concurrency** | 100 Requests | **100% Passed** |
| **Noise Handshake Latency** | 257.21 ms | **Passed** |
| **Throughput** | 39.48 req/sec | **Passed** |
| **Origin Isolation** | Confirmed strictly loopback (`127.0.0.1`) | **Passed** |
| **Memory Footprint** | `<256MB` | **Passed** |

---

## 🚀 Quickstart

### Prerequisites
* Node.js v20+
* npm

### Installation & Build
```bash
git clone [https://github.com/CrushioDarhk/Aeon-Aegis.git](https://github.com/CrushioDarhk/Aeon-Aegis.git)
cd Aeon-Aegis
npm install
npm run build
Running Locally
Start Mock Origin Server (Port 8080):

Bash
npm run start:origin
Start Aeon Aegis Relay Node (Port 9090 P2P, Port 9091 Control):

Bash
npm run start:relay
Execute Benchmark Suite:

Bash
npm run benchmark
Control Plane Telemetry
Bash
# Health Check
curl [http://127.0.0.1:9091/health](http://127.0.0.1:9091/health)

# Live Metrics JSON
curl [http://127.0.0.1:9091/metrics](http://127.0.0.1:9091/metrics)
☁️ Cloud Deployment (Akash Network)
Aeon Aegis is containerized and ready for low-cost cloud deployment via Akash Network using the included deploy.sdl stack manifest.

Bash
# Docker Image
docker pull crushiodarhk/aeon-aegis:latest
🗺️ Roadmap
[x] Phase 1: Core libp2p Noise TCP Relay, Control-Plane Telemetry, Dockerization & Akash .sdl.

[ ] Phase 2: Token-Bucket Rate Limiting, IP Reputation Scoring, and WireGuard/mTLS Origin Tunnels.

[ ] Phase 3: Multi-Hop Onion Routing & Distributed Edge Benchmarks across global nodes.