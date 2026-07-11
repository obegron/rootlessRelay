const WebSocket = require("ws");
const dgram = require("dgram");
const net = require("net");
const crypto = require("crypto");
const { getReverseFlow } = require("./tcp_utils");
const { SlidingWindowRateLimiter } = require("./rate_limiter");
const { TCPRetransmissionQueue } = require("./tcp_retransmission");
const { UDPFlowManager } = require("./udp_flow_manager");
const {
  buildIPv4Packet,
  internetChecksum,
  parseIPv4Packet,
  parseUDPDatagram,
  tcpChecksum,
  udpChecksum,
} = require("./packet_utils");

// ==============================================================================
// CONFIGURATION
// Settings can be configured here as defaults, but can be overridden by
// environment variables.
// ==============================================================================

// --- Basic Settings ---
// ==============================================================================

// RATE_LIMIT_KBPS: Maximum upload/download bandwidth for each VM in kilobytes per second.
// ENV: RATE_LIMIT_KBPS
const RATE_LIMIT_KBPS = process.env.RATE_LIMIT_KBPS ? parseInt(process.env.RATE_LIMIT_KBPS, 10) : 1024;

// MAX_CONNECTIONS_PER_IP: The maximum number of concurrent WebSocket connections allowed from a single IP address.
// ENV: MAX_CONNECTIONS_PER_IP
const MAX_CONNECTIONS_PER_IP = process.env.MAX_CONNECTIONS_PER_IP ? parseInt(process.env.MAX_CONNECTIONS_PER_IP, 10) : 4;

// ENABLE_WSS: Set to true to use Secure WebSockets (WSS), false for standard WebSockets (WS).
// Requires cert.pem and key.pem files to be present if true.
// ENV: ENABLE_WSS
const ENABLE_WSS = process.env.ENABLE_WSS !== undefined ? process.env.ENABLE_WSS === 'true' : true;

// ENABLE_VM_TO_VM: Set to true to allow virtual machines on the same relay to communicate with each other.
// If false, VMs are isolated and can only access the gateway/internet.
// ENV: ENABLE_VM_TO_VM
const ENABLE_VM_TO_VM = process.env.ENABLE_VM_TO_VM !== undefined ? process.env.ENABLE_VM_TO_VM === 'true' : true;

// --- Advanced Settings ---
// ==============================================================================

const LOG_LEVEL_DISABLED = 0;
const LOG_LEVEL_DEBUG = 1;
const LOG_LEVEL_TRACE = 2;

// log_level: Set to LOG_LEVEL_DEBUG for general debug logging,
// LOG_LEVEL_TRACE for verbose packet-level trace logging, or
// LOG_LEVEL_DISABLED to disable all debug/trace logging.
// ENV: LOG_LEVEL
const log_level = process.env.LOG_LEVEL ? parseInt(process.env.LOG_LEVEL, 10) : LOG_LEVEL_DEBUG;

// GATEWAY_IP: The IP address of the virtual gateway within the VM's network.
// ENV: GATEWAY_IP
const GATEWAY_IP = process.env.GATEWAY_IP || "10.0.2.2";

// DHCP_START: The starting IP address for the DHCP pool (the last octet).
// ENV: DHCP_START
const DHCP_START = process.env.DHCP_START ? parseInt(process.env.DHCP_START, 10) : 15; // Assigns IPs from 10.0.2.15

// DHCP_END: The ending IP address for the DHCP pool (the last octet).
// ENV: DHCP_END
const DHCP_END = process.env.DHCP_END ? parseInt(process.env.DHCP_END, 10) : 254; // Assigns IPs up to 10.0.2.254

// DNS_SERVER_IP: The IP address of the DNS server provided to the VMs via DHCP.
// ENV: DNS_SERVER_IP
const DNS_SERVER_IP = process.env.DNS_SERVER_IP || "8.8.8.8";

// TCP_WINDOW_SIZE: The TCP window size used for connections to and from the VM.
// A larger size may improve performance for high-latency connections.
// ENV: TCP_WINDOW_SIZE
const TCP_WINDOW_SIZE = process.env.TCP_WINDOW_SIZE ? parseInt(process.env.TCP_WINDOW_SIZE, 10) : 1024 * 10;

// WS_PORT: The port on which the WebSocket server will listen.
// Defaults to 8443 for WSS and 8086 for WS.
// ENV: WS_PORT
const WS_PORT = process.env.WS_PORT ? parseInt(process.env.WS_PORT, 10) : (ENABLE_WSS ? 8443 : 8086);

// WS_BIND_ADDRESS: IP address for the WebSocket server to bind to.
// ENV: WS_BIND_ADDRESS
const WS_BIND_ADDRESS = process.env.WS_BIND_ADDRESS || "0.0.0.0"; // Default to binding on all interfaces

// ADMIN_PORT: The port for the web-based admin interface.
// ENV: ADMIN_PORT
const ADMIN_PORT = process.env.ADMIN_PORT ? parseInt(process.env.ADMIN_PORT, 10) : 8001;

// ADMIN_BIND_ADDRESS: IP address for the admin interface to bind to.
// ENV: ADMIN_BIND_ADDRESS
const ADMIN_BIND_ADDRESS = process.env.ADMIN_BIND_ADDRESS || "127.0.0.1"; // Default to binding on localhost

// PROXY_PORT: The port for the HTTP reverse proxy server.
// ENV: PROXY_PORT
const PROXY_PORT = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT, 10) : 8080;

// PROXY_BIND_ADDRESS: IP address for the reverse proxy to bind to.
// ENV: PROXY_BIND_ADDRESS
const PROXY_BIND_ADDRESS = process.env.PROXY_BIND_ADDRESS || "127.0.0.1"; // Default to binding on localhost

// REVERSE_TCP_IDLE_TIMEOUT_MS: Idle timeout for reverse TCP connections in milliseconds.
// ENV: REVERSE_TCP_IDLE_TIMEOUT_MS
const REVERSE_TCP_IDLE_TIMEOUT_MS = process.env.REVERSE_TCP_IDLE_TIMEOUT_MS
  ? parseInt(process.env.REVERSE_TCP_IDLE_TIMEOUT_MS, 10)
  : 45000;

const UDP_FLOW_IDLE_TIMEOUT_MS = process.env.UDP_FLOW_IDLE_TIMEOUT_MS
  ? parseInt(process.env.UDP_FLOW_IDLE_TIMEOUT_MS, 10)
  : 30000;

const MAX_UDP_FLOWS_PER_SESSION = process.env.MAX_UDP_FLOWS_PER_SESSION
  ? parseInt(process.env.MAX_UDP_FLOWS_PER_SESSION, 10)
  : 256;

const TCP_RTO_INITIAL_MS = process.env.TCP_RTO_INITIAL_MS
  ? parseInt(process.env.TCP_RTO_INITIAL_MS, 10)
  : 1000;

const TCP_RTO_MAX_MS = process.env.TCP_RTO_MAX_MS
  ? parseInt(process.env.TCP_RTO_MAX_MS, 10)
  : 60000;

const TCP_RTO_MAX_RETRANSMISSIONS = process.env.TCP_RTO_MAX_RETRANSMISSIONS
  ? parseInt(process.env.TCP_RTO_MAX_RETRANSMISSIONS, 10)
  : 4;

// ==============================================================================
// END OF CONFIGURATION
// ==============================================================================

const RATE_LIMIT_BPS = RATE_LIMIT_KBPS * 1024;
const MAX_ETHERNET_IPV4_FRAME_SIZE = 14 + 0xffff;

const connectionsPerIP = new Map();
const activeSessions = new Map();
const macToIP = new Map(); // Track MAC -> IP assignments
const ipToSession = new Map(); // Track IP -> VMSession for inter-VM routing
const usedIPs = new Set([2]); // Gateway is always reserved

function allocateIP(mac) {
  // Check if this MAC already has an IP
  if (macToIP.has(mac)) {
    return macToIP.get(mac);
  }

  // Find next available IP
  for (let i = DHCP_START; i <= DHCP_END; i++) {
    if (!usedIPs.has(i)) {
      const ip = `10.0.2.${i}`;
      usedIPs.add(i);
      macToIP.set(mac, ip);
      console.log(`📋 Allocated ${ip} to MAC ${mac}`);
      return ip;
    }
  }

  throw new Error("No available IPs in pool");
}

function releaseIP(mac) {
  const ip = macToIP.get(mac);
  if (ip) {
    const lastOctet = parseInt(ip.split(".")[3]);
    usedIPs.delete(lastOctet);
    macToIP.delete(mac);
    ipToSession.delete(ip);
    console.log(`🔓 Released ${ip} from MAC ${mac}`);
  }
}

let wss;
if (ENABLE_WSS) {
  const https = require("https");
  const fs = require("fs");

  const httpsServer = https.createServer({
    cert: fs.readFileSync("cert.pem"),
    key: fs.readFileSync("key.pem"),
  });

  wss = new WebSocket.Server({
    server: httpsServer,
    perMessageDeflate: false,
    maxPayload: MAX_ETHERNET_IPV4_FRAME_SIZE,
  });

  httpsServer.listen(WS_PORT, WS_BIND_ADDRESS);
  console.log(
    `Secure WebSocket (WSS) VPN server, visit https://${WS_BIND_ADDRESS}:${WS_PORT} and trust your certificate`,
  );
} else {
  wss = new WebSocket.Server({
    port: WS_PORT,
    host: WS_BIND_ADDRESS,
    perMessageDeflate: false,
    maxPayload: MAX_ETHERNET_IPV4_FRAME_SIZE,
  });
  console.log(`WebSocket VPN server listening on ${WS_BIND_ADDRESS}:${WS_PORT}`);
}

console.log(
  "\x1b[33m%s\x1b[0m",
  `
═══════════════════════════════════════════════════════════════
  ⚠️  SECURITY NOTICE
═══════════════════════════════════════════════════════════════
  
  This relay provides network access to virtual machines.
  
  • Only expose this service to trusted networks
  • Consider using firewall rules to restrict access
  • Authentication is not built-in - add it if needed
  
═══════════════════════════════════════════════════════════════
`,
);

console.log(`Rate limit: ${RATE_LIMIT_KBPS} KB/s`);
console.log(`TCP Window: ${TCP_WINDOW_SIZE} bytes`);
console.log(`DHCP Pool: 10.0.2.${DHCP_START} - 10.0.2.${DHCP_END}`);
console.log(`VM-to-VM routing: ${ENABLE_VM_TO_VM ? "ENABLED" : "DISABLED"}`);

const PassThrough = require("stream").PassThrough;

class VMSession {
  constructor(ws, clientIP) {
    this.ws = ws;
    this.clientIP = clientIP;
    this.vmIP = null;
    this.vmMAC = null;
    this.bytesSent = 0;
    this.bytesReceived = 0;

    this.udpFlows = new UDPFlowManager({
      idleTimeoutMs: UDP_FLOW_IDLE_TIMEOUT_MS,
      maxFlows: MAX_UDP_FLOWS_PER_SESSION,
      onResponse: (payload, flow) => {
        const response = flow.isDNS ? this.filterDNSResponse(payload) : payload;
        this.sendUDPToVM(
          response,
          flow.remotePort,
          flow.vmPort,
          flow.remoteIP,
          flow.vmIP,
        );
      },
      onError: (err, flow) => {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.error(
            `UDP flow error for ${flow.remoteIP}:${flow.remotePort}: ${err.message}`,
          );
        }
      },
    });
    this.tcpConnections = new Map();
    this.reverseTcpConnections = new Map();
    this.recentlyClosed = new Set();
    this.udpProxyNatTable = new Map();

    this.rateLimiter = new SlidingWindowRateLimiter(RATE_LIMIT_BPS, 1000);

    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`New session created for ${clientIP}`);
    }
  }

  forwardUdpPacket(payload, vmPort, clientRinfo, ruleId) {
    // Find an available ephemeral port for the NAT table
    let ephemeralPort = 40000 + Math.floor(Math.random() * 10000);
    while (this.udpProxyNatTable.has(ephemeralPort)) {
      ephemeralPort = 40000 + Math.floor(Math.random() * 10000);
    }

    this.udpProxyNatTable.set(ephemeralPort, {
      clientRinfo,
      ruleId,
      lastSeen: Date.now(),
    });

    // Clean up old entries after a timeout
    setTimeout(() => {
      const entry = this.udpProxyNatTable.get(ephemeralPort);
      if (entry && (Date.now() - entry.lastSeen) > 30000) { // 30 second timeout
        this.udpProxyNatTable.delete(ephemeralPort);
      }
    }, 31000);

    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(
        `[UDP PROXY NAT] Creating NAT entry for ${clientRinfo.address}:${clientRinfo.port} on ephemeral port ${ephemeralPort}`,
      );
    }

    this.sendUDPToVM(payload, ephemeralPort, vmPort, GATEWAY_IP, this.vmIP);
  }

  sendRSTForReverse(srcPort, dstPort, srcIP, dstIP, seqNum) {
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(srcPort, 0);
    tcp.writeUInt16BE(dstPort, 2);
    tcp.writeUInt32BE(seqNum, 4);
    tcp.writeUInt32BE(0, 8);
    tcp[12] = 0x50;
    tcp[13] = 0x04; // RST
    tcp.writeUInt16BE(0, 14);
    tcp.writeUInt16BE(0, 16);
    tcp.writeUInt16BE(0, 18);

    const ip = this.buildIP(tcp, srcIP, dstIP, 6);
    const cksum = this.calcTCPChecksum(ip);
    ip.writeUInt16BE(cksum, 20 + 16);

    this.sendIPToVM(ip);
  }

  initializeRetransmission(conn, initialSequence, isCurrent, onExhausted) {
    conn.retransmission = new TCPRetransmissionQueue({
      initialSequence,
      initialRtoMs: TCP_RTO_INITIAL_MS,
      maxRtoMs: TCP_RTO_MAX_MS,
      maxRetransmissions: TCP_RTO_MAX_RETRANSMISSIONS,
      onRetransmit: (segment, reason) => {
        if (!isCurrent()) {
          conn.retransmission.close();
          return;
        }
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `TCP ${reason} retransmit seq=${segment.seq} ` +
            `len=${segment.payload.length}`,
          );
        }
        this.sendTCP(
          conn,
          segment.payload,
          conn.tx.srcPort,
          conn.tx.dstPort,
          conn.tx.srcIP,
          conn.tx.dstIP,
          segment.flags,
          { sequence: segment.seq, advanceSequence: false },
        );
      },
      onExhausted,
    });
  }

  sendTrackedTCP(conn, payload, flags = {}, options = {}) {
    const segments = this.sendTCP(
      conn,
      payload,
      conn.tx.srcPort,
      conn.tx.dstPort,
      conn.tx.srcIP,
      conn.tx.dstIP,
      flags,
      options,
    );
    for (const segment of segments) conn.retransmission.track(segment);
    return segments;
  }

  abortReverseConnection(connKey, conn, error, sendReset = true) {
    if (this.reverseTcpConnections.get(connKey) !== conn) return;
    if (sendReset && this.ws.readyState === WebSocket.OPEN) {
      this.sendTCP(
        conn,
        Buffer.alloc(0),
        conn.tx.srcPort,
        conn.tx.dstPort,
        conn.tx.srcIP,
        conn.tx.dstIP,
        { rst: true, ack: true },
      );
    }
    conn.state = "CLOSED";
    conn.retransmission?.close();
    this.clearReverseConnTimer(connKey);
    this.reverseTcpConnections.delete(connKey);
    conn.upstream.destroy();
    conn.downstream.destroy();
    conn.onError?.(error);
    this.recentlyClosed.add(connKey);
    setTimeout(() => this.recentlyClosed.delete(connKey), 2000);
  }

  finishReverseConnection(connKey, conn) {
    if (this.reverseTcpConnections.get(connKey) !== conn) return;
    conn.state = "CLOSED";
    conn.retransmission.close();
    this.clearReverseConnTimer(connKey);
    this.reverseTcpConnections.delete(connKey);
    conn.downstream.end();
    conn.upstream.destroy();
    this.recentlyClosed.add(connKey);
    setTimeout(() => this.recentlyClosed.delete(connKey), 2000);
  }

  abortTCPConnection(connKey, conn, error, sendReset = true) {
    if (this.tcpConnections.get(connKey) !== conn) return;
    conn.state = "CLOSED";
    conn.retransmission?.close();
    this.tcpConnections.delete(connKey);
    if (sendReset && this.ws.readyState === WebSocket.OPEN) {
      this.sendTCP(
        conn,
        Buffer.alloc(0),
        conn.tx.srcPort,
        conn.tx.dstPort,
        conn.tx.srcIP,
        conn.tx.dstIP,
        { rst: true, ack: true },
      );
    }
    conn.socket?.destroy();
    if (log_level >= LOG_LEVEL_DEBUG && error) {
      console.error(`TCP connection ${connKey} aborted: ${error.message}`);
    }
  }

  finishTCPConnection(connKey, conn) {
    if (this.tcpConnections.get(connKey) !== conn) return;
    conn.state = "CLOSED";
    conn.retransmission.close();
    conn.socket?.end();
    setTimeout(() => {
      if (this.tcpConnections.get(connKey) === conn) {
        this.tcpConnections.delete(connKey);
      }
    }, 2000);
  }

  createTCPConnection(port) {
    return new Promise((resolve, reject) => {
      let srcPort;
      let attempts = 0;
      do {
        srcPort = nextProxyPort++;
        if (nextProxyPort > 65535) {
          nextProxyPort = 30000;
        }
        attempts++;
        if (attempts > 1000) {
          return reject(new Error("No available proxy ports"));
        }
      } while (
        this.reverseTcpConnections.has(srcPort) ||
        this.recentlyClosed.has(srcPort)
      );
      const dstPort = port;
      const srcIP = GATEWAY_IP;
      const dstIP = this.vmIP;
      const connKey = srcPort;

      const isn = Math.floor(Math.random() * 0xFFFFFFFF);
      let promiseSettled = false;
      const conn = {
        state: "SYN_SENT",
        relayIsn: isn,
        relaySeq: isn >>> 0,
        vmSeq: 0,
        vmLastAck: isn >>> 0,
        vmWindow: TCP_WINDOW_SIZE,
        vmWindowScale: 0,
        sendQueue: [],
        sending: false,
        dupAckCount: 0,
        vmOutOfOrder: new Map(),
        idleTimer: null,
        pendingFin: false,
        finSent: false,
        srcPort,
        dstPort,
        srcIP,
        dstIP,
        tx: { srcPort, dstPort, srcIP, dstIP },
        upstream: new PassThrough(),
        downstream: new PassThrough(),
        onConnected: () => {
          if (promiseSettled) return;
          promiseSettled = true;
          resolve({
            upstream: conn.upstream,
            downstream: conn.downstream,
            connKey: connKey,
          });
        },
        onError: (err) => {
          if (promiseSettled) return;
          promiseSettled = true;
          reject(err);
        },
      };
      this.reverseTcpConnections.set(connKey, conn);
      this.initializeRetransmission(
        conn,
        conn.relaySeq,
        () => this.reverseTcpConnections.get(connKey) === conn,
        (error) => this.abortReverseConnection(connKey, conn, error),
      );
      this.bumpReverseConnActivity(connKey);

      conn.upstream.on("data", (data) => {
        this.bumpReverseConnActivity(connKey);
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `[UPSTREAM] Received ${data.length} bytes from client. Forwarding to VM.`,
          );
        }
        conn.sendQueue.push(data);
        this.trySendReverseToVM(connKey);
      });

      conn.upstream.on("close", () => {
        if (
          this.reverseTcpConnections.get(connKey) !== conn ||
          conn.state === "CLOSED"
        ) return;
        this.bumpReverseConnActivity(connKey);
        conn.pendingFin = true;
        this.trySendReverseToVM(connKey);
      });

      this.sendTrackedTCP(conn, Buffer.alloc(0), {
        syn: true,
      });
    });
  }

  handleReverseTCP(ipPacket) {
    const ihl = (ipPacket[0] & 0x0f) * 4;

    if (ipPacket.length < ihl + 20) return;

    const srcIP = Array.from(ipPacket.slice(12, 16)).join(".");
    const dstIP = Array.from(ipPacket.slice(16, 20)).join(".");
    const srcPort = ipPacket.readUInt16BE(ihl);
    const dstPort = ipPacket.readUInt16BE(ihl + 2);
    const seqNum = ipPacket.readUInt32BE(ihl + 4);
    const ackNum = ipPacket.readUInt32BE(ihl + 8);
    const flags = ipPacket[ihl + 13];
    const dataOffset = (ipPacket[ihl + 12] >> 4) * 4;
    const window = ipPacket.readUInt16BE(ihl + 14);
    const SYN = (flags & 0x02) !== 0;
    const ACK = (flags & 0x10) !== 0;
    const FIN = (flags & 0x01) !== 0;
    const RST = (flags & 0x04) !== 0;
    const payload = ipPacket.slice(ihl + dataOffset);
    const reverseFlow = getReverseFlow(srcIP, dstIP, srcPort, dstPort);

    if (log_level >= LOG_LEVEL_TRACE) {
      const f = [
        SYN ? "SYN" : "",
        ACK ? "ACK" : "",
        FIN ? "FIN" : "",
        RST ? "RST" : "",
      ].filter((x) => x).join(",");

      console.log(
        `[R-TRACE] RECV [${f}] seq=${seqNum} ack=${ackNum} len=${payload.length}`,
      );

      const conn = this.reverseTcpConnections.get(dstPort);

      if (conn) {
        console.log(
          `          STATE: vmSeq=${conn.vmSeq} relaySeq=${conn.relaySeq}`,
        );
      }
    }

    const connKey = dstPort;
    const conn = this.reverseTcpConnections.get(connKey);

    if (log_level >= LOG_LEVEL_TRACE) {
      console.log(
        `[R-TRACE-SEQ] Packet: seq=${seqNum} len=${payload.length}, Current: vmSeq=${conn?.vmSeq}, Expected next: ${
          (conn?.vmSeq || 0) + payload.length
        }`,
      );
    }

    if (!conn) {
      if (this.recentlyClosed.has(connKey)) {
        return;
      }
      if (!RST && log_level >= LOG_LEVEL_DEBUG) {
        console.log(
          `[REVERSE TCP] No connection for port ${connKey}, sending RST`,
        );
      }
      if (!RST) {
        this.sendRSTForReverse(
          reverseFlow.relaySrcPort,
          reverseFlow.relayDstPort,
          reverseFlow.relaySrcIP,
          reverseFlow.relayDstIP,
          ackNum,
        );
      }
      return;
    }

    this.bumpReverseConnActivity(connKey);

    if (RST) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(
          `[REVERSE TCP] RST received, closing connection ${connKey}`,
        );
      }
      this.abortReverseConnection(
        connKey,
        conn,
        new Error("VM reset reverse TCP connection"),
        false,
      );
      return;
    }

    if (conn.state === "SYN_SENT" && SYN && ACK) {
      const ackResult = conn.retransmission.acknowledge(ackNum);
      if (ackResult.status !== "advanced" || conn.retransmission.hasOutstanding) {
        return;
      }
      let windowScale = 0;
      if (dataOffset > 20) {
        let optOffset = ihl + 20;
        const optEnd = ihl + dataOffset;
        while (optOffset < optEnd && optOffset < ipPacket.length) {
          const kind = ipPacket[optOffset];
          if (kind === 0) break;
          if (kind === 1) {
            optOffset++;
            continue;
          }
          if (optOffset + 1 >= ipPacket.length) break;
          const len = ipPacket[optOffset + 1];
          if (len < 2 || optOffset + len > optEnd) break;
          if (kind === 3 && len === 3) {
            windowScale = ipPacket[optOffset + 2];
          }
          optOffset += len;
        }
      }

      conn.state = "ESTABLISHED";
      conn.vmSeq = (seqNum + 1) >>> 0;
      conn.vmLastAck = conn.retransmission.sndUna;
      conn.vmWindowScale = windowScale;
      conn.vmWindow = window << windowScale;

      this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
        ack: true,
      });

      if (conn.onConnected) {
        conn.onConnected();
      }
      this.trySendReverseToVM(connKey);
      return;
    }

    if (conn.state === "SYN_SENT") return;

    if (SYN && ACK) {
      // Our final handshake ACK may have been lost. ACK a repeated SYN-ACK
      // without changing established sequence state.
      this.sendTCP(
        conn,
        Buffer.alloc(0),
        reverseFlow.relaySrcPort,
        reverseFlow.relayDstPort,
        reverseFlow.relaySrcIP,
        reverseFlow.relayDstIP,
        { ack: true },
      );
      return;
    }

    if (
      conn.state !== "ESTABLISHED" &&
      conn.state !== "FIN_WAIT" &&
      conn.state !== "CLOSING"
    ) return;

    // Track peer receive window and acknowledged bytes for reverse stream writes.
    conn.vmWindow = window << (conn.vmWindowScale || 0);
    if (ACK) {
      const ackResult = conn.retransmission.acknowledge(ackNum);
      if (ackResult.status === "advanced") {
        conn.dupAckCount = 0;
        conn.vmLastAck = conn.retransmission.sndUna;
        if (
          conn.peerFin &&
          conn.finSent &&
          !conn.retransmission.hasOutstanding
        ) {
          this.finishReverseConnection(connKey, conn);
          return;
        }
        this.trySendReverseToVM(connKey);
      } else if (
        ackResult.status === "duplicate" &&
        conn.retransmission.hasOutstanding
      ) {
        conn.dupAckCount++;
        if (conn.dupAckCount === 3) {
          conn.retransmission.fastRetransmit();
          conn.dupAckCount = 0;
        }
      }
    }

    if (payload.length === 6) {
      const allSpaces = payload.every((b) => b === 0x20);
      const allZeros = payload.every((b) => b === 0);

      if (allSpaces || allZeros) {
        if (log_level >= LOG_LEVEL_TRACE) {
          console.log(
            `[R-TRACE] Ignoring 6-byte ${
              allSpaces ? "spaces" : "zeros"
            } artifact`,
          );
        }
        // Don't update vmSeq, just ACK
        this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
          ack: true,
        });
        return;
      }
    }

    if (payload.length > 0) {
      let effectiveSeq = seqNum >>> 0;
      let effectivePayload = payload;

      // Check if this is old, already-processed data (a retransmission)
      if (this.seqLessThan(effectiveSeq, conn.vmSeq)) {
        const alreadyHave = this.seqDiff(conn.vmSeq, effectiveSeq);
        if (alreadyHave >= effectivePayload.length) {
          if (log_level >= LOG_LEVEL_TRACE) {
            console.log(
              `[R-TRACE] Ignoring retransmitted packet: seq=${effectiveSeq} but already have up to ${conn.vmSeq}`,
            );
          }
          // Send ACK with current expected sequence number
          this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
            ack: true,
          });
          return;
        }
        // Partial overlap: trim old bytes and keep only new tail.
        effectivePayload = effectivePayload.slice(alreadyHave);
        effectiveSeq = conn.vmSeq;
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `[R-TRACE] Trimmed overlapping segment, kept ${effectivePayload.length} new bytes`,
          );
        }
      }

      // Check if this is future data (out of order)
      if (this.seqLessThan(conn.vmSeq, effectiveSeq)) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `[R-TRACE] Buffering out-of-order packet: seq=${effectiveSeq} expected=${conn.vmSeq}`,
          );
        }
        const seqKey = effectiveSeq >>> 0;
        if (!conn.vmOutOfOrder.has(seqKey)) {
          conn.vmOutOfOrder.set(seqKey, effectivePayload);
        }
        this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
          ack: true,
        });
        return;
      }

      // If we reach here, seqNum === conn.vmSeq (in-order data)
      if (log_level >= LOG_LEVEL_TRACE) {
        console.log(
          `[R-TRACE-DATA] Writing ${effectivePayload.length} bytes to downstream. Data (first 32 bytes): ${
            effectivePayload.toString("hex", 0, Math.min(effectivePayload.length, 32))
          }`,
        );
      }

      conn.downstream.write(effectivePayload);
      conn.vmSeq = (conn.vmSeq + effectivePayload.length) >>> 0;

      // Drain any contiguous out-of-order payload that is now in-order.
      while (conn.vmOutOfOrder && conn.vmOutOfOrder.has(conn.vmSeq)) {
        const buffered = conn.vmOutOfOrder.get(conn.vmSeq);
        conn.vmOutOfOrder.delete(conn.vmSeq);
        conn.downstream.write(buffered);
        conn.vmSeq = (conn.vmSeq + buffered.length) >>> 0;
      }

      this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
        ack: true,
      });
    }

    if (FIN) {
      console.log(
        `[REVERSE TCP] [${this.vmIP}] FIN received, closing connection ${connKey}`,
      );

      const finSequence = (seqNum + payload.length) >>> 0;
      if (finSequence !== conn.vmSeq) {
        this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
          ack: true,
        });
        return;
      }
      conn.vmSeq = (conn.vmSeq + 1) >>> 0;
      conn.peerFin = true;
      conn.state = "CLOSING";
      conn.downstream.end();

      // Send final ACK for the FIN. This uses the updated vmSeq.
      this.sendTCP(conn, Buffer.alloc(0), reverseFlow.relaySrcPort, reverseFlow.relayDstPort, reverseFlow.relaySrcIP, reverseFlow.relayDstIP, {
        ack: true,
      });

      if (conn.finSent && !conn.retransmission.hasOutstanding) {
        this.finishReverseConnection(connKey, conn);
      }
    }
  }

  handleEthernetFrame(data) {
    this.bytesReceived += data.length;
    try {
      const frame = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (frame.length < 14) return;

      const srcMAC = frame.slice(6, 12);
      const etherType = frame.readUInt16BE(12);

      const macStr = Array.from(srcMAC).map((b) =>
        b.toString(16).padStart(2, "0")
      ).join(":");

      // Store MAC address
      if (!this.vmMAC || this.vmMAC !== macStr) {
        this.vmMAC = macStr;
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`🔖 – VM MAC: ${macStr}`);
        }
      }

      if (etherType === 0x0806) {
        this.handleARP(frame.slice(14));
      } else if (etherType === 0x0800) {
        this.handleIPv4(frame.slice(14));
      }
    } catch (err) {
      if (log_level >= LOG_LEVEL_DEBUG) console.error("❌ Error:", err);
    }
  }

  handleARP(arpPacket) {
    if (arpPacket.length < 28) return;

    const opcode = arpPacket.readUInt16BE(6);
    const senderIP = Array.from(arpPacket.slice(14, 18)).join(".");
    const targetIP = Array.from(arpPacket.slice(24, 28)).join(".");

    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(
        `🔍 ARP ${
          opcode === 1 ? "Request" : "Reply"
        }: ${senderIP} -> ${targetIP}`,
      );
    }

    // Assign IP based on MAC if not already assigned
    if (!this.vmIP && this.vmMAC) {
      try {
        this.vmIP = allocateIP(this.vmMAC);
        ipToSession.set(this.vmIP, this); // Register this session
        console.log(`✅ VM IP assigned: ${this.vmIP} (MAC: ${this.vmMAC})`);
      } catch (err) {
        console.error(`❌ Failed to allocate IP: ${err.message}`);
        return;
      }
    }

    if (opcode === 1 && targetIP === GATEWAY_IP) {
      const reply = Buffer.alloc(42);
      arpPacket.slice(8, 14).copy(reply, 0);
      Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).copy(reply, 6);
      reply.writeUInt16BE(0x0806, 12);
      reply.writeUInt16BE(1, 14);
      reply.writeUInt16BE(0x0800, 16);
      reply.writeUInt8(6, 18);
      reply.writeUInt8(4, 19);
      reply.writeUInt16BE(2, 20);
      Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).copy(reply, 22);
      Buffer.from(GATEWAY_IP.split(".").map(Number)).copy(reply, 28);
      arpPacket.slice(8, 14).copy(reply, 32);
      arpPacket.slice(14, 18).copy(reply, 38);

      if (log_level >= LOG_LEVEL_DEBUG) console.log(`Sending ARP reply`);
      this.sendToVM(reply);
    } else if (opcode === 1) {
      // ARP request for another VM on the network
      if (!ENABLE_VM_TO_VM) {
        // Don't respond to ARP requests for other VMs if routing is disabled
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `🚫 VM-to-VM routing disabled, ignoring ARP for ${targetIP}`,
          );
        }
        return;
      }

      const targetSession = ipToSession.get(targetIP);
      if (targetSession && targetSession.vmMAC) {
        // Reply with the target VM's MAC
        const reply = Buffer.alloc(42);
        arpPacket.slice(8, 14).copy(reply, 0); // Dest MAC (requester)

        const targetMACBytes = targetSession.vmMAC.split(":").map((hex) =>
          parseInt(hex, 16)
        );
        Buffer.from(targetMACBytes).copy(reply, 6); // Source MAC (target VM)

        reply.writeUInt16BE(0x0806, 12);
        reply.writeUInt16BE(1, 14);
        reply.writeUInt16BE(0x0800, 16);
        reply.writeUInt8(6, 18);
        reply.writeUInt8(4, 19);
        reply.writeUInt16BE(2, 20); // ARP Reply

        Buffer.from(targetMACBytes).copy(reply, 22); // Sender MAC
        Buffer.from(targetIP.split(".").map(Number)).copy(reply, 28); // Sender IP
        arpPacket.slice(8, 14).copy(reply, 32); // Target MAC
        arpPacket.slice(14, 18).copy(reply, 38); // Target IP

        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`Sending ARP reply for ${targetIP} (VM-to-VM)`);
        }
        this.sendToVM(reply);
      }
    }
  }

  handleIPv4(ipPacket) {
    const parsed = parseIPv4Packet(ipPacket);
    if (!parsed) return;

    ipPacket = parsed.packet;
    const { protocol, srcIP, dstIP } = parsed;

    if (log_level >= LOG_LEVEL_DEBUG) {
      const proto = protocol === 6
        ? "TCP"
        : protocol === 17
        ? "UDP"
        : protocol === 1
        ? "ICMP"
        : protocol;
      console.log(`📦 IPv4 ${proto}: ${srcIP} -> ${dstIP}`);
    }

    if (protocol === 6 && dstIP === GATEWAY_IP) {
      if (parsed.moreFragments || parsed.fragmentOffset !== 0) return;
      this.handleReverseTCP(ipPacket);
      return;
    }

    // Handle UDP broadcast
    if (ENABLE_VM_TO_VM && dstIP === "10.0.2.255" && protocol === 17) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`📢 Broadcasting UDP packet from ${srcIP}`);
      }
      activeSessions.forEach((session, _sessionId) => {
        if (session.vmIP && session.vmIP !== srcIP) {
          if (log_level >= LOG_LEVEL_DEBUG) {
            console.log(`   -> Relaying to ${session.vmIP}`);
          }
          session.sendIPToVM(ipPacket);
        }
      });
      return;
    }

    // Check if this is VM-to-VM traffic
    if (
      ENABLE_VM_TO_VM && dstIP.startsWith("10.0.2.") && dstIP !== GATEWAY_IP &&
      dstIP !== "10.0.2.255"
    ) {
      const targetSession = ipToSession.get(dstIP);
      if (targetSession) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`🔄 Routing to VM ${dstIP}`);
        }
        targetSession.sendIPToVM(ipPacket);
        return;
      }
    }

    // Internet-bound fragments require reassembly before transport parsing.
    // VM-to-VM fragments above are forwarded unchanged and do not need it.
    if (parsed.moreFragments || parsed.fragmentOffset !== 0) return;

    // Otherwise handle normally (internet-bound traffic)
    if (protocol === 1) this.handleICMP(ipPacket, parsed);
    else if (protocol === 17) this.handleUDP(ipPacket, parsed);
    else if (protocol === 6) this.handleTCP(ipPacket);
  }

  handleTCP(ipPacket) {
    const ihl = (ipPacket[0] & 0x0f) * 4;
    if (ipPacket.length < ihl + 20) return;

    const srcIP = Array.from(ipPacket.slice(12, 16)).join(".");
    const dstIP = Array.from(ipPacket.slice(16, 20)).join(".");
    const srcPort = ipPacket.readUInt16BE(ihl);
    const dstPort = ipPacket.readUInt16BE(ihl + 2);
    const seqNum = ipPacket.readUInt32BE(ihl + 4);
    const ackNum = ipPacket.readUInt32BE(ihl + 8);
    const flags = ipPacket[ihl + 13];
    const dataOffset = (ipPacket[ihl + 12] >> 4) * 4;
    const window = ipPacket.readUInt16BE(ihl + 14);

    const SYN = (flags & 0x02) !== 0;
    const ACK = (flags & 0x10) !== 0;
    const FIN = (flags & 0x01) !== 0;
    const RST = (flags & 0x04) !== 0;
    const PSH = (flags & 0x08) !== 0;

    // Parse TCP options for window scaling
    let windowScale = 0;
    if (SYN && dataOffset > 20) {
      let optOffset = ihl + 20;
      const optEnd = ihl + dataOffset;
      while (optOffset < optEnd && optOffset < ipPacket.length) {
        const kind = ipPacket[optOffset];
        if (kind === 0) break; // End of options
        if (kind === 1) { // NOP
          optOffset++;
          continue;
        }
        if (optOffset + 1 >= ipPacket.length) break;
        const len = ipPacket[optOffset + 1];
        if (len < 2 || optOffset + len > optEnd) break;

        if (kind === 3 && len === 3) { // Window Scale
          windowScale = ipPacket[optOffset + 2];
          if (log_level >= LOG_LEVEL_DEBUG) {
            console.log(`     Window scale: ${windowScale}`);
          }
        }
        optOffset += len;
      }
    }

    if (log_level >= LOG_LEVEL_DEBUG) {
      const f = [
        SYN ? "SYN" : "",
        ACK ? "ACK" : "",
        FIN ? "FIN" : "",
        RST ? "RST" : "",
        PSH ? "PSH" : "",
      ].filter((x) => x).join(",");
      console.log(
        `🔌 TCP ${srcIP}:${srcPort} -> ${dstIP}:${dstPort} [${f}] seq=${seqNum} ack=${ackNum} win=${window}`,
      );
    }

    const connKey = `${srcPort}:${dstIP}:${dstPort}`;

    if (SYN && !ACK) {
      const existing = this.tcpConnections.get(connKey);
      if (existing) {
        if (existing.state === "SYN_SENT") {
          existing.retransmission.fastRetransmit();
        }
        return;
      }
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`   Opening connection to ${dstIP}:${dstPort}`);
      }

      const socket = net.connect(dstPort, dstIP, () => {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   ✅ Connected to ${dstIP}:${dstPort}`);
        }
      });

      // Increase socket buffer sizes for better performance
      socket.setNoDelay(true);
      try {
        socket.setKeepAlive(true, 30000);
      } catch (_e) {}

      const isn = Math.floor(Math.random() * 0xFFFFFFFF);
      const actualWindow = window << windowScale;
      const conn = {
        socket: socket,
        relayIsn: isn,
        relaySeq: (isn + 1) >>> 0,
        vmSeq: (seqNum + 1) >>> 0,
        vmOutOfOrder: new Map(),
        vmLastAck: isn >>> 0,
        state: "SYN_SENT",
        sendQueue: [],
        vmWindow: Math.min(actualWindow, TCP_WINDOW_SIZE),
        vmWindowScale: windowScale,
        dupAckCount: 0,
        pendingFin: false,
        finSent: false,
        peerFin: false,
        tx: {
          srcPort: dstPort,
          dstPort: srcPort,
          srcIP: dstIP,
          dstIP: srcIP,
        },
      };
      this.tcpConnections.set(connKey, conn);
      this.initializeRetransmission(
        conn,
        conn.vmLastAck,
        () => this.tcpConnections.get(connKey) === conn,
        (error) => this.abortTCPConnection(connKey, conn, error),
      );

      socket.on("data", (data) => {
        const c = this.tcpConnections.get(connKey);
        if (!c) return;
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `   Received ${data.length} bytes from ${dstIP}:${dstPort}`,
          );
        }
        c.sendQueue.push(data);
        this.trySendToVM(connKey, {
          dstPort,
          srcPort,
          dstIP,
          srcIP,
        });
      });

      socket.on("end", () => {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   Connection ended: ${dstIP}:${dstPort}`);
        }
        const c = this.tcpConnections.get(connKey);
        if (c && c.state !== "CLOSED") {
          c.pendingFin = true;
          this.trySendToVM(connKey, {
            dstPort,
            srcPort,
            dstIP,
            srcIP,
          });
        }
      });

      socket.on("error", (err) => {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.error(`   ❌ TCP error: ${err.message}`);
        }
        const c = this.tcpConnections.get(connKey);
        if (c) {
          this.abortTCPConnection(connKey, c, err);
        }
      });

      this.sendTrackedTCP(
        conn,
        Buffer.alloc(0),
        { syn: true, ack: true, windowSize: TCP_WINDOW_SIZE },
        { sequence: conn.relayIsn, advanceSequence: false },
      );
      return;
    }

    const conn = this.tcpConnections.get(connKey);
    if (!conn) {
      if (log_level >= LOG_LEVEL_DEBUG && !RST) {
        console.log(`   ⚠ No connection for ${connKey}`);
      }
      return;
    }

    // Update window with scaling
    const actualWindow = window << (conn.vmWindowScale || 0);
    conn.vmWindow = Math.min(actualWindow, TCP_WINDOW_SIZE);

    if (RST) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`   🛑 RST received, closing connection`);
      }
      this.abortTCPConnection(
        connKey,
        conn,
        new Error("VM reset TCP connection"),
        false,
      );
      return;
    }

    let ackResult = null;
    if (ACK) {
      ackResult = conn.retransmission.acknowledge(ackNum);
      if (ackResult.status === "advanced") {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `   ✅ VM ACKed ${ackResult.ackedDataBytes} data bytes (to ${ackNum})`,
          );
        }
        conn.dupAckCount = 0;
        conn.vmLastAck = conn.retransmission.sndUna;
      } else if (
        ackResult.status === "duplicate" &&
        conn.retransmission.hasOutstanding
      ) {
        conn.dupAckCount++;
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   🔄 Duplicate ACK #${conn.dupAckCount} for ${ackNum}`);
        }
        if (conn.dupAckCount === 3) {
          if (log_level >= LOG_LEVEL_DEBUG) {
            console.log(`   ⚡ Fast retransmit triggered`);
          }
          conn.retransmission.fastRetransmit();
          conn.dupAckCount = 0;
        }
      }
    }

    const payloadOffset = ihl + dataOffset;
    const payload = ipPacket.slice(payloadOffset);

    if (conn.state === "SYN_SENT") {
      if (
        !ACK ||
        ackResult?.status !== "advanced" ||
        conn.retransmission.hasOutstanding
      ) return;
      conn.state = "ESTABLISHED";
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`   🤝 Connection established: ${connKey}`);
      }

      // Always ACK the handshake, but ignore any piggybacked data
      this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
        ack: true,
      });

      this.trySendToVM(connKey, { dstPort, srcPort, dstIP, srcIP });

      // Don't process payload here - v86 will retransmit it cleanly
      return;
    }

    if (
      conn.state !== "ESTABLISHED" &&
      conn.state !== "FIN_WAIT" &&
      conn.state !== "CLOSING"
    ) return;

    if (ackResult?.status === "advanced") {
      if (
        conn.peerFin &&
        conn.finSent &&
        !conn.retransmission.hasOutstanding
      ) {
        this.finishTCPConnection(connKey, conn);
        return;
      }
      this.trySendToVM(connKey, { dstPort, srcPort, dstIP, srcIP });
    }

    // Check for 6-byte TCP stack artifacts EARLY (before any other processing)
    if (payload.length === 6) {
      const allSpaces = payload.every((b) => b === 0x20);
      const allZeros = payload.every((b) => b === 0);

      if (allSpaces || allZeros) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `   🔍 6-byte packet: ${
              allSpaces ? "all spaces (0x20)" : "all zeros"
            }`,
          );
          console.log(
            `   ⚠️ Ignoring VM TCP stack artifact (6-byte ${
              allSpaces ? "spaces" : "zeros"
            })`,
          );
        }
        // Don't forward, don't update vmSeq, just ACK with current state
        this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
          ack: true,
        });
        return; // ← Exit here, don't process FIN or anything else
      }
    }

    if (payload.length > 0) {
      let effectiveSeq = seqNum >>> 0;
      let effectivePayload = payload;
      const expected = conn.vmSeq;

      if (effectiveSeq === expected) {
        // Perfect - expected sequence
        conn.vmSeq = (effectiveSeq + effectivePayload.length) >>> 0;
      } else if (this.seqLessThan(effectiveSeq, expected)) {
        const alreadyHave = this.seqDiff(expected, effectiveSeq);
        if (alreadyHave >= effectivePayload.length) {
          // Old data - full retransmission
          if (log_level >= LOG_LEVEL_DEBUG) {
            console.log(`   🔄 Retransmission from VM`);
          }
          this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
            ack: true,
          });
          return;
        }
        // Partial overlap with new tail.
        effectivePayload = effectivePayload.slice(alreadyHave);
        effectiveSeq = expected;
        conn.vmSeq = (effectiveSeq + effectivePayload.length) >>> 0;
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   ✂️ Trimmed overlapping segment, forwarding ${effectivePayload.length}B new tail`);
        }
      } else {
        // Future sequence number - out of order
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `   ⚠ Out of order from VM (seq=${effectiveSeq}, expected=${expected})`,
          );
        }
        const seqKey = effectiveSeq >>> 0;
        if (!conn.vmOutOfOrder.has(seqKey)) {
          conn.vmOutOfOrder.set(seqKey, effectivePayload);
        }
        this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
          ack: true,
        });
        return;
      }

      // Forward payload to real socket
      if (conn.socket && conn.socket.writable) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `   📤 Forwarding ${effectivePayload.length} bytes to ${dstIP}:${dstPort}`,
          );
        }
        conn.socket.write(effectivePayload);
      }

      // Drain any contiguous out-of-order payload that is now in-order.
      while (conn.vmOutOfOrder && conn.vmOutOfOrder.has(conn.vmSeq)) {
        const buffered = conn.vmOutOfOrder.get(conn.vmSeq);
        conn.vmOutOfOrder.delete(conn.vmSeq);
        conn.vmSeq = (conn.vmSeq + buffered.length) >>> 0;
        if (conn.socket && conn.socket.writable) {
          conn.socket.write(buffered);
        }
      }

      // ACK after processing
      this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
        ack: true,
      });
    }

    if (FIN) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`   Closing (FIN): ${connKey}`);
      }

      const finSequence = (seqNum + payload.length) >>> 0;
      if (finSequence !== conn.vmSeq) {
        this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
          ack: true,
        });
        return;
      }
      conn.vmSeq = (conn.vmSeq + 1) >>> 0;

      // Send ACK for the FIN.
      this.sendTCP(conn, Buffer.alloc(0), dstPort, srcPort, dstIP, srcIP, {
        ack: true,
      });

      conn.peerFin = true;
      conn.state = "CLOSING";
      if (conn.socket) conn.socket.end();
      if (conn.finSent && !conn.retransmission.hasOutstanding) {
        this.finishTCPConnection(connKey, conn);
      }
      return;
    }
  }

  seqLessThan(a, b) {
    // Handle 32-bit unsigned integer wrap-around
    const diff = (a - b) >>> 0;
    return diff > 0x7FFFFFFF;
  }

  seqLessThanOrEqual(a, b) {
    return a === b || this.seqLessThan(a, b);
  }

  seqDiff(a, b) {
    const diff = (a - b) >>> 0;
    return diff > 0x7FFFFFFF ? 0 : diff;
  }

  bumpReverseConnActivity(connKey) {
    const conn = this.reverseTcpConnections.get(connKey);
    if (!conn) return;

    if (conn.idleTimer) {
      clearTimeout(conn.idleTimer);
    }

    conn.idleTimer = setTimeout(() => {
      const stale = this.reverseTcpConnections.get(connKey);
      if (!stale) return;
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`[REVERSE TCP] Idle timeout closing connection ${connKey}`);
      }

      this.abortReverseConnection(
        connKey,
        stale,
        new Error("Reverse TCP connection timed out"),
      );
    }, REVERSE_TCP_IDLE_TIMEOUT_MS);
  }

  clearReverseConnTimer(connKey) {
    const conn = this.reverseTcpConnections.get(connKey);
    if (conn && conn.idleTimer) {
      clearTimeout(conn.idleTimer);
      conn.idleTimer = null;
    }
  }

  maybeSendReverseFin(connKey, conn) {
    if (
      !conn.pendingFin ||
      conn.finSent ||
      conn.sendQueue.length > 0 ||
      conn.retransmission.payloadBytesInFlight >= conn.vmWindow ||
      this.reverseTcpConnections.get(connKey) !== conn
    ) return;

    conn.pendingFin = false;
    conn.finSent = true;
    conn.state = "FIN_WAIT";
    this.sendTrackedTCP(conn, Buffer.alloc(0), { fin: true, ack: true });
  }

  trySendReverseToVM(connKey) {
    const conn = this.reverseTcpConnections.get(connKey);
    if (
      !conn ||
      conn.sending ||
      (
        conn.state !== "ESTABLISHED" &&
        conn.state !== "FIN_WAIT" &&
        conn.state !== "CLOSING"
      )
    ) return;

    conn.sending = true;
    const MSS = 1460;

    const sendNext = () => {
      if (conn.sendQueue.length === 0) {
        conn.sending = false;
        this.maybeSendReverseFin(connKey, conn);
        return;
      }

      if (this.ws.bufferedAmount > 32768) {
        conn.sending = false;
        setTimeout(() => this.trySendReverseToVM(connKey), 20);
        return;
      }

      const inFlightBytes = conn.retransmission.payloadBytesInFlight;
      const available = Math.max(0, conn.vmWindow - inFlightBytes);
      if (available === 0) {
        conn.sending = false;
        return;
      }

      const data = conn.sendQueue[0];
      const toSend = Math.min(MSS, data.length, available);
      if (toSend <= 0) {
        conn.sending = false;
        return;
      }

      const chunk = data.slice(0, toSend);
      this.sendTrackedTCP(conn, chunk, {
        ack: true,
        psh: true,
      });

      if (toSend >= data.length) {
        conn.sendQueue.shift();
      } else {
        conn.sendQueue[0] = data.slice(toSend);
      }

      if (conn.sendQueue.length > 0) {
        setImmediate(sendNext);
      } else {
        conn.sending = false;
        this.maybeSendReverseFin(connKey, conn);
      }
    };

    sendNext();
  }

  maybeSendTCPFin(connKey, conn) {
    if (
      !conn.pendingFin ||
      conn.finSent ||
      conn.sendQueue.length > 0 ||
      conn.retransmission.payloadBytesInFlight >= conn.vmWindow ||
      this.tcpConnections.get(connKey) !== conn
    ) return;

    conn.pendingFin = false;
    conn.finSent = true;
    conn.state = "FIN_WAIT";
    this.sendTrackedTCP(conn, Buffer.alloc(0), { fin: true, ack: true });
  }

  trySendToVM(connKey, info) {
    const conn = this.tcpConnections.get(connKey);
    if (!conn || conn.sending || conn.state === "SYN_SENT") return;

    conn.sending = true;

    const {
      dstPort,
      srcPort,
      dstIP,
      srcIP,
    } = info;
    const MSS = 1460;

    const sendNext = () => {
      if (conn.sendQueue.length === 0) {
        conn.sending = false;
        this.maybeSendTCPFin(connKey, conn);
        return;
      }

      if (this.ws.bufferedAmount > 32768) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `   🚦 WebSocket buffer full (${this.ws.bufferedAmount}), pausing`,
          );
        }
        conn.sending = false;
        setTimeout(() => this.trySendToVM(connKey, info), 20);
        return;
      }

      const inFlightBytes = conn.retransmission.payloadBytesInFlight;
      const available = Math.max(0, conn.vmWindow - inFlightBytes);

      if (available === 0) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   🚫 Window full (${inFlightBytes} in flight)`);
        }
        conn.sending = false;
        return;
      }

      const data = conn.sendQueue[0];
      const toSend = Math.min(MSS, data.length, available);

      if (toSend === 0) {
        conn.sending = false;
        return;
      }

      if (!this.rateLimiter.tryConsume(toSend)) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   ⏳ Rate limit, waiting...`);
        }
        conn.sending = false;
        setTimeout(() => this.trySendToVM(connKey, info), 20);
        return;
      }

      const chunk = data.slice(0, toSend);

      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(
          `    Sending ${chunk.length}B to VM (queue:${conn.sendQueue.length} inflight:${inFlightBytes} window:${conn.vmWindow})`,
        );
      }

      this.sendTrackedTCP(conn, chunk, {
        ack: true,
        psh: true,
      });

      if (toSend >= data.length) {
        conn.sendQueue.shift();
      } else {
        conn.sendQueue[0] = data.slice(toSend);
      }

      if (conn.sendQueue.length > 0 && available > toSend) {
        setImmediate(sendNext);
      } else {
        conn.sending = false;
        this.maybeSendTCPFin(connKey, conn);
      }
    };

    sendNext();
  }

  sendTCP(
    conn,
    payload,
    srcPort,
    dstPort,
    srcIP,
    dstIP,
    flags = {},
    options = {},
  ) {
    const MSS = 1460; // Maximum Segment Size for TCP over Ethernet
    let offset = 0;
    let sequence = options.sequence === undefined
      ? conn.relaySeq
      : options.sequence >>> 0;
    const sentSegments = [];

    // This loop handles TCP segmentation if the payload is larger than the MSS.
    // It also handles zero-length payloads (like pure ACKs).
    while (offset < payload.length || (offset === 0 && payload.length === 0)) {
      const chunk = payload.slice(offset, offset + MSS);
      offset += chunk.length;

      const isLastSegment = offset >= payload.length;

      // The PSH (push) flag should only be set on the final segment of a push.
      const pshFlag = flags.psh && isLastSegment;
      // The FIN flag also only applies to the very last segment of the connection.
      const finFlag = flags.fin && isLastSegment;

      // Create a flags object for this specific segment.
      const segmentFlags = { ...flags, psh: pshFlag, fin: finFlag };

      // The SYN flag should only be on the very first packet of a connection.
      // We can infer this is not the first packet if we're segmenting.
      if (offset > chunk.length) {
        delete segmentFlags.syn;
      }

      const { fin, rst, ack, psh, syn } = segmentFlags;
      const tcpLen = 20 + chunk.length;
      const tcp = Buffer.alloc(tcpLen);

      tcp.writeUInt16BE(srcPort, 0);
      tcp.writeUInt16BE(dstPort, 2);
      tcp.writeUInt32BE(sequence, 4);
      tcp.writeUInt32BE(conn.vmSeq, 8);
      tcp[12] = 0x50; // Data Offset (5 words)
      tcp[13] = (ack ? 0x10 : 0) | (fin ? 0x01 : 0) | (rst ? 0x04 : 0) |
        (psh ? 0x08 : 0) | (syn ? 0x02 : 0);
      tcp.writeUInt16BE(flags.windowSize ?? 65535, 14); // Window Size
      tcp.writeUInt16BE(0, 16); // Checksum (placeholder)
      tcp.writeUInt16BE(0, 18); // Urgent Pointer

      if (chunk.length > 0) {
        chunk.copy(tcp, 20);
      }

      // Increment the sequence number by the size of the chunk for the next segment.
      const seqIncr = chunk.length + (fin ? 1 : 0) + (syn ? 1 : 0);
      if (seqIncr > 0 && !rst) {
        sentSegments.push({
          seq: sequence,
          payload: chunk,
          flags: { ...segmentFlags },
        });
        sequence = (sequence + seqIncr) >>> 0;
        if (options.advanceSequence !== false) {
          conn.relaySeq = sequence;
        }
      }

      const ip = this.buildIP(tcp, srcIP, dstIP, 6);
      const cksum = this.calcTCPChecksum(ip);
      ip.writeUInt16BE(cksum, 20 + 16); // Write checksum in TCP header within IP packet

      this.sendIPToVM(ip);

      // If we sent a zero-length payload (e.g., a pure ACK or SYN), we've done our one and only loop.
      if (payload.length === 0) {
        break;
      }
    }

    return sentSegments;
  }

  buildIP(payload, srcIP, dstIP, protocol) {
    return buildIPv4Packet(payload, srcIP, dstIP, protocol);
  }

  calcTCPChecksum(ipPacket) {
    return tcpChecksum(ipPacket);
  }

  calcUDPChecksum(ipPacket) {
    return udpChecksum(ipPacket);
  }

  handleICMP(ipPacket, parsed = parseIPv4Packet(ipPacket)) {
    if (!parsed || ipPacket.length < parsed.headerLength + 8) return;
    const icmpOffset = parsed.headerLength;
    const icmpType = ipPacket[icmpOffset];
    const { srcIP, dstIP } = parsed;

    if (icmpType === 8 && dstIP === GATEWAY_IP) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`🔍 ICMP ping from ${srcIP}`);
      }

      const reply = Buffer.alloc(ipPacket.length);
      ipPacket.copy(reply);

      Buffer.from(ipPacket.slice(16, 20)).copy(reply, 12);
      Buffer.from(ipPacket.slice(12, 16)).copy(reply, 16);
      reply[icmpOffset] = 0;

      reply.writeUInt16BE(0, icmpOffset + 2);
      const icmpCksum = this.calcChecksum(reply.subarray(icmpOffset));
      reply.writeUInt16BE(icmpCksum, icmpOffset + 2);

      reply.writeUInt16BE(0, 10);
      const ipCksum = this.calcChecksum(reply.subarray(0, parsed.headerLength));
      reply.writeUInt16BE(ipCksum, 10);

      if (log_level >= LOG_LEVEL_DEBUG) console.log(` ICMP reply`);
      this.sendIPToVM(reply);
    }
  }

  handleUDP(ipPacket, parsed = parseIPv4Packet(ipPacket)) {
    const datagram = parseUDPDatagram(ipPacket, parsed);
    if (!datagram) return;
    const { srcPort, dstPort, payload } = datagram;
    const { srcIP, dstIP } = parsed;

    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`📡 UDP: ${srcPort} -> ${dstPort}`);
    }

    // Check if this is a response for a proxied UDP connection
    if (this.udpProxyNatTable.has(dstPort)) {
      const { clientRinfo, ruleId } = this.udpProxyNatTable.get(dstPort);
      const hostSocket = udpProxySockets.get(ruleId);

      if (hostSocket) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(
            `[UDP PROXY NAT] Forwarding reply from VM to ${clientRinfo.address}:${clientRinfo.port}`,
          );
        }
        hostSocket.send(payload, clientRinfo.port, clientRinfo.address);
      }

      // We don't remove the NAT entry here to allow for multiple back-and-forth packets
      // It will be cleaned up by its timeout
      return;
    }

    if (dstPort === 67) {
      this.handleDHCP(payload);
      return;
    }

    // Check if this is a DNS query (port 53)
    if (dstPort === 53) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`🔍 DNS query detected from port ${srcPort}`);
      }
      if (log_level >= LOG_LEVEL_TRACE && payload.length >= 12) {
        // Parse the DNS question name for tracing
        let qdcount = payload.readUInt16BE(4);
        let offset = 12;
        let hostname = "";
        if (qdcount > 0) {
          hostname = this.parseDnsQuestionName(payload, offset);
        }
        console.log(`   🔎 DNS Query for: ${hostname}`);
      }

      const accepted = this.udpFlows.send(payload, {
        vmPort: srcPort,
        vmIP: srcIP,
        remotePort: dstPort,
        remoteIP: dstIP,
        isDNS: true,
      });
      if (!accepted && log_level >= LOG_LEVEL_DEBUG) {
        console.log(`UDP flow limit reached; dropping DNS query`);
      }
      return;
    }

    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`📀 Forwarding UDP to ${dstIP}:${dstPort}`);
    }

    const accepted = this.udpFlows.send(payload, {
      vmPort: srcPort,
      vmIP: srcIP,
      remotePort: dstPort,
      remoteIP: dstIP,
      isDNS: false,
    });
    if (!accepted && log_level >= LOG_LEVEL_DEBUG) {
      console.log(`UDP flow limit reached; dropping packet`);
    }
  }

  filterDNSResponse(dnsPacket) {
    if (dnsPacket.length < 12) return dnsPacket;

    try {
      //const id = dnsPacket.readUInt16BE(0);
      //const flags = dnsPacket.readUInt16BE(2);
      const qdcount = dnsPacket.readUInt16BE(4);
      const ancount = dnsPacket.readUInt16BE(6);
      //const nscount = dnsPacket.readUInt16BE(8);
      //const arcount = dnsPacket.readUInt16BE(10);

      // If there are no answers, don't filter (might be NXDOMAIN or error)
      if (ancount === 0) return dnsPacket;

      let offset = 12;
      const questionStart = offset;

      // Skip question section
      for (let i = 0; i < qdcount; i++) {
        while (offset < dnsPacket.length && dnsPacket[offset] !== 0) {
          const len = dnsPacket[offset];
          if ((len & 0xC0) === 0xC0) {
            offset += 2;
            break;
          }
          offset += len + 1;
        }
        if (offset < dnsPacket.length && dnsPacket[offset] === 0) offset++;
        offset += 4; // QTYPE + QCLASS
      }

      const questionSection = dnsPacket.slice(questionStart, offset);

      // Parse and filter answers
      const keptAnswers = [];
      let newAncount = 0;
      let hasIPv6Only = true;

      for (let i = 0; i < ancount && offset < dnsPacket.length; i++) {
        const recordStart = offset;

        // Skip name (can be compressed)
        while (offset < dnsPacket.length) {
          const len = dnsPacket[offset];
          if (len === 0) {
            offset++;
            break;
          }
          if ((len & 0xC0) === 0xC0) {
            offset += 2;
            break;
          }
          offset += len + 1;
        }

        if (offset + 10 > dnsPacket.length) break;

        const type = dnsPacket.readUInt16BE(offset);
        const rdlength = dnsPacket.readUInt16BE(offset + 8);
        const recordEnd = offset + 10 + rdlength;

        if (recordEnd > dnsPacket.length) break;

        // Keep everything except AAAA (type 28)
        if (type !== 28) {
          keptAnswers.push(dnsPacket.slice(recordStart, recordEnd));
          newAncount++;
          hasIPv6Only = false;
        } else {
          if (log_level >= LOG_LEVEL_DEBUG) {
            console.log(`   🚫 Filtered out IPv6 (AAAA) record`);
          }
        }

        offset = recordEnd;
      }

      // If ALL answers were IPv6, return original to avoid breaking DNS
      // (client will handle lack of IPv4 support)
      if (hasIPv6Only && keptAnswers.length === 0) {
        if (log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   ⚠ Only IPv6 answers, returning original packet`);
        }
        return dnsPacket;
      }

      // Keep authority and additional sections as-is
      const remainingData = dnsPacket.slice(offset);

      // If we filtered anything, rebuild the packet
      if (newAncount < ancount) {
        const newHeader = Buffer.alloc(12);
        dnsPacket.copy(newHeader, 0, 0, 12);
        newHeader.writeUInt16BE(newAncount, 6); // Update answer count

        return Buffer.concat([
          newHeader,
          questionSection,
          ...keptAnswers,
          remainingData,
        ]);
      }

      return dnsPacket;
    } catch (err) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.error(`   ⚠ DNS filtering error: ${err.message}`);
      }
      return dnsPacket; // Return original on error
    }
  }

  parseDnsQuestionName(dnsPacket, offset) {
    let name = "";
    let currentOffset = offset;
    while (currentOffset < dnsPacket.length && dnsPacket[currentOffset] !== 0) {
      const len = dnsPacket[currentOffset];
      if ((len & 0xC0) === 0xC0) { // Pointer
        const pointerOffset = dnsPacket.readUInt16BE(currentOffset) & 0x3FFF;
        name += this.parseDnsQuestionName(dnsPacket, pointerOffset);
        currentOffset += 2;
        break;
      } else {
        name += dnsPacket.toString(
          "ascii",
          currentOffset + 1,
          currentOffset + 1 + len,
        );
        currentOffset += len + 1;
        if (dnsPacket[currentOffset] !== 0) {
          name += ".";
        }
      }
    }
    return name;
  }

  sendUDPToVM(payload, srcPort, dstPort, srcIP, dstIP) {
    const udpLen = 8 + payload.length;
    const udp = Buffer.alloc(udpLen);

    udp.writeUInt16BE(srcPort, 0);
    udp.writeUInt16BE(dstPort, 2);
    udp.writeUInt16BE(udpLen, 4);
    udp.writeUInt16BE(0, 6);
    payload.copy(udp, 8);

    const ip = this.buildIP(udp, srcIP, dstIP, 17);
    const cksum = this.calcUDPChecksum(ip);
    ip.writeUInt16BE(cksum, 20 + 6);

    this.sendIPToVM(ip);
    if (log_level >= LOG_LEVEL_DEBUG) console.log(`  UDP response sent`);
  }

  handleDHCP(udp) {
    if (udp.length < 240) return;

    const xid = udp.readUInt32BE(4);
    const clientMAC = udp.slice(28, 34);
    const clientMACStr = Array.from(clientMAC).map((b) =>
      b.toString(16).padStart(2, "0")
    ).join(":");

    let msgType = 0;
    let off = 240;

    if (udp.readUInt32BE(236) !== 0x63825363) return;

    while (off < udp.length) {
      const opt = udp[off];
      if (opt === 255) break;
      if (opt === 0) {
        off++;
        continue;
      }

      if (off + 1 >= udp.length) return;
      const len = udp[off + 1];
      if (off + 2 + len > udp.length) return;
      if (opt === 53) msgType = udp[off + 2];
      off += 2 + len;
    }

    // Get or allocate IP for this MAC
    let assignedIP;
    try {
      assignedIP = allocateIP(clientMACStr);
      if (!this.vmIP) {
        this.vmIP = assignedIP;
        ipToSession.set(this.vmIP, this);
      }
    } catch (err) {
      console.error(`❌ ${err.message}`);
      return;
    }

    if (msgType === 1) {
      console.log(`🌐 DHCP DISCOVER from ${clientMACStr}`);
      this.sendDHCP(xid, clientMAC, 2, assignedIP);
      console.log(`   DHCP OFFER: ${assignedIP}`);
    } else if (msgType === 3) {
      console.log(`🌐 DHCP REQUEST from ${clientMACStr}`);
      this.sendDHCP(xid, clientMAC, 5, assignedIP);
      console.log(`✅ DHCP ACK: ${assignedIP}`);
    }
  }

  sendDHCP(xid, clientMAC, msgType, assignedIP) {
    const dhcp = Buffer.alloc(300);
    dhcp[0] = 2;
    dhcp[1] = 1;
    dhcp[2] = 6;
    dhcp[3] = 0;
    dhcp.writeUInt32BE(xid, 4);
    dhcp.writeUInt16BE(0, 8);
    dhcp.writeUInt16BE(0, 10);
    dhcp.fill(0, 12, 16);
    Buffer.from(assignedIP.split(".").map(Number)).copy(dhcp, 16);
    Buffer.from(GATEWAY_IP.split(".").map(Number)).copy(dhcp, 20);
    Buffer.from(GATEWAY_IP.split(".").map(Number)).copy(dhcp, 24);
    clientMAC.copy(dhcp, 28);
    dhcp.writeUInt32BE(0x63825363, 236);

    let off = 240;
    dhcp[off++] = 53;
    dhcp[off++] = 1;
    dhcp[off++] = msgType;
    dhcp[off++] = 54;
    dhcp[off++] = 4;
    Buffer.from(GATEWAY_IP.split(".").map(Number)).copy(dhcp, off);
    off += 4;
    dhcp[off++] = 51;
    dhcp[off++] = 4;
    dhcp.writeUInt32BE(3600, off);
    off += 4;
    dhcp[off++] = 1;
    dhcp[off++] = 4;
    Buffer.from([255, 255, 255, 0]).copy(dhcp, off);
    off += 4;
    dhcp[off++] = 3;
    dhcp[off++] = 4;
    Buffer.from(GATEWAY_IP.split(".").map(Number)).copy(dhcp, off);
    off += 4;
    dhcp[off++] = 6;
    dhcp[off++] = 4;
    Buffer.from(DNS_SERVER_IP.split(".").map(Number)).copy(dhcp, off);
    off += 4;
    dhcp[off++] = 255;

    const udpLen = 8 + off;
    const udp = Buffer.alloc(udpLen);
    udp.writeUInt16BE(67, 0);
    udp.writeUInt16BE(68, 2);
    udp.writeUInt16BE(udpLen, 4);
    udp.writeUInt16BE(0, 6);
    dhcp.slice(0, off).copy(udp, 8);

    const ip = this.buildIP(udp, GATEWAY_IP, "255.255.255.255", 17);
    this.sendIPToVM(ip);
  }

  sendIPToVM(ipPacket, callback) {
    this.bytesSent += ipPacket.length;
    const frame = Buffer.alloc(14 + ipPacket.length);

    if (this.vmMAC) {
      const macBytes = this.vmMAC.split(":").map((hex) => parseInt(hex, 16));
      Buffer.from(macBytes).copy(frame, 0);
    } else {
      frame.fill(0xff, 0, 6);
    }

    Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).copy(frame, 6);

    frame.writeUInt16BE(0x0800, 12);

    ipPacket.copy(frame, 14);

    this.sendToVM(frame, callback);
  }

  sendToVM(data, callback) {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(data, {
        binary: true,
      }, (err) => {
        if (err && log_level >= LOG_LEVEL_DEBUG) {
          console.log(`   ❌ Error sending to VM: ${err.message}`);
        }
        if (callback) callback(err);
      });
    } else {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`   ❌ WebSocket not open (state: ${this.ws.readyState})`);
      }
      if (callback) callback(new Error("WebSocket not open"));
    }
  }

  calcChecksum(data) {
    return internetChecksum(data);
  }

  close() {
    // Release IP when session closes
    if (this.vmMAC) {
      releaseIP(this.vmMAC);
    }

    this.udpFlows.close();

    /*
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    */

    for (const [key, conn] of this.tcpConnections) {
      conn.retransmission?.close();
      if (conn.socket) {
        conn.socket.destroy();
      }
    }
    this.tcpConnections.clear();

    for (const [key, conn] of this.reverseTcpConnections) {
      conn.retransmission?.close();
      if (conn.idleTimer) {
        clearTimeout(conn.idleTimer);
      }
      conn.upstream.destroy();
      conn.downstream.destroy();
      conn.onError?.(new Error("VM session closed"));
    }
    this.reverseTcpConnections.clear();
  }
}

wss.on("connection", (ws, req) => {
  const clientIP = req.socket.remoteAddress;
  try {
    if (ws._socket && typeof ws._socket.setNoDelay === "function") {
      ws._socket.setNoDelay(true);
      ws._socket.setKeepAlive(true, 30000);
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(`🚀 WS transport tuned: TCP_NODELAY + keepalive for ${clientIP}`);
      }
    }
  } catch (e) {
    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`⚠️ Failed to tune WS transport socket: ${e.message}`);
    }
  }

  const currentConnections = connectionsPerIP.get(clientIP) || 0;
  if (currentConnections >= MAX_CONNECTIONS_PER_IP) {
    console.log(`⛔ Connection limit reached for ${clientIP}`);
    ws.close(1008, "Connection limit reached");
    return;
  }

  connectionsPerIP.set(clientIP, currentConnections + 1);
  console.log(`✅ New connection from ${clientIP}`);

  const session = new VMSession(ws, clientIP);
  const sessionId = crypto.randomUUID();
  activeSessions.set(sessionId, session);

  ws.on("message", (data, isBinary) => {
    if (!isBinary) {
      const str = data.toString();
      if (str.startsWith("ping:")) {
        ws.send("pong:" + str.substring(5));
      }
      return;
    }

    session.handleEthernetFrame(data);
  });

  ws.on("close", () => {
    const currentConnections = connectionsPerIP.get(clientIP) || 0;
    connectionsPerIP.set(clientIP, Math.max(0, currentConnections - 1));
    console.log(`❌ Connection closed from ${clientIP}`);

    session.close();
    activeSessions.delete(sessionId);
  });

  ws.on("error", (err) => {
    console.error("⚠️ WebSocket error:", err.message);
  });
});

console.log(
  `💡 VMs will be assigned IPs from 10.0.2.${DHCP_START} to 10.0.2.${DHCP_END}`,
);
console.log(`💡 Gateway: ${GATEWAY_IP}`);
console.log(`💡 DNS: ${DNS_SERVER_IP}`);
if (ENABLE_VM_TO_VM) {
  console.log(`💡 VMs can communicate with each other on the same network`);
} else {
  console.log(
    `💡 VMs are isolated - they can only access the internet, not each other`,
  );
}

const http = require("http");
const fs = require("fs");
const path = require("path");

// Admin server
let nextRuleId = 1;
const proxyRules = [];
let nextProxyPort = 30000;
const runningTcpProxies = new Map();
const runningUdpProxies = new Map();
const udpProxySockets = new Map();

function stopTcpForward(ruleId) {
  if (runningTcpProxies.has(ruleId)) {
    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`[TCP PROXY] Stopping proxy for rule ${ruleId}`);
    }
    const server = runningTcpProxies.get(ruleId);
    server.close();
    runningTcpProxies.delete(ruleId);
  }
}

function stopUdpForward(ruleId) {
  if (runningUdpProxies.has(ruleId)) {
    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`[UDP PROXY] Stopping proxy for rule ${ruleId}`);
    }
    const server = runningUdpProxies.get(ruleId);
    server.close();
    runningUdpProxies.delete(ruleId);
    udpProxySockets.delete(ruleId);
  }
}

function startPortForward(rule) {
  if (rule.protocols.includes("tcp")) {
    startTcpForward(rule);
  }
  if (rule.protocols.includes("udp")) {
    startUdpForward(rule);
  }
}

function stopPortForward(rule) {
  if (rule.protocols.includes("tcp")) {
    stopTcpForward(rule.id);
  }
  if (rule.protocols.includes("udp")) {
    stopUdpForward(rule.id);
  }
}

async function startTcpForward(rule) {
  if (runningTcpProxies.has(rule.id)) {
    console.log(`[TCP PROXY] Proxy for rule ${rule.id} already running.`);
    return;
  }

  if (log_level >= LOG_LEVEL_DEBUG) {
    console.log(
      `[TCP PROXY] Starting proxy for rule ${rule.id}: host port ${rule.host_port} -> ${rule.vm}:${rule.port}`,
    );
  }

  const bindAddress = rule.bind_address || '0.0.0.0';
  const server = net.createServer(async (localSocket) => {
    // Disable Nagle's algorithm for this socket.
    // This is crucial for responsive interactive sessions like SSH,
    // preventing delays by sending small packets immediately.
    localSocket.setNoDelay(true);

    const targetSession = ipToSession.get(rule.vm);
    if (!targetSession) {
      console.log(
        `[TCP PROXY] VM ${rule.vm} not connected for incoming connection on ${bindAddress}:${rule.host_port}`,
      );
      localSocket.end();
      return;
    }

    console.log(
      `[TCP PROXY] Incoming connection on ${bindAddress}:${rule.host_port}, connecting to VM ${rule.vm}:${rule.port}`,
    );

    try {
      const {
        upstream,
        downstream,
        connKey,
      } = await targetSession
        .createTCPConnection(rule.port);
      console.log(
        `[TCP PROXY] Connection to VM established (key: ${connKey}). Piping data.`,
      );

      // Pipe data between the local client and the VM
      localSocket.pipe(upstream);
      downstream.pipe(localSocket);

      localSocket.on("close", () => {
        console.log(
          `[TCP PROXY] Local client disconnected from ${bindAddress}:${rule.host_port}`,
        );
        downstream.unpipe(localSocket);
        const conn = targetSession.reverseTcpConnections.get(connKey);
        if (conn) {
          conn.localClosed = true;
          conn.pendingFin = true;
          targetSession.trySendReverseToVM(connKey);
        }
      });

      localSocket.on("error", (err) => {
        console.error(`[TCP PROXY] Local client socket error: ${err.message}`);
        const conn = targetSession.reverseTcpConnections.get(connKey);
        if (conn) targetSession.abortReverseConnection(connKey, conn, err);
      });

      downstream.on("error", (err) => {
        console.error(`[TCP PROXY] VM downstream error: ${err.message}`);
        localSocket.destroy();
      });

      upstream.on("error", (err) => {
        console.error(`[TCP PROXY] VM upstream error: ${err.message}`);
        localSocket.destroy();
      });
    } catch (err) {
      console.error(
        `[TCP PROXY] Failed to create TCP connection to VM: ${err.message}`,
      );
      localSocket.end();
    }
  });

  server.listen(rule.host_port, bindAddress, () => {
    console.log(`[TCP PROXY] Server listening on ${bindAddress}:${rule.host_port}`);
    runningTcpProxies.set(rule.id, server);
  });

  server.on("error", (err) => {
    console.error(
      `[TCP PROXY] Server error on port ${rule.host_port}: ${err.message}`,
    );
  });
}

async function startUdpForward(rule) {
  if (runningUdpProxies.has(rule.id)) {
    console.log(`[UDP PROXY] Proxy for rule ${rule.id} already running.`);
    return;
  }

  if (log_level >= LOG_LEVEL_DEBUG) {
    console.log(
      `[UDP PROXY] Starting proxy for rule ${rule.id}: host port ${rule.host_port} -> ${rule.vm}:${rule.port}`,
    );
  }

  const hostSocket = dgram.createSocket("udp4");

  hostSocket.on("error", (err) => {
    console.error(
      `[UDP PROXY] Server error on port ${rule.host_port}: ${err.message}`,
    );
    hostSocket.close();
    stopUdpForward(rule.id);
  });

  hostSocket.on("message", (msg, rinfo) => {
    const targetSession = ipToSession.get(rule.vm);
    if (!targetSession) {
      if (log_level >= LOG_LEVEL_DEBUG) {
        console.log(
          `[UDP PROXY] VM ${rule.vm} not connected for incoming packet on port ${rule.host_port}`,
        );
      }
      return;
    }

    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(
        `[UDP PROXY] Incoming packet on port ${rule.host_port} from ${rinfo.address}:${rinfo.port}, forwarding to VM ${rule.vm}:${rule.port}`,
      );
    }
    targetSession.forwardUdpPacket(msg, rule.port, rinfo, rule.id);
  });

  const bindAddress = rule.bind_address || '0.0.0.0';
  hostSocket.bind(rule.host_port, bindAddress, () => {
    console.log(
      `[UDP PROXY] Server listening on ${bindAddress}:${rule.host_port}`,
    );
    runningUdpProxies.set(rule.id, hostSocket);
    udpProxySockets.set(rule.id, hostSocket);
  });
}

const adminServer = http.createServer((req, res) => {
  if (req.url === "/") {
    fs.readFile("admin.html", (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end("Error loading admin.html");
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/html",
      });
      res.end(data);
    });
  } else if (req.url === "/api/sessions") {
    const sessions = [];
    activeSessions.forEach((session, sessionId) => {
      sessions.push({
        sessionId,
        clientIP: session.clientIP,
        vmIP: session.vmIP,
        vmMAC: session.vmMAC,
        bytesSent: session.bytesSent,
        bytesReceived: session.bytesReceived,
        udpFlowCount: session.udpFlows.size,
        udpDroppedPackets: session.udpFlows.droppedPackets,
        udpSendErrors: session.udpFlows.sendErrors,
        nickname: session.nickname,
      });
    });
    res.writeHead(200, {
      "Content-Type": "application/json",
    });
    res.end(JSON.stringify(sessions));
  } else if (
    req.url.match(/\/api\/sessions\/(.+)\/nickname/) && req.method === "POST"
  ) {
    const sessionId = req.url.match(/\/api\/sessions\/(.+)\/nickname/)[1];
    const session = activeSessions.get(sessionId);
    if (session) {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        const { nickname } = JSON.parse(body);
        session.nickname = nickname;
        res.writeHead(200);
        res.end();
      });
    } else {
      res.writeHead(404);
      res.end();
    }
  } else if (req.url === "/api/rules" && req.method === "GET") {
    res.writeHead(200, {
      "Content-Type": "application/json",
    });
    res.end(JSON.stringify(proxyRules));
  } else if (req.url === "/api/rules" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      const rule = JSON.parse(body);
      rule.id = nextRuleId++;
      proxyRules.push(rule);
      if (rule.type === "port") {
        startPortForward(rule);
      }
      res.writeHead(201);
      res.end();
    });
  } else if (req.url.startsWith("/api/rules/") && req.method === "DELETE") {
    const id = parseInt(req.url.split("/")[3]);
    const index = proxyRules.findIndex((rule) => rule.id === id);
    if (index !== -1) {
      const rule = proxyRules[index];
      if (rule.type === "port") {
        stopPortForward(rule);
      } else {
        // Legacy support for old tcp/udp rules
        stopTcpForward(rule.id);
        stopUdpForward(rule.id);
      }
      proxyRules.splice(index, 1);
      res.writeHead(204);
      res.end();
    } else {
      res.writeHead(404);
      res.end();
    }
  } else {
    res.writeHead(404);
    res.end();
  }
});

adminServer.listen(ADMIN_PORT, ADMIN_BIND_ADDRESS, () => {
  console.log(`💡 Admin UI listening on http://${ADMIN_BIND_ADDRESS}:${ADMIN_PORT}`);
});

function findProxyRule(req) {
  const host = req.headers.host;
  const urlPath = req.url;

  let bestMatch = null;
  let bestMatchScore = -1;

  for (const rule of proxyRules) {
    if (rule.type !== "http") continue;

    const vhostMatches = !rule.vhost || rule.vhost === host;
    const pathMatches = urlPath.startsWith(rule.path);

    if (vhostMatches && pathMatches) {
      let score = 0;
      if (rule.vhost) score += 1000; // vhost match is much better
      score += rule.path.length; // longer path is better

      if (score > bestMatchScore) {
        bestMatch = rule;
        bestMatchScore = score;
      }
    }
  }

  return bestMatch;
}

async function proxyRequest(req, res, rule) {
  console.log(
    `[PROXY] Request: ${req.method} ${req.url} -> ${rule.vm}:${rule.port}`,
  );

  const targetSession = ipToSession.get(rule.vm);
  if (!targetSession) {
    res.writeHead(502, {
      "Content-Type": "text/plain",
    });
    res.end("Bad Gateway: VM not connected");
    return;
  }

  try {
    console.log(`[PROXY] Creating TCP connection to ${rule.vm}:${rule.port}`);
    const {
      upstream,
      downstream,
      connKey,
    } = await targetSession
      .createTCPConnection(rule.port);
    console.log(`[PROXY] TCP connection established with key ${connKey}`);
    const clientSocket = res.socket;
    let finished = false;
    let receivedAny = false;
    let responseTimeout = null;

    let url = req.url;
    if (rule.targetPath) {
      const remainingPath = req.url.substring(rule.path.length);
      url = path.join(rule.targetPath, remainingPath);
    }

    const headers = [`${req.method} ${url} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (
        req.rawHeaders[i].toLowerCase() !== "host" &&
        req.rawHeaders[i].toLowerCase() !== "connection"
      ) {
        headers.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
      }
    }
    headers.push(`Host: ${rule.vm}:${rule.port}`);
    headers.push(`Connection: close`);
    headers.push(""); // Empty line to end headers
    headers.push(""); // This creates \r\n\r\n when joined

    const requestData = headers.join("\r\n");
    if (log_level >= LOG_LEVEL_DEBUG) {
      console.log(`[PROXY] Forwarding request headers (${requestData.length} bytes)`);
    }

    const cleanup = () => {
      if (finished) return;
      finished = true;
      if (responseTimeout) clearTimeout(responseTimeout);
      const conn = targetSession.reverseTcpConnections.get(connKey);
      if (conn) {
        targetSession.abortReverseConnection(
          connKey,
          conn,
          new Error("HTTP proxy request completed"),
        );
      }
      upstream.destroy();
      downstream.destroy();
    };

    const resetTimeout = () => {
      if (responseTimeout) clearTimeout(responseTimeout);
      responseTimeout = setTimeout(() => {
        console.log(`[PROXY] ⏰ Response timeout on ${connKey}`);
        if (!receivedAny && !res.headersSent) {
          res.writeHead(504, { "Content-Type": "text/plain" });
          res.end("Gateway Timeout");
        } else if (clientSocket && !clientSocket.destroyed) {
          clientSocket.end();
        }
        cleanup();
      }, 10000);
    };

    resetTimeout();

    const sent = upstream.write(requestData);
    if (!sent) {
      await new Promise((resolve) => upstream.once("drain", resolve));
    }
    req.pipe(upstream);

    req.on("aborted", () => {
      console.log(`[PROXY] Client aborted request`);
      cleanup();
    });

    res.on("close", () => {
      if (!finished) {
        cleanup();
      }
    });

    upstream.on("error", (err) => {
      console.error("[PROXY] Upstream error:", err);
      if (!finished && !res.headersSent) {
        res.writeHead(502, {
          "Content-Type": "text/plain",
        });
        res.end("Bad Gateway");
      }
      cleanup();
    });

    downstream.on("data", (chunk) => {
      receivedAny = true;
      resetTimeout();
      if (clientSocket && !clientSocket.destroyed) {
        clientSocket.write(chunk);
      }
    });

    downstream.on("end", () => {
      if (responseTimeout) clearTimeout(responseTimeout);
      if (!receivedAny && !res.headersSent) {
        res.writeHead(502, {
          "Content-Type": "text/plain",
        });
        res.end("Bad Gateway: No response from VM");
      } else if (clientSocket && !clientSocket.destroyed) {
        clientSocket.end();
      }
      cleanup();
    });

    downstream.on("error", (err) => {
      console.error("[PROXY] Downstream error:", err);
      if (!finished && !res.headersSent) {
        res.writeHead(502, {
          "Content-Type": "text/plain",
        });
        res.end("Bad Gateway");
      }
      cleanup();
    });
  } catch (err) {
    console.error("[PROXY] Error creating TCP connection:", err);
    res.writeHead(502, {
      "Content-Type": "text/plain",
    });
    res.end("Bad Gateway: Could not connect to VM");
  }
}

const proxyServer = http.createServer((req, res) => {
  const rule = findProxyRule(req);
  if (rule) {
    proxyRequest(req, res, rule);
  } else {
    res.writeHead(404, {
      "Content-Type": "text/plain",
    });
    res.end("No proxy rule found.");
  }
});

proxyServer.on("upgrade", async (req, socket, head) => {
  const rule = findProxyRule(req);
  if (!rule) {
    socket.end("HTTP/1.1 404 Not Found\r\n\r\n");
    return;
  }

  const targetSession = ipToSession.get(rule.vm);
  if (!targetSession) {
    socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    return;
  }

  try {
    const {
      upstream,
      downstream,
      connKey,
    } = await targetSession.createTCPConnection(rule.port);

    let url = req.url;
    if (rule.targetPath) {
      const remainingPath = req.url.substring(rule.path.length);
      url = path.join(rule.targetPath, remainingPath);
    }

    const headers = [`${req.method} ${url} HTTP/${req.httpVersion}`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() !== "host") {
        headers.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
      }
    }
    headers.push(`Host: ${rule.vm}:${rule.port}`);
    headers.push("");
    headers.push("");

    const requestData = headers.join("\r\n");
    const sent = upstream.write(requestData);
    if (!sent) {
      await new Promise((resolve) => upstream.once("drain", resolve));
    }
    if (head && head.length > 0) {
      upstream.write(head);
    }

    socket.pipe(upstream);
    downstream.pipe(socket);

    let closed = false;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      const conn = targetSession.reverseTcpConnections.get(connKey);
      if (conn) {
        targetSession.abortReverseConnection(
          connKey,
          conn,
          new Error("Upgrade proxy connection closed"),
        );
      }
      upstream.destroy();
      downstream.destroy();
      socket.destroy();
    };

    socket.on("close", cleanup);
    socket.on("error", cleanup);
    upstream.on("error", cleanup);
    downstream.on("error", cleanup);
  } catch (err) {
    console.error("[PROXY] Upgrade error:", err);
    if (!socket.destroyed) {
      socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    }
  }
});

proxyServer.listen(PROXY_PORT, PROXY_BIND_ADDRESS, () => {
  console.log(
    `💡 Proxy server listening on http://${PROXY_BIND_ADDRESS}:${PROXY_PORT}`,
  );
});
