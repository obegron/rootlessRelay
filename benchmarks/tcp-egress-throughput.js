#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const net = require("node:net");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const WebSocket = require("ws");
const {
  buildIPv4Packet,
  parseIPv4Packet,
  tcpChecksum,
} = require("../packet_utils");
const { parseTCPOptions } = require("../tcp_utils");

const ROOT = path.resolve(__dirname, "..");
const NODE_MODULES = path.dirname(path.dirname(require.resolve("ws")));
const VM_IP = "10.0.2.15";
const REMOTE_IP = "127.0.0.1";
const VM_MAC = Buffer.from([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
const GATEWAY_MAC = Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const DEFAULT_WINDOWS = [10240, 65535];
const DEFAULT_SEND_BURST_SEGMENTS = 3;
const DEFAULT_SEND_BURST_MAX_SEGMENTS = 8;
const DEFAULT_SEND_BURST_INTERVAL_MS = 6;
const DEFAULT_INITIAL_CWND_BYTES = 10240;
const DEFAULT_TCP_MSS = 1460;
const DEFAULT_SOURCE_BYTES = 32 * 1024 * 1024;
const SOURCE_CHUNK_BYTES = 64 * 1024;
const EXPECTED_PAYLOAD = Buffer.alloc(SOURCE_CHUNK_BYTES, 0xa5);

function hasExpectedPayload(payload) {
  for (let offset = 0; offset < payload.length; offset += EXPECTED_PAYLOAD.length) {
    const length = Math.min(EXPECTED_PAYLOAD.length, payload.length - offset);
    if (!payload.subarray(offset, offset + length).equals(
      EXPECTED_PAYLOAD.subarray(0, length),
    )) return false;
  }
  return true;
}

function parseInteger(value, option, { minimum = 1, maximum = Infinity } = {}) {
  const parsed = Number(value);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < minimum ||
    parsed > maximum
  ) {
    const range = maximum === Infinity
      ? `at least ${minimum}`
      : `from ${minimum} through ${maximum}`;
    throw new TypeError(`${option} must be an integer ${range}`);
  }
  return parsed;
}

function parseArgs(args) {
  let sendBurstMaxSpecified = false;
  const options = {
    durationMs: 3000,
    ackDelayMs: 20,
    ackEvery: 2,
    rxQueuePackets: 8,
    rxServiceMs: 5,
    pacingMode: "adaptive",
    sendBurstSegments: DEFAULT_SEND_BURST_SEGMENTS,
    sendBurstMaxSegments: DEFAULT_SEND_BURST_MAX_SEGMENTS,
    sendBurstIntervalMs: DEFAULT_SEND_BURST_INTERVAL_MS,
    initialCwndBytes: DEFAULT_INITIAL_CWND_BYTES,
    tcpMss: DEFAULT_TCP_MSS,
    sourceBytes: DEFAULT_SOURCE_BYTES,
    windows: DEFAULT_WINDOWS,
    relayRoot: ROOT,
    relayRuntime: process.execPath,
    json: false,
  };

  for (const arg of args) {
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--help") {
      options.help = true;
    } else if (arg.startsWith("--duration-ms=")) {
      options.durationMs = parseInteger(
        arg.split("=")[1],
        "--duration-ms",
      );
    } else if (arg.startsWith("--ack-delay-ms=")) {
      options.ackDelayMs = parseInteger(
        arg.split("=")[1],
        "--ack-delay-ms",
        { minimum: 0 },
      );
    } else if (arg.startsWith("--ack-every=")) {
      options.ackEvery = parseInteger(arg.split("=")[1], "--ack-every");
    } else if (arg.startsWith("--rx-queue-packets=")) {
      options.rxQueuePackets = parseInteger(
        arg.split("=")[1],
        "--rx-queue-packets",
        { minimum: 0 },
      );
    } else if (arg.startsWith("--rx-service-ms=")) {
      options.rxServiceMs = parseInteger(
        arg.split("=")[1],
        "--rx-service-ms",
        { minimum: 0 },
      );
    } else if (arg.startsWith("--send-burst-segments=")) {
      options.sendBurstSegments = parseInteger(
        arg.split("=")[1],
        "--send-burst-segments",
      );
    } else if (arg.startsWith("--send-burst-max-segments=")) {
      sendBurstMaxSpecified = true;
      options.sendBurstMaxSegments = parseInteger(
        arg.split("=")[1],
        "--send-burst-max-segments",
      );
    } else if (arg.startsWith("--pacing-mode=")) {
      options.pacingMode = arg.split("=")[1];
      if (!["adaptive", "fixed", "off"].includes(options.pacingMode)) {
        throw new TypeError("--pacing-mode must be adaptive, fixed, or off");
      }
    } else if (arg.startsWith("--send-burst-interval-ms=")) {
      options.sendBurstIntervalMs = parseInteger(
        arg.split("=")[1],
        "--send-burst-interval-ms",
        { minimum: 0 },
      );
    } else if (arg.startsWith("--initial-cwnd-bytes=")) {
      options.initialCwndBytes = parseInteger(
        arg.split("=")[1],
        "--initial-cwnd-bytes",
        { minimum: 1460, maximum: 65535 },
      );
    } else if (arg.startsWith("--tcp-mss=")) {
      options.tcpMss = parseInteger(
        arg.split("=")[1],
        "--tcp-mss",
        { minimum: 536, maximum: 65495 },
      );
    } else if (arg.startsWith("--source-bytes=")) {
      options.sourceBytes = parseInteger(
        arg.split("=")[1],
        "--source-bytes",
        { minimum: SOURCE_CHUNK_BYTES },
      );
    } else if (arg.startsWith("--windows=")) {
      options.windows = arg.split("=")[1].split(",").map((value) =>
        parseInteger(value, "--windows", { minimum: 1, maximum: 65535 })
      );
      if (options.windows.length === 0) {
        throw new TypeError("--windows must contain at least one value");
      }
    } else if (arg.startsWith("--relay-root=")) {
      const relayRoot = arg.slice("--relay-root=".length);
      if (relayRoot.length === 0) {
        throw new TypeError("--relay-root must not be empty");
      }
      options.relayRoot = path.resolve(relayRoot);
    } else if (arg.startsWith("--relay-runtime=")) {
      const relayRuntime = arg.slice("--relay-runtime=".length);
      if (relayRuntime.length === 0) {
        throw new TypeError("--relay-runtime must not be empty");
      }
      options.relayRuntime = relayRuntime;
    } else {
      throw new TypeError(`Unknown option: ${arg}`);
    }
  }

  if (!sendBurstMaxSpecified) {
    options.sendBurstMaxSegments = Math.max(
      DEFAULT_SEND_BURST_MAX_SEGMENTS,
      options.sendBurstSegments,
    );
  }
  if (options.sendBurstMaxSegments < options.sendBurstSegments) {
    throw new TypeError(
      "--send-burst-max-segments must be at least --send-burst-segments",
    );
  }

  return options;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freeTcpPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function buildTCPFrame({
  srcIP,
  dstIP,
  srcPort,
  dstPort,
  seq,
  ack = 0,
  window = 65535,
  flags = {},
  payload = Buffer.alloc(0),
  mss,
}) {
  const options = flags.syn && mss
    ? Buffer.from([2, 4, mss >>> 8, mss & 0xff])
    : Buffer.alloc(0);
  const headerLength = 20 + options.length;
  const tcp = Buffer.alloc(headerLength + payload.length);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = (headerLength / 4) << 4;
  tcp[13] = (flags.fin ? 0x01 : 0) |
    (flags.syn ? 0x02 : 0) |
    (flags.rst ? 0x04 : 0) |
    (flags.psh ? 0x08 : 0) |
    (flags.ack ? 0x10 : 0);
  tcp.writeUInt16BE(window, 14);
  options.copy(tcp, 20);
  payload.copy(tcp, headerLength);

  const ip = buildIPv4Packet(tcp, srcIP, dstIP, 6, 1);
  ip.writeUInt16BE(tcpChecksum(ip), 36);
  const frame = Buffer.alloc(14 + ip.length);
  GATEWAY_MAC.copy(frame, 0);
  VM_MAC.copy(frame, 6);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);
  return frame;
}

function parseTCPFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 54) return null;
  if (frame.readUInt16BE(12) !== 0x0800) return null;
  const parsed = parseIPv4Packet(frame.subarray(14));
  if (!parsed || parsed.protocol !== 6) return null;

  const offset = parsed.headerLength;
  if (parsed.packet.length < offset + 20) return null;
  const dataOffset = (parsed.packet[offset + 12] >>> 4) * 4;
  if (dataOffset < 20 || parsed.packet.length < offset + dataOffset) return null;
  const flags = parsed.packet[offset + 13];
  const tcpOptions = dataOffset > 20
    ? parseTCPOptions(parsed.packet, offset + 20, offset + dataOffset)
    : {};
  return {
    srcIP: parsed.srcIP,
    dstIP: parsed.dstIP,
    srcPort: parsed.packet.readUInt16BE(offset),
    dstPort: parsed.packet.readUInt16BE(offset + 2),
    seq: parsed.packet.readUInt32BE(offset + 4),
    ack: parsed.packet.readUInt32BE(offset + 8),
    window: parsed.packet.readUInt16BE(offset + 14),
    syn: (flags & 0x02) !== 0,
    ackFlag: (flags & 0x10) !== 0,
    fin: (flags & 0x01) !== 0,
    rst: (flags & 0x04) !== 0,
    mss: tcpOptions.mss,
    payload: parsed.packet.subarray(offset + dataOffset),
  };
}

function seqBefore(a, b) {
  const distance = (a - b) >>> 0;
  return distance > 0x7fffffff;
}

class FakeVM {
  constructor(ws, {
    ackDelayMs,
    ackEvery,
    rxQueuePackets,
    rxServiceMs,
    tcpMss,
  }) {
    this.ws = ws;
    this.ackDelayMs = ackDelayMs;
    this.ackEvery = ackEvery;
    this.rxQueuePackets = rxQueuePackets;
    this.rxServiceMs = rxServiceMs;
    this.tcpMss = tcpMss;
    this.vmPort = 41000;
    this.vmSeq = 1001;
    this.remotePort = null;
    this.expectedRelaySeq = null;
    this.lastAckSent = null;
    this.established = false;
    this.synAck = null;
    this.synAckWaiters = [];
    this.ingressQueue = [];
    this.ingressTimer = null;
    this.pendingAckCount = 0;
    this.pendingAckNumber = null;
    this.pendingAckDueAt = null;
    this.pendingAckTimer = null;
    this.ackTimers = new Set();
    this.outOfOrder = new Map();
    this.seenSegments = new Set();
    this.deliveredBytes = 0;
    this.receivedDataSegments = 0;
    this.droppedDataSegments = 0;
    this.retransmittedSegments = 0;
    this.outOfOrderSegments = 0;
    this.invalidPayloadSegments = 0;
    this.ackPackets = 0;
    this.maxDataSegmentBytes = 0;

    ws.on("message", (data, isBinary) => {
      if (!isBinary) return;
      const frame = parseTCPFrame(data);
      if (!frame || frame.dstPort !== this.vmPort) return;
      this.handleFrame(frame, performance.now());
    });
  }

  waitForSynAck(timeoutMs = 2000) {
    if (this.synAck) return Promise.resolve(this.synAck);
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject };
      this.synAckWaiters.push(waiter);
      waiter.timer = setTimeout(() => {
        const index = this.synAckWaiters.indexOf(waiter);
        if (index !== -1) this.synAckWaiters.splice(index, 1);
        reject(new Error("Timed out waiting for relay SYN-ACK"));
      }, timeoutMs);
    });
  }

  handleFrame(frame, receivedAt) {
    if (frame.syn && frame.ackFlag) {
      if (!this.synAck) {
        this.synAck = frame;
        for (const waiter of this.synAckWaiters.splice(0)) {
          clearTimeout(waiter.timer);
          waiter.resolve(frame);
        }
      }
      return;
    }
    if (!this.established || frame.payload.length === 0) return;

    this.receivedDataSegments++;
    this.maxDataSegmentBytes = Math.max(
      this.maxDataSegmentBytes,
      frame.payload.length,
    );
    const key = `${frame.seq}:${frame.payload.length}`;
    if (this.seenSegments.has(key)) this.retransmittedSegments++;
    else this.seenSegments.add(key);

    if (
      this.rxQueuePackets > 0 &&
      this.ingressQueue.length >= this.rxQueuePackets
    ) {
      this.droppedDataSegments++;
      return;
    }

    this.ingressQueue.push({ frame, receivedAt });
    this.scheduleIngressService();
  }

  scheduleIngressService() {
    if (this.ingressTimer !== null) return;
    if (this.rxServiceMs === 0) {
      this.serviceIngress();
      return;
    }
    this.ingressTimer = setTimeout(() => {
      this.ingressTimer = null;
      this.serviceIngress();
    }, this.rxServiceMs);
  }

  serviceIngress() {
    const entries = this.ingressQueue.splice(0);
    for (const entry of entries) this.processSegment(entry);
    if (this.ingressQueue.length > 0) this.scheduleIngressService();
  }

  processSegment({ frame, receivedAt }) {
    if (!hasExpectedPayload(frame.payload)) {
      this.invalidPayloadSegments++;
    }

    if (frame.seq === this.expectedRelaySeq) {
      this.deliveredBytes += frame.payload.length;
      this.expectedRelaySeq = (
        this.expectedRelaySeq + frame.payload.length
      ) >>> 0;
      while (this.outOfOrder.has(this.expectedRelaySeq)) {
        const buffered = this.outOfOrder.get(this.expectedRelaySeq);
        this.outOfOrder.delete(this.expectedRelaySeq);
        this.deliveredBytes += buffered.length;
        this.expectedRelaySeq = (
          this.expectedRelaySeq + buffered.length
        ) >>> 0;
      }
      this.noteInOrderAck(receivedAt);
      return;
    }

    if (seqBefore(frame.seq, this.expectedRelaySeq)) {
      this.scheduleAck(this.expectedRelaySeq, receivedAt, true);
      return;
    }

    this.outOfOrderSegments++;
    if (!this.outOfOrder.has(frame.seq)) {
      this.outOfOrder.set(frame.seq, frame.payload);
    }
    this.scheduleAck(this.expectedRelaySeq, receivedAt, true);
  }

  noteInOrderAck(receivedAt) {
    this.pendingAckCount++;
    this.pendingAckNumber = this.expectedRelaySeq;
    this.pendingAckDueAt = receivedAt + this.ackDelayMs;

    if (this.pendingAckCount >= this.ackEvery) {
      this.flushPendingAck();
      return;
    }

    if (this.pendingAckTimer === null) {
      const delayMs = Math.max(0, this.pendingAckDueAt - performance.now());
      this.pendingAckTimer = setTimeout(() => {
        this.pendingAckTimer = null;
        this.flushPendingAck();
      }, delayMs);
    }
  }

  flushPendingAck() {
    if (this.pendingAckNumber === null) return;
    if (this.pendingAckTimer !== null) {
      clearTimeout(this.pendingAckTimer);
      this.pendingAckTimer = null;
    }
    const ackNumber = this.pendingAckNumber;
    const dueAt = this.pendingAckDueAt;
    this.pendingAckCount = 0;
    this.pendingAckNumber = null;
    this.pendingAckDueAt = null;
    this.scheduleAck(ackNumber, dueAt - this.ackDelayMs, false);
  }

  scheduleAck(ackNumber, receivedAt, duplicate) {
    const dueAt = receivedAt + this.ackDelayMs;
    const delayMs = Math.max(0, dueAt - performance.now());
    const timer = setTimeout(() => {
      this.ackTimers.delete(timer);
      if (!duplicate && this.lastAckSent !== null) {
        if (ackNumber === this.lastAckSent || seqBefore(ackNumber, this.lastAckSent)) {
          return;
        }
      }
      this.sendAck(ackNumber);
    }, delayMs);
    this.ackTimers.add(timer);
  }

  sendAck(ackNumber) {
    if (this.ws.readyState !== WebSocket.OPEN) return;
    this.lastAckSent = ackNumber;
    this.ackPackets++;
    this.ws.send(buildTCPFrame({
      srcIP: VM_IP,
      dstIP: REMOTE_IP,
      srcPort: this.vmPort,
      dstPort: this.remotePort,
      seq: this.vmSeq,
      ack: ackNumber,
      flags: { ack: true },
    }));
  }

  async connect(remotePort) {
    this.remotePort = remotePort;
    this.ws.send(buildTCPFrame({
      srcIP: VM_IP,
      dstIP: REMOTE_IP,
      srcPort: this.vmPort,
      dstPort: remotePort,
      seq: this.vmSeq - 1,
      flags: { syn: true },
      mss: this.tcpMss,
    }));

    const synAck = await this.waitForSynAck();
    this.expectedRelaySeq = (synAck.seq + 1) >>> 0;
    this.lastAckSent = this.expectedRelaySeq;
    this.established = true;
    this.sendAck(this.expectedRelaySeq);
  }

  close() {
    if (this.ingressTimer !== null) clearTimeout(this.ingressTimer);
    if (this.pendingAckTimer !== null) clearTimeout(this.pendingAckTimer);
    for (const timer of this.ackTimers) clearTimeout(timer);
    this.ackTimers.clear();
    this.ingressTimer = null;
    this.pendingAckTimer = null;
  }
}

function connectWebSocket(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { perMessageDeflate: false });
    ws.once("open", () => {
      ws.removeListener("error", reject);
      resolve(ws);
    });
    ws.once("error", reject);
  });
}

async function waitForRelay(url, child) {
  const deadline = performance.now() + 5000;
  let lastError;
  while (performance.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Relay exited before accepting WebSockets (${child.exitCode})`);
    }
    try {
      return await connectWebSocket(url);
    } catch (error) {
      lastError = error;
      await delay(25);
    }
  }
  throw lastError || new Error("Timed out waiting for relay");
}

async function startRelay(tcpWindowSize, options) {
  const wsPort = await freeTcpPort();
  const adminPort = await freeTcpPort();
  const relayRoot = options.relayRoot || ROOT;
  const relayRuntime = options.relayRuntime || process.execPath;
  const inheritedNodePath = process.env.NODE_PATH;
  const nodePath = inheritedNodePath
    ? `${NODE_MODULES}${path.delimiter}${inheritedNodePath}`
    : NODE_MODULES;
  const child = spawn(relayRuntime, [path.join(relayRoot, "relay.js")], {
    cwd: relayRoot,
    env: {
      ...process.env,
      NODE_PATH: nodePath,
      ENABLE_WSS: "false",
      ENABLE_VM_TO_VM: "false",
      LOG_LEVEL: "0",
      RATE_LIMIT_KBPS: "1048576",
      TCP_WINDOW_SIZE: String(tcpWindowSize),
      TCP_PACING_MODE: options.pacingMode ?? "adaptive",
      TCP_SEND_BURST_SEGMENTS: String(options.sendBurstSegments),
      TCP_SEND_BURST_MAX_SEGMENTS: String(
        options.sendBurstMaxSegments ?? Math.max(8, options.sendBurstSegments),
      ),
      TCP_SEND_BURST_INTERVAL_MS: String(options.sendBurstIntervalMs),
      TCP_INITIAL_CWND_BYTES: String(options.initialCwndBytes),
      TCP_ACK_EVERY_SEGMENTS: String(options.relayAckEvery || 2),
      TCP_ACK_DELAY_MS: String(options.relayAckDelayMs ?? 10),
      VM_MTU: String(options.tcpMss + 40),
      TCP_RTO_INITIAL_MS: "1000",
      TCP_RTO_MAX_MS: "8000",
      TCP_RTO_MAX_RETRANSMISSIONS: "20",
      WS_BIND_ADDRESS: "127.0.0.1",
      WS_PORT: String(wsPort),
      ADMIN_BIND_ADDRESS: "127.0.0.1",
      ADMIN_PORT: String(adminPort),
      PROXY_BIND_ADDRESS: "127.0.0.1",
      PROXY_PORT: "0",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  try {
    const ws = await waitForRelay(`ws://127.0.0.1:${wsPort}`, child);
    return { child, ws, stderr: () => stderr };
  } catch (error) {
    await stopChild(child);
    if (stderr.trim()) error.message += `\nRelay stderr:\n${stderr.trim()}`;
    throw error;
  }
}

function stopChild(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    const forceTimer = setTimeout(() => child.kill("SIGKILL"), 1000);
    child.once("exit", () => {
      clearTimeout(forceTimer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

function startSource(socket, totalBytes = DEFAULT_SOURCE_BYTES) {
  const chunk = Buffer.alloc(SOURCE_CHUNK_BYTES, 0xa5);
  let sentBytes = 0;
  let stopped = false;

  const pump = () => {
    while (!stopped && sentBytes < totalBytes && socket.writable) {
      const remaining = totalBytes - sentBytes;
      const payload = remaining >= chunk.length
        ? chunk
        : chunk.subarray(0, remaining);
      sentBytes += payload.length;
      if (!socket.write(payload)) {
        socket.once("drain", pump);
        return;
      }
    }
  };

  pump();
  return {
    stop() {
      stopped = true;
      socket.destroy();
    },
    get sentBytes() {
      return sentBytes;
    },
  };
}

async function runCase(options, tcpWindowSize) {
  options = { tcpMss: DEFAULT_TCP_MSS, ...options };
  let relay;
  let ws;
  let fakeVM;
  let sourceServer;
  let sourceSocket;
  let source;

  try {
    let resolveAccepted;
    const accepted = new Promise((resolve) => {
      resolveAccepted = resolve;
    });
    sourceServer = net.createServer((socket) => {
      sourceSocket = socket;
      socket.setNoDelay(true);
      resolveAccepted(socket);
    });
    const remotePort = await new Promise((resolve, reject) => {
      sourceServer.once("error", reject);
      sourceServer.listen(0, REMOTE_IP, () => {
        sourceServer.removeListener("error", reject);
        resolve(sourceServer.address().port);
      });
    });

    relay = await startRelay(tcpWindowSize, options);
    ws = relay.ws;
    fakeVM = new FakeVM(ws, options);
    await fakeVM.connect(remotePort);
    sourceSocket = await accepted;

    const startedAt = performance.now();
    source = startSource(sourceSocket, options.sourceBytes || DEFAULT_SOURCE_BYTES);
    await delay(options.durationMs);
    const endedAt = performance.now();
    const deliveredBytes = fakeVM.deliveredBytes;
    const elapsedSeconds = (endedAt - startedAt) / 1000;

    return {
      tcpWindowSize,
      elapsedMs: endedAt - startedAt,
      deliveredBytes,
      goodputBytesPerSecond: deliveredBytes / elapsedSeconds,
      theoreticalWindowBytesPerSecond: options.ackDelayMs === 0
        ? null
        : tcpWindowSize / (options.ackDelayMs / 1000),
      sourceBytes: source.sentBytes,
      sourceExhausted: deliveredBytes >=
        (options.sourceBytes || DEFAULT_SOURCE_BYTES),
      receivedDataSegments: fakeVM.receivedDataSegments,
      droppedDataSegments: fakeVM.droppedDataSegments,
      retransmittedSegments: fakeVM.retransmittedSegments,
      outOfOrderSegments: fakeVM.outOfOrderSegments,
      invalidPayloadSegments: fakeVM.invalidPayloadSegments,
      ackPackets: fakeVM.ackPackets,
      maxDataSegmentBytes: fakeVM.maxDataSegmentBytes,
    };
  } catch (error) {
    if (relay?.stderr().trim()) {
      error.message += `\nRelay stderr:\n${relay.stderr().trim()}`;
    }
    throw error;
  } finally {
    source?.stop();
    sourceSocket?.destroy();
    fakeVM?.close();
    if (ws && ws.readyState !== WebSocket.CLOSED) ws.close();
    if (relay) await stopChild(relay.child);
    if (sourceServer) {
      await new Promise((resolve) => sourceServer.close(resolve));
    }
  }
}

async function runBenchmark(options) {
  options = { tcpMss: DEFAULT_TCP_MSS, ...options };
  const results = [];
  for (const tcpWindowSize of options.windows) {
    results.push(await runCase(options, tcpWindowSize));
  }
  return {
    node: process.version,
    relayRoot: options.relayRoot || ROOT,
    relayRuntime: options.relayRuntime || process.execPath,
    durationMs: options.durationMs,
    ackDelayMs: options.ackDelayMs,
    ackEvery: options.ackEvery,
    rxQueuePackets: options.rxQueuePackets,
    rxServiceMs: options.rxServiceMs,
    pacingMode: options.pacingMode ?? "adaptive",
    sendBurstSegments: options.sendBurstSegments,
    sendBurstMaxSegments: options.sendBurstMaxSegments ??
      Math.max(8, options.sendBurstSegments),
    sendBurstIntervalMs: options.sendBurstIntervalMs,
    initialCwndBytes: options.initialCwndBytes,
    tcpMss: options.tcpMss,
    sourceBytes: options.sourceBytes || DEFAULT_SOURCE_BYTES,
    results,
  };
}

function formatRate(bytesPerSecond) {
  return `${(bytesPerSecond / 1024).toFixed(0)} KiB/s`;
}

function printReport(report) {
  const queueDescription = report.rxQueuePackets === 0
    ? "unbounded"
    : `${report.rxQueuePackets} packets`;
  console.log(`TCP egress fake-VM benchmark | ${report.node}`);
  console.log(`Relay ${report.relayRoot} via ${report.relayRuntime}`);
  console.log(
    `Measurement ${report.durationMs} ms, ACK delay ${report.ackDelayMs} ms, ` +
    `ACK every ${report.ackEvery} segments`,
  );
  console.log(
    `Fake NIC queue ${queueDescription}, service interval ${report.rxServiceMs} ms`,
  );
  console.log(
    `Relay pacing ${report.pacingMode} ${report.sendBurstSegments}` +
    `${report.pacingMode === "adaptive" ? `..${report.sendBurstMaxSegments}` : ""} ` +
    `segments every ` +
    `${report.sendBurstIntervalMs} ms, initial cwnd ${report.initialCwndBytes} B, ` +
    `TCP MSS ${report.tcpMss} B`,
  );
  console.log(`Source payload cap ${report.sourceBytes} B per case`);
  console.log("");
  console.log(
    "WINDOW       GOODPUT      WINDOW/RTT    MAX SEG   DROPPED   RETRANS   OUT-OF-ORDER",
  );
  for (const result of report.results) {
    const theoretical = result.theoreticalWindowBytesPerSecond === null
      ? "n/a"
      : formatRate(result.theoreticalWindowBytesPerSecond);
    console.log(
      `${String(result.tcpWindowSize).padStart(6)} B  ` +
      `${formatRate(result.goodputBytesPerSecond).padStart(12)}  ` +
      `${theoretical.padStart(12)}  ` +
      `${String(result.maxDataSegmentBytes).padStart(9)}  ` +
      `${String(result.droppedDataSegments).padStart(9)}  ` +
      `${String(result.retransmittedSegments).padStart(8)}  ` +
      `${String(result.outOfOrderSegments).padStart(12)}`,
    );
  }
}

function printHelp() {
  console.log(`Usage: npm run bench:tcp-egress -- [options]

Options:
  --duration-ms=N       Measurement duration per window (default: 3000)
  --ack-delay-ms=N      Simulated VM ACK delay (default: 20)
  --ack-every=N         Cumulative ACK frequency in segments (default: 2)
  --rx-queue-packets=N  Fake NIC queue capacity; 0 is unbounded (default: 8)
  --rx-service-ms=N     Fake NIC queue service interval (default: 5)
  --send-burst-segments=N
                         Initial/fixed relay burst (default: 3)
  --send-burst-max-segments=N
                         Adaptive relay burst ceiling (default: 8)
  --pacing-mode=MODE     adaptive, fixed, or off (default: adaptive)
  --send-burst-interval-ms=N
                         Delay between relay bursts (default: 6)
  --initial-cwnd-bytes=N Initial relay congestion window (default: 10240)
  --tcp-mss=N           VM-facing TCP MSS (default: 1460)
  --source-bytes=N      Source payload cap (default: 33554432)
  --windows=LIST        TCP window sizes to compare (default: 10240,65535)
  --relay-root=PATH     Directory containing the relay.js under test
  --relay-runtime=PATH  Runtime used to launch relay.js (default: current Node)
  --json                Emit machine-readable JSON
  --help                Show this help`);
}

if (require.main === module) {
  (async () => {
    try {
      const options = parseArgs(process.argv.slice(2));
      if (options.help) {
        printHelp();
        return;
      }
      const report = await runBenchmark(options);
      if (options.json) console.log(JSON.stringify(report, null, 2));
      else printReport(report);
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  })();
}

module.exports = {
  buildTCPFrame,
  delay,
  freeTcpPort,
  parseArgs,
  parseTCPFrame,
  runBenchmark,
  runCase,
  startRelay,
  stopChild,
};
