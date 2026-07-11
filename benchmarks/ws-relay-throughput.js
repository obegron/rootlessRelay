#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { Worker } = require("node:worker_threads");
const WebSocket = require("ws");
const {
  buildIPv4Packet,
  udpChecksum,
} = require("../packet_utils");

const ROOT = path.resolve(__dirname, "..");
const DEFAULT_SIZES = [64, 512, 1400, 8192, 32768];

function parsePositiveInteger(value, option) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TypeError(`${option} must be a positive integer`);
  }
  return parsed;
}

function parseArgs(args) {
  const options = {
    durationMs: 1000,
    warmupMs: 150,
    bufferBytes: 1024 * 1024,
    sizes: DEFAULT_SIZES,
    json: false,
  };

  for (const arg of args) {
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--help") {
      options.help = true;
    } else if (arg.startsWith("--duration-ms=")) {
      options.durationMs = parsePositiveInteger(arg.split("=")[1], "--duration-ms");
    } else if (arg.startsWith("--warmup-ms=")) {
      options.warmupMs = parsePositiveInteger(arg.split("=")[1], "--warmup-ms");
    } else if (arg.startsWith("--buffer-bytes=")) {
      options.bufferBytes = parsePositiveInteger(arg.split("=")[1], "--buffer-bytes");
    } else if (arg.startsWith("--sizes=")) {
      options.sizes = arg.split("=")[1].split(",").map((size) => {
        const parsed = Number(size);
        if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65507) {
          throw new TypeError("--sizes values must be integers from 1 through 65507");
        }
        return parsed;
      });
    } else {
      throw new TypeError(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function buildUdpEthernetFrame(payloadSize, destinationPort, marker = 0) {
  const payload = Buffer.alloc(payloadSize, 0xa5);
  payload[0] = marker;
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(40000, 0);
  udp.writeUInt16BE(destinationPort, 2);
  udp.writeUInt16BE(udp.length, 4);
  udp.writeUInt16BE(0, 6);
  payload.copy(udp, 8);

  const ip = buildIPv4Packet(udp, "10.0.2.15", "127.0.0.1", 17, 1);
  ip.writeUInt16BE(udpChecksum(ip), 26);

  const frame = Buffer.alloc(14 + ip.length);
  Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).copy(frame, 0);
  Buffer.from([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]).copy(frame, 6);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);
  return frame;
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

class UdpReceiver {
  constructor(receiveBufferBytes) {
    this.nextRequestId = 1;
    this.requests = new Map();
    this.terminalError = null;
    this.closing = false;
    this.worker = new Worker(path.join(__dirname, "udp-receiver-worker.js"), {
      workerData: { receiveBufferBytes },
    });
    this.ready = new Promise((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
    this.worker.on("message", (message) => {
      if (message.ready) {
        this.resolveReady(message.ready);
        return;
      }
      if (message.error) {
        const error = new Error(`UDP receiver worker: ${message.error}`);
        this.fail(error);
        return;
      }
      const request = this.requests.get(message.id);
      if (!request) return;
      this.requests.delete(message.id);
      request.resolve(message.result);
    });
    this.worker.once("error", (error) => {
      this.fail(error);
    });
    this.worker.once("exit", (code) => {
      if (!this.closing) {
        this.fail(new Error(`UDP receiver worker exited unexpectedly (${code})`));
      }
    });
  }

  fail(error) {
    if (this.terminalError) return;
    this.terminalError = error;
    this.rejectReady(error);
    for (const request of this.requests.values()) request.reject(error);
    this.requests.clear();
  }

  request(command, extra = {}) {
    return new Promise((resolve, reject) => {
      if (this.terminalError) {
        reject(this.terminalError);
        return;
      }
      if (this.closing) {
        reject(new Error("UDP receiver worker is closing"));
        return;
      }
      const id = this.nextRequestId++;
      this.requests.set(id, { resolve, reject });
      try {
        this.worker.postMessage({ id, command, ...extra });
      } catch (error) {
        this.requests.delete(id);
        reject(error);
      }
    });
  }

  reset(payloadSize, marker) {
    return this.request("reset", { size: payloadSize, phaseMarker: marker });
  }

  stats() {
    return this.request("stats");
  }

  stop() {
    return this.request("stop");
  }

  async close() {
    if (this.closing) return;
    this.closing = true;
    const error = new Error("UDP receiver worker closed");
    for (const request of this.requests.values()) request.reject(error);
    this.requests.clear();
    await this.worker.terminate();
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
      throw new Error(`Relay exited before accepting WebSockets (code ${child.exitCode})`);
    }
    try {
      return await connectWebSocket(url);
    } catch (error) {
      lastError = error;
      await delay(30);
    }
  }

  throw new Error(`Timed out waiting for relay: ${lastError?.message || "unknown error"}`);
}

async function sendFor(
  ws,
  frame,
  durationMs,
  bufferBytes,
) {
  const start = performance.now();
  const deadline = start + durationMs;
  let sentPackets = 0;

  while (performance.now() < deadline) {
    let batch = 0;
    while (
      batch < 256 &&
      ws.readyState === WebSocket.OPEN &&
      ws.bufferedAmount < bufferBytes
    ) {
      ws.send(frame, { binary: true });
      sentPackets++;
      batch++;
    }
    await new Promise((resolve) => setImmediate(resolve));
  }

  return { sentPackets, start, sendEnd: performance.now() };
}

function getRelayBytes(adminPort) {
  return new Promise((resolve, reject) => {
    const request = http.get(
      `http://127.0.0.1:${adminPort}/api/sessions`,
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => {
          try {
            const sessions = JSON.parse(body);
            resolve(sessions[0]?.bytesReceived || 0);
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.on("error", reject);
  });
}

async function waitForReceiverIdle(receiver, expectedPackets = null) {
  const deadline = performance.now() + 3000;
  let stats = await receiver.stats();
  let unchangedPolls = 0;
  let observedAt = performance.now();

  while (performance.now() < deadline) {
    await delay(25);
    const current = await receiver.stats();
    if (current.totalReceivedPackets === stats.totalReceivedPackets) {
      unchangedPolls++;
    } else {
      unchangedPolls = 0;
      observedAt = performance.now();
    }
    stats = current;
    if (expectedPackets !== null && stats.receivedPackets > expectedPackets) {
      throw new Error(
        `UDP receiver counted ${stats.receivedPackets} packets; expected at most ` +
        `${expectedPackets}`,
      );
    }
    if (stats.receivedPackets === expectedPackets || unchangedPolls >= 4) {
      return { ...stats, observedAt };
    }
  }

  throw new Error("Timed out waiting for UDP receiver to become idle");
}

async function waitForRelayIdle(ws, adminPort) {
  const deadline = performance.now() + 5000;
  let bytes = await getRelayBytes(adminPort);
  let unchangedPolls = 0;
  let lastChangedAt = performance.now();

  while (performance.now() < deadline) {
    await delay(25);
    const current = await getRelayBytes(adminPort);
    if (current === bytes) {
      unchangedPolls++;
    } else {
      bytes = current;
      unchangedPolls = 0;
      lastChangedAt = performance.now();
    }
    if (ws.bufferedAmount === 0 && unchangedPolls >= 3) {
      return { bytes, lastChangedAt };
    }
  }

  throw new Error("Timed out waiting for WebSocket relay to become idle");
}

async function runCase(
  ws,
  receiver,
  destinationPort,
  adminPort,
  options,
  payloadSize,
  marker = 1,
) {
  const warmupFrame = buildUdpEthernetFrame(payloadSize, destinationPort, 0);
  const frame = buildUdpEthernetFrame(payloadSize, destinationPort, marker);

  await sendFor(
    ws,
    warmupFrame,
    options.warmupMs,
    options.bufferBytes,
  );
  const baseline = await waitForRelayIdle(ws, adminPort);
  await waitForReceiverIdle(receiver);
  await receiver.reset(payloadSize, marker);

  const sent = await sendFor(
    ws,
    frame,
    options.durationMs,
    options.bufferBytes,
  );
  const processed = await waitForRelayIdle(ws, adminPort);

  const relayedBytes = processed.bytes - baseline.bytes;
  if (relayedBytes % frame.length !== 0) {
    throw new Error(
      `Relay byte accounting (${relayedBytes}) is not divisible by frame size ` +
      `(${frame.length})`,
    );
  }
  const relayedPackets = relayedBytes / frame.length;
  if (relayedPackets !== sent.sentPackets) {
    throw new Error(
      `WebSocket accounting mismatch: sent ${sent.sentPackets}, relay processed ` +
      `${relayedPackets}`,
    );
  }

  await waitForReceiverIdle(receiver, relayedPackets);
  const receiverStats = await receiver.stop();
  if (receiverStats.receivedPackets > relayedPackets) {
    throw new Error("UDP receiver counted more packets than the relay processed");
  }
  const end = Math.max(
    sent.sendEnd,
    processed.lastChangedAt,
    receiverStats.lastReceivedAt,
  );
  const elapsedSeconds = (end - sent.start) / 1000;
  return {
    payloadBytes: payloadSize,
    sentPackets: sent.sentPackets,
    relayedPackets,
    receivedPackets: receiverStats.receivedPackets,
    lossPercent: relayedPackets === 0
      ? 0
      : ((relayedPackets - receiverStats.receivedPackets) / relayedPackets) * 100,
    webSocketLossPercent: sent.sentPackets === 0
      ? 0
      : ((sent.sentPackets - relayedPackets) / sent.sentPackets) * 100,
    relayedPacketsPerSecond: relayedPackets / elapsedSeconds,
    relayedPayloadBytesPerSecond: (relayedPackets * payloadSize) / elapsedSeconds,
    deliveredPacketsPerSecond: receiverStats.receivedPackets / elapsedSeconds,
    deliveredPayloadBytesPerSecond: receiverStats.receivedBytes / elapsedSeconds,
    elapsedMs: elapsedSeconds * 1000,
  };
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

async function runBenchmark(options) {
  const receiver = new UdpReceiver(4 * 1024 * 1024);
  let receiverInfo;
  try {
    receiverInfo = await receiver.ready;
  } catch (error) {
    await receiver.close();
    throw error;
  }
  const destinationPort = receiverInfo.port;
  const wsPort = await freeTcpPort();
  const adminPort = await freeTcpPort();
  const child = spawn(process.execPath, [path.join(ROOT, "relay.js")], {
    cwd: ROOT,
    env: {
      ...process.env,
      ENABLE_WSS: "false",
      ENABLE_VM_TO_VM: "false",
      LOG_LEVEL: "0",
      WS_BIND_ADDRESS: "127.0.0.1",
      WS_PORT: String(wsPort),
      ADMIN_BIND_ADDRESS: "127.0.0.1",
      ADMIN_PORT: String(adminPort),
      PROXY_BIND_ADDRESS: "127.0.0.1",
      PROXY_PORT: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let relayErrors = "";
  child.stdout.resume();
  child.stderr.on("data", (chunk) => {
    relayErrors += chunk.toString();
  });

  let ws;
  try {
    ws = await waitForRelay(`ws://127.0.0.1:${wsPort}`, child);
    const results = [];
    let marker = 1;
    const markerState = {
      next() {
        const value = marker;
        marker = marker === 255 ? 1 : marker + 1;
        return value;
      },
    };
    for (const size of options.sizes) {
      results.push(
        await runCase(
          ws,
          receiver,
          destinationPort,
          adminPort,
          options,
          size,
          markerState.next(),
        ),
      );
    }
    return {
      node: process.version,
      durationMs: options.durationMs,
      warmupMs: options.warmupMs,
      bufferBytes: options.bufferBytes,
      receiveBufferBytes: receiverInfo.receiveBufferBytes,
      results,
    };
  } catch (error) {
    if (relayErrors.trim()) {
      error.message += `\nRelay stderr:\n${relayErrors.trim()}`;
    }
    throw error;
  } finally {
    if (ws && ws.readyState !== WebSocket.CLOSED) ws.close();
    await receiver.close();
    await stopChild(child);
  }
}

function formatRate(bytesPerSecond) {
  return `${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MiB/s`;
}

function printReport(report) {
  console.log(`WebSocket relay choke test | ${report.node}`);
  console.log(
    `Warmup ${report.warmupMs} ms, send window ${report.durationMs} ms, ` +
    `WS high-water mark ${report.bufferBytes} B`,
  );
  if (report.receiveBufferBytes !== null) {
    console.log(`UDP receive buffer ${report.receiveBufferBytes} B (isolated worker)`);
  }
  console.log("");
  console.log("PAYLOAD       RELAYED/S     RELAY RATE       UDP RATE   UDP LOSS");
  for (const result of report.results) {
    console.log(
      `${String(result.payloadBytes).padStart(7)} B  ` +
      `${Math.round(result.relayedPacketsPerSecond).toLocaleString("en-US").padStart(12)}  ` +
      `${formatRate(result.relayedPayloadBytesPerSecond).padStart(13)}  ` +
      `${formatRate(result.deliveredPayloadBytesPerSecond).padStart(13)}  ` +
      `${result.lossPercent.toFixed(2).padStart(7)}%`,
    );
  }

  const maximum = report.results.reduce((best, result) =>
    !best || result.relayedPayloadBytesPerSecond > best.relayedPayloadBytesPerSecond
      ? result
      : best
  , null);
  const deliveredMaximum = report.results.reduce((best, result) =>
    !best || result.deliveredPayloadBytesPerSecond > best.deliveredPayloadBytesPerSecond
      ? result
      : best
  , null);
  console.log("");
  console.log(
    `Maximum WebSocket + relay throughput: ` +
    `${formatRate(maximum.relayedPayloadBytesPerSecond)} ` +
    `(${maximum.payloadBytes} B payloads)`,
  );
  console.log(
    `Maximum UDP-delivered throughput: ` +
    `${formatRate(deliveredMaximum.deliveredPayloadBytesPerSecond)} ` +
    `(${deliveredMaximum.payloadBytes} B payloads, ` +
    `${deliveredMaximum.lossPercent.toFixed(2)}% loss)`,
  );
  const standardMtu = report.results.find((result) => result.payloadBytes === 1400);
  if (standardMtu) {
    console.log(
      `Standard-MTU reference: ` +
      `${formatRate(standardMtu.relayedPayloadBytesPerSecond)} relayed, ` +
      `${formatRate(standardMtu.deliveredPayloadBytesPerSecond)} UDP-delivered`,
    );
  }
}

function printHelp() {
  console.log(`Usage: npm run bench:ws -- [options]

Options:
  --duration-ms=N  Send time per case (default: 1000)
  --warmup-ms=N    Warmup time per case (default: 150)
  --buffer-bytes=N WebSocket bufferedAmount high-water mark (default: 1048576)
  --sizes=LIST     Comma-separated UDP payload sizes, 1..65507
  --json           Emit machine-readable JSON
  --help           Show this help`);
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
  buildUdpEthernetFrame,
  parseArgs,
  runBenchmark,
};
