#!/usr/bin/env node
"use strict";

const net = require("node:net");
const { performance } = require("node:perf_hooks");
const {
  buildTCPFrame,
  delay,
  parseTCPFrame,
  startRelay,
  stopChild,
} = require("./tcp-egress-throughput");

const VM_IP = "10.0.2.15";
const REMOTE_IP = "127.0.0.1";
const DEFAULT_TCP_MSS = 1460;
const EXPECTED_PAYLOAD = Buffer.alloc(64 * 1024, 0xa5);

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
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    const range = maximum === Infinity
      ? `at least ${minimum}`
      : `from ${minimum} through ${maximum}`;
    throw new TypeError(`${option} must be an integer ${range}`);
  }
  return parsed;
}

function parseArgs(args) {
  const options = {
    durationMs: 3000,
    tcpWindowSize: 65535,
    tcpMss: DEFAULT_TCP_MSS,
    bufferBytes: 1024 * 1024,
    relayAckEvery: 2,
    relayAckDelayMs: 10,
    sinkPauseMs: 0,
    sinkPauseCount: Infinity,
    relayRoot: undefined,
    relayRuntime: process.execPath,
    json: false,
  };

  for (const arg of args) {
    if (arg === "--json") options.json = true;
    else if (arg === "--help") options.help = true;
    else if (arg.startsWith("--duration-ms=")) {
      options.durationMs = parseInteger(arg.split("=")[1], "--duration-ms");
    } else if (arg.startsWith("--window=")) {
      options.tcpWindowSize = parseInteger(
        arg.split("=")[1],
        "--window",
        { maximum: 65535 },
      );
    } else if (arg.startsWith("--tcp-mss=")) {
      options.tcpMss = parseInteger(
        arg.split("=")[1],
        "--tcp-mss",
        { minimum: 536, maximum: 65495 },
      );
    } else if (arg.startsWith("--buffer-bytes=")) {
      options.bufferBytes = parseInteger(arg.split("=")[1], "--buffer-bytes");
    } else if (arg.startsWith("--relay-ack-every=")) {
      options.relayAckEvery = parseInteger(
        arg.split("=")[1],
        "--relay-ack-every",
      );
    } else if (arg.startsWith("--relay-ack-delay-ms=")) {
      options.relayAckDelayMs = parseInteger(
        arg.split("=")[1],
        "--relay-ack-delay-ms",
        { minimum: 0 },
      );
    } else if (arg.startsWith("--sink-pause-ms=")) {
      options.sinkPauseMs = parseInteger(
        arg.split("=")[1],
        "--sink-pause-ms",
        { minimum: 0 },
      );
    } else if (arg.startsWith("--sink-pause-count=")) {
      options.sinkPauseCount = parseInteger(arg.split("=")[1], "--sink-pause-count");
    } else if (arg.startsWith("--relay-root=")) {
      options.relayRoot = arg.slice("--relay-root=".length);
      if (!options.relayRoot) throw new TypeError("--relay-root must not be empty");
    } else if (arg.startsWith("--relay-runtime=")) {
      options.relayRuntime = arg.slice("--relay-runtime=".length);
      if (!options.relayRuntime) {
        throw new TypeError("--relay-runtime must not be empty");
      }
    } else if (arg.startsWith("--relay-cpu-prof-dir=")) {
      options.relayCpuProfDir = arg.slice("--relay-cpu-prof-dir=".length);
      if (!options.relayCpuProfDir) {
        throw new TypeError("--relay-cpu-prof-dir must not be empty");
      }
    } else {
      throw new TypeError(`Unknown option: ${arg}`);
    }
  }
  return options;
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, REMOTE_IP, () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

class FakeVMSender {
  constructor(ws, options) {
    this.ws = ws;
    this.options = options;
    this.vmPort = 42000;
    this.vmSeq = 1001;
    this.relayAck = 1001;
    this.relayWindow = options.tcpWindowSize;
    this.remotePort = null;
    this.relaySeq = null;
    this.synAck = null;
    this.waiters = [];
    this.ackPackets = 0;
    this.zeroWindowAcks = 0;
    this.minAdvertisedWindow = options.tcpWindowSize;
    this.windowReopenAcks = 0;
    this.previousWindow = options.tcpWindowSize;
    this.maxOutstandingBytes = 0;
    this.sentBytes = 0;
    this.sentSegments = 0;

    ws.on("message", (data, isBinary) => {
      if (!isBinary) return;
      const frame = parseTCPFrame(data);
      if (!frame || frame.dstPort !== this.vmPort) return;
      if (frame.syn && frame.ackFlag) {
        this.synAck = frame;
        for (const resolve of this.waiters.splice(0)) resolve(frame);
        return;
      }
      if (!frame.ackFlag) return;
      this.ackPackets++;
      this.relayAck = frame.ack;
      this.relayWindow = frame.window;
      this.minAdvertisedWindow = Math.min(this.minAdvertisedWindow, frame.window);
      if (frame.window === 0) this.zeroWindowAcks++;
      if (this.previousWindow === 0 && frame.window > 0) this.windowReopenAcks++;
      this.previousWindow = frame.window;
    });
  }

  waitForSynAck(timeoutMs = 2000) {
    if (this.synAck) return Promise.resolve(this.synAck);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(onSynAck);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(new Error("Timed out waiting for relay SYN-ACK"));
      }, timeoutMs);
      const onSynAck = (frame) => {
        clearTimeout(timer);
        resolve(frame);
      };
      this.waiters.push(onSynAck);
    });
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
      mss: this.options.tcpMss,
      window: this.options.tcpWindowSize,
    }));
    const synAck = await this.waitForSynAck();
    this.relaySeq = (synAck.seq + 1) >>> 0;
    this.relayWindow = synAck.window;
    this.ws.send(buildTCPFrame({
      srcIP: VM_IP,
      dstIP: REMOTE_IP,
      srcPort: this.vmPort,
      dstPort: remotePort,
      seq: this.vmSeq,
      ack: this.relaySeq,
      flags: { ack: true },
      window: this.options.tcpWindowSize,
    }));
  }

  outstandingBytes() {
    return (this.vmSeq - this.relayAck) >>> 0;
  }

  async sendFor(durationMs) {
    const payload = Buffer.alloc(this.options.tcpMss, 0xa5);
    const startedAt = performance.now();
    const deadline = startedAt + durationMs;
    while (performance.now() < deadline) {
      let batch = 0;
      while (
        batch < 256 &&
        this.ws.bufferedAmount < this.options.bufferBytes &&
        this.outstandingBytes() + payload.length <= this.relayWindow
      ) {
        this.ws.send(buildTCPFrame({
          srcIP: VM_IP,
          dstIP: REMOTE_IP,
          srcPort: this.vmPort,
          dstPort: this.remotePort,
          seq: this.vmSeq,
          ack: this.relaySeq,
          flags: { ack: true, psh: true },
          payload,
          window: this.options.tcpWindowSize,
        }));
        this.vmSeq = (this.vmSeq + payload.length) >>> 0;
        this.sentBytes += payload.length;
        this.sentSegments++;
        this.maxOutstandingBytes = Math.max(
          this.maxOutstandingBytes,
          this.outstandingBytes(),
        );
        batch++;
      }
      await new Promise((resolve) => setImmediate(resolve));
    }
    return { startedAt, endedAt: performance.now() };
  }
}

async function runBenchmark(options) {
  let sinkSocket;
  let invalidBytes = 0;
  let deliveredBytes = 0;
  let pauseTimer = null;
  let pauses = 0;
  const sink = net.createServer((socket) => {
    sinkSocket = socket;
    socket.on("data", (data) => {
      deliveredBytes += data.length;
      if (!hasExpectedPayload(data)) invalidBytes += data.length;
      if (options.sinkPauseMs > 0 && pauseTimer === null &&
          pauses < (options.sinkPauseCount ?? Infinity)) {
        pauses++;
        socket.pause();
        pauseTimer = setTimeout(() => {
          pauseTimer = null;
          socket.resume();
        }, options.sinkPauseMs);
      }
    });
  });
  const remotePort = await listen(sink);
  let relay;
  try {
    relay = await startRelay(options.tcpWindowSize, {
      sendBurstSegments: 3,
      sendBurstMaxSegments: 8,
      sendBurstIntervalMs: 6,
      initialCwndBytes: 10240,
      tcpMss: options.tcpMss,
      pacingMode: "adaptive",
      relayAckEvery: options.relayAckEvery,
      relayAckDelayMs: options.relayAckDelayMs,
      relayRoot: options.relayRoot,
      relayRuntime: options.relayRuntime,
      relayCpuProfDir: options.relayCpuProfDir,
    });
    const sender = new FakeVMSender(relay.ws, options);
    await sender.connect(remotePort);
    const timing = await sender.sendFor(options.durationMs);
    const deliveredAtDeadline = deliveredBytes;
    const invalidAtDeadline = invalidBytes;
    await delay(Math.max(50, options.relayAckDelayMs * 2));
    const elapsedSeconds = (timing.endedAt - timing.startedAt) / 1000;
    return {
      node: process.version,
      relayRoot: options.relayRoot,
      relayRuntime: options.relayRuntime,
      relayCpuProfDir: options.relayCpuProfDir,
      durationMs: options.durationMs,
      tcpMss: options.tcpMss,
      relayAckEvery: options.relayAckEvery,
      relayAckDelayMs: options.relayAckDelayMs,
      sinkPauseMs: options.sinkPauseMs,
      sinkPauseCount: options.sinkPauseCount === Infinity ? null : options.sinkPauseCount,
      results: [{
        tcpWindowSize: options.tcpWindowSize,
        elapsedMs: timing.endedAt - timing.startedAt,
        deliveredBytes: deliveredAtDeadline,
        goodputBytesPerSecond: deliveredAtDeadline / elapsedSeconds,
        sourceBytes: sender.sentBytes,
        sourceExhausted: false,
        sentSegments: sender.sentSegments,
        ackPackets: sender.ackPackets,
        zeroWindowAcks: sender.zeroWindowAcks,
        minAdvertisedWindow: sender.minAdvertisedWindow,
        windowReopenAcks: sender.windowReopenAcks,
        maxOutstandingBytes: sender.maxOutstandingBytes,
        invalidPayloadSegments: invalidAtDeadline === 0 ? 0 : 1,
        invalidBytes: invalidAtDeadline,
        droppedDataSegments: 0,
        retransmittedSegments: 0,
        outOfOrderSegments: 0,
      }],
    };
  } finally {
    if (pauseTimer !== null) clearTimeout(pauseTimer);
    sinkSocket?.destroy();
    if (relay?.ws && relay.ws.readyState !== 3) relay.ws.close();
    if (relay) await stopChild(relay.child);
    await new Promise((resolve) => sink.close(resolve));
  }
}

function formatRate(value) {
  return `${(value / (1024 * 1024)).toFixed(1)} MiB/s`;
}

function printReport(report) {
  const result = report.results[0];
  console.log(`TCP ingress fake-VM benchmark | ${report.node}`);
  console.log(
    `Measurement ${report.durationMs} ms, MSS ${report.tcpMss} B, ` +
    `relay ACK every ${report.relayAckEvery} or ${report.relayAckDelayMs} ms`,
  );
  console.log(`Delivered: ${formatRate(result.goodputBytesPerSecond)}`);
  console.log(
    `Segments ${result.sentSegments}, ACKs ${result.ackPackets}, ` +
    `minimum window ${result.minAdvertisedWindow} B, ` +
    `zero/reopen ACKs ${result.zeroWindowAcks}/${result.windowReopenAcks}, ` +
    `invalid bytes ${result.invalidBytes}`,
  );
}

function printHelp() {
  console.log(`Usage: npm run bench:tcp-ingress -- [options]

Options:
  --duration-ms=N          Measurement duration (default: 3000)
  --window=N               VM and relay TCP window (default: 65535)
  --tcp-mss=N              VM payload size (default: 1460)
  --buffer-bytes=N         WebSocket sender high-water mark (default: 1048576)
  --relay-ack-every=N      Relay cumulative ACK frequency (default: 2)
  --relay-ack-delay-ms=N   Maximum relay ACK delay (default: 10)
  --sink-pause-ms=N        Pause sink after reads to create backpressure
  --sink-pause-count=N     Stop pausing after N reads (default: unlimited)
  --relay-root=PATH        Directory containing relay.js
  --relay-cpu-prof-dir=DIR  Save a Node CPU profile of the relay child
  --relay-runtime=PATH     Runtime used to launch relay.js
  --json                   Emit machine-readable JSON
  --help                   Show this help`);
}

if (require.main === module) {
  (async () => {
    try {
      const options = parseArgs(process.argv.slice(2));
      if (options.help) return printHelp();
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
  FakeVMSender,
  parseArgs,
  runBenchmark,
};
