#!/usr/bin/env node
"use strict";

const os = require("node:os");
const { performance } = require("node:perf_hooks");
const {
  buildIPv4Packet,
  tcpChecksum,
  udpChecksum,
} = require("../packet_utils");

const DEFAULT_SIZES = [0, 64, 512, 1460, 8192, 32768];
let checksumSink = 0;

function parsePositiveInteger(value, option) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TypeError(`${option} must be a positive integer`);
  }
  return parsed;
}

function parseArgs(args) {
  const options = {
    durationMs: 750,
    warmupMs: 150,
    protocols: ["tcp", "udp"],
    sizes: DEFAULT_SIZES,
    json: false,
  };

  for (const arg of args) {
    if (arg === "--json") {
      options.json = true;
    } else if (arg.startsWith("--duration-ms=")) {
      options.durationMs = parsePositiveInteger(arg.split("=")[1], "--duration-ms");
    } else if (arg.startsWith("--warmup-ms=")) {
      options.warmupMs = parsePositiveInteger(arg.split("=")[1], "--warmup-ms");
    } else if (arg.startsWith("--protocol=")) {
      const protocol = arg.split("=")[1].toLowerCase();
      if (!new Set(["tcp", "udp", "both"]).has(protocol)) {
        throw new TypeError("--protocol must be tcp, udp, or both");
      }
      options.protocols = protocol === "both" ? ["tcp", "udp"] : [protocol];
    } else if (arg.startsWith("--sizes=")) {
      options.sizes = arg.split("=")[1].split(",").map((size) => {
        const parsed = Number(size);
        if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 65495) {
          throw new TypeError("--sizes values must be integers from 0 through 65495");
        }
        return parsed;
      });
      if (options.sizes.length === 0) {
        throw new TypeError("--sizes must contain at least one payload size");
      }
    } else if (arg === "--help") {
      options.help = true;
    } else {
      throw new TypeError(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function makeTransportPacket(protocol, payloadSize) {
  const headerSize = protocol === "tcp" ? 20 : 8;
  const transport = Buffer.alloc(headerSize + payloadSize, 0xa5);
  transport.writeUInt16BE(49152, 0);
  transport.writeUInt16BE(protocol === "tcp" ? 443 : 53, 2);

  if (protocol === "tcp") {
    transport.writeUInt32BE(0x12345678, 4);
    transport.writeUInt32BE(0x90abcdef, 8);
    transport[12] = 0x50;
    transport[13] = 0x18;
    transport.writeUInt16BE(65535, 14);
    transport.writeUInt16BE(0, 16);
    transport.writeUInt16BE(0, 18);
  } else {
    transport.writeUInt16BE(transport.length, 4);
    transport.writeUInt16BE(0, 6);
  }

  return transport;
}

function exerciseFor(protocol, payloadSize, durationMs) {
  const transport = makeTransportPacket(protocol, payloadSize);
  const checksum = protocol === "tcp" ? tcpChecksum : udpChecksum;
  const checksumOffset = 20 + (protocol === "tcp" ? 16 : 6);
  const deadline = performance.now() + durationMs;
  let packets = 0;
  let localSink = 0;
  let now;

  do {
    // Check the clock once per batch so timer overhead does not dominate small packets.
    for (let batch = 0; batch < 64; batch++) {
      if (protocol === "tcp") {
        transport.writeUInt32BE(packets >>> 0, 4);
      }
      const ipPacket = buildIPv4Packet(
        transport,
        "10.0.2.2",
        "10.0.2.15",
        protocol === "tcp" ? 6 : 17,
      );
      const value = checksum(ipPacket);
      ipPacket.writeUInt16BE(value, checksumOffset);
      localSink ^= value ^ ipPacket[4];
      packets++;
    }
    now = performance.now();
  } while (now < deadline);

  checksumSink ^= localSink;
  return { packets, elapsedMs: now - (deadline - durationMs) };
}

function runCase(protocol, payloadSize, warmupMs, durationMs) {
  exerciseFor(protocol, payloadSize, warmupMs);
  const { packets, elapsedMs } = exerciseFor(protocol, payloadSize, durationMs);
  const elapsedSeconds = elapsedMs / 1000;
  const headerBytes = protocol === "tcp" ? 40 : 28;

  return {
    protocol,
    payloadBytes: payloadSize,
    packets,
    elapsedMs,
    packetsPerSecond: packets / elapsedSeconds,
    payloadBytesPerSecond: (packets * payloadSize) / elapsedSeconds,
    ipBytesPerSecond: (packets * (payloadSize + headerBytes)) / elapsedSeconds,
  };
}

function runBenchmark(options) {
  const results = [];
  for (const protocol of options.protocols) {
    for (const size of options.sizes) {
      results.push(runCase(protocol, size, options.warmupMs, options.durationMs));
    }
  }

  return {
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
    cpu: os.cpus()[0]?.model || "unknown",
    durationMs: options.durationMs,
    warmupMs: options.warmupMs,
    results,
    checksumSink,
  };
}

function formatRate(bytesPerSecond) {
  return `${(bytesPerSecond / (1024 * 1024)).toFixed(1)} MiB/s`;
}

function printReport(report) {
  console.log(`IP-stack choke test | ${report.node} | ${report.cpu}`);
  console.log(`Warmup ${report.warmupMs} ms, measurement ${report.durationMs} ms per case`);
  console.log("");
  console.log("PROTO  PAYLOAD     PACKETS/S   PAYLOAD RATE     IP RATE");

  for (const result of report.results) {
    console.log(
      `${result.protocol.toUpperCase().padEnd(6)}` +
      `${String(result.payloadBytes).padStart(7)} B  ` +
      `${Math.round(result.packetsPerSecond).toLocaleString("en-US").padStart(12)}  ` +
      `${formatRate(result.payloadBytesPerSecond).padStart(13)}  ` +
      `${formatRate(result.ipBytesPerSecond).padStart(11)}`,
    );
  }

  const withPayload = report.results.filter((result) => result.payloadBytes > 0);
  const maximum = withPayload.reduce((best, result) =>
    !best || result.payloadBytesPerSecond > best.payloadBytesPerSecond ? result : best
  , null);
  if (maximum) {
    console.log("");
    console.log(
      `Maximum synthetic payload throughput: ${formatRate(maximum.payloadBytesPerSecond)} ` +
      `(${maximum.protocol.toUpperCase()}, ${maximum.payloadBytes} B payloads)`,
    );
  }

  const tcpMss = report.results.find((result) =>
    result.protocol === "tcp" && result.payloadBytes === 1460
  );
  if (tcpMss) {
    console.log(
      `Production TCP MSS ceiling: ${formatRate(tcpMss.payloadBytesPerSecond)} ` +
      `(${Math.round(tcpMss.packetsPerSecond).toLocaleString("en-US")} packets/s)`,
    );
  }
}

function printHelp() {
  console.log(`Usage: npm run bench:ip-stack -- [options]

Options:
  --duration-ms=N  Measurement time per case (default: 750)
  --warmup-ms=N    Warmup time per case (default: 150)
  --protocol=VALUE tcp, udp, or both (default: both)
  --sizes=LIST     Comma-separated per-packet payload sizes, 0..65495
  --json           Emit machine-readable JSON
  --help           Show this help`);
}

if (require.main === module) {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
      printHelp();
    } else {
      const report = runBenchmark(options);
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        printReport(report);
      }
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = {
  parseArgs,
  runBenchmark,
};
