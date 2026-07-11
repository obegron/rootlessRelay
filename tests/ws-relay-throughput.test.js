"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildUdpEthernetFrame,
  parseArgs,
} = require("../benchmarks/ws-relay-throughput");
const {
  internetChecksum,
} = require("../packet_utils");

test("WebSocket choke benchmark parses workload options", () => {
  assert.deepEqual(
    parseArgs([
      "--duration-ms=500",
      "--warmup-ms=50",
      "--buffer-bytes=65536",
      "--sizes=64,1400",
      "--json",
    ]),
    {
      durationMs: 500,
      warmupMs: 50,
      bufferBytes: 65536,
      sizes: [64, 1400],
      json: true,
    },
  );
});

test("WebSocket choke benchmark builds a valid Ethernet/IPv4/UDP frame", () => {
  const frame = buildUdpEthernetFrame(101, 12345);
  const ip = frame.subarray(14);
  const udp = ip.subarray(20);

  assert.equal(frame.readUInt16BE(12), 0x0800);
  assert.equal(ip[9], 17);
  assert.equal(ip.readUInt16BE(2), 20 + 8 + 101);
  assert.equal(internetChecksum(ip.subarray(0, 20)), 0);
  assert.equal(udp.readUInt16BE(2), 12345);
  assert.equal(udp.readUInt16BE(4), 8 + 101);
  assert.equal(udp.subarray(8).length, 101);
});

test("WebSocket choke benchmark rejects invalid options", () => {
  assert.throws(() => parseArgs(["--sizes=0"]), /1 through 65507/);
  assert.throws(() => parseArgs(["--buffer-bytes=nope"]), /positive integer/);
  assert.throws(() => parseArgs(["--other"]), /Unknown option/);
});
