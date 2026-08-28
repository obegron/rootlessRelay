"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildTCPFrame,
  parseArgs,
  parseTCPFrame,
} = require("../benchmarks/tcp-egress-throughput");
const path = require("node:path");

test("TCP egress benchmark parses the fake-VM workload", () => {
  assert.deepEqual(
    parseArgs([
      "--duration-ms=500",
      "--ack-delay-ms=20",
      "--ack-every=2",
      "--rx-queue-packets=8",
      "--rx-service-ms=5",
      "--pacing-mode=fixed",
      "--send-burst-segments=4",
      "--send-burst-max-segments=12",
      "--send-burst-interval-ms=3",
      "--initial-cwnd-bytes=10240",
      "--tcp-mss=8960",
      "--source-bytes=1048576",
      "--windows=10240,65535",
      "--relay-root=.",
      "--relay-runtime=node",
      "--json",
    ]),
    {
      durationMs: 500,
      ackDelayMs: 20,
      ackEvery: 2,
      rxQueuePackets: 8,
      rxServiceMs: 5,
      pacingMode: "fixed",
      sendBurstSegments: 4,
      sendBurstMaxSegments: 12,
      sendBurstIntervalMs: 3,
      initialCwndBytes: 10240,
      tcpMss: 8960,
      sourceBytes: 1048576,
      windows: [10240, 65535],
      relayRoot: path.resolve("."),
      relayRuntime: "node",
      json: true,
    },
  );
});

test("TCP egress benchmark builds and parses a valid VM ACK frame", () => {
  const frame = buildTCPFrame({
    srcIP: "10.0.2.15",
    dstIP: "127.0.0.1",
    srcPort: 41000,
    dstPort: 443,
    seq: 1001,
    ack: 0x12345678,
    window: 10240,
    flags: { ack: true },
  });
  const parsed = parseTCPFrame(frame);

  assert.equal(parsed.srcIP, "10.0.2.15");
  assert.equal(parsed.dstIP, "127.0.0.1");
  assert.equal(parsed.srcPort, 41000);
  assert.equal(parsed.dstPort, 443);
  assert.equal(parsed.seq, 1001);
  assert.equal(parsed.ack, 0x12345678);
  assert.equal(parsed.window, 10240);
  assert.equal(parsed.ackFlag, true);
  assert.equal(parsed.payload.length, 0);
});

test("TCP egress benchmark builds and parses a SYN MSS option", () => {
  const frame = buildTCPFrame({
    srcIP: "10.0.2.15",
    dstIP: "127.0.0.1",
    srcPort: 41000,
    dstPort: 443,
    seq: 1000,
    flags: { syn: true },
    mss: 8960,
  });

  const parsed = parseTCPFrame(frame);
  assert.equal(parsed.syn, true);
  assert.equal(parsed.mss, 8960);
  assert.equal(parsed.payload.length, 0);
});

test("TCP egress benchmark rejects invalid workload options", () => {
  assert.throws(() => parseArgs(["--duration-ms=0"]), /at least 1/);
  assert.throws(() => parseArgs(["--ack-delay-ms=-1"]), /at least 0/);
  assert.throws(() => parseArgs(["--send-burst-segments=0"]), /at least 1/);
  assert.throws(() => parseArgs(["--pacing-mode=other"]), /adaptive, fixed, or off/);
  assert.throws(
    () => parseArgs([
      "--send-burst-segments=4",
      "--send-burst-max-segments=3",
    ]),
    /must be at least/,
  );
  assert.throws(() => parseArgs(["--initial-cwnd-bytes=1459"]), /from 1460/);
  assert.throws(() => parseArgs(["--tcp-mss=535"]), /from 536/);
  assert.throws(() => parseArgs(["--source-bytes=1024"]), /at least 65536/);
  assert.throws(() => parseArgs(["--windows=65536"]), /through 65535/);
  assert.throws(() => parseArgs(["--relay-root="]), /must not be empty/);
  assert.throws(() => parseArgs(["--relay-runtime="]), /must not be empty/);
  assert.throws(() => parseArgs(["--other"]), /Unknown option/);
});
