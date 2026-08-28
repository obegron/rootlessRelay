"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseArgs } = require("../benchmarks/tcp-ingress-throughput");

test("TCP ingress benchmark parses upload workload options", () => {
  const options = parseArgs([
    "--duration-ms=500",
    "--window=10240",
    "--tcp-mss=8960",
    "--buffer-bytes=65536",
    "--relay-ack-every=3",
    "--relay-ack-delay-ms=5",
    "--sink-pause-ms=2",
    "--relay-root=.",
    "--relay-runtime=bun",
    "--json",
  ]);
  assert.equal(options.durationMs, 500);
  assert.equal(options.tcpWindowSize, 10240);
  assert.equal(options.tcpMss, 8960);
  assert.equal(options.bufferBytes, 65536);
  assert.equal(options.relayAckEvery, 3);
  assert.equal(options.relayAckDelayMs, 5);
  assert.equal(options.sinkPauseMs, 2);
  assert.equal(options.relayRoot, ".");
  assert.equal(options.relayRuntime, "bun");
  assert.equal(options.json, true);
});

test("TCP ingress benchmark rejects invalid options", () => {
  assert.throws(() => parseArgs(["--duration-ms=0"]), /at least 1/);
  assert.throws(() => parseArgs(["--window=65536"]), /through 65535/);
  assert.throws(() => parseArgs(["--tcp-mss=535"]), /from 536/);
  assert.throws(() => parseArgs(["--relay-ack-delay-ms=-1"]), /at least 0/);
  assert.throws(() => parseArgs(["--other"]), /Unknown option/);
});
