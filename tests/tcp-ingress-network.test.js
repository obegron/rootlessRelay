"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { runBenchmark } = require("../benchmarks/tcp-ingress-throughput");

function options(overrides = {}) {
  return {
    durationMs: 1000,
    tcpWindowSize: 65535,
    tcpMss: 1460,
    bufferBytes: 1024 * 1024,
    relayAckEvery: 2,
    relayAckDelayMs: 10,
    sinkPauseMs: 0,
    relayRoot: undefined,
    relayRuntime: process.execPath,
    json: false,
    ...overrides,
  };
}

test(
  "TCP ingress delivers byte-perfect data with delayed cumulative ACKs",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 20000 },
  async () => {
    const report = await runBenchmark(options());
    const result = report.results[0];

    assert.ok(result.deliveredBytes > 0);
    assert.equal(result.invalidBytes, 0);
    assert.equal(result.invalidPayloadSegments, 0);
    assert.ok(result.ackPackets < result.sentSegments * 0.7);
    assert.ok(result.ackPackets > result.sentSegments * 0.4);
    assert.ok(result.maxOutstandingBytes <= 65535);
  },
);

test(
  "TCP ingress remains live and bounded for a slow socket sink",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 20000 },
  async () => {
    const report = await runBenchmark(options({
      durationMs: 3500,
      sinkPauseMs: 500,
    }));
    const result = report.results[0];

    assert.ok(result.deliveredBytes > 0);
    assert.equal(result.invalidBytes, 0);
    assert.ok(result.maxOutstandingBytes <= 65535);
    if (result.zeroWindowAcks > 0) {
      assert.ok(result.windowReopenAcks > 0);
    } else {
      assert.equal(result.minAdvertisedWindow, 65535);
    }
  },
);
