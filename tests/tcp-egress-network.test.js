"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  runBenchmark,
} = require("../benchmarks/tcp-egress-throughput");

test(
  "paced TCP egress uses a large window without oversized-burst collapse",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 20000 },
  async () => {
    const report = await runBenchmark({
      durationMs: 1200,
      ackDelayMs: 20,
      ackEvery: 2,
      rxQueuePackets: 8,
      rxServiceMs: 5,
      sendBurstSegments: 3,
      sendBurstIntervalMs: 6,
      initialCwndBytes: 10240,
      windows: [10240, 65535],
      json: false,
    });
    const [smallWindow, largeWindow] = report.results;

    assert.equal(smallWindow.invalidPayloadSegments, 0);
    assert.equal(largeWindow.invalidPayloadSegments, 0);
    assert.ok(smallWindow.deliveredBytes > 0);
    assert.ok(largeWindow.deliveredBytes > 0);

    // The paced sender must let the fake NIC service each bounded batch instead
    // of treating the entire 65,535-byte receive window as one burst.
    assert.equal(smallWindow.droppedDataSegments, 0);
    assert.equal(largeWindow.droppedDataSegments, 0);
    assert.equal(smallWindow.retransmittedSegments, 0);
    assert.equal(largeWindow.retransmittedSegments, 0);
    assert.ok(
      largeWindow.goodputBytesPerSecond > smallWindow.goodputBytesPerSecond * 1.2,
      `expected the large window to improve goodput: ` +
        `${smallWindow.goodputBytesPerSecond} versus ` +
        `${largeWindow.goodputBytesPerSecond} bytes/s`,
    );

    const expectedWindowRate = 10240 / 0.020;
    assert.ok(smallWindow.goodputBytesPerSecond > expectedWindowRate * 0.6);
    assert.ok(smallWindow.goodputBytesPerSecond < expectedWindowRate * 1.4);
  },
);

test(
  "congestion recovery prevents slow fake-VM loss from becoming RTO collapse",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 20000 },
  async () => {
    const report = await runBenchmark({
      durationMs: 3000,
      ackDelayMs: 20,
      ackEvery: 2,
      rxQueuePackets: 12,
      rxServiceMs: 20,
      sendBurstSegments: 4,
      sendBurstIntervalMs: 3,
      initialCwndBytes: 10240,
      windows: [10240, 65535],
      json: false,
    });
    const [smallWindow, recoveringWindow] = report.results;

    assert.equal(smallWindow.invalidPayloadSegments, 0);
    assert.equal(recoveringWindow.invalidPayloadSegments, 0);
    assert.equal(smallWindow.droppedDataSegments, 0);
    assert.equal(smallWindow.retransmittedSegments, 0);
    assert.ok(recoveringWindow.droppedDataSegments > 0);
    assert.ok(recoveringWindow.retransmittedSegments > 0);
    assert.ok(
      recoveringWindow.goodputBytesPerSecond >
        smallWindow.goodputBytesPerSecond * 0.7,
      `expected recovery to avoid RTO collapse: ` +
        `${smallWindow.goodputBytesPerSecond} versus ` +
        `${recoveringWindow.goodputBytesPerSecond} bytes/s`,
    );
  },
);

test(
  "negotiated jumbo MSS raises goodput without increasing fake-NIC packet load",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 20000 },
  async () => {
    const baseOptions = {
      durationMs: 1500,
      ackDelayMs: 20,
      ackEvery: 2,
      rxQueuePackets: 12,
      rxServiceMs: 20,
      sendBurstSegments: 3,
      sendBurstIntervalMs: 5,
      initialCwndBytes: 10240,
      windows: [65535],
      json: false,
    };
    const standard = await runBenchmark({ ...baseOptions, tcpMss: 1460 });
    const jumbo = await runBenchmark({ ...baseOptions, tcpMss: 8960 });
    const standardResult = standard.results[0];
    const jumboResult = jumbo.results[0];

    assert.equal(standardResult.invalidPayloadSegments, 0);
    assert.equal(jumboResult.invalidPayloadSegments, 0);
    assert.equal(standardResult.maxDataSegmentBytes, 1460);
    assert.equal(jumboResult.maxDataSegmentBytes, 8960);
    assert.equal(jumboResult.droppedDataSegments, 0);
    assert.ok(
      jumboResult.goodputBytesPerSecond >
        standardResult.goodputBytesPerSecond * 2,
      `expected jumbo MSS to at least double goodput: ` +
        `${standardResult.goodputBytesPerSecond} versus ` +
        `${jumboResult.goodputBytesPerSecond} bytes/s`,
    );
  },
);
