"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  median,
  parseArgs,
  summarizeNumbers,
} = require("../benchmarks/compare-tcp-egress");

test("TCP comparison parses comparison and workload options", () => {
  const options = parseArgs([
    "--baseline-ref=HEAD~1",
    "--runs=3",
    "--duration-ms=500",
    "--windows=65535",
    "--json",
  ]);

  assert.equal(options.baselineRef, "HEAD~1");
  assert.equal(options.runs, 3);
  assert.equal(options.json, true);
  assert.equal(options.direction, "egress");
  assert.equal(options.benchmark.durationMs, 500);
  assert.deepEqual(options.benchmark.windows, [65535]);
});

test("TCP comparison selects the ingress workload", () => {
  const options = parseArgs([
    "--direction=ingress",
    "--duration-ms=500",
    "--window=10240",
    "--sink-pause-ms=2",
  ]);
  assert.equal(options.direction, "ingress");
  assert.equal(options.benchmark.durationMs, 500);
  assert.equal(options.benchmark.tcpWindowSize, 10240);
  assert.equal(options.benchmark.sinkPauseMs, 2);
});

test("TCP comparison rejects invalid comparison options", () => {
  assert.throws(() => parseArgs(["--baseline-ref="]), /must not be empty/);
  assert.throws(() => parseArgs(["--runs=0"]), /positive integer/);
  assert.throws(() => parseArgs(["--direction=sideways"]), /egress or ingress/);
});

test("TCP comparison calculates medians and sample variability", () => {
  assert.equal(median([9, 1, 5]), 5);
  assert.equal(median([4, 2, 8, 6]), 5);
  const summary = summarizeNumbers([100, 110, 90]);
  assert.equal(summary.median, 100);
  assert.equal(summary.mean, 100);
  assert.equal(summary.min, 90);
  assert.equal(summary.max, 110);
  assert.equal(summary.coefficientOfVariationPercent, 10);
});
