"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  parseArgs,
  runBenchmark,
} = require("../benchmarks/ip-stack-throughput");

test("throughput benchmark parses reproducible workload options", () => {
  assert.deepEqual(
    parseArgs([
      "--duration-ms=25",
      "--warmup-ms=5",
      "--protocol=tcp",
      "--sizes=64,1460",
      "--json",
    ]),
    {
      durationMs: 25,
      warmupMs: 5,
      protocols: ["tcp"],
      sizes: [64, 1460],
      json: true,
    },
  );
});

test("throughput benchmark rejects invalid workload options", () => {
  assert.throws(() => parseArgs(["--duration-ms=0"]), /positive integer/);
  assert.throws(() => parseArgs(["--protocol=icmp"]), /tcp, udp, or both/);
  assert.throws(() => parseArgs(["--sizes=65500"]), /0 through 65495/);
  assert.throws(() => parseArgs(["--unknown"]), /Unknown option/);
});

test("throughput benchmark smoke test processes checksummed packets", () => {
  const report = runBenchmark({
    durationMs: 1,
    warmupMs: 1,
    protocols: ["tcp"],
    sizes: [64],
  });

  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].protocol, "tcp");
  assert.equal(report.results[0].payloadBytes, 64);
  assert.ok(report.results[0].packets >= 64);
  assert.ok(report.results[0].packetsPerSecond > 0);
  assert.ok(report.results[0].payloadBytesPerSecond > 0);
});
