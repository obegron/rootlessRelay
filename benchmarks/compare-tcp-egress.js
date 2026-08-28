#!/usr/bin/env node
"use strict";

const { execFile } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { promisify } = require("node:util");
const {
  parseArgs: parseEgressArgs,
  runBenchmark: runEgressBenchmark,
} = require("./tcp-egress-throughput");
const {
  parseArgs: parseIngressArgs,
  runBenchmark: runIngressBenchmark,
} = require("./tcp-ingress-throughput");

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(__dirname, "..");

function parsePositiveInteger(value, option) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new TypeError(`${option} must be a positive integer`);
  }
  return parsed;
}

function parseArgs(args) {
  let baselineRef = "main";
  let runs = 5;
  let json = false;
  let help = false;
  let direction = "egress";
  const benchmarkArgs = [];

  for (const arg of args) {
    if (arg.startsWith("--baseline-ref=")) {
      baselineRef = arg.slice("--baseline-ref=".length);
      if (baselineRef.length === 0) {
        throw new TypeError("--baseline-ref must not be empty");
      }
    } else if (arg.startsWith("--runs=")) {
      runs = parsePositiveInteger(arg.slice("--runs=".length), "--runs");
    } else if (arg.startsWith("--direction=")) {
      direction = arg.slice("--direction=".length);
      if (!["egress", "ingress"].includes(direction)) {
        throw new TypeError("--direction must be egress or ingress");
      }
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--help") {
      help = true;
    } else {
      benchmarkArgs.push(arg);
    }
  }

  const benchmark = direction === "ingress"
    ? parseIngressArgs(benchmarkArgs)
    : parseEgressArgs(benchmarkArgs);
  return { baselineRef, runs, json, help, direction, benchmark };
}

function median(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
}

function summarizeNumbers(values) {
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length < 2
    ? 0
    : values.reduce((sum, value) => sum + ((value - mean) ** 2), 0) /
      (values.length - 1);
  return {
    median: median(values),
    mean,
    min: Math.min(...values),
    max: Math.max(...values),
    coefficientOfVariationPercent: mean === 0
      ? 0
      : (Math.sqrt(variance) / mean) * 100,
  };
}

function summarizeReports(reports) {
  const windows = reports[0].results.map((result) => result.tcpWindowSize);
  return windows.map((tcpWindowSize) => {
    const samples = reports.map((report) => {
      const result = report.results.find((entry) =>
        entry.tcpWindowSize === tcpWindowSize
      );
      if (!result) {
        throw new Error(`Missing ${tcpWindowSize}-byte window result`);
      }
      return result;
    });
    return {
      tcpWindowSize,
      goodputBytesPerSecond: summarizeNumbers(
        samples.map((sample) => sample.goodputBytesPerSecond),
      ),
      deliveredBytes: summarizeNumbers(
        samples.map((sample) => sample.deliveredBytes),
      ),
      droppedDataSegments: summarizeNumbers(
        samples.map((sample) => sample.droppedDataSegments),
      ),
      retransmittedSegments: summarizeNumbers(
        samples.map((sample) => sample.retransmittedSegments),
      ),
      outOfOrderSegments: summarizeNumbers(
        samples.map((sample) => sample.outOfOrderSegments),
      ),
      invalidPayloadSegments: samples.reduce(
        (sum, sample) => sum + sample.invalidPayloadSegments,
        0,
      ),
      sourceExhaustedRuns: samples.filter((sample) => sample.sourceExhausted).length,
      samples,
    };
  });
}

async function git(args) {
  const { stdout } = await execFileAsync("git", args, {
    cwd: ROOT,
    maxBuffer: 16 * 1024 * 1024,
  });
  return stdout.trim();
}

async function extractRef(ref, destination, archivePath) {
  await fs.mkdir(destination);
  await execFileAsync(
    "git",
    ["archive", "--format=tar", `--output=${archivePath}`, ref],
    { cwd: ROOT },
  );
  await execFileAsync("tar", ["-xf", archivePath, "-C", destination]);
}

async function describeCurrentWorktree() {
  const revision = await git(["rev-parse", "HEAD"]);
  const status = await git(["status", "--porcelain"]);
  return {
    label: status ? "worktree (dirty)" : "worktree",
    revision,
    root: ROOT,
  };
}

async function runComparison(options) {
  const benchmarkRunner = options.direction === "ingress"
    ? runIngressBenchmark
    : runEgressBenchmark;
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "rootlessrelay-bench-"));
  const baselineRoot = path.join(tempRoot, "baseline");
  const archivePath = path.join(tempRoot, "baseline.tar");

  try {
    const baselineRevision = await git(["rev-parse", options.baselineRef]);
    await extractRef(options.baselineRef, baselineRoot, archivePath);
    const candidates = {
      baseline: {
        label: options.baselineRef,
        revision: baselineRevision,
        root: baselineRoot,
        reports: [],
      },
      current: {
        ...await describeCurrentWorktree(),
        reports: [],
      },
    };

    for (let run = 0; run < options.runs; run++) {
      // Reverse every other pass to reduce temperature/frequency ordering bias.
      const order = run % 2 === 0
        ? [candidates.baseline, candidates.current]
        : [candidates.current, candidates.baseline];
      for (const candidate of order) {
        candidate.reports.push(await benchmarkRunner({
          ...options.benchmark,
          relayRoot: candidate.root,
        }));
      }
    }

    const baseline = {
      label: candidates.baseline.label,
      revision: candidates.baseline.revision,
      results: summarizeReports(candidates.baseline.reports),
    };
    const current = {
      label: candidates.current.label,
      revision: candidates.current.revision,
      results: summarizeReports(candidates.current.reports),
    };
    const comparisons = current.results.map((currentResult) => {
      const baselineResult = baseline.results.find((entry) =>
        entry.tcpWindowSize === currentResult.tcpWindowSize
      );
      const baselineMedian = baselineResult.goodputBytesPerSecond.median;
      const currentMedian = currentResult.goodputBytesPerSecond.median;
      return {
        tcpWindowSize: currentResult.tcpWindowSize,
        goodputRatio: baselineMedian === 0 ? null : currentMedian / baselineMedian,
        goodputChangePercent: baselineMedian === 0
          ? null
          : ((currentMedian / baselineMedian) - 1) * 100,
      };
    });

    return {
      generatedAt: new Date().toISOString(),
      node: process.version,
      platform: `${process.platform} ${process.arch}`,
      cpu: os.cpus()[0]?.model || "unknown",
      direction: options.direction,
      runs: options.runs,
      workload: options.direction === "ingress" ? {
        durationMs: options.benchmark.durationMs,
        tcpWindowSize: options.benchmark.tcpWindowSize,
        tcpMss: options.benchmark.tcpMss,
        bufferBytes: options.benchmark.bufferBytes,
        relayAckEvery: options.benchmark.relayAckEvery,
        relayAckDelayMs: options.benchmark.relayAckDelayMs,
        sinkPauseMs: options.benchmark.sinkPauseMs,
        relayRuntime: options.benchmark.relayRuntime,
      } : {
        durationMs: options.benchmark.durationMs,
        ackDelayMs: options.benchmark.ackDelayMs,
        ackEvery: options.benchmark.ackEvery,
        rxQueuePackets: options.benchmark.rxQueuePackets,
        rxServiceMs: options.benchmark.rxServiceMs,
        pacingMode: options.benchmark.pacingMode,
        sendBurstSegments: options.benchmark.sendBurstSegments,
        sendBurstMaxSegments: options.benchmark.sendBurstMaxSegments,
        sendBurstIntervalMs: options.benchmark.sendBurstIntervalMs,
        initialCwndBytes: options.benchmark.initialCwndBytes,
        tcpMss: options.benchmark.tcpMss,
        sourceBytes: options.benchmark.sourceBytes,
        windows: options.benchmark.windows,
        relayRuntime: options.benchmark.relayRuntime,
      },
      baseline,
      current,
      comparisons,
    };
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
}

function formatRate(bytesPerSecond) {
  return `${(bytesPerSecond / 1024).toFixed(0)} KiB/s`;
}

function printReport(report) {
  console.log(`TCP ${report.direction} comparison | ${report.node} | ${report.cpu}`);
  const workloadDescription = report.direction === "ingress"
    ? `${report.workload.durationMs} ms samples, relay ACK every ` +
      `${report.workload.relayAckEvery} segments or ` +
      `${report.workload.relayAckDelayMs} ms`
    : `${report.workload.durationMs} ms per window, ` +
      `${report.workload.ackDelayMs} ms ACK delay`;
  console.log(`${report.runs} alternating runs, ${workloadDescription}`);
  console.log(`Baseline: ${report.baseline.label} (${report.baseline.revision.slice(0, 12)})`);
  console.log(`Current:  ${report.current.label} (${report.current.revision.slice(0, 12)})`);
  console.log("");
  console.log("WINDOW       BASELINE        CURRENT      CHANGE    BASE CV   CURRENT CV");
  for (const comparison of report.comparisons) {
    const baseline = report.baseline.results.find((entry) =>
      entry.tcpWindowSize === comparison.tcpWindowSize
    );
    const current = report.current.results.find((entry) =>
      entry.tcpWindowSize === comparison.tcpWindowSize
    );
    const change = comparison.goodputChangePercent === null
      ? "n/a"
      : `${comparison.goodputChangePercent >= 0 ? "+" : ""}` +
        `${comparison.goodputChangePercent.toFixed(1)}%`;
    console.log(
      `${String(comparison.tcpWindowSize).padStart(6)} B  ` +
      `${formatRate(baseline.goodputBytesPerSecond.median).padStart(13)}  ` +
      `${formatRate(current.goodputBytesPerSecond.median).padStart(13)}  ` +
      `${change.padStart(9)}  ` +
      `${baseline.goodputBytesPerSecond.coefficientOfVariationPercent.toFixed(1).padStart(7)}%  ` +
      `${current.goodputBytesPerSecond.coefficientOfVariationPercent.toFixed(1).padStart(9)}%`,
    );
  }
  console.log("");
  const exhausted = [...report.baseline.results, ...report.current.results]
    .some((result) => result.sourceExhaustedRuns > 0);
  if (exhausted) {
    console.log(
      "Warning: at least one source exhausted its payload cap; increase --source-bytes " +
      "for a throughput ceiling measurement.",
    );
  }
  console.log("Medians are reported; raw samples and loss counters are available with --json.");
}

function printHelp() {
  console.log(`Usage: npm run bench:tcp-compare -- [options]

Comparison options:
  --baseline-ref=REF    Git revision used as baseline (default: main)
  --runs=N              Alternating runs per candidate (default: 5)
  --direction=NAME      egress or ingress (default: egress)
  --json                Emit machine-readable JSON with all raw samples
  --help                Show this help

TCP workload options are selected by --direction and match bench:tcp-egress or
bench:tcp-ingress. Both directions accept --duration-ms and --relay-runtime.`);
}

if (require.main === module) {
  (async () => {
    try {
      const options = parseArgs(process.argv.slice(2));
      if (options.help) {
        printHelp();
        return;
      }
      const report = await runComparison(options);
      if (options.json) console.log(JSON.stringify(report, null, 2));
      else printReport(report);
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  })();
}

module.exports = {
  median,
  parseArgs,
  runComparison,
  summarizeNumbers,
  summarizeReports,
};
