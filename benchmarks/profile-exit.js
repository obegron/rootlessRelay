"use strict";

// Benchmark children normally die on SIGTERM. A normal exit lets Node flush
// --cpu-prof output. Load this only for explicitly requested profiling runs.
process.once("SIGTERM", () => process.exit(0));
