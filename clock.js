"use strict";

// A millisecond wall clock read at most once per synchronous run of work.
//
// The relay consults the time for every segment (rate limiting, pacing, RTT
// sampling, retransmission deadlines). Date.now() is normally cheap, but on
// hosts whose clocksource is not the TSC (HPET or ACPI PM timers, common on
// some VMs and kernels) each call is a syscall costing a microsecond or more.
// Work triggered by one event (a WebSocket message, a socket read, a timer)
// runs synchronously, and millisecond precision cannot distinguish instants
// within it, so a single reading is shared until the microtask queue drains.
let cachedNow = 0;
let cached = false;

function invalidate() {
  cached = false;
}

function coarseNow() {
  if (!cached) {
    cachedNow = Date.now();
    cached = true;
    queueMicrotask(invalidate);
  }
  return cachedNow;
}

module.exports = { coarseNow };
