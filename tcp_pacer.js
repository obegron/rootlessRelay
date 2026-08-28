"use strict";

const VALID_MODES = new Set(["adaptive", "fixed", "off"]);

class TCPPacer {
  constructor({
    mode = "adaptive",
    initialBurstSegments = 3,
    maxBurstSegments = 8,
    intervalMs = 6,
    now = Date.now,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = {}) {
    if (!VALID_MODES.has(mode)) {
      throw new TypeError("TCP pacing mode must be adaptive, fixed, or off");
    }
    if (!Number.isInteger(initialBurstSegments) || initialBurstSegments < 1) {
      throw new TypeError("initial TCP pacing burst must be a positive integer");
    }
    if (
      !Number.isInteger(maxBurstSegments) ||
      maxBurstSegments < initialBurstSegments
    ) {
      throw new TypeError(
        "maximum TCP pacing burst must be at least the initial burst",
      );
    }
    if (!Number.isInteger(intervalMs) || intervalMs < 0) {
      throw new TypeError("TCP pacing interval must be a non-negative integer");
    }

    this.mode = intervalMs === 0 ? "off" : mode;
    this.initialBurstSegments = initialBurstSegments;
    this.maxBurstSegments = maxBurstSegments;
    this.intervalMs = intervalMs;
    this.now = now;
    this.setTimeoutFn = setTimeoutFn;
    this.clearTimeoutFn = clearTimeoutFn;
    this.burstSegments = initialBurstSegments;
    this.segmentsInBurst = 0;
    this.ackedBytes = 0;
    this.lastSegmentAt = null;
    this.blocked = false;
    this.timer = null;
  }

  get isOff() {
    return this.mode === "off";
  }

  noteAck(ackedBytes, congestionWindowBytes) {
    if (this.mode !== "adaptive" || ackedBytes <= 0) return false;
    const threshold = Math.max(1, Math.floor(congestionWindowBytes));
    this.ackedBytes += ackedBytes;
    if (
      this.ackedBytes < threshold ||
      this.burstSegments >= this.maxBurstSegments
    ) return false;

    this.ackedBytes -= threshold;
    this.burstSegments++;
    return true;
  }

  noteLoss() {
    this.ackedBytes = 0;
    if (this.mode !== "adaptive") return false;
    const reduced = Math.max(
      this.initialBurstSegments,
      Math.floor(this.burstSegments / 2),
    );
    if (reduced === this.burstSegments) return false;
    this.burstSegments = reduced;
    return true;
  }

  noteSegment(onReady) {
    if (this.isOff) return false;
    if (this.blocked) return true;

    const now = this.now();
    if (
      this.lastSegmentAt !== null &&
      now - this.lastSegmentAt >= this.intervalMs
    ) {
      this.segmentsInBurst = 0;
    }
    this.lastSegmentAt = now;
    this.segmentsInBurst++;
    if (this.segmentsInBurst < this.burstSegments) return false;

    this.segmentsInBurst = 0;
    this.blocked = true;
    this.timer = this.setTimeoutFn(() => {
      this.timer = null;
      this.blocked = false;
      onReady();
    }, this.intervalMs);
    return true;
  }

  close() {
    if (this.timer !== null) {
      this.clearTimeoutFn(this.timer);
      this.timer = null;
    }
    this.blocked = false;
    this.segmentsInBurst = 0;
  }
}

module.exports = {
  TCPPacer,
  VALID_MODES,
};
