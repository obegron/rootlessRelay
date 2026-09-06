"use strict";

class SlidingWindowRateLimiter {
  constructor(maxBytes, windowMs, now = Date.now) {
    if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
      throw new TypeError("maxBytes must be positive");
    }
    if (!Number.isFinite(windowMs) || windowMs <= 0) {
      throw new TypeError("windowMs must be positive");
    }

    this.maxBytes = maxBytes;
    this.windowMs = windowMs;
    this.now = now;
    this.entries = [];
    this.head = 0;
    this.totalBytes = 0;
  }

  tryConsume(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) {
      throw new TypeError("bytes must be a non-negative number");
    }

    const now = this.now();
    this.prune(now);
    if (this.totalBytes + bytes > this.maxBytes) return false;

    if (bytes > 0) {
      // Date.now has millisecond precision. Bytes accepted at the same
      // timestamp expire together, so one entry preserves the exact limit.
      const last = this.entries[this.entries.length - 1];
      if (last && last.timestamp === now) last.bytes += bytes;
      else this.entries.push({ timestamp: now, bytes });
      this.totalBytes += bytes;
    }
    return true;
  }

  prune(now = this.now()) {
    const cutoff = now - this.windowMs;
    while (
      this.head < this.entries.length &&
      this.entries[this.head].timestamp <= cutoff
    ) {
      this.totalBytes -= this.entries[this.head].bytes;
      this.head++;
    }

    if (this.head === this.entries.length) {
      this.entries.length = 0;
      this.head = 0;
    } else if (this.head >= 1024 && this.head * 2 >= this.entries.length) {
      this.entries = this.entries.slice(this.head);
      this.head = 0;
    }
  }

  get usage() {
    this.prune();
    return this.totalBytes;
  }
}

module.exports = {
  SlidingWindowRateLimiter,
};
