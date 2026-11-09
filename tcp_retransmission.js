"use strict";

const HALF_SEQUENCE_SPACE = 0x80000000;

function sequenceDistance(later, earlier) {
  return (later - earlier) >>> 0;
}

function sequenceLength(payload, flags) {
  return payload.length + (flags.syn ? 1 : 0) + (flags.fin ? 1 : 0);
}

class TCPRetransmissionQueue {
  constructor({
    initialSequence,
    onRetransmit,
    onExhausted,
    onPersistProbe,
    initialRtoMs = 1000,
    minRtoMs = Math.min(200, initialRtoMs),
    maxRtoMs = 60000,
    maxRetransmissions = 4,
    giveUpMs = 0,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
    now = Date.now,
  }) {
    if (!Number.isInteger(initialSequence)) {
      throw new TypeError("initialSequence must be an integer");
    }
    if (typeof onRetransmit !== "function" || typeof onExhausted !== "function") {
      throw new TypeError("retransmission callbacks are required");
    }
    if (
      initialRtoMs <= 0 || maxRtoMs < initialRtoMs ||
      !(minRtoMs > 0) || minRtoMs > maxRtoMs
    ) {
      throw new TypeError("invalid RTO range");
    }
    if (!Number.isFinite(giveUpMs) || giveUpMs < 0) {
      throw new TypeError("giveUpMs must be a non-negative number");
    }
    if (!Number.isInteger(maxRetransmissions) || maxRetransmissions < 1) {
      throw new TypeError("maxRetransmissions must be a positive integer");
    }

    this.sndUna = initialSequence >>> 0;
    this.sndNxt = initialSequence >>> 0;
    this.onRetransmit = onRetransmit;
    this.onExhausted = onExhausted;
    this.onPersistProbe = onPersistProbe;
    this.persist = false;
    this.initialRtoMs = initialRtoMs;
    this.minRtoMs = minRtoMs;
    this.maxRtoMs = maxRtoMs;
    this.maxRetransmissions = maxRetransmissions;
    this.giveUpMs = giveUpMs;
    this.setTimeoutFn = setTimeoutFn;
    this.clearTimeoutFn = clearTimeoutFn;
    this.now = now;
    // RFC 6298 estimator state. rtoMs is the un-backed-off timeout; it stays
    // at initialRtoMs until the first valid RTT sample.
    this.srttMs = null;
    this.rttvarMs = null;
    this.rtoMs = initialRtoMs;
    this.currentRtoMs = initialRtoMs;
    this.timeoutRetransmissions = 0;
    this.firstTimeoutAt = null;
    this.segments = [];
    this.payloadBytesInFlight = 0;
    this.timer = null;
    this.timerAt = 0; // When the pending timer fires.
    this.deadline = null; // When the retransmission timeout expires.
    this.timerGeneration = 0;
    this.closed = false;
    this.exhausted = false;
  }

  get hasOutstanding() {
    return this.segments.length > 0;
  }

  get oldest() {
    return this.segments[0] || null;
  }

  track({ seq, payload, flags = {} }) {
    if (this.closed || this.exhausted) {
      throw new Error("cannot track data on a closed retransmission queue");
    }
    if (!Buffer.isBuffer(payload)) {
      throw new TypeError("tracked payload must be a Buffer");
    }

    const length = sequenceLength(payload, flags);
    if (length === 0) return false;
    const normalizedSeq = seq >>> 0;
    if (normalizedSeq !== this.sndNxt) {
      throw new RangeError(
        `non-contiguous TCP segment: expected ${this.sndNxt}, got ${normalizedSeq}`,
      );
    }

    const segment = {
      seq: normalizedSeq,
      payload,
      flags: { ...flags },
      sequenceLength: length,
      retransmissions: 0,
      sentAt: this.now(),
      retransmitted: false,
    };
    this.segments.push(segment);
    this.payloadBytesInFlight += payload.length;
    this.sndNxt = (this.sndNxt + length) >>> 0;
    if (this.segments.length === 1 && this.deadline === null) this.armTimer();
    return true;
  }

  acknowledge(ackNumber) {
    const ack = ackNumber >>> 0;
    const advance = sequenceDistance(ack, this.sndUna);
    const outstanding = sequenceDistance(this.sndNxt, this.sndUna);

    if (advance === 0) {
      if (this.persist) this.timeoutRetransmissions = 0;
      return { status: "duplicate", ackedDataBytes: 0 };
    }
    if (advance >= HALF_SEQUENCE_SPACE) {
      return { status: "stale", ackedDataBytes: 0 };
    }
    if (advance > outstanding) {
      return { status: "future", ackedDataBytes: 0 };
    }

    let remaining = advance;
    let ackedDataBytes = 0;
    let sampleSentAt = null;
    let ambiguous = false;
    while (remaining > 0) {
      const segment = this.segments[0];
      if (!segment) throw new Error("ACK advanced beyond tracked TCP segments");

      if (remaining >= segment.sequenceLength) {
        remaining -= segment.sequenceLength;
        ackedDataBytes += segment.payload.length;
        this.payloadBytesInFlight -= segment.payload.length;
        // Karn's algorithm: an ACK covering any retransmitted segment cannot
        // be attributed to a specific transmission, so it yields no sample.
        if (segment.retransmitted) ambiguous = true;
        else sampleSentAt = segment.sentAt;
        this.segments.shift();
        continue;
      }

      const consumed = this.consumeSegmentPrefix(segment, remaining);
      ackedDataBytes += consumed;
      this.payloadBytesInFlight -= consumed;
      remaining = 0;
    }

    this.sndUna = ack;
    this.timeoutRetransmissions = 0;
    this.firstTimeoutAt = null;
    if (!ambiguous && sampleSentAt !== null) {
      this.sampleRtt(Math.max(0, this.now() - sampleSentAt));
    }
    if (!this.persist) this.currentRtoMs = this.rtoMs;
    // Restart the timer (RFC 6298 5.3), or stop it if nothing is left.
    if (!this.hasOutstanding && !this.persist) this.clearTimer();
    else this.armTimer();
    return { status: "advanced", ackedDataBytes };
  }

  // RFC 6298 section 2. Clock granularity is one millisecond (Date.now).
  sampleRtt(rttMs) {
    if (this.srttMs === null) {
      this.srttMs = rttMs;
      this.rttvarMs = rttMs / 2;
    } else {
      this.rttvarMs = 0.75 * this.rttvarMs + 0.25 * Math.abs(this.srttMs - rttMs);
      this.srttMs = 0.875 * this.srttMs + 0.125 * rttMs;
    }
    this.rtoMs = Math.min(
      this.maxRtoMs,
      Math.max(
        this.minRtoMs,
        Math.ceil(this.srttMs + Math.max(1, 4 * this.rttvarMs)),
      ),
    );
  }

  // Exclude a segment from RTT sampling after the caller resent it outside
  // this queue (for example, a NewReno partial-ACK repair or a window probe).
  noteRetransmitted(segment) {
    if (segment) segment.retransmitted = true;
  }

  // Give up only after both the retransmission count and, when configured,
  // a minimum wall-clock budget are spent. With an adaptive RTO the count
  // alone could abort a connection within seconds on a fast link.
  shouldGiveUp() {
    if (this.timeoutRetransmissions < this.maxRetransmissions) return false;
    if (this.giveUpMs === 0 || this.firstTimeoutAt === null) return true;
    return this.now() - this.firstTimeoutAt >= this.giveUpMs;
  }

  noteTimeout() {
    if (this.timeoutRetransmissions === 0) this.firstTimeoutAt = this.now();
    this.timeoutRetransmissions++;
  }

  consumeSegmentPrefix(segment, count) {
    let remaining = count;
    let consumedData = 0;

    if (segment.flags.syn && remaining > 0) {
      segment.flags.syn = false;
      segment.sequenceLength--;
      remaining--;
    }

    if (remaining > 0 && segment.payload.length > 0) {
      const bytes = Math.min(remaining, segment.payload.length);
      segment.payload = segment.payload.subarray(bytes);
      segment.sequenceLength -= bytes;
      remaining -= bytes;
      consumedData += bytes;
    }

    if (segment.flags.fin && remaining > 0) {
      segment.flags.fin = false;
      segment.sequenceLength--;
      remaining--;
    }

    if (remaining !== 0 || segment.sequenceLength <= 0) {
      throw new Error("invalid partial TCP acknowledgement");
    }
    segment.seq = (segment.seq + count) >>> 0;
    return consumedData;
  }

  fastRetransmit() {
    if (this.persist || !this.hasOutstanding || this.closed || this.exhausted) return false;
    this.currentRtoMs = this.rtoMs;
    this.clearTimer();
    if (!this.emitRetransmission("fast")) return false;
    this.armTimer();
    return true;
  }

  setPersist(enabled) {
    if (this.closed || this.exhausted || this.persist === enabled) return;
    if (enabled && typeof this.onPersistProbe !== "function") {
      throw new TypeError("a persist probe callback is required");
    }
    this.persist = enabled;
    this.clearTimer();
    this.currentRtoMs = this.rtoMs;
    this.timeoutRetransmissions = 0;
    this.firstTimeoutAt = null;
    // Repair a rejected/lost probe immediately when the peer reopens its
    // window, rather than making subsequent data wait for another RTO.
    if (!enabled && this.hasOutstanding) this.emitRetransmission("window-open");
    this.armTimer();
  }

  // (Re)start the retransmission timeout at now + currentRtoMs. Restarting
  // happens on every ACK, so it only moves the deadline when the pending
  // timer fires no later than it; the timer then re-arms for the remainder.
  // This avoids a clearTimeout/setTimeout pair per ACK.
  armTimer() {
    if ((!this.hasOutstanding && !this.persist) || this.closed || this.exhausted) return;
    const now = this.now();
    this.deadline = now + this.currentRtoMs;
    if (this.timer !== null) {
      if (this.timerAt <= this.deadline) return;
      this.clearTimeoutFn(this.timer);
      this.timer = null;
    }
    this.scheduleTimer(now);
  }

  scheduleTimer(now) {
    const generation = ++this.timerGeneration;
    const delay = Math.max(0, this.deadline - now);
    this.timerAt = now + delay;
    this.timer = this.setTimeoutFn(() => {
      if (generation !== this.timerGeneration) return;
      this.timer = null;
      if (this.closed || this.exhausted || this.deadline === null) return;
      const firedAt = this.now();
      if (firedAt < this.deadline) {
        this.scheduleTimer(firedAt);
        return;
      }
      this.deadline = null;
      this.handleTimeout();
    }, delay);
  }

  clearTimer() {
    this.timerGeneration++;
    this.deadline = null;
    if (this.timer !== null) {
      this.clearTimeoutFn(this.timer);
      this.timer = null;
    }
  }

  handleTimeout() {
    if (this.closed || this.exhausted) return;
    if (this.persist) {
      if (this.shouldGiveUp()) {
        this.exhausted = true;
        this.clearTimer();
        this.onExhausted(new Error("TCP zero-window probe limit exceeded"), this.oldest);
        return;
      }
      this.noteTimeout();
      this.noteRetransmitted(this.oldest);
      try {
        if (this.onPersistProbe(this.oldest) === false) {
          // Transport backpressure is not a missed response from the peer.
          this.timeoutRetransmissions--;
          if (this.timeoutRetransmissions === 0) this.firstTimeoutAt = null;
        }
      } catch (error) {
        this.exhausted = true;
        this.clearTimer();
        this.onExhausted(error, this.oldest);
        return;
      }
      // A probe can track its first byte and arm a timer; keep exactly one.
      this.clearTimer();
      this.currentRtoMs = Math.min(this.currentRtoMs * 2, this.maxRtoMs);
      this.armTimer();
      return;
    }
    if (!this.hasOutstanding) return;
    if (this.shouldGiveUp()) {
      this.exhausted = true;
      this.clearTimer();
      this.onExhausted(new Error("TCP retransmission limit exceeded"), this.oldest);
      return;
    }

    this.noteTimeout();
    this.oldest.retransmissions++;
    if (!this.emitRetransmission("timeout")) return;
    this.currentRtoMs = Math.min(this.currentRtoMs * 2, this.maxRtoMs);
    this.armTimer();
  }

  emitRetransmission(reason) {
    this.noteRetransmitted(this.oldest);
    try {
      this.onRetransmit(this.oldest, reason);
      return true;
    } catch (error) {
      this.exhausted = true;
      this.clearTimer();
      this.onExhausted(error, this.oldest);
      return false;
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.persist = false;
    this.clearTimer();
    this.segments.length = 0;
    this.payloadBytesInFlight = 0;
  }
}

module.exports = {
  TCPRetransmissionQueue,
  sequenceDistance,
  sequenceLength,
};
