"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { SlidingWindowRateLimiter } = require("../rate_limiter");

test("sliding window limiter accepts bytes up to its exact limit", () => {
  let now = 1000;
  const limiter = new SlidingWindowRateLimiter(100, 1000, () => now);

  assert.equal(limiter.tryConsume(40), true);
  assert.equal(limiter.tryConsume(60), true);
  assert.equal(limiter.usage, 100);
  assert.equal(limiter.tryConsume(1), false);
  assert.equal(limiter.usage, 100);
});

test("sliding window limiter expires entries at the window boundary", () => {
  let now = 1000;
  const limiter = new SlidingWindowRateLimiter(100, 1000, () => now);
  limiter.tryConsume(100);

  now = 1999;
  assert.equal(limiter.tryConsume(1), false);
  now = 2000;
  assert.equal(limiter.tryConsume(100), true);
  assert.equal(limiter.usage, 100);
});

test("sliding window limiter prunes incrementally across timestamps", () => {
  let now = 0;
  const limiter = new SlidingWindowRateLimiter(100, 1000, () => now);
  assert.equal(limiter.tryConsume(30), true);
  now = 500;
  assert.equal(limiter.tryConsume(40), true);
  now = 1000;
  assert.equal(limiter.usage, 40);
  assert.equal(limiter.tryConsume(60), true);
  now = 1500;
  assert.equal(limiter.usage, 60);
});

test("sliding window limiter compacts a long packet history", () => {
  let now = 0;
  const limiter = new SlidingWindowRateLimiter(5000, 1000, () => now);
  for (let index = 0; index < 2048; index++) {
    assert.equal(limiter.tryConsume(1), true);
  }

  now = 1000;
  assert.equal(limiter.usage, 0);
  assert.equal(limiter.entries.length, 0);
  assert.equal(limiter.head, 0);
});

test("sliding window limiter validates configuration and consumption", () => {
  assert.throws(() => new SlidingWindowRateLimiter(0, 1000), /maxBytes/);
  assert.throws(() => new SlidingWindowRateLimiter(100, 0), /windowMs/);

  const limiter = new SlidingWindowRateLimiter(100, 1000);
  assert.throws(() => limiter.tryConsume(-1), /non-negative/);
  assert.equal(limiter.tryConsume(0), true);
});

test("same-millisecond aggregation preserves exact expiration boundaries", () => {
  let now = 0;
  const limiter = new SlidingWindowRateLimiter(5000, 1000, () => now);
  for (let i = 0; i < 2000; i++) assert.equal(limiter.tryConsume(1), true);
  assert.equal(limiter.entries.length, 1);
  now = 1;
  assert.equal(limiter.tryConsume(3000), true);
  assert.equal(limiter.tryConsume(1), false);
  now = 1000;
  assert.equal(limiter.usage, 3000);
  assert.equal(limiter.tryConsume(2000), true);
  assert.equal(limiter.tryConsume(1), false);
  now = 1001;
  assert.equal(limiter.usage, 2000);
  now = 2000;
  assert.equal(limiter.usage, 0);
});
