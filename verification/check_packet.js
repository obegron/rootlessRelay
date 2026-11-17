"use strict";
const pu = require("../packet_utils");
const { check, rng } = require("./sim");
const r = rng(4242);
const rb = () => Math.floor(r() * 256);

// Independent RFC 1071 reference: 16-bit big-endian words, end-around carry.
function refSum(bytes) {
  let s = 0n;
  for (let i = 0; i < bytes.length; i += 2) s += BigInt((bytes[i] << 8) | (i + 1 < bytes.length ? bytes[i + 1] : 0));
  while (s > 0xffffn) s = (s & 0xffffn) + (s >> 16n);
  return Number(s);
}
const refChecksum = (bytes) => (~refSum(bytes)) & 0xffff;

let n = 0;
// Exhaustive: every 0, 1 and 2 byte buffer.
check(pu.internetChecksum(Buffer.alloc(0)) === 0xffff, "empty checksum");
for (let a = 0; a < 256; a++) {
  check(pu.internetChecksum(Buffer.from([a])) === refChecksum([a]), `1-byte ${a}`); n++;
  for (let b = 0; b < 256; b++) { check(pu.internetChecksum(Buffer.from([a, b])) === refChecksum([a, b]), `2-byte ${a},${b}`); n++; }
}
// Randomised across lengths straddling the 8-byte, 64-byte (32-bit path) thresholds, all alignments, extremes.
for (let i = 0; i < 40000; i++) {
  const len = i < 20000 ? Math.floor(r() * 200) : Math.floor(r() * 9000);
  const align = i % 4, pad = i % 3;
  const mode = i % 5;
  const raw = Buffer.alloc(len + 8 + align);
  const view = raw.subarray(align + pad, align + pad + len);
  for (let k = 0; k < view.length; k++) view[k] = mode === 0 ? 0xff : mode === 1 ? 0 : rb();
  check(pu.internetChecksum(view) === refChecksum(view), `checksum len=${len} align=${(raw.byteOffset + align + pad) & 3} mode=${mode}`); n++;
}
// Max-size buffers: no precision loss in the accumulators.
for (const fill of [0xff, 0xfe, 0x01]) {
  const b = Buffer.alloc(65535, fill);
  check(pu.internetChecksum(b) === refChecksum(b), `64KiB fill ${fill}`); n++;
}

function mkPacket(proto, payloadLen) {
  const payload = Buffer.alloc(payloadLen);
  for (let k = 0; k < payload.length; k++) payload[k] = rb();
  const src = [rb(), rb(), rb(), rb()].join("."), dst = [rb(), rb(), rb(), rb()].join(".");
  return { pkt: pu.buildIPv4Packet(payload, src, dst, proto, rb() * 256 + rb()), src, dst };
}
// Header checksum validity and parse round-trip.
for (let i = 0; i < 5000; i++) {
  const { pkt, src, dst } = mkPacket(17, 8 + Math.floor(r() * 300));
  check(pu.internetChecksum(pkt.subarray(0, 20)) === 0, "IPv4 header does not self-verify"); // a valid header sums to 0xffff -> ~ = 0
  const p = pu.parseIPv4Packet(pkt);
  check(p && p.srcIP === src && p.dstIP === dst && p.totalLength === pkt.length && p.headerLength === 20, "parse(build(x)) != x");
  n++;
}
// Transport checksums vs reference (pseudo-header + segment with zeroed checksum field).
for (const [proto, off, fn] of [[6, 16, pu.tcpChecksum], [17, 6, pu.udpChecksum]]) {
  for (let i = 0; i < 6000; i++) {
    const { pkt } = mkPacket(proto, off + 2 + Math.floor(r() * 400));
    const seg = Buffer.from(pkt.subarray(20));
    pkt.writeUInt16BE(rb() * 256 + rb(), 20 + off); // arbitrary existing checksum must be cancelled
    seg.writeUInt16BE(0, off);
    const pseudo = Buffer.concat([pkt.subarray(12, 20), Buffer.from([0, proto, seg.length >> 8, seg.length & 255]), seg]);
    check(fn(pkt) === refChecksum(pseudo), `transport checksum proto=${proto} len=${seg.length}`); n++;
  }
}
// Parsers never throw and only return in-bounds views, on arbitrary bytes.
for (let i = 0; i < 400000; i++) {
  const len = Math.floor(r() * 60);
  const b = Buffer.alloc(len);
  for (let k = 0; k < len; k++) b[k] = r() < 0.3 ? [0x45, 0, 0x11, 0xff][Math.floor(r() * 4)] : rb();
  if (len >= 20 && r() < 0.7) { b[0] = 0x40 | (1 + Math.floor(r() * 15)); b.writeUInt16BE(Math.min(len, 20 + Math.floor(r() * 50)), 2); b[9] = 17; }
  let p, u;
  try { p = pu.parseIPv4Packet(b); u = pu.parseUDPDatagram(b, p); } catch (e) { check(false, `parser threw ${e.message} on ${b.toString("hex")}`); }
  if (p) {
    check(p.headerLength >= 20 && p.headerLength <= p.totalLength && p.totalLength <= b.length, "IPv4 bounds");
    check(p.packet.length === p.totalLength, "packet view length");
  }
  if (u) check(u.length >= 8 && u.payload.length === u.length - 8 && u.payload.byteOffset + u.payload.length <= b.byteOffset + b.length, "UDP payload escapes packet");
  n++;
}
// ipv4Bytes accepts exactly dotted-quad with octets 0..255.
for (const bad of ["1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4", "a.b.c.d", "1..2.3", " 1.2.3.4", "1.2.3.4 ", "1.2.3.0x4", "1e1.2.3.4", ""]) {
  let threw = false; try { pu.ipv4Bytes(bad); } catch (e) { threw = e instanceof TypeError; }
  check(threw, `ipv4Bytes accepted ${JSON.stringify(bad)}`);
}
for (let i = 0; i < 2000; i++) { const o = [rb(), rb(), rb(), rb()]; check(pu.ipv4Bytes(o.join(".")).equals(Buffer.from(o)), "ipv4Bytes round trip"); n++; }
console.log(`packet utils: ${n} cases (checksum exhaustive <=2 bytes + vs RFC 1071 reference, parser fuzz, round-trips) OK`);
