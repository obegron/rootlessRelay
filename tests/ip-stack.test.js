"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildIPv4Packet,
  internetChecksum,
  parseIPv4Packet,
  parseUDPDatagram,
  tcpChecksum,
  udpChecksum,
} = require("../packet_utils");

function checksumWithPseudoHeader(ipPacket) {
  const headerLength = (ipPacket[0] & 0x0f) * 4;
  const transport = ipPacket.subarray(headerLength);
  const pseudoHeader = Buffer.alloc(12);
  ipPacket.copy(pseudoHeader, 0, 12, 20);
  pseudoHeader[9] = ipPacket[9];
  pseudoHeader.writeUInt16BE(transport.length, 10);
  return internetChecksum(Buffer.concat([pseudoHeader, transport]));
}

function addIPv4Options(ipPacket, options) {
  assert.equal(options.length % 4, 0);
  const headerLength = 20 + options.length;
  const packet = Buffer.concat([
    ipPacket.subarray(0, 20),
    options,
    ipPacket.subarray(20),
  ]);
  packet[0] = 0x40 | (headerLength / 4);
  packet.writeUInt16BE(packet.length, 2);
  packet.writeUInt16BE(0, 10);
  packet.writeUInt16BE(internetChecksum(packet.subarray(0, headerLength)), 10);
  return packet;
}

test("internet checksum matches published test vectors", () => {
  const vectors = [
    ["", 0xffff],
    ["0000", 0xffff],
    ["ffff", 0x0000],
    // Numerical example from RFC 1071, section 3.
    ["0001f203f4f5f6f7", 0x220d],
    // The same RFC words represented in byte-swapped order.
    ["010003f2f5f4f7f6", 0x0d22],
    // Common IPv4-header checksum example.
    ["450000730000400040110000c0a80001c0a800c7", 0xb861],
  ];

  for (const [hex, expected] of vectors) {
    assert.equal(internetChecksum(Buffer.from(hex, "hex")), expected, hex);
  }
});

test("internet checksum explicitly covers even and odd input lengths", () => {
  const even = Buffer.from("0001f203f4f5f6f7", "hex");
  const odd = Buffer.from("0001f203f4f5f6f701", "hex");

  assert.equal(even.length % 2, 0);
  assert.equal(odd.length % 2, 1);
  assert.equal(internetChecksum(even), 0x220d);
  assert.equal(internetChecksum(odd), 0x210d);
});

test("buildIPv4Packet creates a valid minimum IPv4 header", () => {
  const payload = Buffer.from("relay payload");
  const packet = buildIPv4Packet(payload, "10.0.2.2", "10.0.2.15", 17, 0x1234);

  assert.equal(packet[0] >> 4, 4);
  assert.equal(packet[0] & 0x0f, 5);
  assert.equal(packet.readUInt16BE(2), 20 + payload.length);
  assert.equal(packet.readUInt16BE(4), 0x1234);
  assert.equal(packet.readUInt16BE(6), 0);
  assert.equal(packet[8], 64);
  assert.equal(packet[9], 17);
  assert.deepEqual([...packet.subarray(12, 16)], [10, 0, 2, 2]);
  assert.deepEqual([...packet.subarray(16, 20)], [10, 0, 2, 15]);
  assert.equal(internetChecksum(packet.subarray(0, 20)), 0);
  assert.deepEqual(packet.subarray(20), payload);
});

test("parseIPv4Packet trims Ethernet padding and exposes header metadata", () => {
  const packet = buildIPv4Packet(
    Buffer.from("payload"),
    "192.0.2.1",
    "198.51.100.2",
    17,
    9,
  );
  const padded = Buffer.concat([packet, Buffer.alloc(18, 0xaa)]);
  const parsed = parseIPv4Packet(padded);

  assert.equal(parsed.headerLength, 20);
  assert.equal(parsed.totalLength, packet.length);
  assert.equal(parsed.protocol, 17);
  assert.equal(parsed.srcIP, "192.0.2.1");
  assert.equal(parsed.dstIP, "198.51.100.2");
  assert.equal(parsed.moreFragments, false);
  assert.equal(parsed.fragmentOffset, 0);
  assert.deepEqual(parsed.packet, packet);
});

test("parseIPv4Packet accepts options and reports fragmentation", () => {
  const base = buildIPv4Packet(Buffer.alloc(8), "10.0.2.15", "10.0.2.2", 1, 1);
  const packet = addIPv4Options(base, Buffer.from([1, 1, 1, 0]));
  packet.writeUInt16BE(0x2001, 6);

  const parsed = parseIPv4Packet(packet);
  assert.equal(parsed.headerLength, 24);
  assert.equal(parsed.moreFragments, true);
  assert.equal(parsed.fragmentOffset, 1);
});

test("parseIPv4Packet rejects malformed versions and lengths", () => {
  assert.equal(parseIPv4Packet(Buffer.alloc(19)), null);

  const wrongVersion = Buffer.alloc(20);
  wrongVersion[0] = 0x65;
  wrongVersion.writeUInt16BE(20, 2);
  assert.equal(parseIPv4Packet(wrongVersion), null);

  const shortIhl = Buffer.from(wrongVersion);
  shortIhl[0] = 0x44;
  assert.equal(parseIPv4Packet(shortIhl), null);

  const truncatedOptions = Buffer.from(wrongVersion);
  truncatedOptions[0] = 0x46;
  assert.equal(parseIPv4Packet(truncatedOptions), null);

  const totalShorterThanHeader = Buffer.alloc(24);
  totalShorterThanHeader[0] = 0x46;
  totalShorterThanHeader.writeUInt16BE(20, 2);
  assert.equal(parseIPv4Packet(totalShorterThanHeader), null);

  const totalLongerThanPacket = Buffer.alloc(20);
  totalLongerThanPacket[0] = 0x45;
  totalLongerThanPacket.writeUInt16BE(21, 2);
  assert.equal(parseIPv4Packet(totalLongerThanPacket), null);
});

test("parseUDPDatagram honors IPv4 options, UDP length, and padding", () => {
  const udp = Buffer.alloc(12);
  udp.writeUInt16BE(40000, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(11, 4);
  Buffer.from("dns").copy(udp, 8);
  udp[11] = 0xaa;

  const base = buildIPv4Packet(udp, "10.0.2.15", "8.8.8.8", 17, 1);
  const packet = addIPv4Options(base, Buffer.from([1, 1, 1, 0]));
  const datagram = parseUDPDatagram(packet);

  assert.equal(datagram.srcPort, 40000);
  assert.equal(datagram.dstPort, 53);
  assert.equal(datagram.length, 11);
  assert.deepEqual(datagram.payload, Buffer.from("dns"));
});

test("parseUDPDatagram rejects wrong protocols and malformed lengths", () => {
  const tcp = buildIPv4Packet(Buffer.alloc(20), "10.0.2.15", "10.0.2.2", 6);
  assert.equal(parseUDPDatagram(tcp), null);

  const shortHeader = buildIPv4Packet(Buffer.alloc(7), "10.0.2.15", "8.8.8.8", 17);
  assert.equal(parseUDPDatagram(shortHeader), null);

  const invalidLength = buildIPv4Packet(
    Buffer.from("9c40003500070000", "hex"),
    "10.0.2.15",
    "8.8.8.8",
    17,
  );
  assert.equal(parseUDPDatagram(invalidLength), null);

  const truncated = Buffer.from(invalidLength);
  truncated.writeUInt16BE(20, 24);
  assert.equal(parseUDPDatagram(truncated), null);
});

test("buildIPv4Packet accepts zero and maximum payload boundaries", () => {
  const empty = buildIPv4Packet(Buffer.alloc(0), "10.0.2.2", "10.0.2.15", 1, 0);
  const maximum = buildIPv4Packet(
    Buffer.alloc(0xffff - 20),
    "10.0.2.2",
    "10.0.2.15",
    1,
    0xffff,
  );

  assert.equal(empty.length, 20);
  assert.equal(empty.readUInt16BE(2), 20);
  assert.equal(maximum.length, 0xffff);
  assert.equal(maximum.readUInt16BE(2), 0xffff);
});

test("buildIPv4Packet rejects a packet one byte over the IPv4 maximum", () => {
  assert.throws(() =>
    buildIPv4Packet(
      Buffer.alloc(0xffff - 20 + 1),
      "10.0.2.2",
      "10.0.2.15",
      6,
    ), /65535-byte maximum/);
});

test("buildIPv4Packet rejects invalid IPv4 address forms", () => {
  for (const address of [
    "1.2.3",
    "1.2.3.4.5",
    "999.1.1.1",
    "1.2.3.a",
    "1.2.3.",
  ]) {
    assert.throws(
      () => buildIPv4Packet(Buffer.alloc(0), address, "10.0.2.15", 6),
      /Invalid IPv4 address/,
      address,
    );
    assert.throws(
      () => buildIPv4Packet(Buffer.alloc(0), "10.0.2.15", address, 6),
      /Invalid IPv4 address/,
      address,
    );
  }
});

test("TCP checksum covers addresses, header, and an odd-length payload", () => {
  const tcp = Buffer.alloc(25);
  tcp.writeUInt16BE(443, 0);
  tcp.writeUInt16BE(49152, 2);
  tcp.writeUInt32BE(0x12345678, 4);
  tcp.writeUInt32BE(0x90abcdef, 8);
  tcp[12] = 0x50;
  tcp[13] = 0x18;
  tcp.writeUInt16BE(32768, 14);
  Buffer.from("hello").copy(tcp, 20);

  const packet = buildIPv4Packet(tcp, "192.0.2.1", "198.51.100.2", 6, 1);
  packet.writeUInt16BE(tcpChecksum(packet), 36);

  assert.equal(packet.readUInt16BE(36), 0x76ba);
  assert.equal(checksumWithPseudoHeader(packet), 0);

  const embedded = packet.readUInt16BE(36);
  const zeroed = Buffer.from(packet);
  zeroed.writeUInt16BE(0, 36);
  assert.equal(tcpChecksum(zeroed), embedded);
});

test("UDP checksum covers addresses, header, and payload", () => {
  const payload = Buffer.from("dns query");
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(53000, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(udp.length, 4);
  payload.copy(udp, 8);

  const packet = buildIPv4Packet(udp, "10.0.2.15", "8.8.8.8", 17, 2);
  packet.writeUInt16BE(udpChecksum(packet), 26);

  assert.equal(packet.readUInt16BE(26), 0xecf8);
  assert.equal(checksumWithPseudoHeader(packet), 0);

  const embedded = packet.readUInt16BE(26);
  const zeroed = Buffer.from(packet);
  zeroed.writeUInt16BE(0, 26);
  assert.equal(udpChecksum(zeroed), embedded);
});

test("transport checksum honors an IPv4 header with options", () => {
  const udp = Buffer.alloc(12);
  udp.writeUInt16BE(12345, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(udp.length, 4);
  Buffer.from("test").copy(udp, 8);

  const base = buildIPv4Packet(udp, "192.0.2.10", "198.51.100.20", 17, 3);
  const packet = addIPv4Options(base, Buffer.from([1, 1, 1, 0]));
  const checksumOffset = 24 + 6;
  packet.writeUInt16BE(udpChecksum(packet), checksumOffset);

  assert.equal(packet[0] & 0x0f, 6);
  assert.equal(internetChecksum(packet.subarray(0, 24)), 0);
  assert.equal(checksumWithPseudoHeader(packet), 0);

  const embedded = packet.readUInt16BE(checksumOffset);
  packet.writeUInt16BE(0, checksumOffset);
  assert.equal(udpChecksum(packet), embedded);
});

test("transport checksum rejects an IHL shorter than 20 bytes", () => {
  const packet = Buffer.alloc(20);
  packet[0] = 0x44;
  assert.throws(() => tcpChecksum(packet), /Invalid IPv4 header length/);
});

test("transport checksum rejects a packet shorter than its IHL", () => {
  const packet = Buffer.alloc(20);
  packet[0] = 0x46;
  assert.throws(() => tcpChecksum(packet), /Invalid IPv4 header length/);
});

test("transport checksum rejects a truncated transport header", () => {
  const packet = buildIPv4Packet(Buffer.alloc(6), "10.0.2.2", "10.0.2.15", 17);
  assert.throws(() => udpChecksum(packet), /too short/);
});
