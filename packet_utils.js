"use strict";

const LITTLE_ENDIAN = new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;

// Sum of big-endian 16-bit words in buf[start, end), byte-wise. For words
// w = h<<8|l, sum(w) === (sum(h) << 8) + sum(l), so high and low bytes are
// summed separately and shifted once.
function sumBytes(buf, start, end) {
  let high = 0;
  let low = 0;
  let i = start;
  const last = end - 1;
  for (; i + 7 < end; i += 8) {
    high += buf[i] + buf[i + 2] + buf[i + 4] + buf[i + 6];
    low += buf[i + 1] + buf[i + 3] + buf[i + 5] + buf[i + 7];
  }
  for (; i < last; i += 2) {
    high += buf[i];
    low += buf[i + 1];
  }
  if (i === last) high += buf[i];
  return high * 256 + low;
}

// One's-complement sum (unfolded) of big-endian 16-bit words in
// buf[start, end). The result is only meaningful after foldChecksum, which
// is all checksum users need. On little-endian hosts aligned spans are read
// as 32-bit words: one's-complement sums are byte-order independent
// (RFC 1071 section 2(B)), so the native-order sum is folded and swapped.
function sumWords(buf, start, end) {
  const length = end - start;
  const offset = buf.byteOffset + start;
  if (!LITTLE_ENDIAN || length < 64 || (offset & 3) !== 0) {
    return sumBytes(buf, start, end);
  }
  const count = length >>> 2;
  const words = new Uint32Array(buf.buffer, offset, count);
  let sum = 0;
  for (let k = 0; k < count; k++) {
    const word = words[k];
    sum += (word & 0xffff) + (word >>> 16);
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  sum = ((sum & 0xff) << 8) | (sum >>> 8);
  return sum + sumBytes(buf, start + count * 4, end);
}

function foldChecksum(sum) {
  while (sum > 0xffff) sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  return (~sum) & 0xffff;
}

function internetChecksum(data) {
  return foldChecksum(sumWords(data, 0, data.length));
}

function ipv4Bytes(address) {
  if (Buffer.isBuffer(address)) {
    if (address.length !== 4) throw new TypeError("IPv4 address must contain four bytes");
    return address;
  }
  if (typeof address !== "string") {
    throw new TypeError(`Invalid IPv4 address: ${address}`);
  }

  const parts = address.split(".");
  const octets = parts.map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => !/^\d{1,3}$/.test(part)) ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    throw new TypeError(`Invalid IPv4 address: ${address}`);
  }
  return Buffer.from(octets);
}

function formatIPv4(ipPacket, offset) {
  return `${ipPacket[offset]}.${ipPacket[offset + 1]}.` +
    `${ipPacket[offset + 2]}.${ipPacket[offset + 3]}`;
}

function parseIPv4Packet(ipPacket) {
  if (!Buffer.isBuffer(ipPacket) || ipPacket.length < 20) return null;

  const version = ipPacket[0] >>> 4;
  const headerLength = (ipPacket[0] & 0x0f) * 4;
  if (version !== 4 || headerLength < 20 || ipPacket.length < headerLength) {
    return null;
  }

  const totalLength = ipPacket.readUInt16BE(2);
  if (totalLength < headerLength || totalLength > ipPacket.length) return null;

  const fragmentField = ipPacket.readUInt16BE(6);
  return {
    packet: ipPacket.subarray(0, totalLength),
    headerLength,
    totalLength,
    protocol: ipPacket[9],
    srcIP: formatIPv4(ipPacket, 12),
    dstIP: formatIPv4(ipPacket, 16),
    moreFragments: (fragmentField & 0x2000) !== 0,
    fragmentOffset: fragmentField & 0x1fff,
  };
}

function parseUDPDatagram(ipPacket, parsed = parseIPv4Packet(ipPacket)) {
  if (!parsed || parsed.protocol !== 17) return null;
  const udpOffset = parsed.headerLength;
  if (parsed.packet.length < udpOffset + 8) return null;

  const length = parsed.packet.readUInt16BE(udpOffset + 4);
  if (length < 8 || udpOffset + length > parsed.packet.length) return null;

  return {
    srcPort: parsed.packet.readUInt16BE(udpOffset),
    dstPort: parsed.packet.readUInt16BE(udpOffset + 2),
    length,
    payload: parsed.packet.subarray(udpOffset + 8, udpOffset + length),
  };
}

let nextIdentification = Math.floor(Math.random() * 0x10000);

// Write a 20-byte IPv4 header (no options, DF clear) into buf at offset.
// srcIP/dstIP may be dotted strings or 4-byte Buffers; pass Buffers on hot
// paths to avoid reparsing the address for every packet.
function writeIPv4Header(
  buf,
  offset,
  totalLength,
  protocol,
  srcIP,
  dstIP,
  identification = nextIdentification = (nextIdentification + 1) & 0xffff,
) {
  if (totalLength > 0xffff) {
    throw new RangeError("IPv4 packet exceeds the 65535-byte maximum");
  }
  buf[offset] = 0x45;
  buf[offset + 1] = 0;
  buf.writeUInt16BE(totalLength, offset + 2);
  buf.writeUInt16BE(identification, offset + 4);
  buf[offset + 6] = 0;
  buf[offset + 7] = 0;
  buf[offset + 8] = 64;
  buf[offset + 9] = protocol;
  buf[offset + 10] = 0;
  buf[offset + 11] = 0;
  ipv4Bytes(srcIP).copy(buf, offset + 12);
  ipv4Bytes(dstIP).copy(buf, offset + 16);
  buf.writeUInt16BE(
    foldChecksum(sumWords(buf, offset, offset + 20)),
    offset + 10,
  );
}

function buildIPv4Packet(payload, srcIP, dstIP, protocol, identification) {
  if (!Buffer.isBuffer(payload)) {
    throw new TypeError("IPv4 payload must be a Buffer");
  }

  const packetLength = 20 + payload.length;
  const packet = Buffer.allocUnsafe(packetLength);
  writeIPv4Header(packet, 0, packetLength, protocol, srcIP, dstIP, identification);
  payload.copy(packet, 20);

  return packet;
}

function transportChecksum(ipPacket, protocol, checksumOffset) {
  const headerLength = (ipPacket[0] & 0x0f) * 4;
  if (headerLength < 20 || ipPacket.length < headerLength) {
    throw new RangeError("Invalid IPv4 header length");
  }

  const transportLength = ipPacket.length - headerLength;
  if (transportLength > 0xffff) throw new RangeError("Transport length exceeds 65535 bytes");
  if (transportLength < checksumOffset + 2) {
    throw new RangeError("Transport packet is too short for its checksum field");
  }

  // Sum the pseudo-header and transport in place. Cancel the existing
  // checksum word by adding its one's complement (equivalent to subtracting
  // it modulo 0xffff, but never negative) rather than copying or mutating
  // the packet to zero it.
  let sum = protocol + transportLength + sumWords(ipPacket, 12, 20);
  sum += (~ipPacket.readUInt16BE(headerLength + checksumOffset)) & 0xffff;
  sum += sumWords(ipPacket, headerLength, ipPacket.length);
  return foldChecksum(sum);
}

function tcpChecksum(ipPacket) {
  return transportChecksum(ipPacket, 6, 16);
}

function udpChecksum(ipPacket) {
  return transportChecksum(ipPacket, 17, 6);
}

module.exports = {
  buildIPv4Packet,
  internetChecksum,
  ipv4Bytes,
  parseIPv4Packet,
  parseUDPDatagram,
  tcpChecksum,
  udpChecksum,
  writeIPv4Header,
};
