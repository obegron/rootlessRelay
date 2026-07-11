"use strict";

function internetChecksum(data) {
  let sum = 0;

  for (let i = 0; i + 1 < data.length; i += 2) {
    sum += data.readUInt16BE(i);
  }

  if (data.length % 2 !== 0) {
    sum += data[data.length - 1] << 8;
  }

  while (sum > 0xffff) {
    sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  }

  return (~sum) & 0xffff;
}

function ipv4Bytes(address) {
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

function buildIPv4Packet(
  payload,
  srcIP,
  dstIP,
  protocol,
  identification = Math.floor(Math.random() * 65535),
) {
  if (!Buffer.isBuffer(payload)) {
    throw new TypeError("IPv4 payload must be a Buffer");
  }

  const packetLength = 20 + payload.length;
  if (packetLength > 0xffff) {
    throw new RangeError("IPv4 packet exceeds the 65535-byte maximum");
  }

  const packet = Buffer.allocUnsafe(packetLength);
  packet[0] = 0x45;
  packet[1] = 0;
  packet.writeUInt16BE(packetLength, 2);
  packet.writeUInt16BE(identification, 4);
  packet.writeUInt16BE(0, 6);
  packet[8] = 64;
  packet[9] = protocol;
  packet.writeUInt16BE(0, 10);
  ipv4Bytes(srcIP).copy(packet, 12);
  ipv4Bytes(dstIP).copy(packet, 16);
  packet.writeUInt16BE(internetChecksum(packet.subarray(0, 20)), 10);
  payload.copy(packet, 20);

  return packet;
}

function transportChecksum(ipPacket, protocol, checksumOffset) {
  const headerLength = (ipPacket[0] & 0x0f) * 4;
  if (headerLength < 20 || ipPacket.length < headerLength) {
    throw new RangeError("Invalid IPv4 header length");
  }

  const transportLength = ipPacket.length - headerLength;
  if (transportLength < checksumOffset + 2) {
    throw new RangeError("Transport packet is too short for its checksum field");
  }

  const pseudoPacket = Buffer.allocUnsafe(12 + transportLength);
  ipPacket.copy(pseudoPacket, 0, 12, 20);
  pseudoPacket[8] = 0;
  pseudoPacket[9] = protocol;
  pseudoPacket.writeUInt16BE(transportLength, 10);
  ipPacket.copy(pseudoPacket, 12, headerLength);
  pseudoPacket.writeUInt16BE(0, 12 + checksumOffset);

  return internetChecksum(pseudoPacket);
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
  parseIPv4Packet,
  parseUDPDatagram,
  tcpChecksum,
  udpChecksum,
};
