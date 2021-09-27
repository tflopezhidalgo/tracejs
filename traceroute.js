#!/usr/local/bin/node

const raw = require('raw-socket');

// adjust port based on tcpdump output
const SRC_PORT = 52692;
const DST_PORT = 3000;

const ip2hex = (ip) => {
  let hexip = ip.split('.').map(Number);
  return Buffer.from(hexip);
}

const port2hex = (port) => {
  // dark magic
  const dec2hex = (n) => (n + 0x10000).toString(16).substr(-4).toUpperCase();

  return Buffer.from(dec2hex(port), 'hex');
}

const unpack = (buffer) => {
  const version = ((0b11110000 & buffer.slice(0, 1).readUint8(0)) >> 4);
  const ttl = buffer.slice(8, 9).readUint8();
  const proto = buffer.slice(9, 10);
  const src = buffer.slice(12, 16).map(x => x).join('.');
  const dst = buffer.slice(16, 20).map(x => x).join('.');

  return { version, ttl, proto, src, dst };
}

const ppPacket = (buffer) => {
  const packet = unpack(buffer);

  console.log(packet.dst);
}

const buildDummyUDP = (destination) => {
 /*
  *  0       7 8     15 16    23 24     31
  *  +--------+--------+--------+--------+
  *  |    src port     |    dst port     |
  *  +--------+--------+--------+--------+
  *  |    msg length   |    checksum     |
  *  +--------+--------+--------+--------+
  */

  /* dummy packet UDP */
  /* dst port 2048 */

  const sendBuffer = Buffer.concat([
    port2hex(SRC_PORT),
    port2hex(DST_PORT),
    Buffer.from([0x00, 0x08]),
    Buffer.from([0x00, 0x00]),
  ])

 /*  Pseudo header diagram
  *
  *  0       7 8     15 16    23 24     31
  *  +--------+--------+--------+--------+
  *  |          source address           |
  *  +--------+--------+--------+--------+
  *  |        destination address        |
  *  +--------+--------+--------+--------+
  *  |  zero  |protocol|   UDP length    |
  *  +--------+--------+--------+--------+
  */

  const pseudoHdrBuf = new Buffer.concat([
    ip2hex('127.0.0.1'),                  // source address (4 bytes)
    ip2hex(destination),
    Buffer.from([0x00, 0x11, 0x00, 0x08]), // zero, protocol, UDP length (4 bytes)
  ]);

  // FIXME: bad chksum 0
  let chckSum = raw.createChecksum(pseudoHdrBuf, sendBuffer);

  raw.writeChecksum(sendBuffer, 6, chckSum);

  return sendBuffer;
}

const sendOneDummyPacket = (sock, ctx) => {
  if (ctx.currentHop >= ctx.MAX_RETRIES)
    return

  let dummyUdp = buildDummyUDP(ctx.dstIp);

  const afterSend = (_error, _bytes) => {
    let nextCtx = {
      MAX_RETRIES: ctx.MAX_RETRIES,
      currentHop: ctx.currentHop + 1,
      dstIp: ctx.dstIp
    }
    sendOneDummyPacket(sock, nextCtx);
  }

  const beforeSend = () => {
    sock.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_TTL, ctx.currentHop);
  }

  sock.send(dummyUdp, 0, dummyUdp.length, ctx.dstIp, beforeSend, afterSend);
}


const traceroute = (destination) => {
  const probeSock = raw.createSocket({ protocol: raw.Protocol.ICMP });

  // TODO: maybe we should use another ICMP here, since UDP gets dropped everytime
  const dummySock = raw.createSocket({ protocol: raw.Protocol.UDP });

  let sockCtx = {
    MAX_RETRIES: 30,
    currentHop: 1,
    dstIp: destination,
  }

  sendOneDummyPacket(dummySock, sockCtx);

  probeSock.on("message", (buffer, source) => {
    console.log("-> Received " + buffer.length + "B from " + source + "<-");

    ppPacket(buffer);
  });

  /* keep running until the end of times */
  /* this is needed for receive icmp replies
   * that can take a little long to arrive */
  // TODO: keep running until icmp invalid port

  setInterval(() => process.exit(0), 1 << 30);
}

if (require.main == module) {
  if (process.argv.length != 3) {
    // we need sudo in order to access L2
    console.log('Usage: sudo ' + process.argv[1] + ' <destination ip>');
    process.exit(1);
  }
  const destination = process.argv[2];

  console.log(`Tracerouting to ${destination}:${DST_PORT}`);

  traceroute(destination);
}
