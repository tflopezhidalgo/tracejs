#!/usr/local/bin/node

const raw = require('raw-socket');

const ip2hex = (ip) => {
    let hexip = ip.split('.').map( i => Number(i) );
    return new Buffer.from(hexip);
}

const buildDummyUDP = (destination) => {

    /* dummy packet UDP */
    /* dst port 2048 */
    let sendBuffer = new Buffer.from([
        0xcd, 0xd4, 0x08, 0x00,
        0x00, 0x08, 0x00, 0x00,
    ]);

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

    let pseudoHdrBuf = new Buffer.from([
        0xc0, 0xA8, 0x00, 0x06,
        0x00, 0x11, 0x00, 0x08,
    ]);

    pseudoHdrBuf = Buffer.concat([ip2hex(destination), pseudoHdrBuf]);

    let chckSum = raw.createChecksum(pseudoHdrBuf, sendBuffer);

    raw.writeChecksum(sendBuffer, 6, chckSum);

    return sendBuffer;
}

class IcmpPckt {

    constructor(buffer) {
        this._version = buffer.slice(0, 1);
        this._ttl = buffer.slice(8, 9);
        this.proto = buffer.slice(9, 10);
        this._srcIp = buffer.slice(12, 16);
        this._dstIp = buffer.slice(16, 20);
    }

    srcIp() {
        /* TODO: use map */
        let srcIp1 = this._srcIp.slice(0,1);
        let srcIp2 = this._srcIp.slice(1,2);
        let srcIp3 = this._srcIp.slice(2,3);
        let srcIp4 = this._srcIp.slice(3,4);

        return [srcIp1.readUint8(), srcIp2.readUint8(), srcIp3.readUint8(), srcIp4.readUint8()].join('.');
    }

    dstIp() {
        /* TODO: use map */
        let dstIp1 = this._dstIp.slice(0,1);
        let dstIp2 = this._dstIp.slice(1,2);
        let dstIp3 = this._dstIp.slice(2,3);
        let dstIp4 = this._dstIp.slice(3,4);

        return [dstIp1.readUint8(), dstIp2.readUint8(), dstIp3.readUint8(), dstIp4.readUint8()].join('.');
    }

    ttl() { return this._ttl.readUint8(); }

    version() { return ((0b11110000 & this._version.readUint8(0)) >> 4); }
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
    const dummySock = raw.createSocket({ protocol: raw.Protocol.UDP });

    let sockCtx = {
        MAX_RETRIES: 30,
        currentHop: 1,
        dstIp: destination,
    }

    sendOneDummyPacket(dummySock, sockCtx);

    probeSock.on ("message", (buffer, source) => {
    	console.log("---------- Received " + buffer.length + " bytes from " + source + "----------");

        /* TODO:
         *  - unpack icmp pckt
         *  - show path trace
         */

    });

    /* keep running until the end of times */
    /* this is needed for receive icmp replies
     * that can take a little long to arrive */
    // TODO: keep running until icmp invalid port

    setInterval(() => {}, 1 << 30);
}

if (require.main == module) {
    if (process.argv.length != 3) {
        // we need sudo in order to access L2
        console.log('Usage: sudo ' + process.argv[1] + ' <destination ip>');
        process.exit(1);
    }
    let destination = process.argv[2];
    traceroute(destination);
    process.exit(0);
}
