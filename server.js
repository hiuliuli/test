const net = require('net');
const dgram = require('dgram');
const tls = require('tls');
const fs = require('fs');
const dns = require('dns');

const PORT = parseInt(process.env.SOCKS_PORT || '1080');
const USERNAME = process.env.SOCKS_USER || null;
const PASSWORD = process.env.SOCKS_PASS || null;
const USE_TLS = process.env.SOCKS_TLS === 'true';

const AUTH_REQUIRED = USERNAME && PASSWORD;

/* ==========================
   TCP SERVER (TLS optional)
========================== */

const tcpServer = USE_TLS
  ? tls.createServer({
      key: fs.readFileSync(process.env.SOCKS_TLS_KEY),
      cert: fs.readFileSync(process.env.SOCKS_TLS_CERT),
    }, onConnection)
  : net.createServer(onConnection);

function onConnection(socket) {
  socket.setKeepAlive(true);
  socket.setNoDelay(true);

  socket.once('data', (chunk) => {
    if (chunk[0] !== 0x05) return socket.destroy();

    const methods = chunk.slice(2, 2 + chunk[1]);

    let method = 0x00;
    if (AUTH_REQUIRED) {
      if (!methods.includes(0x02)) {
        socket.write(Buffer.from([0x05, 0xff]));
        return socket.end();
      }
      method = 0x02;
    }

    socket.write(Buffer.from([0x05, method]));

    if (method === 0x02) return handleAuth(socket);
    handleRequest(socket);
  });
}

/* ==========================
   AUTH
========================== */

function handleAuth(socket) {
  socket.once('data', (chunk) => {
    const ulen = chunk[1];
    const uname = chunk.slice(2, 2 + ulen).toString();
    const plen = chunk[2 + ulen];
    const pass = chunk.slice(3 + ulen, 3 + ulen + plen).toString();

    if (uname === USERNAME && pass === PASSWORD) {
      socket.write(Buffer.from([0x01, 0x00]));
      handleRequest(socket);
    } else {
      socket.write(Buffer.from([0x01, 0x01]));
      socket.destroy();
    }
  });
}

/* ==========================
   REQUEST HANDLER
========================== */

function handleRequest(socket) {
  socket.once('data', async (chunk) => {
    const cmd = chunk[1];
    const atyp = chunk[3];

    let { host, port, offset } = parseAddress(chunk, atyp);
    if (!host) return socket.destroy();

    if (cmd === 0x01) {
      handleTCP(socket, host, port);
    } else if (cmd === 0x03) {
      handleUDP(socket);
    } else {
      socket.write(buildReply(0x07));
      socket.end();
    }
  });
}

/* ==========================
   TCP CONNECT (High Perf)
========================== */

function handleTCP(client, host, port) {
  const remote = net.connect({
    host,
    port,
    keepAlive: true,
  });

  remote.on('connect', () => {
    const addr = remote.localAddress;
    const reply = buildReply(0x00, addr, remote.localPort);
    client.write(reply);

    client.pipe(remote);
    remote.pipe(client);
  });

  remote.on('error', () => {
    client.write(buildReply(0x05));
    client.end();
  });
}

/* ==========================
   UDP ASSOCIATE
========================== */

function handleUDP(tcpSocket) {
  const udpServer = dgram.createSocket('udp4');

  udpServer.on('message', (msg, rinfo) => {
    const frag = msg[2];
    if (frag !== 0x00) return;

    const atyp = msg[3];
    const { host, port, offset } = parseAddress(msg, atyp, 4);

    const data = msg.slice(offset);

    udpServer.send(data, port, host);
  });

  udpServer.bind(0, () => {
    const addr = udpServer.address();
    tcpSocket.write(buildReply(0x00, addr.address, addr.port));
  });
}

/* ==========================
   ADDRESS PARSER
========================== */

function parseAddress(buffer, atyp, start = 4) {
  let offset = start;
  let host;

  if (atyp === 0x01) {
    host = Array.from(buffer.slice(offset, offset + 4)).join('.');
    offset += 4;
  } else if (atyp === 0x03) {
    const len = buffer[offset++];
    host = buffer.slice(offset, offset + len).toString();
    offset += len;
  } else if (atyp === 0x04) {
    const raw = buffer.slice(offset, offset + 16);
    host = raw.toString('hex').match(/.{1,4}/g).join(':');
    offset += 16;
  }

  const port = buffer.readUInt16BE(offset);
  offset += 2;

  return { host, port, offset };
}

/* ==========================
   REPLY BUILDER (IPv6 aware)
========================== */

function buildReply(rep, addr = '0.0.0.0', port = 0) {
  let atyp = 0x01;
  let addrBuf;

  if (net.isIPv6(addr)) {
    atyp = 0x04;
    addrBuf = Buffer.alloc(16);
    addr.split(':').forEach((block, i) => {
      addrBuf.writeUInt16BE(parseInt(block || '0', 16), i * 2);
    });
  } else {
    addrBuf = Buffer.from(addr.split('.').map(Number));
  }

  const buf = Buffer.alloc(4);
  buf[0] = 0x05;
  buf[1] = rep;
  buf[2] = 0x00;
  buf[3] = atyp;

  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port);

  return Buffer.concat([buf, addrBuf, portBuf]);
}

/* ==========================
   START
========================== */

tcpServer.listen(PORT, () => {
  console.log(`SOCKS5 ${USE_TLS ? 'TLS' : ''} server running on ${PORT}`);
});
