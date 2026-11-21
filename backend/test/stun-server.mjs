import dgram from "node:dgram";

const port = Number(process.env.STUN_PORT ?? 3478);
const server = dgram.createSocket("udp4");

server.on("message", (msg, rinfo) => {
  if (msg.length < 20) return;
  // STUN Binding Request: tipo 0x0001, magic cookie 0x2112A442
  const type = msg.readUInt16BE(0);
  const magic = msg.readUInt32BE(4);
  if (type !== 0x0001 || magic !== 0x2112A442) return;
  const tid = msg.subarray(8, 20);
  const resp = Buffer.alloc(32);
  resp.writeUInt16BE(0x0101, 0); // Binding Success Response
  resp.writeUInt16BE(12, 2); // longitud: 1 atributo de 8 + cabecera 4
  resp.writeUInt32BE(0x2112A442, 4);
  tid.copy(resp, 8);
  // XOR-MAPPED-ADDRESS (0x0020), IPv4
  resp.writeUInt16BE(0x0020, 20);
  resp.writeUInt16BE(8, 22);
  resp[24] = 0;
  resp[25] = 0x01;
  const portXor = rinfo.port ^ 0x2112;
  resp.writeUInt16BE(portXor, 26);
  const parts = rinfo.address.split(".").map(Number);
  resp[28] = parts[0] ^ 0x21;
  resp[29] = parts[1] ^ 0x12;
  resp[30] = parts[2] ^ 0xA4;
  resp[31] = parts[3] ^ 0x42;
  server.send(resp, rinfo.port, rinfo.address);
});

server.bind(port, "127.0.0.1", () => console.log(`STUN test server on 127.0.0.1:${port}`));
