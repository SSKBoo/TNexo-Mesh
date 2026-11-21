// Relay UDP mínimo tipo TURN para simulación local:
//Los clientes envían REGISTER|id y el relay reenvía los datagramas al resto de
//participantes registrados. No implementa el protocolo TURN completo (Allocate/
//Refresh/ChannelBind), pero permite probar el data plane a través de un tercero.
import dgram from "node:dgram";

const port = Number(process.env.TURN_RELAY_PORT ?? 3479);
const server = dgram.createSocket("udp4");
const clients = new Map(); // id -> { address, port }

server.on("message", (msg, rinfo) => {
  const text = msg.toString("utf8");
  if (text.startsWith("REGISTER|")) {
    const id = text.split("|")[1]?.trim();
    if (!id) return;
    clients.set(id, { address: rinfo.address, port: rinfo.port });
    const ack = Buffer.from(`REGISTERED|${clients.size}|${[...clients.keys()].join(",")}`);
    server.send(ack, rinfo.port, rinfo.address);
    console.log(`register ${id} from ${rinfo.address}:${rinfo.port} (total ${clients.size})`);
    return;
  }
  // Cabecera: FROM|<id>|<payload>  => reenviar a todos menos al emisor
  if (text.startsWith("FROM|")) {
    const parts = text.split("|");
    const from = parts[1];
    const payload = Buffer.from(msg.subarray(parts[0].length + parts[1].length + 2));
    for (const [id, addr] of clients) {
      if (id === from) continue;
      const framed = Buffer.concat([Buffer.from(`TO|${from}|`), payload]);
      server.send(framed, addr.port, addr.address);
    }
    return;
  }
  // Datagrama sin cabecera: reenviar a todos los registrados
  for (const [id, addr] of clients) {
    if (addr.address === rinfo.address && addr.port === rinfo.port) continue;
    server.send(msg, addr.port, addr.address);
  }
});

server.bind(port, "0.0.0.0", () => console.log(`TURN-like UDP relay on 127.0.0.1:${port}`));

