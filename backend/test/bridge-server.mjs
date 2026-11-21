import http from "node:http";

const port = 51820;
const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");
  if (req.url === "/health") {
    res.end(JSON.stringify({ ok: true }));
  } else if (req.url === "/status") {
    res.end(JSON.stringify({ ok: true, peers: 2, virtualIp: "10.0.0.2" }));
  } else if (req.url === "/command" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => res.end(JSON.stringify({ ok: true, echoed: JSON.parse(body) })));
  } else {
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  }
});
server.listen(port, "127.0.0.1", () => console.log(`bridge mock on 127.0.0.1:${port}`));
