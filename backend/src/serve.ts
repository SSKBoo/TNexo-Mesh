import { start } from "./index.ts";

const port = Number(process.env.PORT ?? 8080);
const signalingPort = Number(process.env.SIGNALING_PORT ?? 8443);
start(port, signalingPort);
