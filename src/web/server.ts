import express from "express";
import cors from "cors";
import path from "node:path";
import http from "node:http";
import { WebSocketServer } from "ws";
import * as pty from "node-pty";

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(process.cwd(), "src/web/public")));

const server = http.createServer(app);

const wss = new WebSocketServer({
  server,
  path: "/terminal"
});

wss.on("connection", ws => {
  const shell = process.platform === "win32" ? "powershell.exe" : "bash";

  const terminal = pty.spawn(shell, [], {
    name: "xterm-color",
    cols: 120,
    rows: 30,
    cwd: process.cwd(),
    env: process.env
  });

  terminal.onData(data => {
    ws.send(data);
  });

  ws.on("message", message => {
    terminal.write(message.toString());
  });

  ws.on("close", () => {
    terminal.kill();
  });
});

server.listen(PORT, () => {
  console.log("Dashboard disponible sur http://localhost:" + PORT);
});