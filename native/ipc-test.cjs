// Local protocol test for the dsh-github-guard helper: runs "serve" on a scratch
// port against a scratch hosts file and exercises the TCP+token protocol.
const { spawn } = require("node:child_process");
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");

const dir = __dirname;
const exe = path.join(dir, "dsh-github-guard.exe");
const hosts = path.join(dir, "tmp-hosts.txt");
const log = path.join(dir, "tmp-helper.log");
const result = path.join(dir, "tmp-result.txt");
const port = 8899;
const token = "test-token-1234";

process.on("uncaughtException", (error) => {
  fs.writeFileSync(result, "UNCAUGHT " + (error && error.stack ? error.stack : String(error)), "utf8");
  process.exit(1);
});
fs.writeFileSync(result, "started pid=" + process.pid, "utf8");

fs.writeFileSync(
  hosts,
  "127.0.0.1 localhost\r\n192.168.1.9 github.com\r\n# dsh-github-guard: pinned edge\r\n9.9.9.9 github.com\r\n9.9.9.9 gist.github.com\r\n# keep me\r\n",
  "ascii",
);
if (fs.existsSync(log)) fs.unlinkSync(log);

const child = spawn(exe, ["serve"], {
  env: { ...process.env, DSH_GUARD_HOSTS: hosts, DSH_GUARD_LOG: log, DSH_GUARD_TOKEN: token, DSH_GUARD_PORT: String(port) },
  windowsHide: true,
  stdio: "ignore",
});
child.on("error", (error) => fs.writeFileSync(result, "SPAWN ERROR " + error.message, "utf8"));

const talk = (lines) =>
  new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    const replies = [];
    let buffer = "";
    socket.on("connect", () => socket.write(lines.join("\n") + "\n"));
    const finish = () => { try { socket.destroy(); } catch {} resolve(replies); };
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        replies.push(buffer.slice(0, index).trim());
        buffer = buffer.slice(index + 1);
      }
      if (replies.length >= lines.length - 1) finish();
    });
    socket.on("error", (error) => resolve(["SOCKET ERROR " + error.message]));
    setTimeout(finish, 6000);
  });

(async () => {
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const wrong = await talk(["AUTH nope"]);
  const good = await talk(["AUTH " + token, "status", "pin 1.2.3.4,5.6.7.8", "pin nonsense", "status", "quit"]);
  const report = [
    "wrong-token: " + JSON.stringify(wrong),
    "good-token : " + JSON.stringify(good),
    "--- hosts after ---",
    fs.readFileSync(hosts, "utf8"),
    "--- helper log ---",
    fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "(no log)",
  ].join("\n");
  fs.writeFileSync(result, report, "utf8");
  try { child.kill(); } catch {}
  process.exit(0);
})();
