import { spawn } from "node:child_process";
import http from "node:http";

const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fetchUrl(urlPath) {
  return new Promise((resolve, reject) => {
    http
      .get(`${BASE}${urlPath}`, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      })
      .on("error", reject);
  });
}

async function run() {
  console.log(`Starting Vite server on port ${PORT}...`);
  const server = spawn("npx", ["vite", "--port", String(PORT), "--host", "127.0.0.1"], {
    stdio: "pipe",
    shell: true,
  });

  server.stdout.on("data", (d) => process.stdout.write(`[server stdout] ${d}`));
  server.stderr.on("data", (d) => process.stderr.write(`[server stderr] ${d}`));

  // Wait for server to come online
  let online = false;
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetchUrl("/");
      if (res.status) {
        online = true;
        break;
      }
    } catch {
      await sleep(500);
    }
  }

  if (!online) {
    console.error("Server failed to come online within 15 seconds.");
    server.kill();
    process.exit(1);
  }

  console.log("Server is online! Running comprehensive route probe...\n");

  const routes = [
    { path: "/", expectedStatus: [200, 302, 307] },
    { path: "/auth", expectedStatus: [200] },
    { path: "/login", expectedStatus: [200, 307] },
    { path: "/register", expectedStatus: [200] },
    { path: "/dashboard", expectedStatus: [200] },
    { path: "/send", expectedStatus: [200] },
    { path: "/inbox", expectedStatus: [200] },
    { path: "/sent", expectedStatus: [200] },
    { path: "/security", expectedStatus: [200] },
    { path: "/audit", expectedStatus: [200] },
    { path: "/profile", expectedStatus: [200] },
    { path: "/admin", expectedStatus: [200] },
    { path: "/settings", expectedStatus: [200] },
    { path: "/demo", expectedStatus: [200] },
    { path: "/digital-twin", expectedStatus: [200] },
    { path: "/security-lab", expectedStatus: [200] },
    { path: "/transfer/sample-transfer-123", expectedStatus: [200] },
    { path: "/api/status", expectedStatus: [200] },
    { path: "/api/auth/session", expectedStatus: [200, 401] },
    { path: "/nonexistent-route-should-404", expectedStatus: [200, 404] }, // Custom 404 page rendered
  ];

  let passCount = 0;
  for (const r of routes) {
    try {
      const res = await fetchUrl(r.path);
      const isExpected = r.expectedStatus.includes(res.status);
      const mark = isExpected ? "PASS" : "FAIL";
      console.log(`[${mark}] ${r.path} -> HTTP ${res.status} (${res.body.length} bytes)`);
      if (isExpected) passCount++;
    } catch (err) {
      console.error(`[FAIL] ${r.path} -> Error: ${err.message}`);
    }
  }

  console.log(`\nTotal Route Probes Passed: ${passCount} / ${routes.length}`);
  server.kill();
  process.exit(passCount === routes.length ? 0 : 1);
}

run();
