import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { config as loadEnv } from "dotenv";

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(frontendRoot, "..");

for (const envFile of [".env", ".env.local"]) {
  const fullPath = path.join(repoRoot, envFile);
  if (existsSync(fullPath)) {
    loadEnv({ path: fullPath, override: true });
  }
}

const command = process.argv[2] ?? "dev";
const forwardedArgs = process.argv.slice(3);
const nextBin = require.resolve("next/dist/bin/next");
const nextArgs = [nextBin, command];

if (command === "dev") {
  nextArgs.push("--turbopack");
}

nextArgs.push(...forwardedArgs);

const child = spawn(process.execPath, nextArgs, {
  cwd: frontendRoot,
  env: process.env,
  stdio: "inherit",
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});
