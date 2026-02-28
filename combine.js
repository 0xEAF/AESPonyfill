#!/usr/bin/env node
const fs = require("fs");

if (process.argv.length < 5) {
  console.error("Usage: node combine.js <wrapper.js> <wasm.js> <asm.js>");
  process.exit(1);
}

const wrapperPath = process.argv[2];
const wasmPath = process.argv[3];
const asmPath  = process.argv[4];
let bundle;

// read inputs
try {
  const wasmCode = fs.readFileSync(wasmPath, "utf8");
  const asmCode  = fs.readFileSync(asmPath, "utf8");
  const template = fs.readFileSync(wrapperPath, "utf8");

  bundle = template
    .replace("/*PLACEHOLDER-DONOTREMOVE-BUILD:WASMJS*/", wasmCode)
    .replace("/*PLACEHOLDER-DONOTREMOVE-BUILD:ASMJS*/", asmCode);
} catch (error) {
  console.error("Error reading files:", error);
  process.exit(1);
}

// output to stdout so user can redirect with >
process.stdout.write(bundle);
