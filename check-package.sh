#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then echo 'Usage: pruefe-paket.sh <package-directory> <version>' >&2; exit 2; fi
command -v node >/dev/null 2>&1 || { echo 'Error: Node.js is required.' >&2; exit 2; }
package_dir=$1
expected_version=$2
if [[ ! -d "$package_dir" ]]; then echo 'Error: package directory is missing.' >&2; exit 1; fi
if [[ ! -f "$package_dir/package.json" ]]; then echo 'Error: package manifest is missing.' >&2; exit 1; fi
node - "$package_dir" "$expected_version" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const dir = process.argv[2];
const expectedVersion = process.argv[3];
function fail(message) {
  console.error(`Error: ${message}`);
  process.exit(1);
}
let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
} catch {
  fail("package.json is not valid JSON.");
}
if (manifest.name !== "@klimbim/subspace") fail("package name must be @klimbim/subspace.");
if (manifest.version !== expectedVersion) fail("package version does not match the release tag.");
if (typeof manifest.license !== "string" || !manifest.license || manifest.license === "UNLICENSED") {
  fail("package license must be present and licensed.");
}
if (!Array.isArray(manifest.files) || manifest.files.some((item) => typeof item !== "string")) {
  fail("package files must be a list of file names.");
}
const actual = [];
function collect(current, relative = "") {
  for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
    const item = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) collect(path.join(current, entry.name), item);
    else if (entry.isFile()) actual.push(item);
    else fail("package directory contains a non-file entry.");
  }
}
collect(dir);
const expected = [...manifest.files].sort();
if (new Set(expected).size !== expected.length || JSON.stringify(expected) !== JSON.stringify([...actual].sort())) {
  fail("package directory files do not match package.json files.");
}
let firstLine;
try {
  firstLine = fs.readFileSync(path.join(dir, "subspace.js"), "utf8").split(/\r?\n/u, 1)[0];
} catch {
  fail("subspace.js is missing.");
}
if (firstLine !== "#!/usr/bin/env node") fail("subspace.js must use the Node.js shebang.");
NODE
