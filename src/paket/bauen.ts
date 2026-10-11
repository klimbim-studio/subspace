import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const wurzel = resolve(import.meta.dir, "../..");
const paketOrdner = join(wurzel, "out/paket/cartridge-paket");
const paketWurzel = join(wurzel, "out/paket");
const archive = join(paketWurzel, "subspace-paket.tar.gz");
const legacyArchive = join(paketWurzel, "cartridge-paket.tar.gz");
const dateien = ["subspace.js", "cartridge.js", "SKILL.md", "README.md", "beispiel-konfig.json"];

const argumente = process.argv.slice(2);
if (argumente.includes("--npm")) {
  const versionIndex = argumente.indexOf("--version");
  const version = versionIndex >= 0 ? argumente[versionIndex + 1] : undefined;
  if (!version || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(version)) {
    console.error("A valid --version in MAJOR.MINOR.PATCH format is required.");
    process.exit(1);
  }
  const outIndex = argumente.indexOf("--out");
  const outValue = outIndex >= 0 ? argumente[outIndex + 1] : undefined;
  if (outIndex >= 0 && (!outValue || outValue.startsWith("--"))) {
    console.error("A directory is required after --out.");
    process.exit(1);
  }
  const out = outValue ? resolve(wurzel, outValue) : join(wurzel, "out/npm");
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  const build = Bun.spawnSync([
    "bun", "build", "src/cli/agentenpost.ts", "--target", "node", "--outfile", join(out, "subspace.js"),
    "--define", `__SUBSPACE_VERSION__="${version}"`,
  ], { cwd: wurzel, stdout: "inherit", stderr: "inherit" });
  if (build.exitCode !== 0) throw new Error("CLI package build failed.");
  let npmBundle = asciiSicher(await readFile(join(out, "subspace.js"), "utf8"));
  npmBundle = npmBundle.replace(/^#![^\r\n]*(?:\r?\n|$)/u, "#!/usr/bin/env node\n");
  if (!npmBundle.startsWith("#!/usr/bin/env node\n")) npmBundle = `#!/usr/bin/env node\n${npmBundle}`;
  await writeFile(join(out, "subspace.js"), npmBundle);
  for (const name of ["README.md", "SKILL.md"]) await copyFile(join(wurzel, "paket", name), join(out, name));
  let license = "UNLICENSED";
  try {
    const spdxLicense = (await readFile(join(wurzel, "paket/LICENSE-SPDX"), "utf8")).split(/\r?\n/u)[0]!.trim();
    await copyFile(join(wurzel, "paket/LICENSE"), join(out, "LICENSE"));
    license = spdxLicense;
  } catch {
    console.error("Warning: paket/LICENSE is missing; package will be marked UNLICENSED.");
  }
  const files = ["package.json", "subspace.js", "README.md", "SKILL.md", ...(license === "UNLICENSED" ? [] : ["LICENSE"])];
  await writeFile(join(out, "package.json"), `${JSON.stringify({
    name: "@klimbim/subspace", version, license, type: "module", bin: { subspace: "subspace.js" },
    engines: { node: ">=18" }, files,
    repository: { type: "git", url: "git+https://github.com/klimbim-studio/subspace.git" },
    publishConfig: { access: "public" },
  }, null, 2)}\n`);
  console.log(`npm package built: ${out}`);
  process.exit(0);
}

function asciiSicher(text: string): string {
  return text.replace(/[^\x00-\x7f]/gu, (zeichen) => {
    const codePoint = zeichen.codePointAt(0)!;
    if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, "0")}`;
    const rest = codePoint - 0x10000;
    const hoch = 0xd800 + (rest >> 10);
    const niedrig = 0xdc00 + (rest & 0x3ff);
    return `\\u${hoch.toString(16)}\\u${niedrig.toString(16)}`;
  });
}

await rm(paketOrdner, { recursive: true, force: true });
await rm(archive, { force: true });
await rm(legacyArchive, { force: true });
await mkdir(paketWurzel, { recursive: true });
await mkdir(paketOrdner, { recursive: true });

const build = Bun.spawnSync([
  "bun", "build", "src/cli/agentenpost.ts", "--target", "node", "--outfile", join(paketOrdner, "subspace.js"),
], { cwd: wurzel, stdout: "inherit", stderr: "inherit" });
if (build.exitCode !== 0) throw new Error("CLI-Paket konnte nicht gebaut werden.");

const bundlePath = join(paketOrdner, "subspace.js");
const bundle = await readFile(bundlePath, "utf8");
await writeFile(bundlePath, asciiSicher(bundle));
await copyFile(bundlePath, join(paketOrdner, "cartridge.js"));

for (const name of ["SKILL.md", "README.md", "beispiel-konfig.json"]) {
  await copyFile(join(wurzel, "paket", name), join(paketOrdner, name));
}

const sums: string[] = [];
for (const name of dateien) {
  const digest = createHash("sha256").update(await readFile(join(paketOrdner, name))).digest("hex");
  sums.push(`${digest}  ${name}`);
}
await writeFile(join(paketOrdner, "SHA256SUMS"), `${sums.join("\n")}\n`, { mode: 0o644 });

const tar = Bun.spawnSync(["tar", "-czf", archive, "-C", paketOrdner, ...dateien, "SHA256SUMS"], {
  cwd: wurzel,
  stdout: "inherit",
  stderr: "inherit",
});
if (tar.exitCode !== 0) throw new Error("Paketarchiv konnte nicht erstellt werden.");
const legacyTar = Bun.spawnSync(["cp", archive, legacyArchive], { cwd: wurzel, stdout: "inherit", stderr: "inherit" });
if (legacyTar.exitCode !== 0) throw new Error("Legacy package archive could not be copied.");
console.log("Paket built: out/paket/subspace-paket.tar.gz");
