import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const root = resolve(import.meta.dir, "../..");
const packageDirectory = join(root, "out/paket/cartridge-paket"); // on-disk format, keep
const packageRoot = join(root, "out/paket");
const archive = join(packageRoot, "subspace-paket.tar.gz");
const legacyArchive = join(packageRoot, "cartridge-paket.tar.gz"); // legacy alias, keep
const packageFiles = ["subspace.js", "cartridge.js", "SKILL.md", "README.md", "example-config.json"]; // legacy alias, keep

const args = process.argv.slice(2);
if (args.includes("--npm")) {
  const versionIndex = args.indexOf("--version");
  const version = versionIndex >= 0 ? args[versionIndex + 1] : undefined;
  if (!version || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(version)) {
    console.error("A valid --version in MAJOR.MINOR.PATCH format is required.");
    process.exit(1);
  }
  const outIndex = args.indexOf("--out");
  const outValue = outIndex >= 0 ? args[outIndex + 1] : undefined;
  if (outIndex >= 0 && (!outValue || outValue.startsWith("--"))) {
    console.error("A directory is required after --out.");
    process.exit(1);
  }
  const out = outValue ? resolve(root, outValue) : join(root, "out/npm");
  let existing = out;
  let canonicalOut: string;
  while (true) {
    try {
      canonicalOut = resolve(await realpath(existing), relative(existing, out));
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
      const parent = dirname(existing);
      if (parent === existing) throw error;
      existing = parent;
    }
  }
  const canonicalRoot = await realpath(root);
  const pathFromOutToRoot = relative(canonicalOut, canonicalRoot);
  if (pathFromOutToRoot === "" || (!isAbsolute(pathFromOutToRoot) && pathFromOutToRoot !== ".." && !pathFromOutToRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`))) {
    console.error("--out must not be the repository root or one of its parent directories.");
    process.exit(2);
  }
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  const build = Bun.spawnSync([
    "bun", "build", "src/cli/subspace.ts", "--target", "node", "--outfile", join(out, "subspace.js"),
    "--define", `__SUBSPACE_VERSION__="${version}"`,
  ], { cwd: root, stdout: "inherit", stderr: "inherit" });
  if (build.exitCode !== 0) throw new Error("CLI package build failed.");
  let npmBundle = toAscii(await readFile(join(out, "subspace.js"), "utf8"));
  npmBundle = npmBundle.replace(/^#![^\r\n]*(?:\r?\n|$)/u, "#!/usr/bin/env node\n");
  if (!npmBundle.startsWith("#!/usr/bin/env node\n")) npmBundle = `#!/usr/bin/env node\n${npmBundle}`;
  await writeFile(join(out, "subspace.js"), npmBundle);
  for (const name of ["README.md", "SKILL.md"]) await copyFile(join(root, "npm", name), join(out, name));
  let license = "UNLICENSED";
  let spdxLicense = "";
  try {
    spdxLicense = (await readFile(join(root, "npm/LICENSE-SPDX"), "utf8")).split(/\r?\n/u)[0]!.trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new Error(`Could not read npm/LICENSE-SPDX: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
  if (spdxLicense) {
    try {
      await copyFile(join(root, "npm/LICENSE"), join(out, "LICENSE"));
      license = spdxLicense;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new Error(`Could not read npm/LICENSE: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
  }
  if (!spdxLicense || license === "UNLICENSED") {
    console.error("Warning: package license is missing or empty; package will be marked UNLICENSED.");
  }
  const files = ["package.json", "subspace.js", "README.md", "SKILL.md", ...(license === "UNLICENSED" ? [] : ["LICENSE"])];
  await writeFile(join(out, "package.json"), `${JSON.stringify({
    name: "@klimbim/subspace", version,
    description: "One-way, end-to-end encrypted messages between personal AI agents.",
    keywords: ["ai-agents", "agents", "end-to-end-encryption", "e2ee", "messaging", "cli", "ed25519", "x25519"],
    homepage: "https://github.com/klimbim-studio/subspace#readme",
    author: "klimbim studio <moin@klimbim.studio>",
    license, type: "module", bin: { subspace: "subspace.js" },
    engines: { node: ">=20" }, files,
    repository: { type: "git", url: "git+https://github.com/klimbim-studio/subspace.git" },
    publishConfig: { access: "public" },
  }, null, 2)}\n`);
  console.log(`npm package built: ${out}`);
  process.exit(0);
}

function toAscii(text: string): string {
  return text.replace(/[^\x00-\x7f]/gu, (character) => {
    const codePoint = character.codePointAt(0)!;
    if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, "0")}`;
    const remainingCodePoint = codePoint - 0x10000;
    const highSurrogate = 0xd800 + (remainingCodePoint >> 10);
    const lowSurrogate = 0xdc00 + (remainingCodePoint & 0x3ff);
    return `\\u${highSurrogate.toString(16)}\\u${lowSurrogate.toString(16)}`;
  });
}

await rm(packageDirectory, { recursive: true, force: true });
await rm(archive, { force: true });
await rm(legacyArchive, { force: true });
await mkdir(packageRoot, { recursive: true });
await mkdir(packageDirectory, { recursive: true });

const build = Bun.spawnSync([
  "bun", "build", "src/cli/subspace.ts", "--target", "node", "--outfile", join(packageDirectory, "subspace.js"),
], { cwd: root, stdout: "inherit", stderr: "inherit" });
if (build.exitCode !== 0) throw new Error("CLI package build failed.");

const bundlePath = join(packageDirectory, "subspace.js");
const bundle = await readFile(bundlePath, "utf8");
await writeFile(bundlePath, toAscii(bundle));
await copyFile(bundlePath, join(packageDirectory, "cartridge.js")); // legacy alias, keep

for (const [source, target] of [["SKILL.md", "SKILL.md"], ["RELAY-README.md", "README.md"], ["example-config.json", "example-config.json"]] as const) {
  await copyFile(join(root, "npm", source), join(packageDirectory, target));
}

const sums: string[] = [];
for (const name of packageFiles) {
  const digest = createHash("sha256").update(await readFile(join(packageDirectory, name))).digest("hex");
  sums.push(`${digest}  ${name}`);
}
await writeFile(join(packageDirectory, "SHA256SUMS"), `${sums.join("\n")}\n`, { mode: 0o644 });

const tar = Bun.spawnSync(["tar", "-czf", archive, "-C", packageDirectory, ...packageFiles, "SHA256SUMS"], {
  cwd: root,
  stdout: "inherit",
  stderr: "inherit",
});
if (tar.exitCode !== 0) throw new Error("Package archive could not be created.");
const legacyTar = Bun.spawnSync(["cp", archive, legacyArchive], { cwd: root, stdout: "inherit", stderr: "inherit" });
if (legacyTar.exitCode !== 0) throw new Error("Legacy package archive could not be copied.");
console.log(`Package built: ${relative(root, archive)}`);
