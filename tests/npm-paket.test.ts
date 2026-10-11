import { afterEach, describe, expect, test } from "bun:test";
import { createHash, randomUUID } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, readlink, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const wurzel = join(import.meta.dir, "..");
const tempRoots: string[] = [];

async function temp(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "subspace-npm-test-"));
  tempRoots.push(path);
  return path;
}

async function run(command: string, args: string[], cwd = wurzel, env?: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  const executable = (env?.PATH ? Bun.which(command, { PATH: env.PATH }) : Bun.which(command)) ?? command;
  const child = Bun.spawn([executable, ...args], { cwd, env: env ? { ...process.env, ...env } : process.env, stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  return { code, stdout, stderr };
}

function npm(args: string[], cwd = wurzel) {
  return run(process.execPath, ["x", "npm@11.5.1", ...args], cwd);
}

async function snapshotDirectory(path: string): Promise<string[]> {
  const entries: string[] = [];
  async function visit(directory: string, prefix = ""): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = join(directory, entry.name);
      if (entry.isDirectory()) {
        entries.push(`directory:${relative}`);
        await visit(full, relative);
      } else if (entry.isSymbolicLink()) {
        entries.push(`symlink:${relative}:${await readlink(full)}`);
      } else {
        const digest = createHash("sha256").update(await readFile(full)).digest("hex");
        entries.push(`file:${relative}:${digest}`);
      }
    }
  }
  await visit(path);
  return entries.sort();
}

async function baueNpmPaket(version?: string, cwd = wurzel, out?: string) {
  const args = [join(cwd, "src/paket/bauen.ts"), "--npm"];
  if (version !== undefined) args.push("--version", version);
  if (out !== undefined) args.push("--out", out);
  return run("bun", args, cwd);
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("npm-Paket", () => {
  test("npm-paketordner: Dateiliste, Manifest und Versionsvalidierung", async () => {
    const out = join(await temp(), "out");
    const built = await baueNpmPaket("0.1.0", wurzel, out);
    expect(built.code).toBe(0);
    const dir = out;
    expect((await readdir(dir)).sort()).toEqual(["LICENSE", "README.md", "SKILL.md", "package.json", "subspace.js"]);
    const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
    expect(manifest).toMatchObject({
      name: "@klimbim/subspace", version: "0.1.0", bin: { subspace: "subspace.js" },
      type: "module", engines: { node: ">=18" }, files: ["package.json", "subspace.js", "README.md", "SKILL.md", "LICENSE"],
      repository: { type: "git", url: "git+https://github.com/klimbim-studio/subspace.git" },
      license: "MIT", publishConfig: { access: "public" },
    });
    expect(manifest.dependencies).toBeUndefined();
    expect(manifest.private).toBeUndefined();
    const missing = await baueNpmPaket(undefined, wurzel, join(await temp(), "missing"));
    expect(missing.code).not.toBe(0);
    expect(missing.stderr).toMatch(/version/i);
    for (const version of ["v0.1.0", "0.1", "0.1.0+build", "x.y.z"]) {
      const invalid = await baueNpmPaket(version, wurzel, join(await temp(), "invalid"));
      expect(invalid.code).not.toBe(0);
      expect(invalid.stderr).toMatch(/version/i);
    }
  });

  test("npm-lizenz: MIT liegt bei und fehlende Lizenz wird als UNLICENSED markiert", async () => {
    const license = await readFile(join(wurzel, "paket/LICENSE"), "utf8");
    expect(license).toContain("Copyright (c) 2026 Stephan Herold (klimbim studio)");
    expect(await readFile(join(wurzel, "paket/LICENSE-SPDX"), "utf8")).toBe("MIT");
    const out = join(await temp(), "out");
    expect((await baueNpmPaket("0.1.0", wurzel, out)).code).toBe(0);
    expect(await readFile(join(out, "LICENSE"), "utf8")).toBe(license);

    const copy = await temp();
    for (const path of ["src", "paket", "package.json", "bun.lock", "tsconfig.json"]) {
      const source = join(wurzel, path);
      const dest = join(copy, path);
      let info;
      try { info = await stat(source); } catch { continue; }
      if (info.isDirectory()) {
        await mkdir(join(dest, ".."), { recursive: true });
        const proc = Bun.spawnSync(["cp", "-R", source, join(dest, "..")]);
        expect(proc.exitCode).toBe(0);
      } else {
        await mkdir(join(dest, ".."), { recursive: true });
        await copyFile(source, dest);
      }
    }
    await rm(join(copy, "paket/LICENSE"), { force: true });
    await rm(join(copy, "paket/LICENSE-SPDX"), { force: true });
    const installed = await run("bun", ["install", "--frozen-lockfile"], copy);
    expect(installed.code).toBe(0);
    const missingOut = join(copy, "temp-package");
    const missing = await baueNpmPaket("0.1.0", copy, missingOut);
    expect(missing.code).toBe(0);
    const manifest = JSON.parse(await readFile(join(missingOut, "package.json"), "utf8"));
    expect(manifest.license).toBe("UNLICENSED");
    expect(await Bun.file(join(missingOut, "LICENSE")).exists()).toBe(false);
    expect(missing.stderr).toMatch(/license/i);

    await copyFile(join(wurzel, "paket/LICENSE-SPDX"), join(copy, "paket/LICENSE-SPDX"));
    const missingLicenseOut = join(copy, "missing-license-package");
    const missingLicense = await baueNpmPaket("0.1.0", copy, missingLicenseOut);
    expect(missingLicense.code).toBe(0);
    const missingLicenseManifest = JSON.parse(await readFile(join(missingLicenseOut, "package.json"), "utf8"));
    expect(missingLicenseManifest.license).toBe("UNLICENSED");
    expect(missingLicenseManifest.files).not.toContain("LICENSE");
    expect(await Bun.file(join(missingLicenseOut, "LICENSE")).exists()).toBe(false);
    expect(missingLicense.stderr).toMatch(/license/i);
  });

  test("npm-version: gebündelte Version und Entwickler-Platzhalter", async () => {
    const out = join(await temp(), "out");
    expect((await baueNpmPaket("0.1.0", wurzel, out)).code).toBe(0);
    const bundle = await run("node", [join(out, "subspace.js"), "--version"]);
    expect(bundle).toMatchObject({ code: 0, stdout: "0.1.0\n" });
    const dev = await run("bun", ["src/cli/agentenpost.ts", "--version"]);
    expect(dev).toMatchObject({ code: 0, stdout: "0.0.0-dev\n" });
    const help = await run("bun", ["src/cli/agentenpost.ts", "help"]);
    expect(help.stdout).toContain("--version");
  });

  test("npm-tarball-startet: fremdes Tarball lässt sich installieren und starten", async () => {
    const out = join(await temp(), "out");
    expect((await baueNpmPaket("0.1.0", wurzel, out)).code).toBe(0);
    const packed = await npm(["pack", "--json"], out);
    expect(packed.code).toBe(0);
    const packageInfo = JSON.parse(packed.stdout)[0];
    expect(packageInfo.files.map((file: { path: string }) => file.path).sort())
      .toEqual(["LICENSE", "README.md", "SKILL.md", "package.json", "subspace.js"]);
    const root = await temp();
    const tarball = join(out, packageInfo.filename);
    const viaExec = await npm(["exec", "--yes", "--package", tarball, "--", "subspace", "--help"], root);
    expect(viaExec.code).toBe(0);
    expect(viaExec.stdout).toContain("subspace send");
    const viaBunx = await run(process.execPath, ["x", "--package", tarball, "subspace", "--version"], root);
    expect(viaBunx.code).toBe(0);
    expect(viaBunx.stdout).toContain("0.1.0");
  }, 30000);

  test("npm-ausgabeordner: --out isoliert den Bau vom Standardordner", async () => {
    const standard = join(wurzel, "out/npm");
    const backup = join(wurzel, "out", `npm-test-preserve-${randomUUID()}`);
    let hadOriginal = false;
    let originalSnapshot: string[] = [];
    await mkdir(join(wurzel, "out"), { recursive: true });
    try {
      try {
        originalSnapshot = await snapshotDirectory(standard);
        await rename(standard, backup);
        hadOriginal = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      await mkdir(standard, { recursive: true });
      await writeFile(join(standard, "marker.txt"), "keep this marker\n");
      const tempOut = join(await temp(), "full-package");
      const built = await baueNpmPaket("0.1.0", wurzel, tempOut);
      expect(built.code).toBe(0);
      expect(await readdir(standard)).toEqual(["marker.txt"]);
      expect(await readFile(join(standard, "marker.txt"), "utf8")).toBe("keep this marker\n");
      expect((await readdir(tempOut)).sort()).toEqual(["LICENSE", "README.md", "SKILL.md", "package.json", "subspace.js"]);
    } finally {
      await rm(standard, { recursive: true, force: true });
      if (hadOriginal) await rename(backup, standard);
    }
    if (hadOriginal) expect(await snapshotDirectory(standard)).toEqual(originalSnapshot);
    else {
      let exists = true;
      try { await stat(standard); } catch { exists = false; }
      expect(exists).toBe(false);
    }
  });

  test("npm-ohne-bun: installiertes Kommando startet über Node-Shebang", async () => {
    const out = join(await temp(), "out");
    expect((await baueNpmPaket("0.1.0", wurzel, out)).code).toBe(0);
    const packed = await npm(["pack", "--json"], out);
    expect(packed.code).toBe(0);
    const tarball = join(out, JSON.parse(packed.stdout)[0].filename);
    const prefix = await temp();
    const install = await npm(["install", "--prefix", prefix, tarball], prefix);
    expect(install.code).toBe(0);
    const node = Bun.which("node")!;
    const nodeOnly = join(prefix, "node-only-bin");
    await mkdir(nodeOnly);
    await symlink(node, join(nodeOnly, "node"));
    const path = `${join(prefix, "node_modules/.bin")}:${nodeOnly}`;
    expect(Bun.which("bun", { PATH: path })).toBeNull();
    expect(Bun.which("node", { PATH: path })).not.toBeNull();
    const started = await run(join(prefix, "node_modules/.bin/subspace"), ["--version"], prefix, { PATH: path });
    expect(started).toMatchObject({ code: 0, stdout: "0.1.0\n" });
  }, 30000);

  if (process.env.SUBSPACE_NPM_NO_BUNX_CHILD !== "1") test("npm-ohne-bunx: alle Pakettests laufen mit bun, node und System-PATH", async () => {
    const bin = join(await temp(), "bin");
    await mkdir(bin);
    const node = Bun.which("node")!;
    await symlink(process.execPath, join(bin, "bun"));
    await symlink(node, join(bin, "node"));
    const path = `${bin}:/usr/bin:/bin`;
    expect(Bun.which("bun" + "x", { PATH: path })).toBeNull();
    expect(Bun.which("bun", { PATH: path })).not.toBeNull();
    expect(Bun.which("node", { PATH: path })).not.toBeNull();
    const child = await run(process.execPath, ["test", join(import.meta.dir, "npm-paket.test.ts")], wurzel, {
      PATH: path,
      SUBSPACE_NPM_NO_BUNX_CHILD: "1",
    });
    if (child.code !== 0) throw new Error(`${child.stdout}\n${child.stderr}`);
    expect(child.code).toBe(0);
    expect(`${child.stdout}\n${child.stderr}`).toMatch(/0 fail/);
  }, 120000);

  test("npm-platzhalter: 0.0.0 Tarball enthält nur README und Lizenz", async () => {
    const dir = join(wurzel, "betrieb/npm-platzhalter");
    const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
    expect(manifest).toMatchObject({
      name: "@klimbim/subspace", version: "0.0.0", license: "MIT",
      repository: { type: "git", url: "git+https://github.com/klimbim-studio/subspace.git" },
      publishConfig: { access: "public" }, files: ["README.md", "LICENSE"],
    });
    expect(manifest.bin).toBeUndefined();
    expect(manifest.dependencies).toBeUndefined();
    expect(manifest.private).toBeUndefined();
    expect((await readdir(dir)).sort()).toEqual(["LICENSE", "README.md", "package.json"]);
    const readme = await readFile(join(dir, "README.md"), "utf8");
    expect(readme.trim().split("\n").filter(Boolean)).toHaveLength(2);
    expect(readme).toMatch(/placeholder/i);
    expect(readme).toMatch(/0\.1\.0/);
    const packed = await npm(["pack", "--dry-run", "--json"], dir);
    expect(packed.code).toBe(0);
    expect(JSON.parse(packed.stdout)[0].files.map((file: { path: string }) => file.path).sort())
      .toEqual(["LICENSE", "README.md", "package.json"]);
  });
});
