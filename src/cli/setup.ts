import { chmod, lstat, mkdir, open, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fingerprint, createKey } from "../seal.ts";
import { decodeSshPublicKey } from "../ssh.ts";
import {
  CliError,
  loadConfiguration,
  publicKeyJson,
  saveConfiguration,
  writeKey,
} from "./shared.ts";


const NAME_PATTERN = /^[a-z][a-z0-9-]{1,31}$/;

export interface SetupInput {
  name: string;
  server: string;
  directory: string;
}

export interface TrustInput {
  configPath: string;
  name: string;
  signature: string;
  box: string;
  fingerprint?: string;
}

function validateName(name: string): void {
  if (!NAME_PATTERN.test(name)) throw new CliError(1, "Invalid name.");
}

function validateServerAddress(serverAddress: string): void {
  let parsedUrl: URL;
  try { parsedUrl = new URL(serverAddress); } catch { throw new CliError(1, "Invalid Subspace server address."); }
  const authorityStart = serverAddress.indexOf("://") + 3;
  const tail = serverAddress.slice(authorityStart).match(/[/?#].*$/)?.[0] ?? "";
  if (parsedUrl.protocol !== "https:" && !(parsedUrl.protocol === "http:" && ["127.0.0.1", "localhost"].includes(parsedUrl.hostname))) {
    throw new CliError(1, "Invalid Subspace server address.");
  }
  if (parsedUrl.username || parsedUrl.password || parsedUrl.pathname !== "/" || parsedUrl.search || parsedUrl.hash || (tail !== "" && tail !== "/")) {
    throw new CliError(1, "Invalid Subspace server address.");
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new CliError(3, "Could not validate the configuration or key file.");
  }
}

export async function setup(input: SetupInput): Promise<void> {
  validateName(input.name);
  validateServerAddress(input.server);
  const targetDirectory = resolve(input.directory);
  const configPath = join(targetDirectory, "config.json");
  const keyPath = join(targetDirectory, "key.json");
  const legacyConfigPath = join(targetDirectory, "konfig.json");
  const legacyKeyPath = join(targetDirectory, "schluessel.json");
  if (await pathExists(configPath) || await pathExists(keyPath) || await pathExists(legacyConfigPath) || await pathExists(legacyKeyPath)) {
    throw new CliError(1, "Configuration or key file already exists.");
  }

  try {
    await mkdir(targetDirectory, { recursive: true, mode: 0o700 });
    const directory = await lstat(targetDirectory);
    if (!directory.isDirectory() || directory.uid !== (process.getuid?.() ?? -1)) throw new CliError(3, "Unsafe directory permissions.");
    await chmod(targetDirectory, 0o700);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "Could not create a secure configuration directory.");
  }

  let configCreated = false;
  try {
    const file = await open(configPath, "wx", 0o600);
    configCreated = true;
    try {
      await file.writeFile(JSON.stringify({
        name: input.name,
        server: input.server.replace(/\/$/, ""),
        storage: join(targetDirectory, "storage"),
        trusted: {},
        channels: {},
      }) + "\n");
      await file.sync();
    } finally {
      await file.close();
    }
    await chmod(configPath, 0o600);
    const key = createKey();
    await writeKey(keyPath, key);
    console.log(JSON.stringify({ name: input.name, ...JSON.parse(publicKeyJson(key)) }));
  } catch (error) {
    if (configCreated) await rm(configPath, { force: true }).catch(() => {});
    if (error instanceof CliError) throw error;
    throw new CliError(1, "Could not create the configuration safely.");
  }
}

function decodePublicKey(value: string, sshAllowed = false): Uint8Array {
  if (sshAllowed && value.trimStart().startsWith("ssh-")) {
    const key = decodeSshPublicKey(value);
    if (!key) throw new CliError(1, "Invalid public key.");
    return key;
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new CliError(1, "Invalid public key.");
  }
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (bytes.length !== 32 || Buffer.from(bytes).toString("base64") !== value) throw new CliError(1, "Invalid public key.");
  return bytes;
}

export async function trust(input: TrustInput): Promise<void> {
  validateName(input.name);
  const signingKey = decodePublicKey(input.signature, true);
  const box = decodePublicKey(input.box);
  const calculatedFingerprint = fingerprint(signingKey, box);
  if (input.fingerprint !== undefined && input.fingerprint !== calculatedFingerprint) {
    throw new CliError(4, "Fingerprint does not match.");
  }
  const configuration = await loadConfiguration(input.configPath);
  const existing = Object.hasOwn(configuration.trusted, input.name) ? configuration.trusted[input.name] : undefined;
  if (existing) {
    if (Buffer.from(existing.signature).equals(Buffer.from(signingKey)) && Buffer.from(existing.box).equals(Buffer.from(box))) return;
    throw new CliError(4, `${input.name} already has a different key. Accept a rotated key with subspace accept ${input.name}.`);
  }
  await saveConfiguration(input.configPath, {
    ...configuration,
    trusted: { ...configuration.trusted, [input.name]: { signature: signingKey, box } },
  });
}
