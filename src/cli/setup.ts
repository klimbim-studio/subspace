import { chmod, lstat, mkdir, open, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fingerabdruck, erzeugeSchluessel } from "../siegel.ts";
import { sshSchluesselDekodieren } from "../ssh.ts";
import {
  atomarSchreiben,
  CliFehler,
  ladeKonfiguration,
  publicKeyJson,
  schreibeSchluessel,
} from "./gemeinsam.ts";

const NAMENSMUSTER = /^[a-z][a-z0-9-]{1,31}$/;

export interface SetupInput {
  name: string;
  postamt: string;
  ordner: string;
}

export interface TrustInput {
  konfig: string;
  name: string;
  signatur: string;
  box: string;
  fingerabdruck?: string;
}

function pruefeName(name: string): void {
  if (!NAMENSMUSTER.test(name)) throw new CliFehler(1, "Invalid name.");
}

function pruefePostamt(postamt: string): void {
  let address: URL;
  try { address = new URL(postamt); } catch { throw new CliFehler(1, "Invalid post office address."); }
  const authorityStart = postamt.indexOf("://") + 3;
  const tail = postamt.slice(authorityStart).match(/[/?#].*$/)?.[0] ?? "";
  if (address.protocol !== "https:" && !(address.protocol === "http:" && ["127.0.0.1", "localhost"].includes(address.hostname))) {
    throw new CliFehler(1, "Invalid post office address.");
  }
  if (address.username || address.password || address.pathname !== "/" || address.search || address.hash || (tail !== "" && tail !== "/")) {
    throw new CliFehler(1, "Invalid post office address.");
  }
}

async function existiert(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new CliFehler(3, "Could not validate the configuration or key file.");
  }
}

export async function setup(input: SetupInput): Promise<void> {
  pruefeName(input.name);
  pruefePostamt(input.postamt);
  const ordner = resolve(input.ordner);
  const configPath = join(ordner, "config.json");
  const keyPath = join(ordner, "key.json");
  const legacyConfigPath = join(ordner, "konfig.json");
  const legacyKeyPath = join(ordner, "schluessel.json");
  if (await existiert(configPath) || await existiert(keyPath) || await existiert(legacyConfigPath) || await existiert(legacyKeyPath)) {
    throw new CliFehler(1, "Configuration or key file already exists.");
  }

  try {
    await mkdir(ordner, { recursive: true, mode: 0o700 });
    const directory = await lstat(ordner);
    if (!directory.isDirectory() || directory.uid !== (process.getuid?.() ?? -1)) throw new CliFehler(3, "Unsafe directory permissions.");
    await chmod(ordner, 0o700);
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(3, "Could not create a secure configuration directory.");
  }

  let configCreated = false;
  try {
    const file = await open(configPath, "wx", 0o600);
    configCreated = true;
    try {
      await file.writeFile(JSON.stringify({
        name: input.name,
        post_office: input.postamt.replace(/\/$/, ""),
        storage: join(ordner, "storage"),
        trusted: {},
        channels: {},
      }) + "\n");
      await file.sync();
    } finally {
      await file.close();
    }
    await chmod(configPath, 0o600);
    const key = erzeugeSchluessel();
    await schreibeSchluessel(keyPath, key);
    console.log(JSON.stringify({ name: input.name, ...JSON.parse(publicKeyJson(key)) }));
  } catch (error) {
    if (configCreated) await rm(configPath, { force: true }).catch(() => {});
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(1, "Could not create the configuration safely.");
  }
}

function decodePublicKey(value: string, sshAllowed = false): Uint8Array {
  if (sshAllowed && value.trimStart().startsWith("ssh-")) {
    const key = sshSchluesselDekodieren(value);
    if (!key) throw new CliFehler(1, "Invalid public key.");
    return key;
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new CliFehler(1, "Invalid public key.");
  }
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (bytes.length !== 32 || Buffer.from(bytes).toString("base64") !== value) throw new CliFehler(1, "Invalid public key.");
  return bytes;
}

export async function trust(input: TrustInput): Promise<void> {
  pruefeName(input.name);
  const signatur = decodePublicKey(input.signatur, true);
  const box = decodePublicKey(input.box);
  const calculatedFingerprint = fingerabdruck(signatur, box);
  if (input.fingerabdruck !== undefined && input.fingerabdruck !== calculatedFingerprint) {
    throw new CliFehler(4, "Fingerprint does not match.");
  }
  const configuration = await ladeKonfiguration(input.konfig);
  const existing = Object.hasOwn(configuration.vertraut, input.name) ? configuration.vertraut[input.name] : undefined;
  if (existing) {
    if (Buffer.from(existing.signatur).equals(Buffer.from(signatur)) && Buffer.from(existing.box).equals(Buffer.from(box))) return;
    throw new CliFehler(4, `${input.name} already has a different key. Accept a rotated key with subspace accept ${input.name}.`);
  }
  const trusted = Object.fromEntries(Object.entries(configuration.vertraut).map(([name, keys]) => [name, {
    signatur: Buffer.from(keys.signatur).toString("base64"),
    box: Buffer.from(keys.box).toString("base64"),
  }]));
  trusted[input.name] = { signatur: Buffer.from(signatur).toString("base64"), box: Buffer.from(box).toString("base64") };
  await atomarSchreiben(input.konfig, JSON.stringify({
    name: configuration.name,
    post_office: configuration.postamt,
    storage: configuration.ablage,
    trusted: Object.fromEntries(Object.entries(trusted).map(([name, keys]) => [name, { signature: keys.signatur, box: keys.box }])),
    channels: configuration.kanaele,
  }) + "\n");
}
