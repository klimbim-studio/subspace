import { chmod, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { text } from "node:stream/consumers";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { fingerprint, type KeyPair } from "../seal.ts";

export class CliError extends Error {
  constructor(readonly exitCode: number, readonly publicMessage: string) {
    super(publicMessage);
  }
}

export function resolveConfigPath(explicitPath?: string): string;
export function resolveConfigPath(explicitPath: string | undefined, required: false): string | undefined;
export function resolveConfigPath(explicitPath?: string, required = true): string | undefined {
  const path = explicitPath ?? process.env.SUBSPACE_CONFIG ?? process.env["AGENTENPOST_KONFIG"]; // legacy key, keep
  if (!path) {
    if (required) throw new CliError(3, "Configuration path is required.");
    return undefined;
  }
  return path;
}

export interface Configuration {
  name: string;
  server: string;
  storage: string;
  trusted: Record<string, { signature: Uint8Array; box: Uint8Array }>;
  channels: Record<string, string[]>;
  invitation_tasks: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function base64(value: unknown, length: number): Uint8Array {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new CliError(3, "Invalid configuration or key file.");
  }
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (bytes.length !== length || Buffer.from(bytes).toString("base64") !== value) {
    throw new CliError(3, "Invalid configuration or key file.");
  }
  return bytes;
}

function currentUser(): number {
  return process.getuid?.() ?? -1;
}

async function validateFilePermissions(path: string, exactMode?: number): Promise<void> {
  const info = await lstat(path);
  if (!info.isFile() || info.uid !== currentUser()) throw new CliError(3, "Unsafe file permissions.");
  const permissions = info.mode & 0o777;
  if (exactMode !== undefined ? permissions !== exactMode : (permissions & 0o022) !== 0) {
    throw new CliError(3, "Unsafe file permissions.");
  }
}

export async function loadConfiguration(path: string): Promise<Configuration> {
  try {
    await validateFilePermissions(path);
    const raw: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!isRecord(raw) || typeof raw.name !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(raw.name)) {
      throw new CliError(3, "Invalid configuration or key file.");
    }
    const serverUrl = raw.server ?? raw.post_office ?? raw.postamt; // legacy key, keep
    const storage = raw.storage ?? raw.ablage; // legacy key, keep
    const trustedRaw = raw.trusted ?? raw.vertraut; // legacy key, keep
    const channelsRaw = raw.channels ?? raw.kanaele; // legacy key, keep
    if (typeof serverUrl !== "string" || typeof storage !== "string" || !isRecord(trustedRaw) || !isRecord(channelsRaw)
      || (raw.invitation_tasks !== undefined && typeof raw.invitation_tasks !== "boolean")) {
      throw new CliError(3, "Invalid configuration or key file.");
    }
    let address: URL;
    try { address = new URL(serverUrl); } catch { throw new CliError(3, "Invalid configuration or key file."); }
    const authorityStart = serverUrl.indexOf("://") + 3;
    const tail = serverUrl.slice(authorityStart).match(/[/?#].*$/)?.[0] ?? "";
    if (address.protocol !== "https:" && !(address.protocol === "http:" && ["127.0.0.1", "localhost"].includes(address.hostname))) {
      throw new CliError(3, "Invalid configuration or key file.");
    }
    if (address.username || address.password || address.pathname !== "/" || address.search || address.hash || (tail !== "" && tail !== "/")) {
      throw new CliError(3, "Invalid configuration or key file.");
    }
    const trustedContacts: Configuration["trusted"] = {};
    for (const [name, entry] of Object.entries(trustedRaw)) {
      if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !isRecord(entry)) throw new CliError(3, "Invalid configuration or key file.");
      if (!Object.hasOwn(trustedContacts, name)) trustedContacts[name] = { signature: base64(entry.signature ?? entry.signatur, 32), box: base64(entry.box, 32) }; // legacy key, keep
    }
    const channelMap: Record<string, string[]> = {};
    for (const [name, members] of Object.entries(channelsRaw)) {
      if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !Array.isArray(members)
        || members.some((member) => typeof member !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(member))
        || new Set(members).size !== members.length) {
        throw new CliError(3, "Invalid configuration or key file.");
      }
      channelMap[name] = members as string[];
    }
    return { name: raw.name, server: serverUrl.replace(/\/$/, ""), storage: storage, trusted: trustedContacts, channels: channelMap, invitation_tasks: raw.invitation_tasks !== false };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "Configuration is unreadable or unsafe.");
  }
}

const configurationFields = ["name", "server", "storage", "trusted", "channels", "invitation_tasks"];

/**
 * Writes the configuration back and changes only what the configuration object owns.
 * Fields this version does not know stay as they are. Legacy keys that older command lines
 * still read follow the current values when the file already has them; they are never created.
 */
export async function saveConfiguration(path: string, configuration: Configuration, indent?: number): Promise<void> {
  let existing: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (isRecord(parsed)) existing = parsed;
  } catch { /* the caller loaded this file before; without readable content only the owned fields are written */ }
  const trusted = Object.fromEntries(Object.entries(configuration.trusted).map(([contact, keys]) => [contact, {
    signature: Buffer.from(keys.signature).toString("base64"),
    box: Buffer.from(keys.box).toString("base64"),
  }]));
  const unknown = Object.fromEntries(Object.entries(existing).filter(([field]) => !configurationFields.includes(field)));
  const next: Record<string, unknown> = {
    name: configuration.name,
    server: configuration.server,
    storage: configuration.storage,
    trusted,
    channels: configuration.channels,
    invitation_tasks: configuration.invitation_tasks,
    ...unknown,
  };
  if (Object.hasOwn(existing, "post_office")) next.post_office = configuration.server; // legacy key, keep
  if (Object.hasOwn(existing, "postamt")) next.postamt = configuration.server; // legacy key, keep
  if (Object.hasOwn(existing, "ablage")) next.ablage = configuration.storage; // legacy key, keep
  if (Object.hasOwn(existing, "kanaele")) next.kanaele = configuration.channels; // legacy key, keep
  if (Object.hasOwn(existing, "vertraut")) { // legacy key, keep
    next.vertraut = Object.fromEntries(Object.entries(trusted).map(([contact, keys]) => [contact, { signatur: keys.signature, box: keys.box }]));
  }
  await atomicWrite(path, JSON.stringify(next, null, indent) + "\n");
}

export async function loadKey(path: string): Promise<KeyPair> {
  try {
    let content: string;
    if (path === "-") {
      content = await text(process.stdin);
      if (content.length > 8192) throw new CliError(3, "Invalid configuration or key file.");
    } else {
      await validateFilePermissions(path, 0o600);
      content = await readFile(path, "utf8");
    }
    const value: unknown = JSON.parse(content);
    if (!isRecord(value)) throw new CliError(3, "Invalid configuration or key file.");
    const schluessel: KeyPair = {
      signaturPrivat: base64(value.signaturPrivat, 32),
      signaturOeffentlich: base64(value.signaturOeffentlich, 32),
      boxPrivat: base64(value.boxPrivat, 32),
      boxOeffentlich: base64(value.boxOeffentlich, 32),
    };
    if (Buffer.compare(Buffer.from(ed25519.getPublicKey(schluessel.signaturPrivat)), Buffer.from(schluessel.signaturOeffentlich)) !== 0
      || Buffer.compare(Buffer.from(x25519.getPublicKey(schluessel.boxPrivat)), Buffer.from(schluessel.boxOeffentlich)) !== 0) {
      throw new CliError(3, "Invalid configuration or key file.");
    }
    return schluessel;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "Key is unreadable or unsafe.");
  }
}

export function publicKeyJson(key: KeyPair): string {
  return JSON.stringify({
    signature: Buffer.from(key.signaturOeffentlich).toString("base64"),
    box: Buffer.from(key.boxOeffentlich).toString("base64"),
    fingerprint: fingerprint(key.signaturOeffentlich, key.boxOeffentlich),
  });
}

export async function writeKey(path: string, key: KeyPair): Promise<void> {
  let file;
  let created = false;
  try {
    file = await open(path, "wx", 0o600);
    created = true;
    await file.writeFile(JSON.stringify({
      signaturPrivat: Buffer.from(key.signaturPrivat).toString("base64"),
      signaturOeffentlich: Buffer.from(key.signaturOeffentlich).toString("base64"),
      boxPrivat: Buffer.from(key.boxPrivat).toString("base64"),
      boxOeffentlich: Buffer.from(key.boxOeffentlich).toString("base64"),
    }) + "\n");
    await file.sync();
    await file.close();
    await chmod(path, 0o600);
  } catch {
    await file?.close().catch(() => {});
    if (created) await rm(path, { force: true }).catch(() => {});
    throw new CliError(1, "Could not write the key file exclusively.");
  }
}

export async function ensureStorage(root: string): Promise<{ quarantine: string; rejected: string; seen: string }> {
  try {
    const info = await lstat(root).catch(() => undefined);
    if (info && (!info.isDirectory() || info.uid !== currentUser())) throw new CliError(3, "Unsafe storage permissions.");
    await mkdir(root, { recursive: true, mode: 0o700 });
    const renames = [["quarantaene", "quarantine"], ["abgewiesen", "rejected"], ["gesehen.json", "seen.json"]] as const;
    const present = await Promise.all(renames.map(async ([oldName, newName]) => ({
      oldPath: join(root, oldName), newPath: join(root, newName),
      oldExists: Boolean(await lstat(join(root, oldName)).catch(() => undefined)),
      newExists: Boolean(await lstat(join(root, newName)).catch(() => undefined)),
    })));
    if (present.some(({ oldExists, newExists }) => oldExists && newExists)) throw new CliError(3, "Legacy storage and English storage both exist; resolve the name conflict before retrying.");
    for (const item of present) if (item.oldExists) await rename(item.oldPath, item.newPath);
    const quarantinePath = join(root, "quarantine");
    const rejectedPath = join(root, "rejected");
    for (const directory of [quarantinePath, rejectedPath]) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const directoryInfo = await lstat(directory);
      if (!directoryInfo.isDirectory() || directoryInfo.uid !== currentUser()) throw new CliError(3, "Unsafe storage permissions.");
      await chmod(directory, 0o700);
    }
    return { quarantine: quarantinePath, rejected: rejectedPath, seen: join(root, "seen.json") };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "Could not prepare storage safely.");
  }
}

export async function atomicWrite(path: string, content: string | Uint8Array): Promise<void> {
  const temporary = join(dirname(path), `.${randomBytes(12).toString("hex")}.tmp`);
  let file;
  try {
    file = await open(temporary, "wx", 0o600);
    await file.writeFile(content);
    await file.sync();
    await file.close();
    await rename(temporary, path);
    await chmod(path, 0o600);
  } catch {
    await file?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw new CliError(1, "Could not write the storage file safely.");
  }
}

export async function readSeen(path: string): Promise<Record<string, string>> {
  try {
    const info = await lstat(path).catch(() => undefined);
    if (!info) return {};
    await validateFilePermissions(path, 0o600);
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!isRecord(value) || Object.entries(value).some(([id, expiry]) => !/^[0-9a-f]{32}$/.test(id)
      || typeof expiry !== "string" || !Number.isFinite(Date.parse(expiry)))) throw new Error();
    return value as Record<string, string>;
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "seen.json is invalid or unsafe.");
  }
}

export async function saveSeen(path: string, seen: Record<string, string>): Promise<void> {
  await atomicWrite(path, JSON.stringify(seen) + "\n");
}
