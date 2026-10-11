import { chmod, lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { text } from "node:stream/consumers";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { fingerabdruck, type Schluessel } from "../siegel.ts";

export class CliFehler extends Error {
  constructor(readonly exitCode: number, readonly publicMessage: string) {
    super(publicMessage);
  }
}

export function englischerOptionsname(flag: string): string {
  const namen: Record<string, string> = {
    "--config": "--config", "--key": "--key", "--ordner": "--dir", "--postamt": "--post-office",
    "--an": "--to", "--kanal": "--channel", "--art": "--kind", "--betreff": "--subject", "--text-datei": "--text-file",
    "--bezug": "--ref", "--anhang": "--attach", "--ausgeloest-von": "--triggered-by", "--fuer": "--for",
    "--skript": "--script", "--warten": "--wait", "--fortsetzen": "--resume", "--signatur": "--signature",
    "--fingerabdruck": "--fingerprint", "--ausgabe": "--out", "--laufzeit": "--lifetime", "--post-office": "--post-office",
  };
  return namen[flag] ?? flag;
}

export interface Konfiguration {
  name: string;
  postamt: string;
  ablage: string;
  vertraut: Record<string, { signatur: Uint8Array; box: Uint8Array }>;
  kanaele: Record<string, string[]>;
}

function objekt(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function base64(value: unknown, length: number): Uint8Array {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new CliFehler(3, "Invalid configuration or key file.");
  }
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (bytes.length !== length || Buffer.from(bytes).toString("base64") !== value) {
    throw new CliFehler(3, "Invalid configuration or key file.");
  }
  return bytes;
}

function aktuellerBenutzer(): number {
  return process.getuid?.() ?? -1;
}

async function sichereDatei(path: string, exactMode?: number): Promise<void> {
  const info = await lstat(path);
  if (!info.isFile() || info.uid !== aktuellerBenutzer()) throw new CliFehler(3, "Unsafe file permissions.");
  const permissions = info.mode & 0o777;
  if (exactMode !== undefined ? permissions !== exactMode : (permissions & 0o022) !== 0) {
    throw new CliFehler(3, "Unsafe file permissions.");
  }
}

export async function ladeKonfiguration(path: string): Promise<Konfiguration> {
  try {
    await sichereDatei(path);
    const raw: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!objekt(raw) || typeof raw.name !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(raw.name)) {
      throw new CliFehler(3, "Invalid configuration or key file.");
    }
    const postOffice = raw.post_office ?? raw.postamt;
    const storage = raw.storage ?? raw.ablage;
    const trustedRaw = raw.trusted ?? raw.vertraut;
    const channelsRaw = raw.channels ?? raw.kanaele;
    if (typeof postOffice !== "string" || typeof storage !== "string" || !objekt(trustedRaw) || !objekt(channelsRaw)) {
      throw new CliFehler(3, "Invalid configuration or key file.");
    }
    let address: URL;
    try { address = new URL(postOffice); } catch { throw new CliFehler(3, "Invalid configuration or key file."); }
    const authorityStart = postOffice.indexOf("://") + 3;
    const tail = postOffice.slice(authorityStart).match(/[/?#].*$/)?.[0] ?? "";
    if (address.protocol !== "https:" && !(address.protocol === "http:" && ["127.0.0.1", "localhost"].includes(address.hostname))) {
      throw new CliFehler(3, "Invalid configuration or key file.");
    }
    if (address.username || address.password || address.pathname !== "/" || address.search || address.hash || (tail !== "" && tail !== "/")) {
      throw new CliFehler(3, "Invalid configuration or key file.");
    }
    const vertraut: Konfiguration["vertraut"] = {};
    for (const [name, entry] of Object.entries(trustedRaw)) {
      if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !objekt(entry)) throw new CliFehler(3, "Invalid configuration or key file.");
      if (!Object.hasOwn(vertraut, name)) vertraut[name] = { signatur: base64(entry.signature ?? entry.signatur, 32), box: base64(entry.box, 32) };
    }
    const kanaele: Record<string, string[]> = {};
    for (const [name, members] of Object.entries(channelsRaw)) {
      if (!/^[a-z][a-z0-9-]{1,31}$/.test(name) || !Array.isArray(members)
        || members.some((member) => typeof member !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(member))
        || new Set(members).size !== members.length) {
        throw new CliFehler(3, "Invalid configuration or key file.");
      }
      kanaele[name] = members as string[];
    }
    return { name: raw.name, postamt: postOffice.replace(/\/$/, ""), ablage: storage, vertraut, kanaele };
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(3, "Configuration is unreadable or unsafe.");
  }
}

export async function ladeSchluessel(path: string): Promise<Schluessel> {
  try {
    let content: string;
    if (path === "-") {
      content = await text(process.stdin);
      if (content.length > 8192) throw new CliFehler(3, "Invalid configuration or key file.");
    } else {
      await sichereDatei(path, 0o600);
      content = await readFile(path, "utf8");
    }
    const value: unknown = JSON.parse(content);
    if (!objekt(value)) throw new CliFehler(3, "Invalid configuration or key file.");
    const schluessel: Schluessel = {
      signaturPrivat: base64(value.signaturPrivat, 32),
      signaturOeffentlich: base64(value.signaturOeffentlich, 32),
      boxPrivat: base64(value.boxPrivat, 32),
      boxOeffentlich: base64(value.boxOeffentlich, 32),
    };
    if (Buffer.compare(Buffer.from(ed25519.getPublicKey(schluessel.signaturPrivat)), Buffer.from(schluessel.signaturOeffentlich)) !== 0
      || Buffer.compare(Buffer.from(x25519.getPublicKey(schluessel.boxPrivat)), Buffer.from(schluessel.boxOeffentlich)) !== 0) {
      throw new CliFehler(3, "Invalid configuration or key file.");
    }
    return schluessel;
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(3, "Key is unreadable or unsafe.");
  }
}

export function publicKeyJson(key: Schluessel): string {
  return JSON.stringify({
    signature: Buffer.from(key.signaturOeffentlich).toString("base64"),
    box: Buffer.from(key.boxOeffentlich).toString("base64"),
    fingerprint: fingerabdruck(key.signaturOeffentlich, key.boxOeffentlich),
  });
}

export async function schreibeSchluessel(path: string, key: Schluessel): Promise<void> {
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
    throw new CliFehler(1, "Could not write the key file exclusively.");
  }
}

export async function sichereAblage(root: string): Promise<{ quarantene: string; abgewiesen: string; gesehen: string }> {
  try {
    const info = await lstat(root).catch(() => undefined);
    if (info && (!info.isDirectory() || info.uid !== aktuellerBenutzer())) throw new CliFehler(3, "Unsafe storage permissions.");
    await mkdir(root, { recursive: true, mode: 0o700 });
    const renames = [["quarantaene", "quarantine"], ["abgewiesen", "rejected"], ["gesehen.json", "seen.json"]] as const;
    const present = await Promise.all(renames.map(async ([oldName, newName]) => ({
      oldPath: join(root, oldName), newPath: join(root, newName),
      oldExists: Boolean(await lstat(join(root, oldName)).catch(() => undefined)),
      newExists: Boolean(await lstat(join(root, newName)).catch(() => undefined)),
    })));
    if (present.some(({ oldExists, newExists }) => oldExists && newExists)) throw new CliFehler(3, "Legacy storage and English storage both exist; resolve the name conflict before retrying.");
    for (const item of present) if (item.oldExists) await rename(item.oldPath, item.newPath);
    const quarantene = join(root, "quarantine");
    const abgewiesen = join(root, "rejected");
    for (const directory of [quarantene, abgewiesen]) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const directoryInfo = await lstat(directory);
      if (!directoryInfo.isDirectory() || directoryInfo.uid !== aktuellerBenutzer()) throw new CliFehler(3, "Unsafe storage permissions.");
      await chmod(directory, 0o700);
    }
    return { quarantene, abgewiesen, gesehen: join(root, "seen.json") };
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(3, "Could not prepare storage safely.");
  }
}

export async function atomarSchreiben(path: string, content: string | Uint8Array): Promise<void> {
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
    throw new CliFehler(1, "Could not write the storage file safely.");
  }
}

export async function leseGesehen(path: string): Promise<Record<string, string>> {
  try {
    const info = await lstat(path).catch(() => undefined);
    if (!info) return {};
    await sichereDatei(path, 0o600);
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!objekt(value) || Object.entries(value).some(([id, expiry]) => !/^[0-9a-f]{32}$/.test(id)
      || typeof expiry !== "string" || !Number.isFinite(Date.parse(expiry)))) throw new Error();
    return value as Record<string, string>;
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(3, "seen.json is invalid or unsafe.");
  }
}

export async function speichereGesehen(path: string, seen: Record<string, string>): Promise<void> {
  await atomarSchreiben(path, JSON.stringify(seen) + "\n");
}
