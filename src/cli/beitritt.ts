import { createHash, randomBytes } from "node:crypto";
import { chmod, link, lstat, mkdir, open, readFile, readdir, rename, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import type { Stats } from "node:fs";
import { existsSync, renameSync } from "node:fs";
import { text } from "node:stream/consumers";
import { setTimeout as sleep } from "node:timers/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  bestaetigungsNachricht,
  einladungsSchluessel,
  einloesungsNachricht,
  festlegung,
  oeffnungsNachricht,
  type Beitrittsprotokoll,
} from "../beitritt.ts";
import { signiereAnfrage } from "../anfrage.ts";
import { fingerabdruck, type Schluessel } from "../siegel.ts";
import { sshFingerabdruck } from "../ssh.ts";
import { ermittleEmpfaengerSchluesselstaende } from "./buergschaft.ts";
import { atomarSchreiben, CliFehler, englischerOptionsname, ladeKonfiguration, ladeSchluessel, type Konfiguration } from "./gemeinsam.ts";
import { setup } from "./setup.ts";
import { wiederholeBeiDrosselung } from "./netz.ts";

export interface BeitrittOptionen {
  positionen: string[];
  werte: Map<string, string[]>;
  schalter: Set<string>;
}

type Befehl = "einladen" | "einladungen" | "oeffnen" | "join" | "confirm" | "kontakte";

interface EinladungZustand {
  art: "einladung";
  token: string;
  instanz: string;
  name_I: string;
  fuer: string;
  sig_I: string;
  box_I: string;
  c_I: string;
  n_I: string;
  pk_s: string;
  zustand: "offen" | "geoeffnet" | "bestaetigt" | "verbrannt";
  fehler: number;
  sig_J?: string;
  box_J?: string;
  n_J?: string;
}

interface BeitrittZustand {
  art: "beitritt";
  token: string;
  instanz: string;
  name_I: string;
  name_J: string;
  sig_I: string;
  box_I: string;
  c_I: string;
  sig_J: string;
  box_J: string;
  n_J: string;
  n_I?: string;
  zustand: "eingeloest" | "wartet_auf_code" | "bestaetigt";
  secret?: string;
}

interface LinkDaten {
  instanz: string;
  token: string;
  fp: string;
  sha?: string;
  secret?: string;
}

interface OeffentlicheEinladung {
  instanz: string;
  einladender: string;
  sig_I: string;
  box_I: string;
  fuer: string;
  c: string;
  pk_s: string;
  ablauf: string;
  zustand: string;
}

const b64url = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const kurzesToken = (value: string) => value.slice(0, 8);
const druckbar = (value: string) => [...value].filter((character) => !/[\p{C}\p{Zl}\p{Zp}]/u.test(character)).join("");
const shellWert = (value: string) => /^[A-Za-z0-9_./:-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
const bytes = (value: string, length: number): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new CliFehler(3, "Invalid join state or post office receipt.");
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (decoded.length !== length || b64url(decoded) !== value) throw new CliFehler(3, "Invalid join state or post office receipt.");
  return decoded;
};

function einzel(options: BeitrittOptionen, flag: string, required = false): string | undefined {
  const values = options.werte.get(flag) ?? [];
  if (values.length > 1 || (required && values.length !== 1)) throw new CliFehler(1, `Missing or repeated option: ${englischerOptionsname(flag)}.`);
  return values[0];
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function englishJoinState(value: string): string {
  const states: Record<string, string> = { offen: "open", geoeffnet: "opened", bestaetigt: "confirmed", verbrannt: "burned", eingeloest: "redeemed", wartet_auf_code: "waiting_for_code" };
  return states[value] ?? value;
}

function stateRoot(config: Konfiguration, art: "invitations" | "joins"): string {
  const oldName = art === "invitations" ? "einladungen" : "beitritte";
  const oldPath = join(config.ablage, oldName);
  const newPath = join(config.ablage, art);
  if (existsSync(oldPath) && existsSync(newPath)) throw new CliFehler(3, `Legacy and English ${art} storage both exist; resolve the name conflict before retrying.`);
  if (existsSync(oldPath)) renameSync(oldPath, newPath);
  return newPath;
}

async function bereiteZustandsordnerVor(path: string): Promise<void> {
  try {
    await mkdir(path, { recursive: true, mode: 0o700 });
    const info = await lstat(path);
    if (!info.isDirectory() || info.uid !== (process.getuid?.() ?? -1)) throw new CliFehler(3, "Unsafe join storage directory.");
    await chmod(path, 0o700);
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(3, "Could not create the join storage directory safely.");
  }
}

async function leseZustand<T>(path: string): Promise<T> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.uid !== (process.getuid?.() ?? -1) || (info.mode & 0o777) !== 0o600) throw new Error();
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    throw new CliFehler(3, "Join state is missing or cannot be read safely.");
  }
}

async function schreibeZustand(path: string, value: unknown): Promise<void> {
  await atomarSchreiben(path, JSON.stringify(value) + "\n");
}

function fehlerAntwort(response: Response, value: unknown): CliFehler {
  if (response.status >= 300 && response.status < 400) return new CliFehler(2, "Post office redirect was rejected.");
  if (response.status === 408) return new CliFehler(2, "Post office request timed out.");
  if (response.status === 404) return new CliFehler(2, "Invitation is no longer valid.");
  if (response.status === 410 && object(value) && value.grund === "invitation_outdated") return new CliFehler(3, "This invitation was made with an older version. Ask for a new one.");
  if (response.status === 409) {
    const reason = object(value)
      ? (typeof value.meldung === "string" ? value.meldung : typeof value.grund === "string" ? value.grund : "Conflict")
      : "Conflict";
    const translatedReason = reason === "f\u00fcr diesen Namen gibt es schon eine offene Einladung"
      ? "An invitation for this name is already open"
      : reason === "konflikt" || reason === "Konflikt" ? "Conflict" : druckbar(reason);
    return new CliFehler(2, `Post office reported a conflict: ${translatedReason}.`);
  }
  if (response.status >= 500) return new CliFehler(2, `Post office reported a server error (${response.status}).`);
  return new CliFehler(2, `Post office request failed (HTTP ${response.status}).`);
}

function fehlerAbruf(error: unknown): CliFehler {
  if (error instanceof Error && (error.message.startsWith("UnexpectedRedirect")
    || (error instanceof TypeError && object(error.cause) && typeof error.cause.message === "string" && /redirect/i.test(error.cause.message)))) {
    return new CliFehler(2, "Post office redirect was rejected.");
  }
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
    return new CliFehler(2, "Post office request timed out.");
  }
  return new CliFehler(2, "Post office request failed.");
}

function statePath(config: Konfiguration, art: "invitations" | "joins", token: string): string {
  return join(stateRoot(config, art), `${token}.json`);
}

async function signedFetch(base: string, path: string, method: string, body: Uint8Array, config: Konfiguration, key: Schluessel): Promise<Response> {
  const url = `${base.replace(/\/$/, "")}${path}`;
  return wiederholeBeiDrosselung(() => fetch(url, {
    method,
    headers: signiereAnfrage({ methode: method, url, koerper: body, name: config.name, signaturPrivat: key.signaturPrivat }),
    ...(body.length ? { body: Buffer.from(body) } : {}),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  }));
}

async function signedJson(base: string, path: string, method: string, body: unknown, config: Konfiguration, key: Schluessel): Promise<unknown> {
  const encoded = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
  let response: Response;
  try { response = await signedFetch(base, path, method, encoded, config, key); } catch (error) { if (error instanceof CliFehler) throw error; throw fehlerAbruf(error); }
  let value: unknown;
  try { value = await response.json(); } catch {
    if (!response.ok) throw fehlerAntwort(response, undefined);
    throw new CliFehler(2, "Invalid response from the post office.");
  }
  if (!response.ok) throw fehlerAntwort(response, value);
  return value;
}

async function publicJson(url: string, method = "GET", body?: unknown): Promise<{ response: Response; value: unknown }> {
  let response: Response;
  try {
    response = await wiederholeBeiDrosselung(() => fetch(url, {
      method,
      ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    }));
  } catch (error) { if (error instanceof CliFehler) throw error; throw fehlerAbruf(error); }
  let value: unknown;
  try { value = await response.json(); } catch {
    if (response.ok) throw new CliFehler(2, "Invalid response from the post office.");
  }
  return { response, value };
}

function parseLink(raw: string): LinkDaten {
  let url: URL;
  try {
    const address = /^[A-Za-z0-9.-]+(?::[0-9]+)?\//.test(raw) ? `${raw.startsWith("localhost") || raw.startsWith("127.0.0.1") ? "http://" : "https://"}${raw}` : raw;
    url = new URL(address);
  } catch { throw new CliFehler(1, "Invalid agent line. Use the agent line, not the browser address."); }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost"].includes(url.hostname))) {
    throw new CliFehler(1, `Unsupported protocol in agent line: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new CliFehler(1, "Invalid agent line.");
  }
  const match = /^\/e\/([A-Za-z0-9_-]{22})$/.exec(url.pathname);
  if (!match) throw new CliFehler(1, "Invalid invitation link.");
  bytes(match[1]!, 16);
  const legacy = /^#fp=([a-f0-9]{64})&sha=([a-f0-9]{64})$/.exec(url.hash);
  const secret = url.searchParams.get("s");
  const fp = url.searchParams.get("fp") ?? legacy?.[1];
  const sha = url.searchParams.get("sha") ?? legacy?.[2];
  const keys = [...url.searchParams.keys()].sort().join(",");
  if (!fp || !sha || !/^[a-f0-9]{64}$/.test(fp) || !/^[a-f0-9]{64}$/.test(sha)
    || (secret ? keys !== "fp,s,sha" || url.hash !== "" : keys !== "" && keys !== "fp,sha")) {
    throw new CliFehler(1, "Browser address is incomplete; use the agent line from the invitation.");
  }
  if (secret) bytes(secret, 32);
  return { instanz: url.origin, token: match[1]!, fp, sha, ...(secret ? { secret } : {}) };
}

function einladungProtocol(state: EinladungZustand): Beitrittsprotokoll {
  if (!state.sig_J || !state.box_J || !state.n_J) throw new CliFehler(3, "Invitation has no valid redemption yet.");
  return {
    instanz: state.instanz,
    token: bytes(state.token, 16),
    name_I: state.name_I,
    name_J: state.fuer,
    sig_I: bytes(state.sig_I, 32),
    box_I: bytes(state.box_I, 32),
    sig_J: bytes(state.sig_J, 32),
    box_J: bytes(state.box_J, 32),
    c_I: bytes(state.c_I, 32),
    n_J: bytes(state.n_J, 32),
    n_I: bytes(state.n_I, 32),
  };
}

function joinProtocol(state: BeitrittZustand): Beitrittsprotokoll {
  if (!state.n_I) throw new CliFehler(3, "Join is waiting for the invitation to be opened.");
  return {
    instanz: state.instanz,
    token: bytes(state.token, 16),
    name_I: state.name_I,
    name_J: state.name_J,
    sig_I: bytes(state.sig_I, 32),
    box_I: bytes(state.box_I, 32),
    sig_J: bytes(state.sig_J, 32),
    box_J: bytes(state.box_J, 32),
    c_I: bytes(state.c_I, 32),
    n_J: bytes(state.n_J, 32),
    n_I: bytes(state.n_I, 32),
  };
}

async function trust(configPath: string, name: string, sig: Uint8Array, box: Uint8Array): Promise<void> {
  const current = await ladeKonfiguration(configPath);
  const existing = Object.hasOwn(current.vertraut, name) ? current.vertraut[name] : undefined;
  if (existing && (Buffer.compare(Buffer.from(existing.signatur), Buffer.from(sig)) !== 0
    || Buffer.compare(Buffer.from(existing.box), Buffer.from(box)) !== 0)) {
    throw new CliFehler(3, `Key conflict for ${name}; the existing trusted key is unchanged.`);
  }
  const trusted = Object.fromEntries(Object.entries(current.vertraut).map(([contact, keys]) => [contact, {
    signatur: Buffer.from(keys.signatur).toString("base64"),
    box: Buffer.from(keys.box).toString("base64"),
  }]));
  trusted[name] = { signatur: Buffer.from(sig).toString("base64"), box: Buffer.from(box).toString("base64") };
  await atomarSchreiben(configPath, JSON.stringify({
    name: current.name,
    post_office: current.postamt,
    storage: current.ablage,
    trusted: Object.fromEntries(Object.entries(trusted).map(([name, keys]) => [name, { signature: keys.signatur, box: keys.box }])),
    channels: current.kanaele,
  }) + "\n");
}

async function pruefeVertrauenSchreibbar(configPath: string, name: string, sig: Uint8Array, box: Uint8Array): Promise<void> {
  const current = await ladeKonfiguration(configPath);
  const existing = Object.hasOwn(current.vertraut, name) ? current.vertraut[name] : undefined;
  if (existing && (Buffer.compare(Buffer.from(existing.signatur), Buffer.from(sig)) !== 0
    || Buffer.compare(Buffer.from(existing.box), Buffer.from(box)) !== 0)) {
    throw new CliFehler(3, `Key conflict for ${name}; the existing trusted key is unchanged.`);
  }
  const probePath = join(dirname(configPath), `.beitritt-${process.pid}-${b64url(randomBytes(12))}.tmp`);
  let probe;
  try {
    probe = await open(probePath, "wx", 0o600);
    await probe.sync();
  } catch {
    throw new CliFehler(1, "Configuration is not writable; join was not confirmed.");
  } finally {
    await probe?.close().catch(() => undefined);
    await unlink(probePath).catch(() => undefined);
  }
}

interface SperrdateiOperationen {
  open(path: string, flags: string, mode?: number): Promise<FileHandle>;
  lstat(path: string): Promise<Stats>;
  rename(source: string, destination: string): Promise<void>;
  link(source: string, destination: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

export async function sperreErwerben(
  lockPath: string,
  dateien: SperrdateiOperationen = { open, lstat, rename, link, unlink },
) {
  const gesperrt = () => new CliFehler(3, `Invitation is locked (${lockPath}); check the process or remove a stale lock and try again.`);
  const create = async () => {
    const lock = await dateien.open(lockPath, "wx", 0o600);
    try {
      const owner = { pid: process.pid, zeit: Date.now() };
      await lock.writeFile(JSON.stringify(owner) + "\n");
      await lock.sync();
      const info = await lock.stat();
      return { handle: lock, dev: info.dev, ino: info.ino };
    } catch (error) {
      const info = await lock.stat().catch(() => undefined);
      await lock.close().catch(() => undefined);
      if (info) {
        try {
          const current = await dateien.lstat(lockPath);
          if (current.dev === info.dev && current.ino === info.ino) await dateien.unlink(lockPath);
        } catch { }
      }
      throw error;
    }
  };
  const leseText = async (path: string) => {
    const handle = await dateien.open(path, "r");
    try { return await handle.readFile("utf8"); }
    finally { await handle.close(); }
  };
  const guardPath = `${lockPath}.uebernahme`;
  const erzeugeGuard = async () => {
    const guard = await dateien.open(guardPath, "wx", 0o600);
    try {
      await guard.writeFile(JSON.stringify({ pid: process.pid, zeit: Date.now() }) + "\n");
      await guard.sync();
      const info = await guard.stat();
      return { handle: guard, dev: info.dev, ino: info.ino };
    } catch (error) {
      const info = await guard.stat().catch(() => undefined);
      await guard.close().catch(() => undefined);
      if (info) {
        try {
          const current = await dateien.lstat(guardPath);
          if (current.dev === info.dev && current.ino === info.ino) await dateien.unlink(guardPath);
        } catch { }
      }
      throw error;
    }
  };
  const releaseGuard = async (guard: Awaited<ReturnType<typeof erzeugeGuard>>) => {
    await guard.handle.close().catch(() => undefined);
    try {
      const current = await dateien.lstat(guardPath);
      if (current.dev === guard.dev && current.ino === guard.ino) await dateien.unlink(guardPath);
    } catch { }
  };

  let initial: Awaited<ReturnType<typeof lstat>> | undefined;
  try { initial = await dateien.lstat(lockPath); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw gesperrt(); }

  let guard: Awaited<ReturnType<typeof erzeugeGuard>>;
  try { guard = await erzeugeGuard(); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new CliFehler(3, `Could not create ownership lock (${guardPath}).`);
    let observed;
    try {
      observed = await dateien.lstat(guardPath);
      if (!observed.isFile() || observed.uid !== (process.getuid?.() ?? -1) || (observed.mode & 0o777) !== 0o600) throw new Error();
    } catch { throw gesperrt(); }
    let stale = false;
    try {
      const metadata: unknown = JSON.parse(await leseText(guardPath));
      if (!object(metadata) || !Number.isSafeInteger(metadata.pid) || typeof metadata.zeit !== "number" || !Number.isFinite(metadata.zeit)) throw new Error();
      stale = Date.now() - metadata.zeit > 60_000;
    } catch { stale = Date.now() - observed.mtimeMs > 60_000; }
    if (!stale) throw gesperrt();
    const staleGuardPath = `${guardPath}.verwaist-${process.pid}-${b64url(randomBytes(12))}`;
    try { await dateien.rename(guardPath, staleGuardPath); } catch { throw gesperrt(); }
    let movedGuard;
    try { movedGuard = await dateien.lstat(staleGuardPath); } catch { throw gesperrt(); }
    if (movedGuard.dev !== observed.dev || movedGuard.ino !== observed.ino) {
      try {
        await dateien.link(staleGuardPath, guardPath);
        await dateien.unlink(staleGuardPath);
      } catch { }
      throw gesperrt();
    }
    await dateien.unlink(staleGuardPath).catch(() => undefined);
    try { guard = await erzeugeGuard(); }
    catch { throw gesperrt(); }
  }

  try {
    try { return await create(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new CliFehler(3, `Could not create lock file (${lockPath}).`); }

    let observed;
    try {
      observed = await dateien.lstat(lockPath);
      if (!observed.isFile() || observed.uid !== (process.getuid?.() ?? -1) || (observed.mode & 0o777) !== 0o600) throw new Error();
      if (!initial || observed.dev !== initial.dev || observed.ino !== initial.ino) throw gesperrt();
    } catch (error) { if (error instanceof CliFehler) throw error; throw gesperrt(); }

    let stale = false;
    try {
      const metadata: unknown = JSON.parse(await leseText(lockPath));
      if (!object(metadata) || !Number.isSafeInteger(metadata.pid) || typeof metadata.zeit !== "number" || !Number.isFinite(metadata.zeit)) throw new Error();
      if (Date.now() - metadata.zeit > 600_000) stale = true;
      else {
        try { process.kill(metadata.pid as number, 0); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === "ESRCH") stale = true; }
      }
    } catch { stale = Date.now() - observed.mtimeMs > 600_000; }
    const afterRead = await dateien.lstat(lockPath).catch(() => undefined);
    if (!afterRead || afterRead.dev !== observed.dev || afterRead.ino !== observed.ino || !stale) throw gesperrt();

    const stalePath = `${lockPath}.verwaist-${process.pid}-${b64url(randomBytes(12))}`;
    try { await dateien.rename(lockPath, stalePath); } catch { throw gesperrt(); }
    let moved;
    try { moved = await dateien.lstat(stalePath); } catch { throw new CliFehler(3, `Could not safely take over lock file (${lockPath}).`); }
    if (moved.dev !== observed.dev || moved.ino !== observed.ino) {
      try {
        await dateien.link(stalePath, lockPath);
        await dateien.unlink(stalePath);
      } catch { }
      throw gesperrt();
    }
    let replacement;
    try { replacement = await create(); }
    catch {
      try {
        await dateien.link(stalePath, lockPath);
        await dateien.unlink(stalePath);
      } catch { }
      throw gesperrt();
    }
    const staleCurrent = await dateien.lstat(stalePath).catch(() => undefined);
    if (staleCurrent?.dev === moved.dev && staleCurrent.ino === moved.ino) await dateien.unlink(stalePath).catch(() => undefined);
    return replacement;
  } finally { await releaseGuard(guard); }
}

function fingerprintWithoutSpaces(value: string): string {
  return value.replaceAll(" ", "");
}

async function einladen(options: BeitrittOptionen): Promise<void> {
  const configPath = einzel(options, "--config", true)!;
  const config = await ladeKonfiguration(configPath);
  const key = await ladeSchluessel(einzel(options, "--key", true)!);
  const fuer = einzel(options, "--fuer", true)!;
  const script = einzel(options, "--skript") ?? (typeof process.argv[1] === "string" && /\.js$/i.test(process.argv[1]) ? process.argv[1] : undefined);
  if (!script) throw new CliFehler(1, "SHA-256 of the running script is unavailable; specify --script.");
  const invitation = await erstelleEinladung(config, key, fuer, script);
  console.log(`Browser address: ${invitation.browserAddress}`);
  console.log(`Agent line: ${invitation.agentLine}`);
  console.log("Give the agent line only to the invited person's own agent; never enter it in a browser.");
}

async function erstelleEinladung(config: Konfiguration, key: Schluessel, fuer: string, script: string): Promise<{ token: string; browserAddress: string; agentLine: string }> {
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(fuer) || fuer === config.name) throw new CliFehler(1, "Invalid invitation name.");
  const instanz = new URL(config.postamt).origin;
  const token = b64url(randomBytes(16));
  const nI = randomBytes(32);
  const secret = randomBytes(32);
  const signing = einladungsSchluessel(secret);
  const sigI = key.signaturOeffentlich;
  const boxI = key.boxOeffentlich;
  const cI = festlegung(instanz, new Uint8Array(Buffer.from(token, "base64url")), config.name, sigI, boxI, nI, signing.publicKey);
  let sha: string;
  try { sha = createHash("sha256").update(await readFile(script)).digest("hex"); }
  catch { throw new CliFehler(1, "Could not read the script for its SHA-256 fingerprint; check --script."); }
  const root = stateRoot(config, "invitations");
  await bereiteZustandsordnerVor(root);
  const local: EinladungZustand = {
    art: "einladung", token, instanz, name_I: config.name, fuer,
    sig_I: b64url(sigI), box_I: b64url(boxI), c_I: b64url(cI), n_I: b64url(nI),
    pk_s: b64url(signing.publicKey),
    zustand: "offen", fehler: 0,
  };
  const response = await signedJson(config.postamt, "/v1/einladung", "POST", {
    token, fuer, c: b64url(cI), box: b64url(boxI), pk_s: b64url(signing.publicKey),
  }, config, key);
  if (!object(response) || response.token !== token) throw new CliFehler(2, "Invalid response from the post office.");
  await schreibeZustand(statePath(config, "invitations", token), local);
  const fingerprint = fingerprintWithoutSpaces(fingerabdruck(sigI, boxI));
  const browserAddress = `${instanz}/e/${token}`;
  const authority = new URL(instanz).host;
  const agentLine = `${authority}/e/${token}?s=${b64url(secret)}&fp=${fingerprint}&sha=${sha}`;
  return { token, browserAddress, agentLine };
}


export async function bearbeiteEinladungsauftraege(config: Konfiguration, key: Schluessel, ueberspringen = false): Promise<void> {
  if (ueberspringen) return;
  let result: unknown;
  try {
    result = await signedJson(config.postamt, "/v1/einladungsauftraege", "GET", undefined, config, key);
  } catch (error) {
    if (error instanceof CliFehler && error.publicMessage === "Invitation is no longer valid.") return;
    const grund = error instanceof CliFehler && /server error \(\d{3}\)|HTTP \d{3}/.test(error.publicMessage)
      ? error.publicMessage.replace(/[^\x20-\x7e]/g, "?") : "Post office request failed.";
    console.warn("Warning: invitation tasks could not be processed.");
    console.log(JSON.stringify({ invitation_tasks: "error", reason: grund }));
    return;
  }
  if (!object(result) || !Array.isArray(result.auftraege)) {
    console.warn("Warning: invitation tasks could not be processed.");
    console.log(JSON.stringify({ invitation_tasks: "error", reason: "Invalid invitation task response." }));
    return;
  }
  const verbrenne = async (token: string): Promise<void> => {
    if (!/^[A-Za-z0-9_-]{22}$/.test(token)) return;
    const localPath = statePath(config, "invitations", token);
    const local = await leseZustand<EinladungZustand>(localPath).catch(() => undefined);
    if (local?.art !== "einladung" || local.token !== token) return;
    const response = await signedFetch(config.postamt, `/v1/einladung/${token}/verbrennen`, "POST", new Uint8Array(), config, key).catch(() => undefined);
    if (!response?.ok) return;
    await schreibeZustand(localPath, { ...local, zustand: "verbrannt" });
  };
  const validCandidates = result.auftraege.filter((candidate): candidate is Record<string, unknown> => object(candidate)
    && typeof candidate.id === "string" && /^[a-f0-9]{32}$/.test(candidate.id)
    && typeof candidate.fuer === "string");
  const toBurn = validCandidates.filter((candidate) => candidate.zustand === "verworfen" && typeof candidate.token === "string").slice(0, 10);
  const toCreate = validCandidates.filter((candidate) => candidate.zustand === "offen").slice(0, 3);
  for (const candidate of [...toBurn, ...toCreate]) {
    if (candidate.zustand === "verworfen") {
      await verbrenne(candidate.token as string);
      continue;
    }
    let outcome = "fehler";
    let createdToken: string | undefined;
    try {
      const fuer = candidate.fuer as string;
      const invitation = await erstelleEinladung(config, key, fuer, fileURLToPath(import.meta.url));
      createdToken = invitation.token;
      const uploaded = await signedJson(config.postamt, `/v1/einladungsauftraege/${candidate.id}`, "POST", { token: invitation.token }, config, key);
      if (!object(uploaded) || uploaded.status !== "erzeugt") throw new CliFehler(2, "Invitation task upload failed.");
      outcome = "erzeugt";
      console.log(JSON.stringify({ invitation_tasks: { name: fuer, browser_address: invitation.browserAddress, agent_line: invitation.agentLine } }));
    } catch {
      if (createdToken) await verbrenne(createdToken);
      outcome = "fehler";
    }
    if (outcome !== "erzeugt") console.log(JSON.stringify({ invitation_task_id: candidate.id, for: candidate.fuer, result: "error" }));
  }
}


async function einladungen(options: BeitrittOptionen): Promise<void> {
  const config = await ladeKonfiguration(einzel(options, "--config", true)!);
  const key = await ladeSchluessel(einzel(options, "--key", true)!);
  const result = await signedJson(config.postamt, "/v1/einladungen", "GET", undefined, config, key);
  if (!object(result) || !Array.isArray(result.einladungen) || !Array.isArray(result.meldungen)) throw new CliFehler(2, "Invalid response from the post office.");
  const root = stateRoot(config, "invitations");
  const names = await readdir(root).catch(() => []);
  const localInvitations = await Promise.all(names.filter((name) => /^[A-Za-z0-9_-]{22}\.json$/.test(name))
    .map((name) => leseZustand<EinladungZustand>(join(root, name))));
  const seenTokens = new Set<string>();
  for (const local of localInvitations) {
    if (local.art !== "einladung") throw new CliFehler(3, "Invalid join state.");
    seenTokens.add(local.token);
    const remote = result.einladungen.find((item) => object(item) && item.token === local.token);
    let fingerprint: string | null = null;
    if (!object(remote)) {
      console.error(`ALARM Post office: Invitation ${kurzesToken(local.token)} is missing from the server list.`);
    } else if (remote.einloesung !== null && remote.einloesung !== undefined) {
      if (!object(remote.einloesung) || typeof remote.einloesung.sig_J !== "string" || typeof remote.einloesung.box_J !== "string") {
        console.error(`ALARM Post office: Invalid redemption for ${kurzesToken(local.token)}.`);
      } else {
        try {
          fingerprint = fingerabdruck(bytes(remote.einloesung.sig_J, 32), bytes(remote.einloesung.box_J, 32));
          if (typeof remote.einloesung.fingerabdruck !== "string" || remote.einloesung.fingerabdruck !== fingerprint) {
            console.error(`ALARM Post office: Redemption fingerprint does not match for ${kurzesToken(local.token)}.`);
          }
          if (typeof remote.einloesung.sig_s === "string" && typeof remote.einloesung.n_J === "string") {
            const protocol = {
              instanz: local.instanz, token: bytes(local.token, 16), name_J: local.fuer,
              sig_J: bytes(remote.einloesung.sig_J, 32), box_J: bytes(remote.einloesung.box_J, 32),
              c_I: bytes(local.c_I, 32), n_J: bytes(remote.einloesung.n_J, 32),
            };
            const valid = ed25519.verify(bytes(remote.einloesung.sig_s, 64), einloesungsNachricht(protocol), bytes(local.pk_s, 32));
            if (valid) console.log(`${local.fuer} redeemed your invitation. Fingerprint ${fingerprint}. Accept with: subspace confirm ${local.fuer}`);
            else console.error(`Warning: invalid redemption for ${local.fuer}; verify before confirming.`);
          }
        } catch {
          console.error(`ALARM Post office: Invalid redemption fingerprint for ${kurzesToken(local.token)}.`);
          fingerprint = null;
        }
      }
    }
    if (object(remote) && remote.zustand !== local.zustand && !(remote.zustand === "eingeloest" && local.zustand === "offen")) {
      console.error(`ALARM Post office: State for ${kurzesToken(local.token)} differs from local state.`);
    }
    console.log(JSON.stringify({ token: kurzesToken(local.token), for: local.fuer, state: englishJoinState(local.zustand), post_office_state: object(remote) ? englishJoinState(String(remote.zustand)) : null, fingerprint }));
  }
  for (const item of result.einladungen) {
    if (object(item) && typeof item.token === "string" && !seenTokens.has(item.token)) {
      console.error(`ALARM Post office: Unknown invitation ${kurzesToken(druckbar(item.token))} in the server list.`);
    }
  }
  for (const warning of result.meldungen) {
    if (object(warning) && warning.grund === "zweite_einloesung" && typeof warning.token === "string") {
      const invitation = localInvitations.find((candidate) => candidate.token === warning.token);
      if (invitation) console.error(`Warning: ${invitation.fuer} redeemed this invitation again; the confirmed contact remains unchanged.`);
    }
    console.error(druckbar(`ALARM Post office: ${JSON.stringify(warning, (key, value: unknown) => key === "token" && typeof value === "string" ? kurzesToken(value) : value)}`));
  }
}

async function oeffnenIntern(options: BeitrittOptionen): Promise<void> {
  const configPath = einzel(options, "--config", true)!;
  const config = await ladeKonfiguration(configPath);
  const key = await ladeSchluessel(einzel(options, "--key", true)!);
  const fuer = options.positionen[1];
  if (!fuer) throw new CliFehler(1, "Name is required.");
  const result = await signedJson(config.postamt, "/v1/einladungen", "GET", undefined, config, key);
  if (!object(result) || !Array.isArray(result.einladungen)) throw new CliFehler(2, "Invalid response from the post office.");
  const matching = result.einladungen.filter((item) => object(item) && item.fuer === fuer && item.einladender === config.name);
  const remote = matching.find((item) => object(item) && item.zustand === "eingeloest") ?? matching.at(-1);
  if (!object(remote)) throw new CliFehler(3, "No matching local invitation found.");
  const token = typeof remote.token === "string" ? remote.token : "";
  bytes(token, 16);
  const localPath = statePath(config, "invitations", token);
  const lockPath = `${localPath}.lock`;
  const lock = await sperreErwerben(lockPath);
  try {
    const local = await leseZustand<EinladungZustand>(localPath);
    if (local.art !== "einladung" || local.token !== token || local.fuer !== fuer || local.instanz !== new URL(config.postamt).origin) {
      throw new CliFehler(3, "Local invitation state does not match the post office.");
    }
    if (Buffer.compare(Buffer.from(bytes(local.sig_I, 32)), Buffer.from(key.signaturOeffentlich)) !== 0
      || Buffer.compare(Buffer.from(bytes(local.box_I, 32)), Buffer.from(key.boxOeffentlich)) !== 0) {
      throw new CliFehler(3, "Local invitation state belongs to a different key.");
    }
    if (local.zustand === "bestaetigt" || local.zustand === "verbrannt") throw new CliFehler(3, "ALARM: Invitation can no longer be opened.");
    if (!object(remote.einloesung)) throw new CliFehler(3, "Invitation has not been validly redeemed yet.");
    if (typeof remote.pk_s !== "string" || remote.pk_s !== local.pk_s) {
      await schreibeZustand(localPath, { ...local, zustand: "verbrannt" });
      const burned = await signedFetch(config.postamt, `/v1/einladung/${token}/verbrennen`, "POST", new Uint8Array(), config, key).catch(() => undefined);
      console.error("Warning: post office invitation key does not match local state; invitation burned.");
      if (!burned?.ok) console.error("Warning: post office could not confirm that the invitation was burned.");
      throw new CliFehler(3, "Invalid invitation secret key from the post office.");
    }
    const redemption = remote.einloesung;
    if (typeof redemption.sig_J !== "string" || typeof redemption.box_J !== "string" || typeof redemption.n_J !== "string" || typeof redemption.beleg !== "string" || typeof redemption.sig_s !== "string") {
      throw new CliFehler(3, "Invalid redemption receipt.");
    }
    const sigJ = bytes(redemption.sig_J, 32);
    const boxJ = bytes(redemption.box_J, 32);
    const nJ = bytes(redemption.n_J, 32);
    if (local.zustand === "geoeffnet" && (local.sig_J !== redemption.sig_J || local.box_J !== redemption.box_J || local.n_J !== redemption.n_J)) {
      throw new CliFehler(3, "ALARM: Redemption differs from the stored opening record.");
    }
    const proof = bytes(redemption.beleg, 64);
    let valid = false;
    try {
      valid = ed25519.verify(proof, einloesungsNachricht({
        instanz: local.instanz, token: bytes(local.token, 16), name_J: local.fuer,
        sig_J: sigJ, box_J: boxJ, c_I: bytes(local.c_I, 32), n_J: nJ,
      }), sigJ);
    } catch { }
    if (!valid) throw new CliFehler(3, "Invalid redemption receipt.");
    let validSecret = false;
    try { validSecret = ed25519.verify(bytes(redemption.sig_s, 64), einloesungsNachricht({
      instanz: local.instanz, token: bytes(local.token, 16), name_J: local.fuer,
      sig_J: sigJ, box_J: boxJ, c_I: bytes(local.c_I, 32), n_J: nJ,
    }), bytes(local.pk_s, 32)); } catch { }
    if (!validSecret) {
      await schreibeZustand(localPath, { ...local, zustand: "verbrannt" });
      const burned = await signedFetch(config.postamt, `/v1/einladung/${token}/verbrennen`, "POST", new Uint8Array(), config, key).catch(() => undefined);
      console.error("Warning: invitation secret signature is invalid; invitation burned.");
      if (!burned?.ok) console.error("Warning: post office could not confirm that the invitation was burned.");
      throw new CliFehler(3, "Invalid invitation secret signature.");
    }

    let opened = local;
    if (local.zustand === "geoeffnet") {
      const pending = await publicJson(`${local.instanz}/v1/einladung/${token}/oeffnung`);
      if (pending.response.status === 200 && object(pending.value)
        && typeof pending.value.n_I === "string" && typeof pending.value.unterschrift === "string") {
        const protocol = einladungProtocol(local);
        let matches = false;
        try {
          matches = pending.value.n_I === local.n_I
            && ed25519.verify(bytes(pending.value.unterschrift, 64), oeffnungsNachricht(protocol), protocol.sig_I);
        } catch { }
        if (matches) {
      console.log("Invitation is already open.");
          return;
        }
      }
      if (pending.response.status !== 202 || !object(pending.value) || pending.value.grund !== "wartet") {
        throw new CliFehler(3, "ALARM: Post office opening state differs from the stored record.");
      }
    } else {
      opened = { ...local, zustand: "geoeffnet", sig_J: b64url(sigJ), box_J: b64url(boxJ), n_J: b64url(nJ) };
      await schreibeZustand(localPath, opened);
    }
    const protocol = einladungProtocol(opened);
    const signature = ed25519.sign(oeffnungsNachricht(protocol), key.signaturPrivat);
    const answer = await signedJson(config.postamt, `/v1/einladung/${token}/oeffnung`, "POST", {
      n_I: opened.n_I, unterschrift: b64url(signature),
    }, config, key);
    if (!object(answer) || answer.grund !== "geoeffnet") throw new CliFehler(2, "Post office did not confirm the opening.");
    console.log("Invitation opened.");
  } finally {
    await lock.handle.close().catch(() => undefined);
    try {
      const current = await lstat(lockPath);
      if (current.dev === lock.dev && current.ino === lock.ino) await unlink(lockPath);
    } catch { }
  }
}

async function oeffnen(options: BeitrittOptionen): Promise<void> {
  const name = options.positionen[1] ?? "<name>";
  throw new CliFehler(1, `open is no longer needed. Use: subspace confirm ${name}`);
}

async function linkVonStdin(options: BeitrittOptionen): Promise<LinkDaten> {
  if (options.positionen[1] !== "-" && einzel(options, "--link") !== "-") throw new CliFehler(1, "Use join - to read the agent line from standard input.");
  let raw: string;
  try { raw = (await text(process.stdin)).trim(); } catch { throw new CliFehler(1, "Could not read the invitation link."); }
  return parseLink(raw);
}

async function pruefeLink(link: LinkDaten): Promise<OeffentlicheEinladung> {
  const { response, value } = await publicJson(`${link.instanz}/v1/einladung/${link.token}`);
  if (!response.ok) throw fehlerAntwort(response, value);
  if (!object(value)
    || typeof value.instanz !== "string" || typeof value.einladender !== "string"
    || typeof value.sig_I !== "string" || typeof value.box_I !== "string"
    || typeof value.fuer !== "string" || typeof value.c !== "string" || typeof value.ablauf !== "string" || typeof value.zustand !== "string") {
    throw new CliFehler(2, "Could not retrieve the invitation securely.");
  }
  if (typeof value.pk_s !== "string" || !link.secret) throw new CliFehler(3, "This invitation was made with an older version. Ask for a new one.");
  const invitation = value as unknown as OeffentlicheEinladung;
  const sigI = bytes(invitation.sig_I, 32);
  const boxI = bytes(invitation.box_I, 32);
  bytes(invitation.c, 32);
  const derived = einladungsSchluessel(bytes(link.secret, 32));
  if (Buffer.compare(Buffer.from(derived.publicKey), Buffer.from(bytes(invitation.pk_s, 32))) !== 0) throw new CliFehler(3, "Agent line does not match the invitation secret.");
  if (invitation.instanz !== link.instanz) throw new CliFehler(3, "Post office instance does not match the link.");
  if (fingerprintWithoutSpaces(fingerabdruck(sigI, boxI)) !== link.fp) throw new CliFehler(3, "Fingerprint does not match.");
  return invitation;
}

async function codeEmpfangen(options: BeitrittOptionen): Promise<number> {
  const value = einzel(options, "--warten");
  if (value === undefined) return 600;
  if (!/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 3600) throw new CliFehler(1, "--wait must be between 1 and 3600 seconds.");
  return Number(value);
}

export function abfrageIntervallMs(value = process.env.AGENTENPOST_BEITRITT_ABFRAGE_MS): number {
  if (value === undefined || !/^\d+$/.test(value)) return 5000;
  const milliseconds = Number(value);
  return Number.isSafeInteger(milliseconds) && milliseconds >= 10 ? milliseconds : 5000;
}

async function wartenAufOeffnung(config: Konfiguration, local: BeitrittZustand, waitSeconds: number, configPath: string, keyPath: string): Promise<BeitrittZustand> {
  const deadline = Date.now() + waitSeconds * 1000;
  while (Date.now() <= deadline) {
    const { response, value } = await publicJson(`${local.instanz}/v1/einladung/${local.token}/oeffnung`);
    if (response.status === 200 && object(value) && typeof value.n_I === "string" && typeof value.unterschrift === "string") {
      const nI = bytes(value.n_I, 32);
      const signature = bytes(value.unterschrift, 64);
      const protocol: Beitrittsprotokoll = {
        instanz: local.instanz, token: bytes(local.token, 16), name_I: local.name_I, name_J: local.name_J,
        sig_I: bytes(local.sig_I, 32), box_I: bytes(local.box_I, 32), sig_J: bytes(local.sig_J, 32),
        box_J: bytes(local.box_J, 32), c_I: bytes(local.c_I, 32), n_J: bytes(local.n_J, 32), n_I: nI,
      };
      const secret = local.secret ? bytes(local.secret, 32) : undefined;
      if (!secret || Buffer.compare(Buffer.from(festlegung(local.instanz, protocol.token, local.name_I, protocol.sig_I, protocol.box_I, nI, einladungsSchluessel(secret).publicKey)), Buffer.from(protocol.c_I)) !== 0
        || !ed25519.verify(signature, oeffnungsNachricht(protocol), protocol.sig_I)) throw new CliFehler(3, "Invalid opening from the inviter.");
      const updated = { ...local, n_I: b64url(nI), zustand: "wartet_auf_code" as const };
      await schreibeZustand(statePath(config, "joins", local.token), updated);
      console.log(`Fingerprint I: ${fingerprintWithoutSpaces(fingerabdruck(protocol.sig_I, protocol.box_I)).slice(0, 8)}`);
      console.log("Waiting for the inviter to confirm.");
      return updated;
    }
    if (!response.ok && response.status !== 202) throw fehlerAntwort(response, value);
    await sleep(Math.min(abfrageIntervallMs(), Math.max(0, deadline - Date.now())));
  }
  throw new CliFehler(2, "Timed out waiting for the invitation to be opened.");
}

function fortsetzenFehler(fehler: CliFehler, pathConfig: string, pathKey: string): CliFehler {
  return new CliFehler(fehler.exitCode, `${fehler.publicMessage} Join state is saved; resume with subspace join --resume --config ${shellWert(pathConfig)} --key ${shellWert(pathKey)}.`);
}

async function sendeEinloesung(local: BeitrittZustand, key: Schluessel, path: string, pathConfig: string, pathKey: string): Promise<void> {
  const message = einloesungsNachricht({
    instanz: local.instanz, token: bytes(local.token, 16), name_J: local.name_J,
    sig_J: bytes(local.sig_J, 32), box_J: bytes(local.box_J, 32),
    c_I: bytes(local.c_I, 32), n_J: bytes(local.n_J, 32),
  });
  const proof = ed25519.sign(message, key.signaturPrivat);
  if (!local.secret) throw new CliFehler(3, "Join state is missing the invitation secret.");
  const secretSignature = ed25519.sign(message, einladungsSchluessel(bytes(local.secret, 32)).secretKey);
  let redeemed: { response: Response; value: unknown };
  try {
    redeemed = await publicJson(`${local.instanz}/v1/einladung/${local.token}/einloesen`, "POST", {
      sig_J: local.sig_J, box_J: local.box_J, n_J: local.n_J, beleg: b64url(proof), sig_s: b64url(secretSignature),
    });
  } catch (error) {
    const failure = error instanceof CliFehler ? error : new CliFehler(2, "Post office request failed.");
    throw fortsetzenFehler(failure, pathConfig, pathKey);
  }
  if (redeemed.response.status !== 202 || !object(redeemed.value) || redeemed.value.grund !== "angenommen") {
    if (redeemed.response.status >= 400 && redeemed.response.status <= 499) await unlink(path).catch(() => undefined);
    if (redeemed.response.status === 409 && object(redeemed.value) && redeemed.value.grund === "verbrannt") {
      throw new CliFehler(3, "Invitation has been used; request a new one.");
    }
    if (redeemed.response.status >= 500 || redeemed.response.status < 400) {
      const failure = redeemed.response.status >= 400
        ? fehlerAntwort(redeemed.response, redeemed.value)
        : new CliFehler(2, "Invalid response from the post office.");
      throw fortsetzenFehler(failure, pathConfig, pathKey);
    }
    throw fehlerAntwort(redeemed.response, redeemed.value);
  }
}

async function pruefeFortsetzenUndLoese(local: BeitrittZustand, key: Schluessel, path: string, pathConfig: string, pathKey: string): Promise<void> {
  let invitation: { response: Response; value: unknown };
  try {
    invitation = await publicJson(`${local.instanz}/v1/einladung/${local.token}`);
  } catch (error) {
    const failure = error instanceof CliFehler ? error : new CliFehler(2, "Post office request failed.");
    throw fortsetzenFehler(failure, pathConfig, pathKey);
  }
  if (invitation.response.status === 404) {
    await unlink(path).catch(() => undefined);
    throw new CliFehler(3, "Invitation has been used or expired; request a new one.");
  }
  if (invitation.response.status >= 500) {
    throw fortsetzenFehler(fehlerAntwort(invitation.response, invitation.value), pathConfig, pathKey);
  }
  if (invitation.response.status !== 200 || !object(invitation.value) || typeof invitation.value.zustand !== "string") {
    throw fehlerAntwort(invitation.response, invitation.value);
  }
  const zustand = invitation.value.zustand;
  if (zustand === "offen") return sendeEinloesung(local, key, path, pathConfig, pathKey);
  if (zustand === "eingeloest" || zustand === "geoeffnet" || zustand === "bestaetigt") return;
  if (zustand === "verbrannt" || zustand === "abgelaufen") {
    await unlink(path).catch(() => undefined);
    throw new CliFehler(3, "Invitation has been used or expired; request a new one.");
  }
  throw new CliFehler(3, "Invitation cannot be resumed because the server returned an unsupported state.");
}

async function joinLink(options: BeitrittOptionen): Promise<void> {
  let link: LinkDaten;
  const input = options.positionen[1];
  if (input === "-") link = await linkVonStdin(options);
  else if (input) link = parseLink(input);
  else if (einzel(options, "--link") === "-") link = await linkVonStdin(options);
  else throw new CliFehler(1, "Provide the agent line or use join - to read it from standard input.");
  if (link.sha) {
    console.log(`Link checksum: ${link.sha}`);
    if (typeof process.argv[1] === "string" && /\.js$/i.test(process.argv[1])) {
      let ownSha: string;
      try { ownSha = createHash("sha256").update(await readFile(process.argv[1])).digest("hex"); }
      catch { throw new CliFehler(1, "Could not read the running script checksum."); }
      if (ownSha !== link.sha) throw new CliFehler(1, "Checksum does not match the running script.");
    } else console.error("Warning: Could not determine the running CLI checksum; the link checksum was not verified.");
  }
  const invitation = await pruefeLink(link);
  const ablauf = Date.parse(invitation.ablauf);
  if (!Number.isFinite(ablauf) || ablauf <= Date.now()) throw new CliFehler(3, "Invitation has expired.");
  const directory = einzel(options, "--ordner");
  const configPath = einzel(options, "--config");
  const keyPath = einzel(options, "--key");
  if ((directory === undefined) === (configPath === undefined || keyPath === undefined)) {
    throw new CliFehler(1, "Specify either --dir or both --config and --key.");
  }
  if (invitation.fuer !== (directory ? invitation.fuer : (await ladeKonfiguration(configPath!)).name)) throw new CliFehler(1, "Invitation is for a different name.");
  let config: Konfiguration;
  let loadedKey: Schluessel;
  let pathConfig: string;
  let pathKey: string;
  if (directory) {
    await setup({ name: invitation.fuer, postamt: link.instanz, ordner: directory });
    pathConfig = join(directory, "config.json");
    pathKey = join(directory, "key.json");
    config = await ladeKonfiguration(pathConfig);
    loadedKey = await ladeSchluessel(pathKey);
  } else {
    pathConfig = configPath!;
    pathKey = keyPath!;
    config = await ladeKonfiguration(pathConfig);
    loadedKey = await ladeSchluessel(pathKey);
    if (new URL(config.postamt).origin !== link.instanz) throw new CliFehler(1, "Invitation link and configured post office do not match.");
  }
  const invitedKey = Object.hasOwn(config.vertraut, invitation.einladender) ? config.vertraut[invitation.einladender] : undefined;
  if (invitedKey && (Buffer.compare(Buffer.from(invitedKey.signatur), Buffer.from(bytes(invitation.sig_I, 32))) !== 0
    || Buffer.compare(Buffer.from(invitedKey.box), Buffer.from(bytes(invitation.box_I, 32))) !== 0)) {
    throw new CliFehler(3, `Key conflict for ${druckbar(invitation.einladender)}; the existing trusted key is unchanged.`);
  }
  const tokenBytes = bytes(link.token, 16);
  const nJ = randomBytes(32);
  const sigJ = loadedKey.signaturOeffentlich;
  const boxJ = loadedKey.boxOeffentlich;
  const cI = bytes(invitation.c, 32);
  const local: BeitrittZustand = {
    art: "beitritt", token: link.token, instanz: link.instanz,
    name_I: invitation.einladender, name_J: invitation.fuer,
    sig_I: b64url(bytes(invitation.sig_I, 32)), box_I: b64url(bytes(invitation.box_I, 32)), c_I: b64url(cI),
    sig_J: b64url(sigJ), box_J: b64url(boxJ), n_J: b64url(nJ), zustand: "eingeloest", secret: link.secret,
  };
  const root = stateRoot(config, "joins");
  await bereiteZustandsordnerVor(root);
  const path = statePath(config, "joins", link.token);
  try { await lstat(path); throw new CliFehler(3, "A join for this invitation is already in progress; use --resume."); }
  catch (error) {
    if (error instanceof CliFehler) throw error;
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new CliFehler(3, "Could not check join state.");
  }
  await schreibeZustand(path, local);
  await sendeEinloesung(local, loadedKey, path, pathConfig, pathKey);
  const opened = await wartenAufOeffnung(config, local, await codeEmpfangen(options), pathConfig, pathKey);
  await wartenAufBestaetigung(config, loadedKey, pathConfig, opened, await codeEmpfangen(options));
}

async function wartenAufBestaetigung(config: Konfiguration, key: Schluessel, configPath: string, local: BeitrittZustand, waitSeconds: number): Promise<void> {
  const deadline = Date.now() + waitSeconds * 1000;
  while (Date.now() <= deadline) {
    const { response, value } = await publicJson(`${local.instanz}/v1/einladung/${local.token}/bestaetigung`);
    if (response.status === 200 && object(value) && typeof value.unterschrift === "string") {
      const signature = bytes(value.unterschrift, 64);
      const protocol = joinProtocol(local);
      if (!ed25519.verify(signature, bestaetigungsNachricht(protocol), protocol.sig_I)) throw new CliFehler(3, "Invalid confirmation for this join.");
      await trust(configPath, local.name_I, protocol.sig_I, protocol.box_I);
      await schreibeZustand(statePath(config, "joins", local.token), { ...local, zustand: "bestaetigt" });
      console.log("Join confirmed.");
      return;
    }
    if (!response.ok && response.status !== 202) throw fehlerAntwort(response, value);
    await sleep(Math.min(abfrageIntervallMs(), Math.max(0, deadline - Date.now())));
  }
  throw new CliFehler(2, "Wait for confirmation expired.");
}

async function completeJoin(options: BeitrittOptionen): Promise<void> {
  if (options.schalter.has("--fortsetzen")) {
    const configPath = einzel(options, "--config", true)!;
    const config = await ladeKonfiguration(configPath);
    const key = await ladeSchluessel(einzel(options, "--key", true)!);
    const prefix = einzel(options, "--token");
    if (prefix !== undefined && !/^[A-Za-z0-9_-]{8}$/.test(prefix)) throw new CliFehler(1, "--token must contain the first 8 token characters.");
    const root = stateRoot(config, "joins");
    const names = await readdir(root).catch(() => []);
    const pending = (await Promise.all(names.filter((name) => /^[A-Za-z0-9_-]{22}\.json$/.test(name)).map((name) => leseZustand<BeitrittZustand>(join(root, name)))))
      .filter((state) => state.art === "beitritt" && state.name_J === config.name
        && (state.zustand === "eingeloest" || state.zustand === "wartet_auf_code")
        && (prefix === undefined || state.token.startsWith(prefix)));
    if (pending.length === 0) throw new CliFehler(3, "No matching pending join found.");
    if (prefix === undefined && pending.length > 1) throw new CliFehler(3, "Multiple joins are pending; specify the first 8 characters with --token.");
    if (prefix !== undefined && pending.length > 1) throw new CliFehler(3, "--token prefix is not unique.");
    const local = pending[0]!;
    if (Buffer.compare(Buffer.from(bytes(local.sig_J, 32)), Buffer.from(key.signaturOeffentlich)) !== 0
      || Buffer.compare(Buffer.from(bytes(local.box_J, 32)), Buffer.from(key.boxOeffentlich)) !== 0) {
      throw new CliFehler(3, "Join state belongs to a different key.");
    }
    if (local.zustand === "eingeloest") {
      await pruefeFortsetzenUndLoese(local, key, statePath(config, "joins", local.token), configPath, einzel(options, "--key", true)!);
      await wartenAufOeffnung(config, local, await codeEmpfangen(options), configPath, einzel(options, "--key", true)!);
      return;
    }
    return wartenAufBestaetigung(config, key, configPath, local, await codeEmpfangen(options));
  }
  return joinLink(options);
}

async function confirm(options: BeitrittOptionen): Promise<void> {
  const fuer = options.positionen[1];
  if (!fuer) throw new CliFehler(1, "Name is required.");
  const configPath = einzel(options, "--config", true)!;
  const config = await ladeKonfiguration(configPath);
  const key = await ladeSchluessel(einzel(options, "--key", true)!);
  const prefix = einzel(options, "--token");
  if (prefix !== undefined && !/^[A-Za-z0-9_-]{8}$/.test(prefix)) throw new CliFehler(1, "--token must contain the first 8 token characters.");
  await oeffnenIntern(options);
  const directory = stateRoot(config, "invitations");
  const names = await readdir(directory).catch(() => []);
  const candidateNames = names.filter((name) => /^[A-Za-z0-9_-]{22}\.json$/.test(name));
  const opened: { state: EinladungZustand; path: string }[] = [];
  let confirmed: EinladungZustand | undefined;
  let burned: EinladungZustand | undefined;
  for (const name of candidateNames) {
    const path = join(directory, name);
    const candidate = await leseZustand<EinladungZustand>(path);
    if (candidate.fuer !== fuer || candidate.art !== "einladung") continue;
    if (candidate.zustand === "geoeffnet") opened.push({ state: candidate, path });
    if (candidate.zustand === "bestaetigt") confirmed = candidate;
    if (candidate.zustand === "verbrannt") burned = candidate;
  }
  if (opened.length === 0 && confirmed) throw new CliFehler(3, "Invitation has already been confirmed.");
  if (opened.length === 0 && burned) throw new CliFehler(3, "Invitation is locally burned.");
  if (opened.length === 0) throw new CliFehler(3, "No matching local invitation found.");
  if (prefix === undefined && opened.length > 1) throw new CliFehler(3, "Multiple invitations are open; specify the first 8 characters with --token.");
  const matching = prefix === undefined ? opened : opened.filter((entry) => entry.state.token.startsWith(prefix));
  if (matching.length === 0) throw new CliFehler(3, "No open invitation matches this --token prefix.");
  if (matching.length > 1) throw new CliFehler(3, "--token prefix is not unique.");
  const { state: local, path: localFile } = matching[0]!;
  if (local.zustand !== "geoeffnet") throw new CliFehler(3, "Invitation has not been opened yet.");
  if (local.instanz !== new URL(config.postamt).origin) throw new CliFehler(3, "Local invitation state belongs to a different post office.");
  if (Buffer.compare(Buffer.from(bytes(local.sig_I, 32)), Buffer.from(key.signaturOeffentlich)) !== 0
    || Buffer.compare(Buffer.from(bytes(local.box_I, 32)), Buffer.from(key.boxOeffentlich)) !== 0) {
    throw new CliFehler(3, "Local invitation state belongs to a different key.");
  }
  if (local.fehler >= 3) {
    await schreibeZustand(localFile, { ...local, zustand: "verbrannt" });
    throw new CliFehler(3, "Invitation is locally burned.");
  }
  const protocol = einladungProtocol(local);
  await pruefeVertrauenSchreibbar(configPath, fuer, protocol.sig_J, protocol.box_J);

  const pinAndComplete = async (signature: Uint8Array): Promise<void> => {
    if (!ed25519.verify(signature, bestaetigungsNachricht(protocol), protocol.sig_I)) {
      throw new CliFehler(3, "Invalid confirmation for this join.");
    }
    await trust(configPath, fuer, protocol.sig_J, protocol.box_J);
    await schreibeZustand(localFile, { ...local, zustand: "bestaetigt" });
    console.log("Join confirmed.");
  };

  const bestaetigungAbrufen = async (expected?: Uint8Array): Promise<boolean> => {
    const { response, value } = await publicJson(`${local.instanz}/v1/einladung/${local.token}/bestaetigung`);
    if (response.status === 200 && object(value) && typeof value.unterschrift === "string") {
      const signature = bytes(value.unterschrift, 64);
      if (expected && Buffer.compare(Buffer.from(signature), Buffer.from(expected)) !== 0) {
        throw new CliFehler(3, "Post office confirmation does not match the submitted signature.");
      }
      await pinAndComplete(signature);
      return true;
    }
    if (!response.ok && response.status !== 202) throw fehlerAntwort(response, value);
    return false;
  };

  if (await bestaetigungAbrufen()) return;
  const signature = ed25519.sign(bestaetigungsNachricht(protocol), key.signaturPrivat);
  try {
    const result = await signedJson(config.postamt, `/v1/einladung/${local.token}/bestaetigung`, "POST", { unterschrift: b64url(signature) }, config, key);
    if (!object(result) || result.grund !== "bestaetigt") throw new CliFehler(2, "Post office did not accept the confirmation.");
  } catch (error) {
    if (await bestaetigungAbrufen(signature)) return;
    throw error;
  }
  await trust(configPath, fuer, protocol.sig_J, protocol.box_J);
  await schreibeZustand(localFile, { ...local, zustand: "bestaetigt" });
  console.log("Join confirmed.");
}

async function kontakte(options: BeitrittOptionen): Promise<void> {
  const config = await ladeKonfiguration(einzel(options, "--config", true)!);
  const keyPath = einzel(options, "--key");
  const ownKey = keyPath ? await ladeSchluessel(keyPath) : undefined;
  const contacts = Object.entries(config.vertraut).sort(([left], [right]) => left.localeCompare(right));
  const statuses = ownKey ? await ermittleEmpfaengerSchluesselstaende(config, ownKey, contacts.map(([name]) => name)) : undefined;
  let alarm = false;
  let nichtPruefbar = false;
  for (const [name, keys] of contacts) {
    const contact: Record<string, unknown> = { name, ssh: sshFingerabdruck(keys.signatur, `${name}@subspace`), fingerprint: fingerabdruck(keys.signatur, keys.box) };
    if (ownKey) {
      const status = statuses![name]!;
      contact.key = status.stand === "nicht_pruefbar" || status.stand === "alarm" ? { status: status.stand === "nicht_pruefbar" ? "unverified" : "alarm" } : { status: ({ aktuell: "current", gewechselt: "rotated", ohne_buergschaft: "unauthorized", vorlauf: "pending", abgelaufen: "expired", alarm: "alarm", nicht_pruefbar: "unverified" } as Record<string, string>)[status.stand] ?? status.stand, fingerprint: "fingerabdruck" in status ? status.fingerabdruck : undefined, hint: "hinweis" in status ? status.hinweis : undefined };
      if (status.stand === "alarm") {
        alarm = true;
        console.error(`ALARM: Key from ${name} was revoked or forked.`);
      } else if (["gewechselt", "ohne_buergschaft", "vorlauf", "abgelaufen"].includes(status.stand)) {
        alarm = true;
      } else if (status.stand === "nicht_pruefbar") {
        nichtPruefbar = true;
      }
    }
    console.log(JSON.stringify(contact));
  }
  console.log("Waiting for confirmation:");
  for (const kind of ["invitations", "joins"] as const) {
    const root = stateRoot(config, kind);
    const names = await readdir(root).catch(() => []);
    for (const name of names.filter((entry) => /^[A-Za-z0-9_-]{22}\.json$/.test(entry))) {
      if (kind === "invitations") {
        const state = await leseZustand<EinladungZustand>(join(root, name));
        if (state.zustand === "geoeffnet") console.log(JSON.stringify({ name: state.fuer, state: "waiting for confirmation", token: kurzesToken(state.token) }));
      } else {
        const state = await leseZustand<BeitrittZustand>(join(root, name));
        if (state.zustand === "wartet_auf_code") console.log(JSON.stringify({ name: state.name_I, state: "waiting for confirmation", token: kurzesToken(state.token) }));
      }
    }
  }
  if (!ownKey) console.log("Key status not checked; verify with --key.");
  if (alarm) process.exitCode = 4;
  else if (nichtPruefbar) process.exitCode = 2;
}

export async function fuehreBeitrittAus(command: string, options: BeitrittOptionen): Promise<boolean> {
  if (!["einladen", "einladungen", "oeffnen", "join", "confirm", "kontakte"].includes(command)) return false;
  switch (command as Befehl) {
    case "einladen": await einladen(options); break;
    case "einladungen": await einladungen(options); break;
    case "oeffnen": await oeffnen(options); break;
    case "join": await completeJoin(options); break;
    case "confirm": await confirm(options); break;
    case "kontakte": await kontakte(options); break;
  }
  return true;
}
