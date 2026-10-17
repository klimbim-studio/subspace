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
  confirmationMessage,
  deriveInvitationKey,
  redemptionMessage,
  createJoinCommitment,
  openingMessage,
  type JoinTranscript,
} from "../join.ts";
import { signRequest } from "../request.ts";
import { fingerprint, type KeyPair } from "../seal.ts";
import { MAX_GROUP_MEMBERS } from "../group.ts";
import { sshPublicKeyFingerprint } from "../ssh.ts";
import { getRecipientKeyStatuses } from "./authorization.ts";
import { atomicWrite, CliError, loadConfiguration, loadKey, resolveConfigPath, saveConfiguration, type Configuration } from "./shared.ts";
import { setup } from "./setup.ts";
import { retryOnRateLimit } from "./network.ts";
import { groupsFilePath, loadGroups } from "./group.ts";
import { queueOrSendGroupInvitation } from "./group-invitations.ts";
import { parseGroupState } from "../group.ts";

export interface JoinOptions {
  positionals: string[];
  values: Map<string, string[]>;
  flags: Set<string>;
}

type CommandName = "invite" | "invites" | "open" | "join" | "confirm" | "contacts";

interface InvitationState {
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
  // wire format, keep
  zustand: "offen" | "geoeffnet" | "bestaetigt" | "verbrannt";
  fehler: number; // on-disk format, keep
  sig_J?: string;
  box_J?: string;
  n_J?: string;
}

interface JoinState {
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

interface LinkData {
  instanz: string;
  token: string;
  fp: string;
  sha?: string;
  secret?: string;
}

interface PublicInvitation {
  instanz: string;
  einladender: string; // wire format, keep
  sig_I: string;
  box_I: string;
  fuer: string;
  c: string;
  pk_s: string;
  // wire format, keep
  ablauf: string;
  zustand: string;
}

const b64url = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const shortToken = (value: string) => value.slice(0, 8);
const printableText = (value: string) => [...value].filter((character) => !/[\p{C}\p{Zl}\p{Zp}]/u.test(character)).join("");
const shellValue = (value: string) => /^[A-Za-z0-9_./:-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
const bytes = (value: string, length: number): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new CliError(3, "Invalid join state or Subspace server receipt.");
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (decoded.length !== length || b64url(decoded) !== value) throw new CliError(3, "Invalid join state or Subspace server receipt.");
  return decoded;
};

function singleOption(options: JoinOptions, flag: string, required = false): string | undefined {
  const values = options.values.get(flag) ?? [];
  if (values.length > 1 || (required && values.length !== 1)) throw new CliError(1, `Missing or repeated option: ${flag}.`);
  return values[0];
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function englishJoinState(value: string): string {
  switch (value) {
    case "offen": return "open";
    case "geoeffnet": return "opened";
    case "bestaetigt": return "confirmed";
    case "verbrannt": return "burned";
    case "eingeloest": return "redeemed";
    case "wartet_auf_code": return "waiting_for_code";
    case "abgelaufen": return "expired";
    case "nicht_gefunden": return "not_found";
    default: return value;
  }
}

function englishContactKeyStatus(value: string): string {
  switch (value) {
    case "aktuell": return "current";
    case "gewechselt": return "rotated";
    case "ohne_buergschaft": return "unauthorized";
    case "vorlauf": return "pending";
    case "abgelaufen": return "expired";
    case "alarm": return "alarm";
    case "nicht_pruefbar": return "unverified";
    default: return value;
  }
}

function stateRoot(config: Configuration, storageKind: "invitations" | "joins"): string {
  const oldName = storageKind === "invitations" ? "einladungen" : "beitritte";
  const oldPath = join(config.storage, oldName);
  const newPath = join(config.storage, storageKind);
  if (existsSync(oldPath) && existsSync(newPath)) throw new CliError(3, `Legacy and English ${storageKind} storage both exist; resolve the name conflict before retrying.`);
  if (existsSync(oldPath)) {
    try { renameSync(oldPath, newPath); }
    catch { throw new CliError(3, `Could not migrate the ${storageKind} storage directory safely.`); }
  }
  return newPath;
}

async function prepareStateDirectory(path: string): Promise<void> {
  try {
    await mkdir(path, { recursive: true, mode: 0o700 });
    const info = await lstat(path);
    if (!info.isDirectory() || info.uid !== (process.getuid?.() ?? -1)) throw new CliError(3, "Unsafe join storage directory.");
    await chmod(path, 0o700);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "Could not create the join storage directory safely.");
  }
}

async function readState<T>(path: string): Promise<T> {
  try {
    const info = await lstat(path);
    if (!info.isFile() || info.uid !== (process.getuid?.() ?? -1) || (info.mode & 0o777) !== 0o600) throw new Error();
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    throw new CliError(3, "Join state is missing or cannot be read safely.");
  }
}

async function writeState(path: string, value: unknown): Promise<void> {
  await atomicWrite(path, JSON.stringify(value) + "\n");
}

function responseError(response: Response, value: unknown): CliError {
  if (response.status >= 300 && response.status < 400) return new CliError(2, "Subspace server redirect was rejected.");
  if (response.status === 408) return new CliError(2, "Subspace server request timed out.");
  if (response.status === 404) return new CliError(2, "Invitation is no longer valid.");
  if (response.status === 410 && object(value) && value.grund === "invitation_outdated") return new CliError(3, "This invitation was made with an older version. Ask for a new one.");
  if (response.status === 409) {
    const reason = object(value)
      ? (typeof value.meldung /* wire format, keep */ === "string" ? value.meldung /* wire format, keep */ : typeof value.grund === "string" ? value.grund : "Conflict")
      : "Conflict";
    const translatedReason = reason === "f\u00fcr diesen Namen gibt es schon eine offene Einladung" // wire format, keep
      ? "An invitation for this name is already open"
      : reason === "konflikt" || reason === "Konflikt" ? "Conflict" : printableText(reason);
    return new CliError(2, `Subspace server reported a conflict: ${translatedReason}.`);
  }
  if (response.status >= 500) return new CliError(2, `Subspace server reported a server error (${response.status}).`);
  return new CliError(2, `Subspace server request failed (HTTP ${response.status}).`);
}

function fetchError(error: unknown): CliError {
  if (error instanceof Error && (error.message.startsWith("UnexpectedRedirect")
    || (error instanceof TypeError && object(error.cause) && typeof error.cause.message === "string" && /redirect/i.test(error.cause.message)))) {
    return new CliError(2, "Subspace server redirect was rejected.");
  }
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
    return new CliError(2, "Subspace server request timed out.");
  }
  return new CliError(2, "Request to the Subspace server failed.");
}

function statePath(config: Configuration, storageKind: "invitations" | "joins", token: string): string {
  return join(stateRoot(config, storageKind), `${token}.json`);
}

async function signedFetch(base: string, path: string, method: string, body: Uint8Array, config: Configuration, key: KeyPair): Promise<Response> {
  const url = `${base.replace(/\/$/, "")}${path}`;
  return retryOnRateLimit(() => fetch(url, {
    method,
    headers: signRequest({ method: method, url, body: body, name: config.name, privateKey: key.signaturPrivat }),
    ...(body.length ? { body: Buffer.from(body) } : {}),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  }));
}

async function signedJson(base: string, path: string, method: string, body: unknown, config: Configuration, key: KeyPair): Promise<unknown> {
  const encoded = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
  let response: Response;
  try { response = await signedFetch(base, path, method, encoded, config, key); } catch (error) { if (error instanceof CliError) throw error; throw fetchError(error); }
  let value: unknown;
  try { value = await response.json(); } catch {
    if (!response.ok) throw responseError(response, undefined);
    throw new CliError(2, "Invalid response from the Subspace server.");
  }
  if (!response.ok) throw responseError(response, value);
  return value;
}

async function publicJson(url: string, method = "GET", body?: unknown): Promise<{ response: Response; value: unknown }> {
  let response: Response;
  try {
    response = await retryOnRateLimit(() => fetch(url, {
      method,
      ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    }));
  } catch (error) { if (error instanceof CliError) throw error; throw fetchError(error); }
  let value: unknown;
  try { value = await response.json(); } catch {
    if (response.ok) throw new CliError(2, "Invalid response from the Subspace server.");
  }
  return { response, value };
}

const AGENT_LINE_FORMAT = " Expected format: https://<subspace-server>/e/<token>?s=<secret>&fp=<fingerprint>&sha=<checksum>.";

function parseLink(raw: string): LinkData {
  raw = raw.trim().replace(/^Agent line:/i, "").trim();
  let url: URL;
  try {
    const address = /^[A-Za-z0-9.-]+(?::[0-9]+)?\//.test(raw) ? `${raw.startsWith("localhost") || raw.startsWith("127.0.0.1") ? "http://" : "https://"}${raw}` : raw;
    url = new URL(address);
  } catch { throw new CliError(1, `Invalid agent line. Use the agent line, not the browser address.${AGENT_LINE_FORMAT}`); }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost"].includes(url.hostname))) {
    throw new CliError(1, `Unsupported protocol in agent line: ${url.protocol}.${AGENT_LINE_FORMAT}`);
  }
  if (url.username || url.password) {
    throw new CliError(1, `Invalid agent line.${AGENT_LINE_FORMAT}`);
  }
  const match = /^\/e\/([A-Za-z0-9_-]{22})$/.exec(url.pathname);
  if (!match) throw new CliError(1, `Invalid invitation link.${AGENT_LINE_FORMAT}`);
  bytes(match[1]!, 16);
  const legacy = /^#fp=([a-f0-9]{64})&sha=([a-f0-9]{64})$/.exec(url.hash);
  const secret = url.searchParams.get("s");
  const fp = url.searchParams.get("fp") ?? legacy?.[1];
  const sha = url.searchParams.get("sha") ?? legacy?.[2];
  const keys = [...url.searchParams.keys()].sort().join(",");
  if (!fp || !sha || !/^[a-f0-9]{64}$/.test(fp) || !/^[a-f0-9]{64}$/.test(sha)
    || (secret ? keys !== "fp,s,sha" || url.hash !== "" : keys !== "" && keys !== "fp,sha")) {
    throw new CliError(1, `Browser address is incomplete; use the agent line from the invitation.${AGENT_LINE_FORMAT}`);
  }
  if (secret) bytes(secret, 32);
  return { instanz: url.origin, token: match[1]!, fp, sha, ...(secret ? { secret } : {}) };
}

function invitationTranscript(state: InvitationState): JoinTranscript {
  if (!state.sig_J || !state.box_J || !state.n_J) throw new CliError(3, "Invitation has no valid redemption yet.");
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

function joinProtocol(state: JoinState): JoinTranscript {
  if (!state.n_I) throw new CliError(3, "Join is waiting for the invitation to be opened.");
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
  const current = await loadConfiguration(configPath);
  const existing = Object.hasOwn(current.trusted, name) ? current.trusted[name] : undefined;
  if (existing && (Buffer.compare(Buffer.from(existing.signature), Buffer.from(sig)) !== 0
    || Buffer.compare(Buffer.from(existing.box), Buffer.from(box)) !== 0)) {
    throw new CliError(3, `Key conflict for ${name}; the existing trusted key is unchanged.`);
  }
  await saveConfiguration(configPath, {
    ...current,
    trusted: { ...current.trusted, [name]: { signature: sig, box } },
  });
}

async function assertTrustWritable(configPath: string, name: string, sig: Uint8Array, box: Uint8Array): Promise<void> {
  const current = await loadConfiguration(configPath);
  const existing = Object.hasOwn(current.trusted, name) ? current.trusted[name] : undefined;
  if (existing && (Buffer.compare(Buffer.from(existing.signature), Buffer.from(sig)) !== 0
    || Buffer.compare(Buffer.from(existing.box), Buffer.from(box)) !== 0)) {
    throw new CliError(3, `Key conflict for ${name}; the existing trusted key is unchanged.`);
  }
  const probePath = join(dirname(configPath), `.beitritt-${process.pid}-${b64url(randomBytes(12))}.tmp`);
  let probe;
  try {
    probe = await open(probePath, "wx", 0o600);
    await probe.sync();
  } catch {
    throw new CliError(1, "Configuration is not writable; join was not confirmed.");
  } finally {
    await probe?.close().catch(() => undefined);
    await unlink(probePath).catch(() => undefined);
  }
}

interface LockFileOperations {
  open(path: string, flags: string, mode?: number): Promise<FileHandle>;
  lstat(path: string): Promise<Stats>;
  rename(source: string, destination: string): Promise<void>;
  link(source: string, destination: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

export async function acquireLock(
  lockPath: string,
  fileOps: LockFileOperations = { open, lstat, rename, link, unlink },
) {
  const lockError = () => new CliError(3, `Invitation is locked (${lockPath}); check the process or remove a stale lock and try again.`);
  const create = async () => {
    const lock = await fileOps.open(lockPath, "wx", 0o600);
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
          const current = await fileOps.lstat(lockPath);
          if (current.dev === info.dev && current.ino === info.ino) await fileOps.unlink(lockPath);
        } catch { }
      }
      throw error;
    }
  };
  const readText = async (path: string) => {
    const handle = await fileOps.open(path, "r");
    try { return await handle.readFile("utf8"); }
    finally { await handle.close(); }
  };
  const guardPath = `${lockPath}.uebernahme`;
  const createGuard = async () => {
    const guard = await fileOps.open(guardPath, "wx", 0o600);
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
          const current = await fileOps.lstat(guardPath);
          if (current.dev === info.dev && current.ino === info.ino) await fileOps.unlink(guardPath);
        } catch { }
      }
      throw error;
    }
  };
  const releaseGuard = async (guard: Awaited<ReturnType<typeof createGuard>>) => {
    await guard.handle.close().catch(() => undefined);
    try {
      const current = await fileOps.lstat(guardPath);
      if (current.dev === guard.dev && current.ino === guard.ino) await fileOps.unlink(guardPath);
    } catch { }
  };

  let initial: Awaited<ReturnType<typeof lstat>> | undefined;
  try { initial = await fileOps.lstat(lockPath); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw lockError(); }

  let guard: Awaited<ReturnType<typeof createGuard>>;
  try { guard = await createGuard(); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new CliError(3, `Could not create ownership lock (${guardPath}).`);
    let observed;
    try {
      observed = await fileOps.lstat(guardPath);
      if (!observed.isFile() || observed.uid !== (process.getuid?.() ?? -1) || (observed.mode & 0o777) !== 0o600) throw new Error();
    } catch { throw lockError(); }
    let stale = false;
    try {
      const metadata: unknown = JSON.parse(await readText(guardPath));
      if (!object(metadata) || !Number.isSafeInteger(metadata.pid) || typeof metadata.zeit !== "number" || !Number.isFinite(metadata.zeit)) throw new Error();
      stale = Date.now() - metadata.zeit > 60_000;
    } catch { stale = Date.now() - observed.mtimeMs > 60_000; }
    if (!stale) throw lockError();
    const staleGuardPath = `${guardPath}.verwaist-${process.pid}-${b64url(randomBytes(12))}`;
    try { await fileOps.rename(guardPath, staleGuardPath); } catch { throw lockError(); }
    let movedGuard;
    try { movedGuard = await fileOps.lstat(staleGuardPath); } catch { throw lockError(); }
    if (movedGuard.dev !== observed.dev || movedGuard.ino !== observed.ino) {
      try {
        await fileOps.link(staleGuardPath, guardPath);
        await fileOps.unlink(staleGuardPath);
      } catch { }
      throw lockError();
    }
    await fileOps.unlink(staleGuardPath).catch(() => undefined);
    try { guard = await createGuard(); }
    catch { throw lockError(); }
  }

  try {
    try { return await create(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new CliError(3, `Could not create lock file (${lockPath}).`); }

    let observed;
    try {
      observed = await fileOps.lstat(lockPath);
      if (!observed.isFile() || observed.uid !== (process.getuid?.() ?? -1) || (observed.mode & 0o777) !== 0o600) throw new Error();
      if (!initial || observed.dev !== initial.dev || observed.ino !== initial.ino) throw lockError();
    } catch (error) { if (error instanceof CliError) throw error; throw lockError(); }

    let stale = false;
    try {
      const metadata: unknown = JSON.parse(await readText(lockPath));
      if (!object(metadata) || !Number.isSafeInteger(metadata.pid) || typeof metadata.zeit !== "number" || !Number.isFinite(metadata.zeit)) throw new Error();
      if (Date.now() - metadata.zeit > 600_000) stale = true;
      else {
        try { process.kill(metadata.pid as number, 0); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === "ESRCH") stale = true; }
      }
    } catch { stale = Date.now() - observed.mtimeMs > 600_000; }
    const afterRead = await fileOps.lstat(lockPath).catch(() => undefined);
    if (!afterRead || afterRead.dev !== observed.dev || afterRead.ino !== observed.ino || !stale) throw lockError();

    const stalePath = `${lockPath}.verwaist-${process.pid}-${b64url(randomBytes(12))}`;
    try { await fileOps.rename(lockPath, stalePath); } catch { throw lockError(); }
    let moved;
    try { moved = await fileOps.lstat(stalePath); } catch { throw new CliError(3, `Could not safely take over lock file (${lockPath}).`); }
    if (moved.dev !== observed.dev || moved.ino !== observed.ino) {
      try {
        await fileOps.link(stalePath, lockPath);
        await fileOps.unlink(stalePath);
      } catch { }
      throw lockError();
    }
    let replacement;
    try { replacement = await create(); }
    catch {
      try {
        await fileOps.link(stalePath, lockPath);
        await fileOps.unlink(stalePath);
      } catch { }
      throw lockError();
    }
    const staleCurrent = await fileOps.lstat(stalePath).catch(() => undefined);
    if (staleCurrent?.dev === moved.dev && staleCurrent.ino === moved.ino) await fileOps.unlink(stalePath).catch(() => undefined);
    return replacement;
  } finally { await releaseGuard(guard); }
}

function fingerprintWithoutSpaces(value: string): string {
  return value.replaceAll(" ", "");
}

async function inviteAgent(options: JoinOptions): Promise<void> {
  const configPath = resolveConfigPath(singleOption(options, "--config"));
  const config = await loadConfiguration(configPath);
  const key = await loadKey(singleOption(options, "--key", true)!);
  const invitedName = singleOption(options, "--for", true)!;
  const script = singleOption(options, "--script") ?? (typeof process.argv[1] === "string" && /\.js$/i.test(process.argv[1]) ? process.argv[1] : undefined);
  if (!script) throw new CliError(1, "SHA-256 of the running script is unavailable; specify --script.");
  const invitation = await createInvitation(config, key, invitedName, script);
  console.log(`Browser address: ${invitation.browserAddress}`);
  console.log(`Agent line: ${invitation.agentLine}`);
  console.log("Give the agent line only to the invited person's own agent; never enter it in a browser.");
}

async function createInvitation(config: Configuration, key: KeyPair, invitedName: string, script: string): Promise<{ token: string; browserAddress: string; agentLine: string }> {
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(invitedName) || invitedName === config.name) throw new CliError(1, "Invalid invitation name.");
  const instance = new URL(config.server).origin;
  const token = b64url(randomBytes(16));
  const nI = randomBytes(32);
  const secret = randomBytes(32);
  const signing = deriveInvitationKey(secret);
  const sigI = key.signaturOeffentlich;
  const boxI = key.boxOeffentlich;
  const cI = createJoinCommitment(instance, new Uint8Array(Buffer.from(token, "base64url")), config.name, sigI, boxI, nI, signing.publicKey);
  let sha: string;
  try { sha = createHash("sha256").update(await readFile(script)).digest("hex"); }
  catch { throw new CliError(1, "Could not read the script for its SHA-256 fingerprint; check --script."); }
  const root = stateRoot(config, "invitations");
  await prepareStateDirectory(root);
  const local: InvitationState = {
    art: "einladung", token, instanz: instance, name_I: config.name, fuer: invitedName,
    sig_I: b64url(sigI), box_I: b64url(boxI), c_I: b64url(cI), n_I: b64url(nI),
    pk_s: b64url(signing.publicKey),
    zustand: "offen", fehler: 0,
  };
  const response = await signedJson(config.server, "/v1/einladung", "POST", {
    token, fuer: invitedName, c: b64url(cI), box: b64url(boxI), pk_s: b64url(signing.publicKey),
  }, config, key);
  if (!object(response) || response.token !== token) throw new CliError(2, "Invalid response from the Subspace server.");
  await writeState(statePath(config, "invitations", token), local);
  const fingerprintCode = fingerprintWithoutSpaces(fingerprint(sigI, boxI));
  const browserAddress = `${instance}/e/${token}`;
  const authority = new URL(instance).host;
  const agentLine = `${authority}/e/${token}?s=${b64url(secret)}&fp=${fingerprintCode}&sha=${sha}`;
  return { token, browserAddress, agentLine };
}


export async function processInvitationTasks(config: Configuration, key: KeyPair, skipTasks = false): Promise<void> {
  if (skipTasks) return;
  if (!config.invitation_tasks) {
    try {
      await signedJson(config.server, "/v1/einladungsauftraege/abmelden", "POST", undefined, config, key);
    } catch {
      console.warn("Warning: invitation task opt-out could not be sent.");
    }
    return;
  }
  let result: unknown;
  try {
    result = await signedJson(config.server, "/v1/einladungsauftraege", "GET", undefined, config, key);
  } catch (error) {
    if (error instanceof CliError && error.publicMessage === "Invitation is no longer valid.") return;
    const grund = error instanceof CliError && /server error \(\d{3}\)|HTTP \d{3}/.test(error.publicMessage)
      ? error.publicMessage.replace(/[^\x20-\x7e]/g, "?") : "Request to the Subspace server failed.";
    console.warn("Warning: invitation tasks could not be processed.");
    console.log(JSON.stringify({ invitation_tasks: "error", reason: grund }));
    return;
  }
  // wire format, keep
  if (!object(result) || !Array.isArray(result.auftraege)) {
    console.warn("Warning: invitation tasks could not be processed.");
    console.log(JSON.stringify({ invitation_tasks: "error", reason: "Invalid invitation task response." }));
    return;
  }
  const burn = async (token: string): Promise<void> => {
    if (!/^[A-Za-z0-9_-]{22}$/.test(token)) return;
    const localPath = statePath(config, "invitations", token);
    const local = await readState<InvitationState>(localPath).catch(() => undefined);
    if (local?.art !== "einladung" || local.token !== token) return;
    const response = await signedFetch(config.server, `/v1/einladung/${token}/verbrennen`, "POST", new Uint8Array(), config, key).catch(() => undefined);
    if (!response?.ok) return;
    await writeState(localPath, { ...local, zustand: "verbrannt" });
  };
  const validCandidates = result.auftraege /* wire format, keep */.filter((candidate): candidate is Record<string, unknown> => object(candidate)
    && typeof candidate.id === "string" && /^[a-f0-9]{32}$/.test(candidate.id)
    && typeof candidate.fuer === "string");
  const toBurn = validCandidates.filter((candidate) => candidate.zustand === "verworfen" && typeof candidate.token === "string").slice(0, 10);
  const toCreate = validCandidates.filter((candidate) => candidate.zustand === "offen").slice(0, 3);
  for (const candidate of [...toBurn, ...toCreate]) {
    if (candidate.zustand === "verworfen") {
      await burn(candidate.token as string);
      continue;
    }
    let outcome = "fehler";
    let createdToken: string | undefined;
    try {
      const invitedName = candidate.fuer as string;
      const invitation = await createInvitation(config, key, invitedName, fileURLToPath(import.meta.url));
      createdToken = invitation.token;
      const uploaded = await signedJson(config.server, `/v1/einladungsauftraege/${candidate.id}`, "POST", { token: invitation.token }, config, key);
      if (!object(uploaded) || uploaded.status !== "erzeugt") throw new CliError(2, "Invitation task upload failed.");
      outcome = "erzeugt";
      console.log(JSON.stringify({ invitation_tasks: { name: invitedName, browser_address: invitation.browserAddress, agent_line: invitation.agentLine } }));
    } catch {
      if (createdToken) await burn(createdToken);
      outcome = "fehler";
    }
    if (outcome !== "erzeugt") console.log(JSON.stringify({ invitation_task_id: candidate.id, for: candidate.fuer, result: "error" }));
  }
}


async function listInvitations(options: JoinOptions): Promise<void> {
  const config = await loadConfiguration(resolveConfigPath(singleOption(options, "--config")));
  const key = await loadKey(singleOption(options, "--key", true)!);
  const result = await signedJson(config.server, "/v1/einladungen", "GET", undefined, config, key);
  if (!object(result) || !Array.isArray(result.einladungen) || !Array.isArray(result.meldungen /* wire format, keep */)) throw new CliError(2, "Invalid response from the Subspace server."); // wire format, keep
  const root = stateRoot(config, "invitations");
  const names = await readdir(root).catch(() => []);
  const localInvitations = await Promise.all(names.filter((name) => /^[A-Za-z0-9_-]{22}\.json$/.test(name))
    .map((name) => readState<InvitationState>(join(root, name))));
  const seenTokens = new Set<string>();
  for (const local of localInvitations) {
    if (local.art !== "einladung") throw new CliError(3, "Invalid join state.");
    seenTokens.add(local.token);
    const remote = result.einladungen.find((item) => object(item) && item.token === local.token);
    let redemptionFingerprint: string | null = null;
    if (!object(remote)) {
      console.error(`ALARM Subspace server: Invitation ${shortToken(local.token)} is missing from the server list.`);
    } else if (remote.einloesung !== null && remote.einloesung !== undefined) { // wire format, keep
      if (!object(remote.einloesung) || typeof remote.einloesung.sig_J !== "string" || typeof remote.einloesung.box_J !== "string") {
        console.error(`ALARM Subspace server: Invalid redemption for ${shortToken(local.token)}.`);
      } else {
        try {
          redemptionFingerprint = fingerprint(bytes(remote.einloesung.sig_J, 32), bytes(remote.einloesung.box_J, 32));
          if (typeof remote.einloesung.fingerabdruck !== "string" || remote.einloesung.fingerabdruck !== redemptionFingerprint) { // wire format, keep
            console.error(`ALARM Subspace server: Redemption fingerprint does not match for ${shortToken(local.token)}.`);
          }
          if (typeof remote.einloesung.sig_s === "string" && typeof remote.einloesung.n_J === "string") {
            const protocol = {
              instanz: local.instanz, token: bytes(local.token, 16), name_J: local.fuer,
              sig_J: bytes(remote.einloesung.sig_J, 32), box_J: bytes(remote.einloesung.box_J, 32),
              c_I: bytes(local.c_I, 32), n_J: bytes(remote.einloesung.n_J, 32),
            };
            const valid = ed25519.verify(bytes(remote.einloesung.sig_s, 64), redemptionMessage(protocol), bytes(local.pk_s, 32));
            if (valid) console.log(`${local.fuer} redeemed your invitation. Fingerprint ${redemptionFingerprint}. Accept with: subspace confirm ${local.fuer}`);
            else console.error(`Warning: invalid redemption for ${local.fuer}; verify before confirming.`);
          }
        } catch {
          console.error(`ALARM Subspace server: Invalid redemption fingerprint for ${shortToken(local.token)}.`);
          redemptionFingerprint = null;
        }
      }
    }
    if (object(remote) && remote.zustand !== local.zustand && !(remote.zustand === "eingeloest" && local.zustand === "offen")) {
      console.error(`ALARM Subspace server: State for ${shortToken(local.token)} differs from local state.`);
    }
    const relayState = object(remote) ? englishJoinState(String(remote.zustand)) : null;
    const localState = object(remote) && remote.zustand === "abgelaufen" ? "abgelaufen" : local.zustand;
    console.log(JSON.stringify({ token: shortToken(local.token), for: local.fuer, state: englishJoinState(localState), relay_state: relayState, post_office_state: relayState, fingerprint: redemptionFingerprint })); // JSON output, keep (post_office_state)
  }
  for (const item of result.einladungen) {
    if (object(item) && typeof item.token === "string" && !seenTokens.has(item.token)) {
      console.error(`ALARM Subspace server: Unknown invitation ${shortToken(printableText(item.token))} in the server list.`);
    }
  }
  for (const warning of result.meldungen /* wire format, keep */) {
    if (object(warning) && warning.grund === "zweite_einloesung" && typeof warning.token === "string") {
      const invitation = localInvitations.find((candidate) => candidate.token === warning.token);
      if (invitation) console.error(`Warning: ${invitation.fuer} redeemed this invitation again; the confirmed contact remains unchanged.`);
    }
    console.error(printableText(`ALARM Subspace server: ${JSON.stringify(warning, (key, value: unknown) => key === "token" && typeof value === "string" ? shortToken(value) : value)}`));
  }
}

async function openInvitation(options: JoinOptions): Promise<void> {
  const configPath = resolveConfigPath(singleOption(options, "--config"));
  const config = await loadConfiguration(configPath);
  const key = await loadKey(singleOption(options, "--key", true)!);
  const requestedName = options.positionals[1];
  if (!requestedName) throw new CliError(1, "Name is required.");
  const result = await signedJson(config.server, "/v1/einladungen", "GET", undefined, config, key);
  if (!object(result) || !Array.isArray(result.einladungen)) throw new CliError(2, "Invalid response from the Subspace server.");
  const matching = result.einladungen.filter((item) => object(item) && item.fuer === requestedName && item.einladender === config.name);
  const remote = matching.find((item) => object(item) && item.zustand === "eingeloest") ?? matching.at(-1);
  if (!object(remote)) throw new CliError(3, "No matching local invitation found.");
  const token = typeof remote.token === "string" ? remote.token : "";
  bytes(token, 16);
  const localPath = statePath(config, "invitations", token);
  const lockPath = `${localPath}.lock`;
  const lock = await acquireLock(lockPath);
  try {
    const local = await readState<InvitationState>(localPath);
    if (local.art !== "einladung" || local.token !== token || local.fuer !== requestedName || local.instanz !== new URL(config.server).origin) {
      throw new CliError(3, "Local invitation state does not match the Subspace server.");
    }
    if (Buffer.compare(Buffer.from(bytes(local.sig_I, 32)), Buffer.from(key.signaturOeffentlich)) !== 0
      || Buffer.compare(Buffer.from(bytes(local.box_I, 32)), Buffer.from(key.boxOeffentlich)) !== 0) {
      throw new CliError(3, "Local invitation state belongs to a different key.");
    }
    if (local.zustand === "bestaetigt" || local.zustand === "verbrannt") throw new CliError(3, "ALARM: Invitation can no longer be opened.");
    if (!object(remote.einloesung)) throw new CliError(3, "Invitation has not been validly redeemed yet.");
    if (typeof remote.pk_s !== "string" || remote.pk_s !== local.pk_s) {
      await writeState(localPath, { ...local, zustand: "verbrannt" });
      const burned = await signedFetch(config.server, `/v1/einladung/${token}/verbrennen`, "POST", new Uint8Array(), config, key).catch(() => undefined);
      console.error("Warning: Subspace server invitation key does not match local state; invitation burned.");
      if (!burned?.ok) console.error("Warning: Subspace server could not confirm that the invitation was burned.");
      throw new CliError(3, "Invalid invitation secret key from the Subspace server.");
    }
    const redemption = remote.einloesung;
    // wire format, keep
    if (typeof redemption.sig_J !== "string" || typeof redemption.box_J !== "string" || typeof redemption.n_J !== "string" || typeof redemption.beleg !== "string" || typeof redemption.sig_s !== "string") {
      throw new CliError(3, "Invalid redemption receipt.");
    }
    const sigJ = bytes(redemption.sig_J, 32);
    const boxJ = bytes(redemption.box_J, 32);
    const nJ = bytes(redemption.n_J, 32);
    if (local.zustand === "geoeffnet" && (local.sig_J !== redemption.sig_J || local.box_J !== redemption.box_J || local.n_J !== redemption.n_J)) {
      throw new CliError(3, "ALARM: Redemption differs from the stored opening record.");
    }
    const proof = bytes(redemption.beleg /* wire format, keep */, 64);
    let valid = false;
    try {
      valid = ed25519.verify(proof, redemptionMessage({
        instanz: local.instanz, token: bytes(local.token, 16), name_J: local.fuer,
        sig_J: sigJ, box_J: boxJ, c_I: bytes(local.c_I, 32), n_J: nJ,
      }), sigJ);
    } catch { }
    if (!valid) throw new CliError(3, "Invalid redemption receipt.");
    let validSecret = false;
    try { validSecret = ed25519.verify(bytes(redemption.sig_s, 64), redemptionMessage({
      instanz: local.instanz, token: bytes(local.token, 16), name_J: local.fuer,
      sig_J: sigJ, box_J: boxJ, c_I: bytes(local.c_I, 32), n_J: nJ,
    }), bytes(local.pk_s, 32)); } catch { }
    if (!validSecret) {
      await writeState(localPath, { ...local, zustand: "verbrannt" });
      const burned = await signedFetch(config.server, `/v1/einladung/${token}/verbrennen`, "POST", new Uint8Array(), config, key).catch(() => undefined);
      console.error("Warning: invitation secret signature is invalid; invitation burned.");
      if (!burned?.ok) console.error("Warning: Subspace server could not confirm that the invitation was burned.");
      throw new CliError(3, "Invalid invitation secret signature.");
    }

    let opened = local;
    if (local.zustand === "geoeffnet") {
      const pending = await publicJson(`${local.instanz}/v1/einladung/${token}/oeffnung`);
      if (pending.response.status === 200 && object(pending.value)
        && typeof pending.value.n_I === "string" && typeof pending.value.unterschrift === "string") {
        const protocol = invitationTranscript(local);
        let matches = false;
        try {
          matches = pending.value.n_I === local.n_I
            && ed25519.verify(bytes(pending.value.unterschrift, 64), openingMessage(protocol), protocol.sig_I);
        } catch { }
        if (matches) {
      console.log("Invitation is already open.");
          return;
        }
      }
      if (pending.response.status !== 202 || !object(pending.value) || pending.value.grund !== "wartet") {
        throw new CliError(3, "ALARM: Subspace server opening state differs from the stored record.");
      }
    } else {
      opened = { ...local, zustand: "geoeffnet", sig_J: b64url(sigJ), box_J: b64url(boxJ), n_J: b64url(nJ) };
      await writeState(localPath, opened);
    }
    const protocol = invitationTranscript(opened);
    const signature = ed25519.sign(openingMessage(protocol), key.signaturPrivat);
    const answer = await signedJson(config.server, `/v1/einladung/${token}/oeffnung`, "POST", {
      n_I: opened.n_I, unterschrift: b64url(signature),
    }, config, key);
    if (!object(answer) || answer.grund !== "geoeffnet") throw new CliError(2, "Subspace server did not confirm the opening.");
    console.log("Invitation opened.");
  } finally {
    await lock.handle.close().catch(() => undefined);
    try {
      const current = await lstat(lockPath);
      if (current.dev === lock.dev && current.ino === lock.ino) await unlink(lockPath);
    } catch { }
  }
}

async function openLegacyInvitation(options: JoinOptions): Promise<void> {
  const name = options.positionals[1] ?? "<name>";
  throw new CliError(1, `open is no longer needed. Use: subspace confirm ${name}`);
}

async function readLinkFromStdin(options: JoinOptions): Promise<LinkData> {
  if (options.positionals[1] !== "-" && singleOption(options, "--link") !== "-") throw new CliError(1, "Use join - to read the agent line from standard input.");
  let raw: string;
  try { raw = (await text(process.stdin)).trim(); } catch { throw new CliError(1, "Could not read the invitation link."); }
  return parseLink(raw);
}

async function verifyAgentLine(link: LinkData): Promise<PublicInvitation> {
  const { response, value } = await publicJson(`${link.instanz}/v1/einladung/${link.token}`);
  if (!response.ok) throw responseError(response, value);
  if (!object(value)
    || typeof value.instanz !== "string" || typeof value.einladender !== "string"
    || typeof value.sig_I !== "string" || typeof value.box_I !== "string"
    || typeof value.fuer !== "string" || typeof value.c !== "string" || typeof value.ablauf !== "string" || typeof value.zustand !== "string") {
    throw new CliError(2, "Could not retrieve the invitation securely.");
  }
  if (typeof value.pk_s !== "string" || !link.secret) throw new CliError(3, "This invitation was made with an older version. Ask for a new one.");
  const invitation = value as unknown as PublicInvitation;
  const sigI = bytes(invitation.sig_I, 32);
  const boxI = bytes(invitation.box_I, 32);
  bytes(invitation.c, 32);
  const derived = deriveInvitationKey(bytes(link.secret, 32));
  if (Buffer.compare(Buffer.from(derived.publicKey), Buffer.from(bytes(invitation.pk_s, 32))) !== 0) throw new CliError(3, "Agent line does not match the invitation secret.");
  if (invitation.instanz !== link.instanz) throw new CliError(3, "Subspace server instance does not match the link.");
  if (fingerprintWithoutSpaces(fingerprint(sigI, boxI)) !== link.fp) throw new CliError(3, `Fingerprint does not match.${AGENT_LINE_FORMAT}`);
  return invitation;
}

async function readWaitSeconds(options: JoinOptions): Promise<number> {
  const value = singleOption(options, "--wait");
  if (value === undefined) return 600;
  if (!/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 3600) throw new CliError(1, "--wait must be between 1 and 3600 seconds.");
  return Number(value);
}

export function pollIntervalMs(value = process.env.SUBSPACE_JOIN_POLL_MS ?? process.env.AGENTENPOST_BEITRITT_ABFRAGE_MS): number { // legacy key, keep
  if (value === undefined || !/^\d+$/.test(value)) return 5000;
  const milliseconds = Number(value);
  return Number.isSafeInteger(milliseconds) && milliseconds >= 10 ? milliseconds : 5000;
}

async function waitForInvitationOpen(config: Configuration, local: JoinState, waitSeconds: number, configPath: string, keyPath: string): Promise<JoinState> {
  const deadline = Date.now() + waitSeconds * 1000;
  while (Date.now() <= deadline) {
    const { response, value } = await publicJson(`${local.instanz}/v1/einladung/${local.token}/oeffnung`);
    if (response.status === 200 && object(value) && typeof value.n_I === "string" && typeof value.unterschrift === "string") {
      const nI = bytes(value.n_I, 32);
      const signature = bytes(value.unterschrift, 64);
      const protocol: JoinTranscript = {
        instanz: local.instanz, token: bytes(local.token, 16), name_I: local.name_I, name_J: local.name_J,
        sig_I: bytes(local.sig_I, 32), box_I: bytes(local.box_I, 32), sig_J: bytes(local.sig_J, 32),
        box_J: bytes(local.box_J, 32), c_I: bytes(local.c_I, 32), n_J: bytes(local.n_J, 32), n_I: nI,
      };
      const secret = local.secret ? bytes(local.secret, 32) : undefined;
      if (!secret || Buffer.compare(Buffer.from(createJoinCommitment(local.instanz, protocol.token, local.name_I, protocol.sig_I, protocol.box_I, nI, deriveInvitationKey(secret).publicKey)), Buffer.from(protocol.c_I)) !== 0) {
        throw new CliError(3, "Invalid opening from the inviter.");
      }
      if (!ed25519.verify(signature, openingMessage(protocol), protocol.sig_I)) {
        throw new CliError(3, "ALARM: Invalid opening from the inviter. It does not match your key, so someone else may have redeemed this agent line. Tell the inviter not to confirm this join, and ask for a new invitation.");
      }
      const updated = { ...local, n_I: b64url(nI), zustand: "wartet_auf_code" as const };
      await writeState(statePath(config, "joins", local.token), updated);
      console.log(`Fingerprint I: ${fingerprintWithoutSpaces(fingerprint(protocol.sig_I, protocol.box_I)).slice(0, 8)}`);
      console.log("Waiting for the inviter to confirm.");
      return updated;
    }
    if (!response.ok && response.status !== 202) throw responseError(response, value);
    await sleep(Math.min(pollIntervalMs(), Math.max(0, deadline - Date.now())));
  }
  throw new CliError(2, "Timed out waiting for the invitation to be opened.");
}

function resumableError(error: CliError, pathConfig: string, pathKey: string): CliError {
  return new CliError(error.exitCode, `${error.publicMessage} Join state is saved; resume with subspace join --resume --config ${shellValue(pathConfig)} --key ${shellValue(pathKey)}.`);
}

async function sendRedemption(local: JoinState, key: KeyPair, path: string, pathConfig: string, pathKey: string): Promise<void> {
  const message = redemptionMessage({
    instanz: local.instanz, token: bytes(local.token, 16), name_J: local.name_J,
    sig_J: bytes(local.sig_J, 32), box_J: bytes(local.box_J, 32),
    c_I: bytes(local.c_I, 32), n_J: bytes(local.n_J, 32),
  });
  const proof = ed25519.sign(message, key.signaturPrivat);
  if (!local.secret) throw new CliError(3, "Join state is missing the invitation secret.");
  const secretSignature = ed25519.sign(message, deriveInvitationKey(bytes(local.secret, 32)).secretKey);
  let redeemed: { response: Response; value: unknown };
  try {
    redeemed = await publicJson(`${local.instanz}/v1/einladung/${local.token}/einloesen`, "POST", {
      sig_J: local.sig_J, box_J: local.box_J, n_J: local.n_J, beleg: b64url(proof), sig_s: b64url(secretSignature),
    });
  } catch (error) {
    const failure = error instanceof CliError ? error : new CliError(2, "Request to the Subspace server failed.");
    throw resumableError(failure, pathConfig, pathKey);
  }
  if (redeemed.response.status !== 202 || !object(redeemed.value) || redeemed.value.grund !== "angenommen") {
    if (redeemed.response.status >= 400 && redeemed.response.status <= 499) await unlink(path).catch(() => undefined);
    if (redeemed.response.status === 409 && object(redeemed.value) && redeemed.value.grund === "verbrannt") {
      throw new CliError(3, "Invitation has been used; request a new one.");
    }
    if (redeemed.response.status >= 500 || redeemed.response.status < 400) {
      const failure = redeemed.response.status >= 400
        ? responseError(redeemed.response, redeemed.value)
        : new CliError(2, "Invalid response from the Subspace server.");
      throw resumableError(failure, pathConfig, pathKey);
    }
    throw responseError(redeemed.response, redeemed.value);
  }
  console.log(`Fingerprint J: ${fingerprintWithoutSpaces(fingerprint(bytes(local.sig_J, 32), bytes(local.box_J, 32)))}`);
  console.log("Share this fingerprint with the inviter through a channel outside Subspace.");
}

async function verifyResumeAndRedeem(local: JoinState, key: KeyPair, path: string, pathConfig: string, pathKey: string): Promise<void> {
  let invitation: { response: Response; value: unknown };
  try {
    invitation = await publicJson(`${local.instanz}/v1/einladung/${local.token}`);
  } catch (error) {
    const failure = error instanceof CliError ? error : new CliError(2, "Request to the Subspace server failed.");
    throw resumableError(failure, pathConfig, pathKey);
  }
  if (invitation.response.status === 404) {
    await unlink(path).catch(() => undefined);
    throw new CliError(3, "Invitation has been used or expired; request a new one.");
  }
  if (invitation.response.status >= 500) {
    throw resumableError(responseError(invitation.response, invitation.value), pathConfig, pathKey);
  }
  if (invitation.response.status !== 200 || !object(invitation.value) || typeof invitation.value.zustand !== "string") {
    throw responseError(invitation.response, invitation.value);
  }
  const zustand = invitation.value.zustand;
  if (zustand === "offen") return sendRedemption(local, key, path, pathConfig, pathKey);
  if (zustand === "eingeloest" || zustand === "geoeffnet" || zustand === "bestaetigt") return;
  if (zustand === "verbrannt" || zustand === "abgelaufen") {
    await unlink(path).catch(() => undefined);
    throw new CliError(3, "Invitation has been used or expired; request a new one.");
  }
  throw new CliError(3, "Invitation cannot be resumed because the server returned an unsupported state.");
}

async function joinLink(options: JoinOptions): Promise<void> {
  let link: LinkData;
  const input = options.positionals[1];
  if (input === "-") link = await readLinkFromStdin(options);
  else if (input) link = parseLink(input);
  else if (singleOption(options, "--link") === "-") link = await readLinkFromStdin(options);
  else throw new CliError(1, "Provide the agent line or use join - to read it from standard input.");
  if (link.sha) {
    console.log(`Link checksum: ${link.sha}`);
    if (typeof process.argv[1] === "string" && /\.js$/i.test(process.argv[1])) {
      let ownSha: string;
      try { ownSha = createHash("sha256").update(await readFile(process.argv[1])).digest("hex"); }
      catch { throw new CliError(1, "Could not read the running script checksum."); }
      if (ownSha !== link.sha) throw new CliError(1, "Checksum does not match the running script.");
    } else console.error("Warning: Could not determine the running CLI checksum; the link checksum was not verified.");
  }
  const invitation = await verifyAgentLine(link);
  const ablauf = Date.parse(invitation.ablauf);
  if (!Number.isFinite(ablauf) || ablauf <= Date.now()) throw new CliError(3, "Invitation has expired.");
  const directory = singleOption(options, "--dir");
  const hasDirectory = directory !== undefined;
  const explicitConfigPath = singleOption(options, "--config");
  const configPath = hasDirectory ? explicitConfigPath : resolveConfigPath(explicitConfigPath, false);
  const keyPath = singleOption(options, "--key");
  if ((directory === undefined) === (configPath === undefined || keyPath === undefined)) {
    throw new CliError(1, "Specify either --dir or both --config and --key.");
  }
  if (invitation.fuer !== (directory ? invitation.fuer : (await loadConfiguration(configPath!)).name)) throw new CliError(1, "Invitation is for a different name.");
  let config: Configuration;
  let loadedKey: KeyPair;
  let pathConfig: string;
  let pathKey: string;
  if (hasDirectory) {
    await setup({ name: invitation.fuer, server: link.instanz, directory: directory });
    pathConfig = join(directory, "config.json");
    pathKey = join(directory, "key.json");
    config = await loadConfiguration(pathConfig);
    loadedKey = await loadKey(pathKey);
  } else {
    pathConfig = configPath!;
    pathKey = keyPath!;
    config = await loadConfiguration(pathConfig);
    loadedKey = await loadKey(pathKey);
    if (new URL(config.server).origin !== link.instanz) throw new CliError(1, "Invitation link and configured Subspace server do not match.");
  }
  const invitedKey = Object.hasOwn(config.trusted, invitation.einladender) ? config.trusted[invitation.einladender] : undefined;
  if (invitedKey && (Buffer.compare(Buffer.from(invitedKey.signature), Buffer.from(bytes(invitation.sig_I, 32))) !== 0
    || Buffer.compare(Buffer.from(invitedKey.box), Buffer.from(bytes(invitation.box_I, 32))) !== 0)) {
    throw new CliError(3, `Key conflict for ${printableText(invitation.einladender)}; the existing trusted key is unchanged.`);
  }
  const tokenBytes = bytes(link.token, 16);
  const nJ = randomBytes(32);
  const sigJ = loadedKey.signaturOeffentlich;
  const boxJ = loadedKey.boxOeffentlich;
  const cI = bytes(invitation.c, 32);
  const local: JoinState = {
    art: "beitritt", token: link.token, instanz: link.instanz,
    name_I: invitation.einladender, name_J: invitation.fuer,
    sig_I: b64url(bytes(invitation.sig_I, 32)), box_I: b64url(bytes(invitation.box_I, 32)), c_I: b64url(cI),
    sig_J: b64url(sigJ), box_J: b64url(boxJ), n_J: b64url(nJ), zustand: "eingeloest", secret: link.secret,
  };
  const root = stateRoot(config, "joins");
  await prepareStateDirectory(root);
  const path = statePath(config, "joins", link.token);
  try { await lstat(path); throw new CliError(3, "A join for this invitation is already in progress; use --resume."); }
  catch (error) {
    if (error instanceof CliError) throw error;
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new CliError(3, "Could not check join state.");
  }
  await writeState(path, local);
  await sendRedemption(local, loadedKey, path, pathConfig, pathKey);
  const opened = await waitForInvitationOpen(config, local, await readWaitSeconds(options), pathConfig, pathKey);
  await waitForConfirmation(config, loadedKey, pathConfig, opened, await readWaitSeconds(options));
}

async function waitForConfirmation(config: Configuration, key: KeyPair, configPath: string, local: JoinState, waitSeconds: number): Promise<void> {
  const deadline = Date.now() + waitSeconds * 1000;
  while (Date.now() <= deadline) {
    const { response, value } = await publicJson(`${local.instanz}/v1/einladung/${local.token}/bestaetigung`);
    if (response.status === 200 && object(value) && typeof value.unterschrift === "string") {
      const signature = bytes(value.unterschrift, 64);
      const protocol = joinProtocol(local);
      if (!ed25519.verify(signature, confirmationMessage(protocol), protocol.sig_I)) throw new CliError(3, "Invalid confirmation for this join.");
      await trust(configPath, local.name_I, protocol.sig_I, protocol.box_I);
      await writeState(statePath(config, "joins", local.token), { ...local, zustand: "bestaetigt" });
      console.log("Join confirmed.");
      return;
    }
    if (!response.ok && response.status !== 202) throw responseError(response, value);
    await sleep(Math.min(pollIntervalMs(), Math.max(0, deadline - Date.now())));
  }
  throw new CliError(2, "Wait for confirmation expired.");
}

async function completeJoin(options: JoinOptions): Promise<void> {
  if (options.flags.has("--resume")) {
    const configPath = resolveConfigPath(singleOption(options, "--config"));
    const config = await loadConfiguration(configPath);
    const key = await loadKey(singleOption(options, "--key", true)!);
    const prefix = singleOption(options, "--token");
    if (prefix !== undefined && !/^[A-Za-z0-9_-]{8}$/.test(prefix)) throw new CliError(1, "--token must contain the first 8 token characters.");
    const root = stateRoot(config, "joins");
    const names = await readdir(root).catch(() => []);
    const pending = (await Promise.all(names.filter((name) => /^[A-Za-z0-9_-]{22}\.json$/.test(name)).map((name) => readState<JoinState>(join(root, name)))))
      .filter((state) => state.art === "beitritt" && state.name_J === config.name
        && (state.zustand === "eingeloest" || state.zustand === "wartet_auf_code")
        && (prefix === undefined || state.token.startsWith(prefix)));
    if (pending.length === 0) throw new CliError(3, "No matching pending join found.");
    if (prefix === undefined && pending.length > 1) throw new CliError(3, "Multiple joins are pending; specify the first 8 characters with --token.");
    if (prefix !== undefined && pending.length > 1) throw new CliError(3, "--token prefix is not unique.");
    const local = pending[0]!;
    if (Buffer.compare(Buffer.from(bytes(local.sig_J, 32)), Buffer.from(key.signaturOeffentlich)) !== 0
      || Buffer.compare(Buffer.from(bytes(local.box_J, 32)), Buffer.from(key.boxOeffentlich)) !== 0) {
      throw new CliError(3, "Join state belongs to a different key.");
    }
    const waitSeconds = await readWaitSeconds(options);
    if (local.zustand === "eingeloest") {
      await verifyResumeAndRedeem(local, key, statePath(config, "joins", local.token), configPath, singleOption(options, "--key", true)!);
      const opened = await waitForInvitationOpen(config, local, waitSeconds, configPath, singleOption(options, "--key", true)!);
      return waitForConfirmation(config, key, configPath, opened, waitSeconds);
    }
    return waitForConfirmation(config, key, configPath, local, waitSeconds);
  }
  return joinLink(options);
}

async function confirm(options: JoinOptions): Promise<void> {
  const requestedName = options.positionals[1];
  if (!requestedName) throw new CliError(1, "Name is required.");
  const configPath = resolveConfigPath(singleOption(options, "--config"));
  const config = await loadConfiguration(configPath);
  const key = await loadKey(singleOption(options, "--key", true)!);
  const groupOption = singleOption(options, "--group");
  const groupsToInvite: { gid: string; name: string }[] = [];
  let groupsPath: string | undefined;
  if (groupOption !== undefined) {
    const names = groupOption.split(",");
    if (names.some((name) => !name)) throw new CliError(4, "--group must contain comma-separated group names.");
    groupsPath = groupsFilePath(config.storage);
    const groupsFile = await loadGroups(groupsPath);
    for (const groupName of names) {
      const entry = Object.entries(groupsFile.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      const parsed = entry && parseGroupState(entry[1].stand);
      if (!entry || !parsed) throw new CliError(4, `Group ${groupName} is not stored on this agent.`);
      if (parsed.stand.gruender.name !== config.name || !Buffer.from(parsed.stand.gruender.sig).equals(Buffer.from(key.signaturOeffentlich))) {
        throw new CliError(4, `Only the founder can invite to group ${groupName}.`);
      }
      if (parsed.stand.mitglieder.length >= MAX_GROUP_MEMBERS) throw new CliError(4, `Group ${groupName} is full (${MAX_GROUP_MEMBERS} members).`);
      groupsToInvite.push({ gid: entry[0], name: groupName });
    }
  }
  const prefix = singleOption(options, "--token");
  if (prefix !== undefined && !/^[A-Za-z0-9_-]{8}$/.test(prefix)) throw new CliError(1, "--token must contain the first 8 token characters.");
  await openInvitation(options);
  const directory = stateRoot(config, "invitations");
  const names = await readdir(directory).catch(() => []);
  const candidateNames = names.filter((name) => /^[A-Za-z0-9_-]{22}\.json$/.test(name));
  const opened: { state: InvitationState; path: string }[] = [];
  let confirmed: InvitationState | undefined;
  let burned: InvitationState | undefined;
  for (const name of candidateNames) {
    const path = join(directory, name);
    const candidate = await readState<InvitationState>(path);
    if (candidate.fuer !== requestedName || candidate.art !== "einladung") continue;
    if (candidate.zustand === "geoeffnet") opened.push({ state: candidate, path });
    if (candidate.zustand === "bestaetigt") confirmed = candidate;
    if (candidate.zustand === "verbrannt") burned = candidate;
  }
  if (opened.length === 0 && confirmed) throw new CliError(3, "Invitation has already been confirmed.");
  if (opened.length === 0 && burned) throw new CliError(3, "Invitation is locally burned.");
  if (opened.length === 0) throw new CliError(3, "No matching local invitation found.");
  if (prefix === undefined && opened.length > 1) throw new CliError(3, "Multiple invitations are open; specify the first 8 characters with --token.");
  const matching = prefix === undefined ? opened : opened.filter((entry) => entry.state.token.startsWith(prefix));
  if (matching.length === 0) throw new CliError(3, "No open invitation matches this --token prefix.");
  if (matching.length > 1) throw new CliError(3, "--token prefix is not unique.");
  const { state: local, path: localFile } = matching[0]!;
  if (local.zustand !== "geoeffnet") throw new CliError(3, "Invitation has not been opened yet.");
  if (local.instanz !== new URL(config.server).origin) throw new CliError(3, "Local invitation state belongs to a different Subspace server.");
  if (Buffer.compare(Buffer.from(bytes(local.sig_I, 32)), Buffer.from(key.signaturOeffentlich)) !== 0
    || Buffer.compare(Buffer.from(bytes(local.box_I, 32)), Buffer.from(key.boxOeffentlich)) !== 0) {
    throw new CliError(3, "Local invitation state belongs to a different key.");
  }
  if (local.fehler >= 3) {
    await writeState(localFile, { ...local, zustand: "verbrannt" });
    throw new CliError(3, "Invitation is locally burned.");
  }
  const protocol = invitationTranscript(local);
  await assertTrustWritable(configPath, requestedName, protocol.sig_J, protocol.box_J);

  const inviteGroupsAfterConfirmation = async (): Promise<void> => {
    if (!groupsPath || !groupsToInvite.length) return;
    const freshGroups = await loadGroups(groupsPath);
    const updatedConfig = await loadConfiguration(configPath);
    let failed = false;
    for (const requested of groupsToInvite) {
      const local = freshGroups.gruppen[requested.gid];
      const parsed = local && parseGroupState(local.stand);
      const groupName = parsed?.stand.name ?? requested.name;
      let reason: string | undefined;
      if (!local || !parsed) reason = `Group ${requested.name} is no longer stored on this agent.`;
      else if (parsed.stand.gruender.name !== config.name || !Buffer.from(parsed.stand.gruender.sig).equals(Buffer.from(key.signaturOeffentlich))) {
        reason = `Only the founder can invite to group ${groupName}.`;
      } else if (parsed.stand.mitglieder.length >= MAX_GROUP_MEMBERS) {
        reason = `Group ${groupName} is full (${MAX_GROUP_MEMBERS} members).`;
      }
      if (reason) {
        failed = true;
        console.error(`Warning: could not invite ${requestedName} to group ${groupName}: ${reason.replace(/\.$/, "")}. Run: subspace group invite ${groupName} ${requestedName}`);
        continue;
      }
      try {
        await queueOrSendGroupInvitation(updatedConfig, key, freshGroups, requested.gid, local!, requestedName, groupsPath);
      } catch (error) {
        failed = true;
        const cause = (error instanceof CliError ? error.publicMessage : error instanceof Error ? error.message : String(error)).replace(/\.$/, "");
        console.error(`Warning: could not invite ${requestedName} to group ${groupName}: ${cause}. Run: subspace group invite ${groupName} ${requestedName}`);
      }
    }
    if (failed) throw new CliError(4, "One or more group invitations could not be sent.");
  };

  const pinAndComplete = async (signature: Uint8Array): Promise<void> => {
    if (!ed25519.verify(signature, confirmationMessage(protocol), protocol.sig_I)) {
      throw new CliError(3, "Invalid confirmation for this join.");
    }
    await trust(configPath, requestedName, protocol.sig_J, protocol.box_J);
    await writeState(localFile, { ...local, zustand: "bestaetigt" });
    console.log("Join confirmed.");
    await inviteGroupsAfterConfirmation();
  };

  const fetchConfirmation = async (expected?: Uint8Array): Promise<boolean> => {
    const { response, value } = await publicJson(`${local.instanz}/v1/einladung/${local.token}/bestaetigung`);
    if (response.status === 200 && object(value) && typeof value.unterschrift === "string") {
      const signature = bytes(value.unterschrift, 64);
      if (expected && Buffer.compare(Buffer.from(signature), Buffer.from(expected)) !== 0) {
        throw new CliError(3, "Subspace server confirmation does not match the submitted signature.");
      }
      await pinAndComplete(signature);
      return true;
    }
    if (!response.ok && response.status !== 202) throw responseError(response, value);
    return false;
  };

  if (await fetchConfirmation()) return;
  const signature = ed25519.sign(confirmationMessage(protocol), key.signaturPrivat);
  try {
    const result = await signedJson(config.server, `/v1/einladung/${local.token}/bestaetigung`, "POST", { unterschrift: b64url(signature) }, config, key);
    if (!object(result) || result.grund !== "bestaetigt") throw new CliError(2, "Subspace server did not accept the confirmation.");
  } catch (error) {
    if (await fetchConfirmation(signature)) return;
    throw error;
  }
  await trust(configPath, requestedName, protocol.sig_J, protocol.box_J);
  await writeState(localFile, { ...local, zustand: "bestaetigt" });
  console.log("Join confirmed.");
  await inviteGroupsAfterConfirmation();
}

async function listContacts(options: JoinOptions): Promise<void> {
  const config = await loadConfiguration(resolveConfigPath(singleOption(options, "--config")));
  const keyPath = singleOption(options, "--key");
  const ownKey = keyPath ? await loadKey(keyPath) : undefined;
  const contacts = Object.entries(config.trusted).sort(([left], [right]) => left.localeCompare(right));
  const statuses = ownKey ? await getRecipientKeyStatuses(config, ownKey, contacts.map(([name]) => name)) : undefined;
  let alarm = false;
  let cannotVerify = false;
  let groupFile: Awaited<ReturnType<typeof loadGroups>> = { version: 1, gruppen: {} };
  try { groupFile = await loadGroups(groupsFilePath(config.storage)); }
  catch { console.error("Warning: Could not read groups.json; group contacts are unavailable."); }
  const directNames = new Set(contacts.map(([name]) => name));
  const groupContacts: Record<string, unknown>[] = [];
  for (const local of Object.values(groupFile.gruppen)) {
    const signed = parseGroupState(local.stand);
    if (!signed || local.syncFailed || local.gabelungen.length || Date.parse(signed.stand.gueltig_bis) <= Date.now()
      || (local.pending?.role === "invitee" && ["awaiting_code", "consent_sent"].includes(String(local.pending.state)))
      || !signed.stand.mitglieder.some((member) => member.name === config.name)) continue;
    for (const member of signed.stand.mitglieder) {
      if (member.name === config.name || directNames.has(member.name) || local.ausgetreten.includes(member.name)) continue;
      groupContacts.push({ name: member.name, group: signed.stand.name, founder: signed.stand.gruender.name, version: local.kopf.version, fingerprint: fingerprint(member.sig, member.box) });
    }
  }
  if (groupContacts.length) console.log("Direct");
  for (const [name, keys] of contacts) {
    const contact: Record<string, unknown> = { name, ssh: sshPublicKeyFingerprint(keys.signature, `${name}@subspace`), fingerprint: fingerprint(keys.signature, keys.box) };
    if (ownKey) {
      const status = statuses![name]!;
      contact.key = status.status === "nicht_pruefbar" || status.status === "alarm" ? { status: status.status === "nicht_pruefbar" ? "unverified" : "alarm" } : { status: englishContactKeyStatus(status.status), fingerprint: "fingerprint" in status ? status.fingerprint : undefined, hint: "hint" in status ? status.hint : undefined };
      if (status.status === "alarm") {
        alarm = true;
        console.error(`ALARM: Key from ${name} was revoked or forked.`);
      } else if (["gewechselt", "ohne_buergschaft", "vorlauf", "abgelaufen"].includes(status.status)) {
        alarm = true;
      } else if (status.status === "nicht_pruefbar") {
        cannotVerify = true;
      }
    }
    console.log(JSON.stringify(contact));
  }
  if (groupContacts.length) {
    console.log("Via group");
    for (const contact of groupContacts) console.log(JSON.stringify(contact));
  }
  console.log("Waiting for confirmation:");
  for (const kind of ["invitations", "joins"] as const) {
    const root = stateRoot(config, kind);
    const names = await readdir(root).catch(() => []);
    for (const name of names.filter((entry) => /^[A-Za-z0-9_-]{22}\.json$/.test(entry))) {
      if (kind === "invitations") {
        const state = await readState<InvitationState>(join(root, name));
        if (state.zustand === "geoeffnet") console.log(JSON.stringify({ name: state.fuer, state: "waiting for confirmation", token: shortToken(state.token) }));
      } else {
        const state = await readState<JoinState>(join(root, name));
        if (state.zustand === "wartet_auf_code") console.log(JSON.stringify({ name: state.name_I, state: "waiting for confirmation", token: shortToken(state.token) }));
      }
    }
  }
  if (!ownKey) console.log("Key status not checked; verify with --key.");
  if (alarm) process.exitCode = 4;
  else if (cannotVerify) process.exitCode = 2;
}

export async function runJoinCommand(command: string, options: JoinOptions): Promise<boolean> {
  if (!["invite", "invites", "open", "join", "confirm", "contacts"].includes(command)) return false;
  switch (command as CommandName) {
    case "invite": await inviteAgent(options); break;
    case "invites": await listInvitations(options); break;
    case "open": await openLegacyInvitation(options); break;
    case "join": await completeJoin(options); break;
    case "confirm": await confirm(options); break;
    case "contacts": await listContacts(options); break;
  }
  return true;
}
