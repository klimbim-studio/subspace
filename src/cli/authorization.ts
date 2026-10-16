import { access, chmod, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { signRequest } from "../request.ts";
import { authorizationJson, hashAuthorization, parseAuthorization, verifyAuthorization, signAuthorization, type Authorization, type SignedAuthorization } from "../authorization.ts";
import { CliError, atomicWrite, loadConfiguration, loadKey, saveConfiguration, type Configuration } from "./shared.ts";
import { createKey, fingerprint, type KeyPair } from "../seal.ts";
import { sshPublicKeyFingerprint } from "../ssh.ts";
import { signDispute, disputeJson } from "../dispute.ts";
import { retryDelay, retryOnRateLimit } from "./network.ts";

const NULL_HASH = new Uint8Array(32);
const MAX_AGE = 30 * 24 * 60 * 60 * 1000;

class ServerStatusError extends CliError {}

function instanceUrl(config: Configuration): string {
  return new URL(config.server).origin;
}

async function signedRequest(config: Configuration, key: KeyPair, path: string, method = "GET", body = new Uint8Array(), redirect: RequestRedirect = "error", retryGateway = true): Promise<Response> {
  const url = new URL(path, config.server);
  try {
    const request = () => {
      const freshHeaders = signRequest({ method: method, url, body: body, name: config.name, privateKey: key.signaturPrivat });
      return fetch(url, { method, headers: freshHeaders, body: method === "GET" ? undefined : body, redirect, signal: AbortSignal.timeout(30_000) });
    };
    return retryGateway ? await retryOnRateLimit(request) : await request();
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(2, "Request to the Subspace server failed.");
  }
}

async function jsonResponse(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new CliError(2, "Invalid response from the Subspace server.");
  }
}

function decodeKey(value: unknown): Uint8Array | undefined {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return undefined;
  const bytes = Buffer.from(value, "base64");
  return bytes.length === 32 && bytes.toString("base64") === value ? new Uint8Array(bytes) : undefined;
}

interface KeyQueryEntry {
  signatur: Uint8Array; // wire format, keep
  buergschaften: SignedAuthorization[]; // wire format, keep
}

async function queryKeys(config: Configuration, ownKey: KeyPair, names: string[]): Promise<Map<string, KeyQueryEntry | { widerrufen: true }>> {
  if (names.length < 1 || names.length > 50) throw new CliError(2, "Could not verify the current contact key.");
  // wire format, keep
  const body = new TextEncoder().encode(JSON.stringify({ namen: names }));
  let response = await signedRequest(config, ownKey, "/v1/schluessel/abfrage", "POST", body);
  const hasRetryableReason = async (candidate: Response): Promise<boolean> => {
    if (candidate.status !== 429) return false;
    try {
      const raw: unknown = await candidate.clone().json();
      return Boolean(raw && typeof raw === "object" && !Array.isArray(raw)
        && (Object.hasOwn(raw, "grund") || Object.hasOwn(raw, "reason")));
    } catch {
      return false;
    }
  };
  if ((response.status === 502 || response.status === 503 || response.status === 504) || await hasRetryableReason(response)) {
    await new Promise((resolve) => setTimeout(resolve, retryDelay(response, 0)));
    response = await signedRequest(config, ownKey, "/v1/schluessel/abfrage", "POST", body, "error", false);
  }
  if (!response.ok) {
    const retryable = response.status === 502 || response.status === 503 || response.status === 504 || response.status === 429;
    throw new CliError(2, `Could not verify the current contact key (HTTP ${response.status}).${retryable ? " Try again in a minute." : ""}`);
  }
  const raw: unknown = await jsonResponse(response);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new CliError(2, "Invalid key query response.");
  const requested = new Set(names);
  const entries = new Map<string, KeyQueryEntry | { widerrufen: true }>(); // wire format, keep
  for (const [name, value] of Object.entries(raw)) {
    if (!requested.has(name)) throw new CliError(2, "Invalid key query response.");
    if (value && typeof value === "object" && !Array.isArray(value) && (value as Record<string, unknown>).widerrufen === true
      && Object.keys(value).length === 1) {
      entries.set(name, { widerrufen: true });
      continue;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new CliError(2, "Invalid key query response.");
    const fields = value as Record<string, unknown>;
    const signing = decodeKey(fields.signatur);
    if (!signing || !Array.isArray(fields.buergschaften) || Object.keys(fields).length !== 2) throw new CliError(2, "Invalid key query response.");
    const bonds = fields.buergschaften.map(parseAuthorization);
    if (bonds.some((entry) => entry === undefined)) throw new CliError(2, "Invalid key authorizations.");
    entries.set(name, { signatur: signing, buergschaften: bonds as SignedAuthorization[] });
  }
  return entries;
}

function analyzeAuthorization(config: Configuration, name: string, pinned: { signature: Uint8Array; box: Uint8Array }, authorizations: SignedAuthorization[], remote: Uint8Array, now = new Date()):
  | { art: "gleich" }
  | { art: "nachfolger"; buergschaft: Authorization }
  | { art: "alarm" }
  | { art: "vorlauf"; buergschaft: Authorization }
  | { art: "abgelaufen"; buergschaft: Authorization }
  | { art: "ohne" } {
  const indexed = new Map(authorizations.map(({ buergschaft }) => [buergschaft.folgenummer, buergschaft]));
  const isStructurallyValid = (bond: Authorization): boolean => {
    if (bond.folgenummer === 1) return Buffer.from(bond.vorgaenger_hash).equals(Buffer.from(NULL_HASH));
    const previous = indexed.get(bond.folgenummer - 1);
    return previous !== undefined && Buffer.from(bond.vorgaenger_hash).equals(Buffer.from(hashAuthorization(previous)));
  };
  const direct = authorizations.map(({ buergschaft, unterschrift }) => ({ buergschaft, unterschrift }))
    .filter(({ buergschaft, unterschrift }) => buergschaft.buerge_name === name
      && buergschaft.instanz === instanceUrl(config)
      && Buffer.from(buergschaft.buerge_sig).equals(Buffer.from(pinned.signature))
      && Buffer.from(buergschaft.buerge_box).equals(Buffer.from(pinned.box))
      && isStructurallyValid(buergschaft)
      && verifyAuthorization(buergschaft, unterschrift));
  if (direct.some(({ buergschaft }) => buergschaft.art === "widerruf")) return { art: "alarm" };
  const successors = direct.filter(({ buergschaft }) => buergschaft.art === "nachfolger");
  const revokedSuccessor = authorizations.some(({ buergschaft, unterschrift }) => {
    if (buergschaft.art !== "widerruf" || buergschaft.buerge_name !== name
      || buergschaft.instanz !== instanceUrl(config) || !isStructurallyValid(buergschaft)
      || !verifyAuthorization(buergschaft, unterschrift)) return false;
    return successors.some(({ buergschaft: successor }) => Buffer.from(successor.neu_sig).equals(Buffer.from(buergschaft.buerge_sig))
      && Buffer.from(buergschaft.neu_sig).equals(Buffer.from(buergschaft.buerge_sig))
      && Buffer.from(buergschaft.neu_box).equals(Buffer.from(buergschaft.buerge_box)));
  });
  if (revokedSuccessor) return { art: "alarm" };
  const sequences = new Map<number, Set<string>>();
  for (const { buergschaft } of successors) {
    const identities = sequences.get(buergschaft.folgenummer) ?? new Set<string>();
    identities.add(`${Buffer.from(buergschaft.neu_sig).toString("hex")}:${Buffer.from(buergschaft.neu_box).toString("hex")}`);
    sequences.set(buergschaft.folgenummer, identities);
  }
  if ([...sequences.values()].some((keys) => keys.size > 1)) return { art: "alarm" };
  if (Buffer.from(remote).equals(Buffer.from(pinned.signature))) return { art: "gleich" };
  const valid = successors.filter(({ buergschaft }) => {
    const age = now.getTime() - Date.parse(buergschaft.zeit);
    return Number.isFinite(age) && age >= 0 && age <= MAX_AGE
      && Buffer.from(buergschaft.neu_sig).equals(Buffer.from(remote));
  });
  if (valid.length > 0) return { art: "nachfolger", buergschaft: valid[0]!.buergschaft };
  const matching = successors.find(({ buergschaft }) => Buffer.from(buergschaft.neu_sig).equals(Buffer.from(remote)));
  if (matching) {
    const age = now.getTime() - Date.parse(matching.buergschaft.zeit);
    if (age < 0 && age >= -5 * 60 * 1000) return { art: "vorlauf", buergschaft: matching.buergschaft };
    if (age > MAX_AGE) return { art: "abgelaufen", buergschaft: matching.buergschaft };
  }
  return { art: "ohne" };
}

export type RecipientKeyStatus =
  | { status: "aktuell" }
  | { status: "gewechselt"; fingerprint: string; hint: string }
  | { status: "ohne_buergschaft" }
  | { status: "vorlauf"; zeit: string }
  | { status: "abgelaufen" }
  | { status: "alarm"; cause?: unknown }
  | { status: "nicht_pruefbar"; cause: unknown };

function statusFromKeyQuery(config: Configuration, name: string, pinned: { signature: Uint8Array; box: Uint8Array }, entry: KeyQueryEntry | { widerrufen: true } | undefined): RecipientKeyStatus {
  if (!entry) return { status: "nicht_pruefbar", cause: new CliError(2, "Could not verify the current contact key.") };
  if ("widerrufen" in entry) return { status: "alarm" };
  const analysis = analyzeAuthorization(config, name, pinned, entry.buergschaften, entry.signatur);
  if (analysis.art === "alarm") return { status: "alarm" };
  if (Buffer.from(entry.signatur).equals(Buffer.from(pinned.signature))) return { status: "aktuell" };
  if (analysis.art === "nachfolger") {
    return {
      status: "gewechselt",
      fingerprint: fingerprint(analysis.buergschaft.neu_sig, analysis.buergschaft.neu_box),
      hint: "Have a person verify the fingerprint before accepting the key.",
    };
  }
  if (analysis.art === "vorlauf") return { status: "vorlauf", zeit: analysis.buergschaft.zeit };
  if (analysis.art === "abgelaufen") return { status: "abgelaufen" };
  return { status: "ohne_buergschaft" };
}

export async function getRecipientKeyStatuses(config: Configuration, ownKey: KeyPair, names: string[], groupKeys: Record<string, { signature: Uint8Array; box: Uint8Array }> = {}): Promise<Record<string, RecipientKeyStatus>> {
  const directPins = Object.fromEntries(names.map((name) => [name, Object.hasOwn(config.trusted, name) ? config.trusted[name] : undefined]));
  const pinned = Object.fromEntries(names.map((name) => [name, directPins[name] ?? (Object.hasOwn(groupKeys, name) ? groupKeys[name] : undefined)]));
  const validNames = names.filter((name) => pinned[name]);
  let entries = new Map<string, KeyQueryEntry | { widerrufen: true }>();
  let failure: unknown;
  try {
    if (validNames.length > 0) entries = await queryKeys(config, ownKey, validNames);
  } catch (error) {
    if (error instanceof CliError && error.publicMessage === "Invalid response from the Subspace server.") throw error;
    failure = error;
  }
  const statuses: Record<string, RecipientKeyStatus> = {};
  for (const name of names) {
    const contact = pinned[name];
    statuses[name] = contact
      ? failure ? { status: "nicht_pruefbar", cause: failure } : statusFromKeyQuery(config, name, contact, entries.get(name))
      : { status: "nicht_pruefbar", cause: new CliError(4, "Recipient is not in the trusted contacts.") };
  }
  return statuses;
}

export async function getRecipientKeyStatus(config: Configuration, ownKey: KeyPair, name: string): Promise<RecipientKeyStatus> {
  const trusted = config.trusted;
  const pinned = Object.hasOwn(trusted, name) ? trusted[name] : undefined;
  if (!pinned) return { status: "nicht_pruefbar", cause: new CliError(4, "Recipient is not in the trusted contacts.") };
  try {
    const entry = (await queryKeys(config, ownKey, [name])).get(name);
    return statusFromKeyQuery(config, name, pinned, entry);
  } catch (cause) {
    return { status: "nicht_pruefbar", cause };
  }
}

export async function verifyRecipientKeys(config: Configuration, ownKey: KeyPair, names: string[], groupKeys: Record<string, { signature: Uint8Array; box: Uint8Array }> = {}): Promise<Record<string, Uint8Array>> {
  const keys: Record<string, Uint8Array> = {};
  const statuses = await getRecipientKeyStatuses(config, ownKey, names, groupKeys);
  for (const name of names) {
    const hasDirect = Object.hasOwn(config.trusted, name);
    const hasGroup = Object.hasOwn(groupKeys, name);
    const pinned = hasDirect ? config.trusted[name] : hasGroup ? groupKeys[name] : undefined;
    const status = statuses[name]!;
    if (!pinned) {
      if (status.status === "nicht_pruefbar") throw status.cause;
      throw new CliError(4, Object.keys(groupKeys).length === 0
        ? "Recipient is not in the trusted contacts."
        : "Recipient is not a trusted contact or an approved group member.");
    }
    if (status.status === "aktuell") {
      keys[name] = pinned.box;
      continue;
    }
    if (status.status === "gewechselt") throw new CliError(4, `${name} rotated their key. The previous key authorization is valid. New fingerprint: ${status.fingerprint}. Sending is blocked until you run subspace accept ${name}.`);
    if (status.status === "alarm") {
      if (status.cause !== undefined) throw status.cause;
      throw new CliError(4, `ALARM: Key from ${name} was revoked or forked. Sending is blocked.`);
    }
    if (status.status === "vorlauf") throw new CliError(4, `Key authorization for ${name} is valid starting ${status.zeit}. Try again in a few minutes.`);
    if (status.status === "abgelaufen") throw new CliError(4, `Key authorization for ${name} is older than 30 days. Only a new invitation with a code can restore trust.`);
    if (status.status === "ohne_buergschaft") throw new CliError(4, `Key from ${name} changed without authorization. Only a new invitation with a code can restore trust.`);
    throw status.cause;
  }
  return keys;
}

function createAuthorization(config: Configuration, key: KeyPair, next: KeyPair, art: Authorization["art"], sequence: number, previousHash: Uint8Array): SignedAuthorization {
  const b: Authorization = {
    instanz: instanceUrl(config),
    art,
    buerge_name: config.name,
    buerge_sig: key.signaturOeffentlich,
    buerge_box: key.boxOeffentlich,
    neu_name: config.name,
    neu_sig: next.signaturOeffentlich,
    neu_box: next.boxOeffentlich,
    folgenummer: sequence,
    vorgaenger_hash: previousHash,
    zeit: new Date().toISOString(),
  };
  return { buergschaft: b, unterschrift: signAuthorization(b, key.signaturPrivat) };
}

async function nextSequence(config: Configuration, key: KeyPair): Promise<{ sequence: number; hash: Uint8Array }> {
  const entry = (await queryKeys(config, key, [config.name])).get(config.name);
  if (!entry || "widerrufen" in entry) throw new CliError(2, "Could not verify key authorizations.");
  const history = entry.buergschaften;
  const last = history.at(-1);
  return { sequence: (last?.buergschaft.folgenummer ?? 0) + 1, hash: last ? hashAuthorization(last.buergschaft) : NULL_HASH };
}

async function sendAuthorization(config: Configuration, key: KeyPair, signed: SignedAuthorization): Promise<void> {
  const body = new TextEncoder().encode(JSON.stringify(authorizationJson(signed)));
  const response = await signedRequest(config, key, "/v1/schluessel/nachfolger", "POST", body, "manual");
  if (response.status === 409) {
    const detail = await jsonResponse(response) as { grund?: string };
    if (detail?.grund === "verwaltet_per_liste") throw new ServerStatusError(1, "Key is managed by a list; update it in the participant file.");
    if (detail?.grund === "zu_viele_buergschaften") throw new ServerStatusError(2, "Too many key rotations for this name. Ask the operator for a new invitation.");
  }
  if (response.status === 403) {
    const detail = await jsonResponse(response) as { grund?: string };
    if (detail?.grund === "fremder_schluessel") throw new ServerStatusError(2, "The key in this authorization is not your current key.");
    if (detail?.grund === "fremder_buerge") throw new ServerStatusError(2, "This authorization names a different authorizer.");
  }
  if (response.status >= 400 && response.status <= 499) throw new ServerStatusError(2, "Subspace server rejected the key authorization.");
  if (!response.ok) throw new Error("Subspace server response is unclear.");
}

function keyJson(key: KeyPair): string {
  return JSON.stringify({
    signaturPrivat: Buffer.from(key.signaturPrivat).toString("base64"),
    signaturOeffentlich: Buffer.from(key.signaturOeffentlich).toString("base64"),
    boxPrivat: Buffer.from(key.boxPrivat).toString("base64"),
    boxOeffentlich: Buffer.from(key.boxOeffentlich).toString("base64"),
  }) + "\n";
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new CliError(1, "Could not validate the key file.");
  }
}

async function archiveNewKey(pendingPath: string): Promise<string> {
  const content = await readFile(pendingPath);
  const prefix = new Date().toISOString().replace(/[:.]/g, "-");
  for (let attempt = 0; attempt < 100; attempt++) {
    const suffix = attempt === 0 ? "" : `-${attempt}`;
    const archive = join(dirname(pendingPath), `${basename(pendingPath) === "key.new.json" ? "key.discarded" : "schluessel.verworfen"}-${prefix}${suffix}.json`);
    try {
      await writeFile(archive, content, { flag: "wx", mode: 0o600 });
      await chmod(archive, 0o600);
      await rm(pendingPath);
      return archive;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw new CliError(1, `New key remains at ${pendingPath}; could not complete the archive at ${archive}.`);
    }
  }
  throw new CliError(1, `New key remains at ${pendingPath}; could not create an unused discarded-key path.`);
}

async function finalizeRotation(keyPath: string, pendingPath: string, next: KeyPair): Promise<void> {
  const pendingName = basename(pendingPath);
  const archivePrefix = basename(keyPath) === "key.json" ? "key.old" : "schluessel.alt";
  const archive = join(dirname(keyPath), `${archivePrefix}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  try {
    const oldFile = await readFile(keyPath);
    await writeFile(archive, oldFile, { flag: "wx", mode: 0o600 });
    await chmod(archive, 0o600);
    await atomicWrite(keyPath, keyJson(next));
    await rm(pendingPath);
  } catch {
    throw new CliError(1, `Subspace server saved the rotation, but local finalization failed. ${pendingName} was preserved.`);
  }
  console.log(`Key rotated. Old key archived at: ${archive}`);
}

export async function rotateKey(configPath: string, keyPath: string, resume = false): Promise<void> {
  if (keyPath === "-") throw new CliError(1, "Key rotation requires a file path; stdin is not supported.");
  const config = await loadConfiguration(configPath);
  const key = await loadKey(keyPath);
  const pendingPath = join(dirname(keyPath), basename(keyPath) === "key.json" ? "key.new.json" : "schluessel.neu.json");
  const pendingName = basename(pendingPath);
  const keyName = basename(keyPath);
  if (resume) {
    if (!await fileExists(pendingPath)) throw new CliError(1, `No ${pendingName} is available to resume.`);
    const next = await loadKey(pendingPath);
    if (keyJson(key) === keyJson(next)) {
      await rm(pendingPath);
      return;
    }
    const nextCurrent = await queryKeys(config, next, [config.name]).catch(() => undefined);
    const nextEntry = nextCurrent?.get(config.name);
    if (nextEntry && !("widerrufen" in nextEntry) && Buffer.from(nextEntry.signatur).equals(Buffer.from(next.signaturOeffentlich))) {
      await finalizeRotation(keyPath, pendingPath, next);
      return;
    }
    const oldCurrent = await queryKeys(config, key, [config.name]).catch(() => undefined);
    const oldEntry = oldCurrent?.get(config.name);
    if (oldEntry && !("widerrufen" in oldEntry) && Buffer.from(oldEntry.signatur).equals(Buffer.from(key.signaturOeffentlich))) {
      const archived = await archiveNewKey(pendingPath);
      throw new CliError(2, `Rotation was not applied; ${keyName} is unchanged. New key saved to: ${archived}. If the rotation was saved despite the failed probe, copy the archived file back to ${keyPath}.`);
    }
    throw new CliError(2, `Rotation status is unclear. ${pendingName} was preserved; retry with subspace key rotate --resume.`);
  }
  if (await fileExists(pendingPath)) throw new CliError(1, `${pendingName} already exists. Check the rotation with --resume.`);
  const next = createKey();
  try {
    await writeFile(pendingPath, keyJson(next), { flag: "wx", mode: 0o600 });
    await chmod(pendingPath, 0o600);
  } catch {
    throw new CliError(1, `Could not safely save the new key at ${pendingPath}.`);
  }
  let bond: SignedAuthorization;
  try {
    const { sequence, hash } = await nextSequence(config, key);
    bond = createAuthorization(config, key, next, "nachfolger", sequence, hash);
  } catch (error) {
    const archived = await archiveNewKey(pendingPath);
    throw new CliError(error instanceof CliError ? error.exitCode : 2, `Rotation was not applied. New key saved to: ${archived}`);
  }
  try {
    await sendAuthorization(config, key, bond);
  } catch (error) {
    if (error instanceof ServerStatusError) {
      const archived = await archiveNewKey(pendingPath);
      throw new CliError(error.exitCode, `${error.publicMessage} New key saved to: ${archived}`);
    }
    throw new CliError(2, `Subspace server response is unclear. Key remains in ${pendingName}; resume with subspace key rotate --resume --config PATH --key PATH.`);
  }
  await finalizeRotation(keyPath, pendingPath, next);
}

export async function revokeKey(configPath: string, keyPath: string): Promise<void> {
  if (keyPath === "-") throw new CliError(1, "Key revocation requires a file path; stdin is not supported.");
  const config = await loadConfiguration(configPath);
  const key = await loadKey(keyPath);
  const { sequence, hash } = await nextSequence(config, key);
  await sendAuthorization(config, key, createAuthorization(config, key, key, "widerruf", sequence, hash));
  console.log("Key revoked.");
}

export async function disputeKey(configPath: string, keyPath: string): Promise<void> {
  if (keyPath === "-") throw new CliError(1, "Key dispute requires a file path; stdin is not supported.");
  const config = await loadConfiguration(configPath);
  const key = await loadKey(keyPath);
  const value = {
    name: config.name,
    alter_schluessel: key.signaturOeffentlich,
    zeit: new Date().toISOString(),
  };
  const body = new TextEncoder().encode(JSON.stringify({
    ...disputeJson({ ...value, unterschrift: signDispute(instanceUrl(config), value, key.signaturPrivat) }),
  }));
  let response: Response;
  try {
    const url = new URL("/v1/schluessel/widerspruch", config.server);
    response = await retryOnRateLimit(() => fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    }));
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(2, "Request to the Subspace server failed.");
  }
  if (response.status === 403) throw new CliError(4, "Dispute rejected: no rotation with this key in the last 30 days.");
  if (response.status === 409) throw new CliError(4, "Dispute rejected: the name is already blocked.");
  if (!response.ok) throw new CliError(2, "Subspace server could not accept the dispute.");
  console.log(`Dispute filed. The name ${config.name} is blocked. A new invitation is required for access.`);
}

export async function acceptKey(configPath: string, keyPath: string, name: string): Promise<void> {
  const config = await loadConfiguration(configPath);
  const ownKey = await loadKey(keyPath);
  const pinned = Object.hasOwn(config.trusted, name) ? config.trusted[name] : undefined;
  if (!pinned) throw new CliError(4, "Participant is not in the trusted contacts.");
  const entry = (await queryKeys(config, ownKey, [name])).get(name);
  if (!entry) throw new CliError(2, "Could not verify the current contact key.");
  if ("widerrufen" in entry) throw new CliError(4, `ALARM: Key from ${name} was revoked or forked; acceptance denied.`);
  const analysis = analyzeAuthorization(config, name, pinned, entry.buergschaften, entry.signatur);
  if (analysis.art === "gleich") throw new CliError(1, "This key is already current.");
  if (analysis.art === "alarm") throw new CliError(4, `ALARM: Key from ${name} was revoked or forked; acceptance denied.`);
  if (analysis.art === "vorlauf") throw new CliError(4, `Key authorization for ${name} is valid starting ${analysis.buergschaft.zeit}. Try again in a few minutes.`);
  if (analysis.art === "abgelaufen") throw new CliError(4, `Key authorization for ${name} is older than 30 days.`);
  if (analysis.art !== "nachfolger") throw new CliError(4, `Key from ${name} changed without authorization. Only a new invitation with a code can restore trust.`);
  const bond = analysis.buergschaft;
  console.log(sshPublicKeyFingerprint(bond.neu_sig, `${name}@subspace`));
  console.log(`Subspace fingerprint: ${fingerprint(bond.neu_sig, bond.neu_box)}`);
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await prompt.question("Accept key? Type yes: ")).trim().toLowerCase();
  prompt.close();
  if (answer !== "yes") throw new CliError(1, "Key acceptance cancelled.");
  await saveConfiguration(configPath, {
    ...config,
    trusted: { ...config.trusted, [name]: { signature: bond.neu_sig, box: bond.neu_box } },
  }, 2);
  console.log(`Accepted key from ${name}.`);
}
