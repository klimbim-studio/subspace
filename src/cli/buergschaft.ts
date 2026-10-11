import { access, chmod, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { createInterface } from "node:readline/promises";
import { signiereAnfrage } from "../anfrage.ts";
import { buergschaftJson, hashBuergschaft, parseBuergschaft, pruefeBuergschaft, signiereBuergschaft, type Buergschaft, type SignierteBuergschaft } from "../buergschaft.ts";
import { CliFehler, atomarSchreiben, ladeKonfiguration, ladeSchluessel, type Konfiguration } from "./gemeinsam.ts";
import { erzeugeSchluessel, fingerabdruck, type Schluessel } from "../siegel.ts";
import { sshFingerabdruck } from "../ssh.ts";
import { signiereWiderspruch, widerspruchJson } from "../widerspruch.ts";
import { wiederholeBeiDrosselung } from "./netz.ts";

const NULL_HASH = new Uint8Array(32);
const MAX_ALTER = 30 * 24 * 60 * 60 * 1000;

class PostamtStatusFehler extends CliFehler {}

function urlInstanz(config: Konfiguration): string {
  return new URL(config.postamt).origin;
}

async function signierterAufruf(config: Konfiguration, key: Schluessel, path: string, method = "GET", body = new Uint8Array(), redirect: RequestRedirect = "error"): Promise<Response> {
  const url = new URL(path, config.postamt);
  try {
    return await wiederholeBeiDrosselung(() => {
      const freshHeaders = signiereAnfrage({ methode: method, url, koerper: body, name: config.name, signaturPrivat: key.signaturPrivat });
      return fetch(url, { method, headers: freshHeaders, body: method === "GET" ? undefined : body, redirect, signal: AbortSignal.timeout(30_000) });
    });
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(2, "Post office request failed.");
  }
}

async function jsonAntwort(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new CliFehler(2, "Invalid response from the post office.");
  }
}

function decodeKey(value: unknown): Uint8Array | undefined {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return undefined;
  const bytes = Buffer.from(value, "base64");
  return bytes.length === 32 && bytes.toString("base64") === value ? new Uint8Array(bytes) : undefined;
}

interface SchluesselAbfrageEintrag {
  signatur: Uint8Array;
  buergschaften: SignierteBuergschaft[];
}

async function leseSchluesselAbfrage(config: Konfiguration, ownKey: Schluessel, names: string[]): Promise<Map<string, SchluesselAbfrageEintrag | { widerrufen: true }>> {
  if (names.length < 1 || names.length > 50) throw new CliFehler(2, "Could not verify the current contact key.");
  const body = new TextEncoder().encode(JSON.stringify({ namen: names }));
  const response = await signierterAufruf(config, ownKey, "/v1/schluessel/abfrage", "POST", body);
  if (!response.ok) throw new CliFehler(2, "Could not verify the current contact key.");
  const raw: unknown = await jsonAntwort(response);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new CliFehler(2, "Invalid key query response.");
  const requested = new Set(names);
  const entries = new Map<string, SchluesselAbfrageEintrag | { widerrufen: true }>();
  for (const [name, value] of Object.entries(raw)) {
    if (!requested.has(name)) throw new CliFehler(2, "Invalid key query response.");
    if (value && typeof value === "object" && !Array.isArray(value) && (value as Record<string, unknown>).widerrufen === true
      && Object.keys(value).length === 1) {
      entries.set(name, { widerrufen: true });
      continue;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new CliFehler(2, "Invalid key query response.");
    const fields = value as Record<string, unknown>;
    const signing = decodeKey(fields.signatur);
    if (!signing || !Array.isArray(fields.buergschaften) || Object.keys(fields).length !== 2) throw new CliFehler(2, "Invalid key query response.");
    const bonds = fields.buergschaften.map(parseBuergschaft);
    if (bonds.some((entry) => entry === undefined)) throw new CliFehler(2, "Invalid key authorizations.");
    entries.set(name, { signatur: signing, buergschaften: bonds as SignierteBuergschaft[] });
  }
  return entries;
}

function analysiere(config: Konfiguration, name: string, gepinnt: { signatur: Uint8Array; box: Uint8Array }, remote: Uint8Array, buergschaften: SignierteBuergschaft[], jetzt = new Date()):
  | { art: "gleich" }
  | { art: "nachfolger"; buergschaft: Buergschaft }
  | { art: "alarm" }
  | { art: "vorlauf"; buergschaft: Buergschaft }
  | { art: "abgelaufen"; buergschaft: Buergschaft }
  | { art: "ohne" } {
  const indexed = new Map(buergschaften.map(({ buergschaft }) => [buergschaft.folgenummer, buergschaft]));
  const strukturellGueltig = (bond: Buergschaft): boolean => {
    if (bond.folgenummer === 1) return Buffer.from(bond.vorgaenger_hash).equals(Buffer.from(NULL_HASH));
    const previous = indexed.get(bond.folgenummer - 1);
    return previous !== undefined && Buffer.from(bond.vorgaenger_hash).equals(Buffer.from(hashBuergschaft(previous)));
  };
  const direkt = buergschaften.map(({ buergschaft, unterschrift }) => ({ buergschaft, unterschrift }))
    .filter(({ buergschaft, unterschrift }) => buergschaft.buerge_name === name
      && buergschaft.instanz === urlInstanz(config)
      && Buffer.from(buergschaft.buerge_sig).equals(Buffer.from(gepinnt.signatur))
      && Buffer.from(buergschaft.buerge_box).equals(Buffer.from(gepinnt.box))
      && strukturellGueltig(buergschaft)
      && pruefeBuergschaft(buergschaft, unterschrift));
  if (direkt.some(({ buergschaft }) => buergschaft.art === "widerruf")) return { art: "alarm" };
  const successors = direkt.filter(({ buergschaft }) => buergschaft.art === "nachfolger");
  const widerrufeneNachfolger = buergschaften.some(({ buergschaft, unterschrift }) => {
    if (buergschaft.art !== "widerruf" || buergschaft.buerge_name !== name
      || buergschaft.instanz !== urlInstanz(config) || !strukturellGueltig(buergschaft)
      || !pruefeBuergschaft(buergschaft, unterschrift)) return false;
    return successors.some(({ buergschaft: successor }) => Buffer.from(successor.neu_sig).equals(Buffer.from(buergschaft.buerge_sig))
      && Buffer.from(buergschaft.neu_sig).equals(Buffer.from(buergschaft.buerge_sig))
      && Buffer.from(buergschaft.neu_box).equals(Buffer.from(buergschaft.buerge_box)));
  });
  if (widerrufeneNachfolger) return { art: "alarm" };
  const sequences = new Map<number, Set<string>>();
  for (const { buergschaft } of successors) {
    const identities = sequences.get(buergschaft.folgenummer) ?? new Set<string>();
    identities.add(`${Buffer.from(buergschaft.neu_sig).toString("hex")}:${Buffer.from(buergschaft.neu_box).toString("hex")}`);
    sequences.set(buergschaft.folgenummer, identities);
  }
  if ([...sequences.values()].some((keys) => keys.size > 1)) return { art: "alarm" };
  if (Buffer.from(remote).equals(Buffer.from(gepinnt.signatur))) return { art: "gleich" };
  const valid = successors.filter(({ buergschaft }) => {
    const age = jetzt.getTime() - Date.parse(buergschaft.zeit);
    return Number.isFinite(age) && age >= 0 && age <= MAX_ALTER
      && Buffer.from(buergschaft.neu_sig).equals(Buffer.from(remote));
  });
  if (valid.length > 0) return { art: "nachfolger", buergschaft: valid[0]!.buergschaft };
  const matching = successors.find(({ buergschaft }) => Buffer.from(buergschaft.neu_sig).equals(Buffer.from(remote)));
  if (matching) {
    const age = jetzt.getTime() - Date.parse(matching.buergschaft.zeit);
    if (age < 0 && age >= -5 * 60 * 1000) return { art: "vorlauf", buergschaft: matching.buergschaft };
    if (age > MAX_ALTER) return { art: "abgelaufen", buergschaft: matching.buergschaft };
  }
  return { art: "ohne" };
}

export type EmpfaengerSchluesselstand =
  | { stand: "aktuell" }
  | { stand: "gewechselt"; fingerabdruck: string; hinweis: string }
  | { stand: "ohne_buergschaft" }
  | { stand: "vorlauf"; zeit: string }
  | { stand: "abgelaufen" }
  | { stand: "alarm"; ursache?: unknown }
  | { stand: "nicht_pruefbar"; ursache: unknown };

function ermittleStandAusAbfrage(config: Konfiguration, name: string, pinned: { signatur: Uint8Array; box: Uint8Array }, entry: SchluesselAbfrageEintrag | { widerrufen: true } | undefined): EmpfaengerSchluesselstand {
  if (!entry) return { stand: "nicht_pruefbar", ursache: new CliFehler(2, "Could not verify the current contact key.") };
  if ("widerrufen" in entry) return { stand: "alarm" };
  const analysis = analysiere(config, name, pinned, entry.signatur, entry.buergschaften);
  if (analysis.art === "alarm") return { stand: "alarm" };
  if (Buffer.from(entry.signatur).equals(Buffer.from(pinned.signatur))) return { stand: "aktuell" };
  if (analysis.art === "nachfolger") {
    return {
      stand: "gewechselt",
      fingerabdruck: fingerabdruck(analysis.buergschaft.neu_sig, analysis.buergschaft.neu_box),
      hinweis: "Have a person verify the fingerprint before accepting the key.",
    };
  }
  if (analysis.art === "vorlauf") return { stand: "vorlauf", zeit: analysis.buergschaft.zeit };
  if (analysis.art === "abgelaufen") return { stand: "abgelaufen" };
  return { stand: "ohne_buergschaft" };
}

export async function ermittleEmpfaengerSchluesselstaende(config: Konfiguration, ownKey: Schluessel, names: string[]): Promise<Record<string, EmpfaengerSchluesselstand>> {
  const pinned = Object.fromEntries(names.map((name) => [name, Object.hasOwn(config.vertraut, name) ? config.vertraut[name] : undefined]));
  const validNames = names.filter((name) => pinned[name]);
  let entries = new Map<string, SchluesselAbfrageEintrag | { widerrufen: true }>();
  let failure: unknown;
  try {
    if (validNames.length > 0) entries = await leseSchluesselAbfrage(config, ownKey, validNames);
  } catch (error) {
    if (error instanceof CliFehler && error.publicMessage === "Invalid response from the post office.") throw error;
    failure = error;
  }
  const statuses: Record<string, EmpfaengerSchluesselstand> = {};
  for (const name of names) {
    const contact = pinned[name];
    statuses[name] = contact
      ? failure ? { stand: "nicht_pruefbar", ursache: failure } : ermittleStandAusAbfrage(config, name, contact, entries.get(name))
      : { stand: "nicht_pruefbar", ursache: new CliFehler(4, "Recipient is not in the trusted contacts.") };
  }
  return statuses;
}

export async function ermittleEmpfaengerSchluesselstand(config: Konfiguration, ownKey: Schluessel, name: string): Promise<EmpfaengerSchluesselstand> {
  const pinned = Object.hasOwn(config.vertraut, name) ? config.vertraut[name] : undefined;
  if (!pinned) return { stand: "nicht_pruefbar", ursache: new CliFehler(4, "Recipient is not in the trusted contacts.") };
  try {
    const entry = (await leseSchluesselAbfrage(config, ownKey, [name])).get(name);
    return ermittleStandAusAbfrage(config, name, pinned, entry);
  } catch (ursache) {
    return { stand: "nicht_pruefbar", ursache };
  }
}

export async function pruefeEmpfaengerSchluessel(config: Konfiguration, ownKey: Schluessel, names: string[]): Promise<Record<string, Uint8Array>> {
  const keys: Record<string, Uint8Array> = {};
  const statuses = await ermittleEmpfaengerSchluesselstaende(config, ownKey, names);
  for (const name of names) {
    const pinned = Object.hasOwn(config.vertraut, name) ? config.vertraut[name] : undefined;
    if (!pinned) throw new CliFehler(4, "Recipient is not in the trusted contacts.");
    const status = statuses[name]!;
    if (status.stand === "aktuell") {
      keys[name] = pinned.box;
      continue;
    }
    if (status.stand === "gewechselt") throw new CliFehler(4, `${name} rotated their key. The previous key authorization is valid. New fingerprint: ${status.fingerabdruck}. Sending is blocked until you run subspace accept ${name}.`);
    if (status.stand === "alarm") {
      if (status.ursache !== undefined) throw status.ursache;
      throw new CliFehler(4, `ALARM: Key from ${name} was revoked or forked. Sending is blocked.`);
    }
    if (status.stand === "vorlauf") throw new CliFehler(4, `Key authorization for ${name} is valid starting ${status.zeit}. Try again in a few minutes.`);
    if (status.stand === "abgelaufen") throw new CliFehler(4, `Key authorization for ${name} is older than 30 days. Only a new invitation with a code can restore trust.`);
    if (status.stand === "ohne_buergschaft") throw new CliFehler(4, `Key from ${name} changed without authorization. Only a new invitation with a code can restore trust.`);
    throw status.ursache;
  }
  return keys;
}

function baueBuergschaft(config: Konfiguration, key: Schluessel, next: Schluessel, art: Buergschaft["art"], folge: number, previousHash: Uint8Array): SignierteBuergschaft {
  const b: Buergschaft = {
    instanz: urlInstanz(config),
    art,
    buerge_name: config.name,
    buerge_sig: key.signaturOeffentlich,
    buerge_box: key.boxOeffentlich,
    neu_name: config.name,
    neu_sig: next.signaturOeffentlich,
    neu_box: next.boxOeffentlich,
    folgenummer: folge,
    vorgaenger_hash: previousHash,
    zeit: new Date().toISOString(),
  };
  return { buergschaft: b, unterschrift: signiereBuergschaft(b, key.signaturPrivat) };
}

async function naechsteFolge(config: Konfiguration, key: Schluessel): Promise<{ folge: number; hash: Uint8Array }> {
  const entry = (await leseSchluesselAbfrage(config, key, [config.name])).get(config.name);
  if (!entry || "widerrufen" in entry) throw new CliFehler(2, "Could not verify key authorizations.");
  const history = entry.buergschaften;
  const last = history.at(-1);
  return { folge: (last?.buergschaft.folgenummer ?? 0) + 1, hash: last ? hashBuergschaft(last.buergschaft) : NULL_HASH };
}

async function sendeBuergschaft(config: Konfiguration, key: Schluessel, signed: SignierteBuergschaft): Promise<void> {
  const body = new TextEncoder().encode(JSON.stringify(buergschaftJson(signed)));
  const response = await signierterAufruf(config, key, "/v1/schluessel/nachfolger", "POST", body, "manual");
  if (response.status === 409) {
    const detail = await jsonAntwort(response) as { grund?: string };
    if (detail?.grund === "verwaltet_per_liste") throw new PostamtStatusFehler(1, "Key is managed by a list; update it in the participant file.");
    if (detail?.grund === "zu_viele_buergschaften") throw new PostamtStatusFehler(2, "Too many key rotations for this name. Ask the operator for a new invitation.");
  }
  if (response.status === 403) {
    const detail = await jsonAntwort(response) as { grund?: string };
    if (detail?.grund === "fremder_schluessel") throw new PostamtStatusFehler(2, "The key in this authorization is not your current key.");
    if (detail?.grund === "fremder_buerge") throw new PostamtStatusFehler(2, "This authorization names a different authorizer.");
  }
  if (response.status >= 400 && response.status <= 499) throw new PostamtStatusFehler(2, "Post office rejected the key authorization.");
  if (!response.ok) throw new Error("Postamt-Antwort ist unklar.");
}

function schluesselJson(key: Schluessel): string {
  return JSON.stringify({
    signaturPrivat: Buffer.from(key.signaturPrivat).toString("base64"),
    signaturOeffentlich: Buffer.from(key.signaturOeffentlich).toString("base64"),
    boxPrivat: Buffer.from(key.boxPrivat).toString("base64"),
    boxOeffentlich: Buffer.from(key.boxOeffentlich).toString("base64"),
  }) + "\n";
}

async function istDateiVorhanden(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new CliFehler(1, "Could not validate the key file.");
  }
}

async function archiviereNeuenSchluessel(pendingPath: string): Promise<string> {
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
      throw new CliFehler(1, `New key remains at ${pendingPath}; could not complete the archive at ${archive}.`);
    }
  }
  throw new CliFehler(1, `New key remains at ${pendingPath}; could not create an unused discarded-key path.`);
}

async function schliesseTauschAb(keyPath: string, pendingPath: string, next: Schluessel): Promise<void> {
  const pendingName = basename(pendingPath);
  const archivePrefix = basename(keyPath) === "key.json" ? "key.old" : "schluessel.alt";
  const archive = join(dirname(keyPath), `${archivePrefix}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
  try {
    const oldFile = await readFile(keyPath);
    await writeFile(archive, oldFile, { flag: "wx", mode: 0o600 });
    await chmod(archive, 0o600);
    await atomarSchreiben(keyPath, schluesselJson(next));
    await rm(pendingPath);
  } catch {
    throw new CliFehler(1, `Post office saved the rotation, but local finalization failed. ${pendingName} was preserved.`);
  }
  console.log(`Key rotated. Old key archived at: ${archive}`);
}

export async function tauscheSchluessel(configPath: string, keyPath: string, fortsetzen = false): Promise<void> {
  if (keyPath === "-") throw new CliFehler(1, "Key rotation requires a file path; stdin is not supported.");
  const config = await ladeKonfiguration(configPath);
  const key = await ladeSchluessel(keyPath);
  const pendingPath = join(dirname(keyPath), basename(keyPath) === "key.json" ? "key.new.json" : "schluessel.neu.json");
  const pendingName = basename(pendingPath);
  const keyName = basename(keyPath);
  if (fortsetzen) {
    if (!await istDateiVorhanden(pendingPath)) throw new CliFehler(1, `No ${pendingName} is available to resume.`);
    const next = await ladeSchluessel(pendingPath);
    if (schluesselJson(key) === schluesselJson(next)) {
      await rm(pendingPath);
      return;
    }
    const nextCurrent = await leseSchluesselAbfrage(config, next, [config.name]).catch(() => undefined);
    const nextEntry = nextCurrent?.get(config.name);
    if (nextEntry && !("widerrufen" in nextEntry) && Buffer.from(nextEntry.signatur).equals(Buffer.from(next.signaturOeffentlich))) {
      await schliesseTauschAb(keyPath, pendingPath, next);
      return;
    }
    const oldCurrent = await leseSchluesselAbfrage(config, key, [config.name]).catch(() => undefined);
    const oldEntry = oldCurrent?.get(config.name);
    if (oldEntry && !("widerrufen" in oldEntry) && Buffer.from(oldEntry.signatur).equals(Buffer.from(key.signaturOeffentlich))) {
      const archived = await archiviereNeuenSchluessel(pendingPath);
      throw new CliFehler(2, `Rotation was not applied; ${keyName} is unchanged. New key saved to: ${archived}. If the rotation was saved despite the failed probe, copy the archived file back to ${keyPath}.`);
    }
    throw new CliFehler(2, `Rotation status is unclear. ${pendingName} was preserved; retry with subspace key rotate --resume.`);
  }
  if (await istDateiVorhanden(pendingPath)) throw new CliFehler(1, `${pendingName} already exists. Check the rotation with --resume.`);
  const next = erzeugeSchluessel();
  try {
    await writeFile(pendingPath, schluesselJson(next), { flag: "wx", mode: 0o600 });
    await chmod(pendingPath, 0o600);
  } catch {
    throw new CliFehler(1, `Could not safely save the new key at ${pendingPath}.`);
  }
  let bond: SignierteBuergschaft;
  try {
    const { folge, hash } = await naechsteFolge(config, key);
    bond = baueBuergschaft(config, key, next, "nachfolger", folge, hash);
  } catch (error) {
    const archived = await archiviereNeuenSchluessel(pendingPath);
    throw new CliFehler(error instanceof CliFehler ? error.exitCode : 2, `Rotation was not applied. New key saved to: ${archived}`);
  }
  try {
    await sendeBuergschaft(config, key, bond);
  } catch (error) {
    if (error instanceof PostamtStatusFehler) {
      const archived = await archiviereNeuenSchluessel(pendingPath);
      throw new CliFehler(error.exitCode, `${error.publicMessage} New key saved to: ${archived}`);
    }
    throw new CliFehler(2, `Post office response is unclear. Key remains in ${pendingName}; resume with subspace key rotate --resume --config PATH --key PATH.`);
  }
  await schliesseTauschAb(keyPath, pendingPath, next);
}

export async function widerrufeSchluessel(configPath: string, keyPath: string): Promise<void> {
  if (keyPath === "-") throw new CliFehler(1, "Key revocation requires a file path; stdin is not supported.");
  const config = await ladeKonfiguration(configPath);
  const key = await ladeSchluessel(keyPath);
  const { folge, hash } = await naechsteFolge(config, key);
  await sendeBuergschaft(config, key, baueBuergschaft(config, key, key, "widerruf", folge, hash));
  console.log("Key revoked.");
}

export async function widersprecheSchluessel(configPath: string, keyPath: string): Promise<void> {
  if (keyPath === "-") throw new CliFehler(1, "Key dispute requires a file path; stdin is not supported.");
  const config = await ladeKonfiguration(configPath);
  const key = await ladeSchluessel(keyPath);
  const value = {
    name: config.name,
    alter_schluessel: key.signaturOeffentlich,
    zeit: new Date().toISOString(),
  };
  const body = new TextEncoder().encode(JSON.stringify({
    ...widerspruchJson({ ...value, unterschrift: signiereWiderspruch(urlInstanz(config), value, key.signaturPrivat) }),
  }));
  let response: Response;
  try {
    const url = new URL("/v1/schluessel/widerspruch", config.postamt);
    response = await wiederholeBeiDrosselung(() => fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    }));
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(2, "Post office request failed.");
  }
  if (response.status === 403) throw new CliFehler(4, "Dispute rejected: no rotation with this key in the last 30 days.");
  if (response.status === 409) throw new CliFehler(4, "Dispute rejected: the name is already blocked.");
  if (!response.ok) throw new CliFehler(2, "Post office could not accept the dispute.");
  console.log(`Dispute filed. The name ${config.name} is blocked. A new invitation is required for access.`);
}

export async function annehmen(configPath: string, keyPath: string, name: string): Promise<void> {
  const config = await ladeKonfiguration(configPath);
  const ownKey = await ladeSchluessel(keyPath);
  const pinned = Object.hasOwn(config.vertraut, name) ? config.vertraut[name] : undefined;
  if (!pinned) throw new CliFehler(4, "Participant is not in the trusted contacts.");
  const entry = (await leseSchluesselAbfrage(config, ownKey, [name])).get(name);
  if (!entry) throw new CliFehler(2, "Could not verify the current contact key.");
  if ("widerrufen" in entry) throw new CliFehler(4, `ALARM: Key from ${name} was revoked or forked; acceptance denied.`);
  const analysis = analysiere(config, name, pinned, entry.signatur, entry.buergschaften);
  if (analysis.art === "gleich") throw new CliFehler(1, "This key is already current.");
  if (analysis.art === "alarm") throw new CliFehler(4, `ALARM: Key from ${name} was revoked or forked; acceptance denied.`);
  if (analysis.art === "vorlauf") throw new CliFehler(4, `Key authorization for ${name} is valid starting ${analysis.buergschaft.zeit}. Try again in a few minutes.`);
  if (analysis.art === "abgelaufen") throw new CliFehler(4, `Key authorization for ${name} is older than 30 days.`);
  if (analysis.art !== "nachfolger") throw new CliFehler(4, `Key from ${name} changed without authorization. Only a new invitation with a code can restore trust.`);
  const bond = analysis.buergschaft;
  console.log(sshFingerabdruck(bond.neu_sig, `${name}@subspace`));
  console.log(`Subspace fingerprint: ${fingerabdruck(bond.neu_sig, bond.neu_box)}`);
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await prompt.question("Accept key? Type yes: ")).trim().toLowerCase();
  prompt.close();
  if (answer !== "yes") throw new CliFehler(1, "Key acceptance cancelled.");
  const trusted = Object.fromEntries(Object.entries(config.vertraut).map(([contact, keys]) => [contact, {
    signature: Buffer.from(keys.signatur).toString("base64"), box: Buffer.from(keys.box).toString("base64"),
  }]));
  trusted[name] = { signature: Buffer.from(bond.neu_sig).toString("base64"), box: Buffer.from(bond.neu_box).toString("base64") };
  await atomarSchreiben(configPath, `${JSON.stringify({ name: config.name, post_office: config.postamt, storage: config.ablage, trusted, channels: config.kanaele }, null, 2)}\n`);
  console.log(`Accepted key from ${name}.`);
}
