import { access, readFile, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { createKey, fingerprint, readEnvelopeHeader, openEnvelope, sealEnvelope, type OpenError, type KeyPair } from "../seal.ts";
import { sshPublicKeyFingerprint, sshPublicKey } from "../ssh.ts";
import { detectType, stripMetadata } from "../attachment.ts";
import type { Envelope } from "../envelope.ts";
import { submitMessage, fetchMessage, listMailbox, acknowledge, status, submitGroupState, fetchGroupHistory, listGroups, submitGroupLeave, fetchGroupLeaves, type ClientError, type MailboxEntry } from "../client.ts";
import {
  atomicWrite,
  CliError,
  loadConfiguration,
  loadKey,
  resolveConfigPath,
  readSeen,
  publicKeyJson,
  writeKey,
  ensureStorage,
  saveSeen,
  type Configuration,
} from "./shared.ts";
import { setup as createSetup, trust as trustContact } from "./setup.ts";
import { acceptKey, verifyRecipientKeys, rotateKey, disputeKey, revokeKey } from "./authorization.ts";
import { processInvitationTasks, runJoinCommand } from "./join.ts";
import { runAccountCommand } from "./account.ts";
import { connect as connectAgent } from "./connect.ts";
import { groupAdmissionCode, createGroupNonce, hashGroupLeave, hashGroupState, hashGroupConsent, parseGroupLeave, parseGroupState, verifyGroupLeave, verifyGroupInvitation, verifyGroupConsent, verifyGroupState, validateRevision, createGroupId, signGroupLeave, signGroupInvitation, signGroupConsent, signGroupState, groupStateJson, MAX_GROUP_MEMBERS, type GroupInvitation, type SignedGroupState } from "../group.ts";
import { groupsFilePath, loadGroups, saveGroups, setGroupState, requireActiveHead } from "./group.ts";
import { GROUP_INVITATION_TTL_MS, GroupInvitationSendError, invitationJson, protocolText, queueOrSendGroupInvitation, sendGroupInvitation, sendGroupProtocol, sendNextQueuedGroupInvitation } from "./group-invitations.ts";

interface CliOptions {
  positionals: string[];
  values: Map<string, string[]>;
  flags: Set<string>;
}

// Names of the retired German command-line surface. They are rejected, never executed.
const retiredCommands = new Set(["annehmen", "oeffentlich", "senden", "einladen", "einladungen", "oeffnen", "kontakte", "konto", "verbinden", "hilfe", "schluessel"]); // legacy alias, keep
const retiredOptions = new Set(["konfig", "schluessel", "ordner", "laufzeit", "an", "kanal", "art", "betreff", "text-datei", "bezug", "anhang", "ausgeloest-von", "fuer", "skript", "warten", "fortsetzen", "signatur", "fingerabdruck", "ausgabe"]); // legacy alias, keep
// Spellings from older instructions that still work: they point at the English names.
const legacyCommandAliases = new Map([["gruppe", "group"]]); // legacy alias, keep
const legacyOptionAliases = new Map([["--gruppe", "--group"]]); // legacy alias, keep
// help with a command name has always accepted the retired spelling of that command.
const legacyHelpAliases = new Map([ // legacy alias, keep
  ["annehmen", "accept"], ["oeffentlich", "public"], ["senden", "send"], ["einladen", "invite"], ["einladungen", "invites"],
  ["oeffnen", "open"], ["kontakte", "contacts"], ["konto", "account"], ["hilfe", "help"], ["gruppe", "group"],
]);

function parseOptions(args: string[]): CliOptions {
  let firstCommand = 0;
  while (firstCommand < args.length && args[firstCommand]!.startsWith("--")) {
    if (args[firstCommand] !== "--help" && args[firstCommand] !== "--resume") firstCommand += 1;
    firstCommand += 1;
  }
  if (args[firstCommand] && retiredCommands.has(args[firstCommand]!)) throw new CliError(1, "German command names are no longer supported. Use subspace help.");
  const retiredFlag = args.find((arg) => arg.startsWith("--") && retiredOptions.has(arg.slice(2)));
  if (retiredFlag) throw new CliError(1, "This option is no longer supported. Use subspace help.");
  args = args.map((arg) => arg.startsWith("--") ? legacyOptionAliases.get(arg) ?? arg : arg);
  let commandIndex = 0;
  while (commandIndex < args.length && args[commandIndex]!.startsWith("--")) {
    if (args[commandIndex] !== "--help" && args[commandIndex] !== "--resume") commandIndex += 1;
    commandIndex += 1;
  }
  const commandName = args[commandIndex];
  if (commandName && commandName !== "key") args[commandIndex] = legacyCommandAliases.get(commandName) ?? commandName;
  // The command line value is English; the wire value of the envelope is set when the envelope is built.
  const kindIndex = args.indexOf("--kind");
  if (kindIndex >= 0 && args[kindIndex + 1] === "anfrage") throw new CliError(1, "Invalid message kind. Use info or request."); // wire format, keep
  const positionalArgs: string[] = [];
  const values = new Map<string, string[]>();
  const switches = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("--")) {
      positionalArgs.push(arg);
      continue;
    }
    if (arg === "--help" || arg === "--resume" || arg === "--skip-invitation-tasks" || arg === "--now") {
      switches.add(arg);
      continue;
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) throw new CliError(1, `Missing value for ${arg}.`);
    const items = values.get(arg) ?? [];
    items.push(value);
    values.set(arg, items);
    index += 1;
  }
  return { positionals: positionalArgs, values: values, flags: switches };
}

function singleOption(cliOptions: CliOptions, flag: string, required = false): string | undefined {
  const values = cliOptions.values.get(flag) ?? [];
  if (values.length > 1 || (required && values.length !== 1)) throw new CliError(1, `Missing or repeated option: ${flag}.`);
  return values[0];
}

function globalConfigPath(options: CliOptions): string {
  return resolveConfigPath(singleOption(options, "--config"));
}

async function config(options: CliOptions): Promise<Configuration> {
  return loadConfiguration(globalConfigPath(options));
}

async function key(options: CliOptions) {
  return loadKey(singleOption(options, "--key", true)!);
}

async function defaultKeyPath(configPath: string): Promise<string> {
  const directory = dirname(configPath);
  for (const name of ["key.json", "schluessel.json"]) {
    const candidate = join(directory, name);
    try { await access(candidate); return candidate; } catch { /* try the next supported layout */ }
  }
  return join(directory, "key.json");
}

function isClientError<T extends object>(value: T | ClientError): value is ClientError {
  return typeof value === "object" && value !== null && "grund" in value;
}

function printPublicKeys(generated: KeyPair, comment: string): void {
  const json = publicKeyJson(generated);
  console.log(json);
  console.log(sshPublicKey(generated.signaturOeffentlich, comment));
  console.log(sshPublicKeyFingerprint(generated.signaturOeffentlich, comment));
  console.log(`Subspace fingerprint: ${fingerprint(generated.signaturOeffentlich, generated.boxOeffentlich)}`);
}

export async function generateKey(options: CliOptions): Promise<void> {
  const output = singleOption(options, "--out", true)!;
  const generated = createKey();
  await writeKey(output, generated);
  printPublicKeys(generated, "subspace");
}

export async function publicKey(options: CliOptions): Promise<void> {
  const generated = await key(options);
  const name = singleOption(options, "--name");
  printPublicKeys(generated, name ? `${name}@subspace` : "subspace");
}

function detectSecretPattern(text: string): string | undefined {
  const patterns: [RegExp, string][] = [
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "privater_schluessel"],
    [/ghp_[A-Za-z0-9]{20,}/, "github_token"],
    [/glpat-[A-Za-z0-9_-]{20}/, "gitlab_token"],
    [/sk-[A-Za-z0-9]{20,}/, "api_token"],
    [/AKIA[0-9A-Z]{16}/, "aws_schluessel"],
    [/xox[baprs]-[A-Za-z0-9-]{10,}/, "chat_token"],
    [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, "jwt"],
  ];
  for (const [pattern, label] of patterns) if (pattern.test(text)) return label;
  return undefined;
}

async function readFileText(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    throw new CliError(1, "Could not read the input file.");
  }
}

async function send(options: CliOptions): Promise<void> {
  const configuration = await config(options);
  const signingKey = await key(options);
  const triggeredByValue = singleOption(options, "--triggered-by")
    ?? (process.env.SUBSPACE_TRIGGERED_BY !== undefined
      ? process.env.SUBSPACE_TRIGGERED_BY || undefined
      // legacy key, keep
      : process.env.CARTRIDGE_TRIGGERED_BY || process.env.CARTRIDGE_AUSGELOEST_VON || undefined); // legacy key, keep
  let triggeredBy: Envelope["ausgeloest_von"];
  if (triggeredByValue !== undefined) {
    const matches = /^([a-z][a-z0-9-]{1,31}):([0-9a-f]{32})$/.exec(triggeredByValue);
    if (!matches) throw new CliError(1, "--triggered-by must use <name>:<envelope_id>.");
    triggeredBy = { von: matches[1]!, huelle_id: matches[2]! };
  }
  const kindValue = singleOption(options, "--kind", true);
  const subject = singleOption(options, "--subject", true)!;
  const textPath = singleOption(options, "--text-file", true)!;
  const lifetimeValue = singleOption(options, "--lifetime");
  const lifetime = lifetimeValue === undefined ? 7 : /^(?:[1-9]|[12][0-9]|30)$/.test(lifetimeValue) ? Number(lifetimeValue) : 0;
  if (lifetime < 1 || lifetime > 30) throw new CliError(1, "--lifetime must be an integer from 1 to 30.");
  if (kindValue !== "info" && kindValue !== "request") throw new CliError(1, "Invalid message kind.");
  const messageKind = kindValue === "request" ? "anfrage" : "info"; // wire format, keep
  const text = await readFileText(textPath);
  const attachmentPaths = options.values.get("--attach") ?? [];
  if (attachmentPaths.length > 10) throw new CliError(1, "Too many attachments.");
  const attachments = await Promise.all(attachmentPaths.map(async (path) => {
    let bytes: Uint8Array;
    try { bytes = new Uint8Array(await readFile(path)); } catch { throw new CliError(1, "Could not read the attachment."); }
    const detected = detectType(basename(path), bytes);
    if (!detected.ok) throw new CliError(5, `Attachment rejected: ${detected.reason}`);
    if (detected.mediaType.startsWith("text/")) {
      const blocked = detectSecretPattern(Buffer.from(bytes).toString("utf8"));
      if (blocked) throw new CliError(5, `Content blocked: ${blocked}`);
    }
    bytes = stripMetadata(detected.mediaType, bytes);
    return { name: basename(path), typ: detected.mediaType, inhalt: Buffer.from(bytes).toString("base64") };
  }));
  for (const value of [subject, text]) {
    const blocked = detectSecretPattern(value);
    if (blocked) throw new CliError(5, `Content blocked: ${blocked}`);
  }

  const direct = singleOption(options, "--to");
  const channel = singleOption(options, "--channel");
  const groupName = singleOption(options, "--group");
  if ([direct, channel, groupName].filter((value) => value !== undefined).length !== 1) throw new CliError(1, "Specify exactly one of --to, --channel or --group.");
  let recipients: string[];
  let groupRef: Envelope["gruppe"] | undefined;
  let groupKeys: Record<string, { signature: Uint8Array; box: Uint8Array }> = {};
  if (channel !== undefined) {
    const members = configuration.channels[channel];
    if (!members) throw new CliError(4, "Channel is not configured.");
    recipients = members.filter((name) => name !== configuration.name);
  } else if (groupName !== undefined) {
    if (messageKind !== "info") throw new CliError(1, "Group messages must be information.");
    const groups = await loadGroups(groupsFilePath(configuration.storage));
    const match = Object.entries(groups.gruppen).find(([, value]) => {
      const parsed = parseGroupState(value.stand);
      return parsed?.stand.name === groupName;
    });
    if (!match) throw new CliError(4, "Group is not stored on this agent.");
    const [gid, local] = match;
    requireActiveHead(local);
    const signed = parseGroupState(local.stand)!;
    const founder = signed.stand.gruender.name === configuration.name
      ? { signature: signingKey.signaturOeffentlich, box: signingKey.boxOeffentlich }
      : configuration.trusted[signed.stand.gruender.name];
    if (!founder || !Buffer.from(founder.signature).equals(Buffer.from(signed.stand.gruender.sig))
      || !verifyGroupState(signed, new URL(configuration.server).origin, founder.signature)) throw new CliError(4, "Group founder key does not match a direct trusted contact.");
    if (local.kopf.version !== signed.stand.version || local.kopf.hash !== Buffer.from(hashGroupState(signed.stand)).toString("hex")) throw new CliError(3, "Stored group head does not match its signed state.");
    const members = signed.stand.mitglieder;
    if (!members.some((member) => member.name === configuration.name)) throw new CliError(4, "This agent is not a member of the group.");
    if (local.ausgetreten.includes(configuration.name)) throw new CliError(4, "This agent has left the group.");
    for (const member of members) {
      if (member.name === configuration.name || local.ausgetreten.includes(member.name)) continue;
      if (member.name !== signed.stand.gruender.name && member.seit_version > 1 && !local.ack.includes(member.name)) continue;
      const directKey = configuration.trusted[member.name];
      if (directKey && (!Buffer.from(directKey.signature).equals(Buffer.from(member.sig)) || !Buffer.from(directKey.box).equals(Buffer.from(member.box)))) {
        throw new CliError(4, `ALARM: Group key for ${member.name} conflicts with a direct trusted key.`);
      }
      groupKeys[member.name] = { signature: member.sig, box: member.box };
    }
    recipients = Object.keys(groupKeys);
    if (recipients.length === 0) throw new CliError(1, "Group has no approved recipients.");
    groupRef = { gid, version: signed.stand.version, hash: local.kopf.hash };
  } else {
    recipients = direct!.split(",");
  }
  if (recipients.length === 0 || new Set(recipients).size !== recipients.length || recipients.includes(configuration.name)) {
    throw new CliError(1, "Invalid recipient list.");
  }
  const recipientKeys = await verifyRecipientKeys(configuration, signingKey, recipients, groupKeys);
  const now = new Date();
  const reference = singleOption(options, "--ref") ?? null;
  const envelope: Envelope = {
    v: 1,
    id: randomBytes(16).toString("hex"),
    von: configuration.name,
    an: recipients,
    kanal: channel ?? null,
    erstellt: now.toISOString(),
    gueltig_bis: new Date(now.getTime() + lifetime * 24 * 60 * 60 * 1000).toISOString(),
    art: messageKind,
    bezug: reference,
    betreff: subject,
    text,
    anhaenge: attachments,
    ...(triggeredBy === undefined ? {} : { ausgeloest_von: triggeredBy }),
    ...(groupRef === undefined ? {} : { gruppe: groupRef }),
  };
  const bytes = sealEnvelope(envelope, signingKey, recipientKeys);
  const result = await submitMessage(configuration.server, bytes, configuration.name, signingKey.signaturPrivat);
  if (isClientError(result)) throw new CliError(2, "Request to the Subspace server failed.");
  console.log(JSON.stringify({ id: result.id, relay_id: result.id, post_office_id: result.id, envelope_id: envelope.id })); // JSON output, keep (post_office_id)
}

function englishReason(reason: OpenError): string {
  switch (reason) {
    case "zu_gross": return "too_large";
    case "format": return "format";
    case "nicht_an_mich": return "wrong_recipient";
    case "entschluesselung": return "decryption";
    case "schema": return "schema";
    case "umschlag_passt_nicht": return "envelope_mismatch";
    case "absender_unbekannt": return "unknown_sender";
    case "unterschrift": return "signature";
    case "wiederholung": return "replay";
    case "abgelaufen": return "expired";
    case "zukunft": return "future_timestamp";
    case "anhang_typ": return "attachment_type";
    case "group_state": return "group_state";
  }
}

function englishEnvelope(envelope: Envelope): Record<string, unknown> {
  return {
    envelope_id: envelope.id,
    from: envelope.von, to: envelope.an, channel: envelope.kanal, created: envelope.erstellt,
    expires: envelope.gueltig_bis, kind: envelope.art === "anfrage" ? "request" : envelope.art,
    ref: envelope.bezug, subject: envelope.betreff, text: envelope.text,
    attachments: envelope.anhaenge.map((item) => ({ name: item.name, type: item.typ, content: item.inhalt })),
    ...(envelope.ausgeloest_von ? { triggered_by: { from: envelope.ausgeloest_von.von, envelope_id: envelope.ausgeloest_von.huelle_id } } : {}),
    ...(envelope.gruppe ? { group: { gid: envelope.gruppe.gid, version: envelope.gruppe.version, hash: envelope.gruppe.hash } } : {}),
  };
}

function quarantineFileName(entry: MailboxEntry, envelope: Envelope): string {
  return `${envelope.erstellt.slice(0, 10)}-${envelope.id}.json`;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function isMailboxEntry(value: unknown): value is MailboxEntry {
  if (!isObject(value)) return false;
  return typeof value.id === "string" && /^[a-f0-9]{32}$/.test(value.id)
    && typeof value.von === "string" && /^[a-z][a-z0-9-]{1,31}$/.test(value.von)
    && typeof value.groesse === "number" && Number.isFinite(value.groesse) && value.groesse >= 0
    && isTimestamp(value.eingang);
}

const GROUP_PROTOCOL_PREFIX = "subspace-group-protocol-v1\n";

function protocolMessage(text: string): Record<string, unknown> | undefined {
  if (!text.startsWith(GROUP_PROTOCOL_PREFIX)) return;
  try {
    const value: unknown = JSON.parse(text.slice(GROUP_PROTOCOL_PREFIX.length));
    if (!isObject(value) || value.version !== 1 || typeof value.type !== "string" || !isObject(value.body)) return;
    return value;
  } catch { return; }
}

function parseInvitation(value: unknown): GroupInvitation | undefined {
  if (!isObject(value) || Object.keys(value).sort().join(",") !== "fuer,gid,stand_hash,unterschrift,zeit" /* wire format, keep */
    || typeof value.gid !== "string" || typeof value.fuer !== "string" || typeof value.zeit !== "string"
    || typeof value.stand_hash !== "string" || typeof value.unterschrift !== "string") return;
  const stateHash = Buffer.from(value.stand_hash, "base64"), signature = Buffer.from(value.unterschrift, "base64");
  if (stateHash.length !== 32 || stateHash.toString("base64") !== value.stand_hash || signature.length !== 64 || signature.toString("base64") !== value.unterschrift) return;
  return { gid: value.gid, stand_hash: new Uint8Array(stateHash), fuer: value.fuer, zeit: value.zeit, unterschrift: new Uint8Array(signature) };
}

function groupKeyForEnvelope(
  bytes: Uint8Array,
  groups: Awaited<ReturnType<typeof loadGroups>>,
  configuration: Configuration,
  sender: string,
  ownName: string,
  ownSignature: Uint8Array,
): { key?: Uint8Array; origins: string[]; valid: boolean } {
  const head = readEnvelopeHeader(bytes);
  const ref = head?.gruppe;
  if (!head || !ref) return { origins: [], valid: false };
  const local = groups.gruppen[ref.gid];
  const signed = local && parseGroupState(local.stand);
  const founder = signed ? signed.stand.gruender.name === ownName
    ? { signature: ownSignature }
    : configuration.trusted[signed.stand.gruender.name] : undefined;
  if (!local || local.syncFailed || local.gabelungen.length || !signed || !founder
    || !Buffer.from(founder.signature).equals(Buffer.from(signed.stand.gruender.sig))
    || !verifyGroupState(signed, new URL(configuration.server).origin, founder.signature)
    || ref.version > signed.stand.version || (ref.version === local.kopf.version && local.kopf.hash !== ref.hash)
    || (ref.version === signed.stand.version && Buffer.from(hashGroupState(signed.stand)).toString("hex") !== ref.hash)
    || (local.pending?.role === "invitee" && ["awaiting_code", "consent_sent"].includes(String(local.pending.state)))
    || Date.parse(signed.stand.gueltig_bis) <= Date.now()) return { origins: [], valid: false };
  let referenced: SignedGroupState | undefined;
  if (ref.version === signed.stand.version) referenced = signed;
  else {
    let prior: SignedGroupState | undefined;
    for (let version = ref.version; version <= signed.stand.version; version++) {
      const cached = local.gepruefteVersionen?.[String(version)];
      const candidate = cached?.signed && parseGroupState(cached.signed);
      if (!candidate || candidate.stand.version !== version || cached.hash !== Buffer.from(hashGroupState(candidate.stand)).toString("hex")
        || !verifyGroupState(candidate, new URL(configuration.server).origin, founder.signature)
        || (version === ref.version ? cached.hash !== ref.hash : !prior || validateRevision(candidate, prior, new URL(configuration.server).origin, founder.signature).status !== "neu")) {
        return { origins: [], valid: false };
      }
      if (version === ref.version) referenced = candidate;
      prior = candidate;
    }
    if (!prior || Buffer.from(hashGroupState(prior.stand)).toString("hex") !== Buffer.from(hashGroupState(signed.stand)).toString("hex")) return { origins: [], valid: false };
  }
  if (!referenced || Buffer.from(hashGroupState(referenced.stand)).toString("hex") !== ref.hash
    || Date.parse(referenced.stand.gueltig_bis) <= Date.now()) return { origins: [], valid: false };
  const members = referenced.stand.mitglieder;
  const atVersion = (name: string) => members.find((entry) => entry.name === name && entry.seit_version <= ref.version);
  const currentMember = (name: string) => signed.stand.mitglieder.find((entry) => entry.name === name && entry.seit_version <= signed.stand.version);
  const leftAtVersion = (name: string) => {
    const member = atVersion(name);
    return (local.austritte ?? []).some((leave) => leave.name === name && leave.ab_version >= (member?.seit_version ?? ref.version) && leave.ab_version <= ref.version)
      || (!local.austritte?.length && local.ausgetreten.includes(name));
  };
  const leftCurrently = (name: string) => {
    const member = currentMember(name);
    return !member || (local.austritte ?? []).some((leave) => leave.name === name && leave.ab_version >= member.seit_version && leave.ab_version <= signed.stand.version)
      || (!local.austritte?.length && local.ausgetreten.includes(name));
  };
  if (!atVersion(ownName) || !atVersion(sender) || !head.an.every((name) => atVersion(name) && !leftAtVersion(name))
    || leftAtVersion(sender) || leftAtVersion(ownName) || leftCurrently(ownName) || leftCurrently(sender)
    || !head.an.every((name) => !leftCurrently(name))) return { origins: [], valid: false };
  const member = atVersion(sender)!;
  const direct = configuration.trusted[sender];
  if (direct && (!Buffer.from(direct.signature).equals(Buffer.from(member.sig)) || !Buffer.from(direct.box).equals(Buffer.from(member.box)))) return { origins: [], valid: false };
  for (const other of Object.values(groups.gruppen)) {
    const otherState = parseGroupState(other.stand);
    if (!otherState || !otherState.stand.mitglieder.some((entry) => entry.name === ownName)) continue;
    const otherMember = otherState.stand.mitglieder.find((entry) => entry.name === sender);
    if (otherMember && !Buffer.from(otherMember.sig).equals(Buffer.from(member.sig))) return { origins: [], valid: false };
  }
  return { key: direct ? undefined : member.sig, origins: [signed.stand.name], valid: true };
}

async function fetchMessages(options: CliOptions): Promise<void> {
  const configuration = await config(options);
  const signingKey = await key(options);
  const folders = await ensureStorage(configuration.storage);
  const groupFile = groupsFilePath(configuration.storage);
  const localGroups = await loadGroups(groupFile);
  for (const [gid, storedLocal] of Object.entries(localGroups.gruppen)) {
    let local = storedLocal;
    delete local.syncFailed;
    let current = parseGroupState(local.stand);
    const ownMembership = current?.stand.mitglieder.some((member) => member.name === configuration.name) ?? false;
    if (local.pending?.role === "invitee" && !ownMembership && ["awaiting_code", "burned"].includes(String(local.pending.state))) continue;
    if (local.pending?.role === "invitee" && !ownMembership && local.pending.state === "consent_sent") {
      const published = await listGroups(configuration.server, configuration.name, signingKey.signaturPrivat);
      const admitted = !isClientError(published) && published.some((raw) => {
        const candidate = parseGroupState(raw);
        return candidate?.stand.gid === gid && candidate.stand.mitglieder.some((member) => member.name === configuration.name);
      });
      if (!admitted) continue;
    }
    const founderSignature = current && (current.stand.gruender.name === configuration.name
      ? signingKey.signaturOeffentlich : configuration.trusted[current.stand.gruender.name]?.signature);
    if (!current || !founderSignature || !Buffer.from(founderSignature).equals(Buffer.from(current.stand.gruender.sig))
      || !verifyGroupState(current, new URL(configuration.server).origin, founderSignature)) {
      if (local.pending?.role !== "invitee") {
        local.syncFailed = true;
        console.error("Warning: Could not synchronize group state; group sending is stopped until a successful fetch.");
      }
      continue;
    }
    const chain = await fetchGroupHistory(configuration.server, gid, current.stand.version, configuration.name, signingKey.signaturPrivat);
    if (isClientError(chain)) {
      local.syncFailed = true;
      console.error(`Warning: Could not synchronize group ${current.stand.name}; group sending is stopped until a successful fetch.`);
      continue;
    }
    for (const raw of chain) {
      const next = parseGroupState(raw);
      if (!next) {
        local.syncFailed = true;
        console.error(`Warning: The Subspace server returned an invalid state for group ${current.stand.name}; group sending is stopped until a successful fetch.`);
        break;
      }
      const result = validateRevision(next, current, new URL(configuration.server).origin, founderSignature);
      if (result.status === "fork") {
        local.gabelungen.push({ version: next.stand.version, hashes: result.proofs?.map((item) => Buffer.from(hashGroupState(item.stand)).toString("hex")) ?? [] });
        await saveGroups(groupFile, localGroups);
        local.syncFailed = true;
        console.error("Warning: Group fork detected; group sending is stopped.");
        break;
      }
      if (result.status !== "neu" && result.status !== "aktuell") {
        local.syncFailed = true;
        console.error(`Warning: Group ${current.stand.name} state chain is invalid or rolled back; group sending is stopped until a successful fetch.`);
        break;
      }
      const previousNames = new Set(current.stand.mitglieder.map((member) => member.name));
      setGroupState(localGroups, gid, next, hashGroupState(next.stand));
      const changed = localGroups.gruppen[gid]!;
      local = changed;
      for (const member of next.stand.mitglieder) {
        if (!previousNames.has(member.name)) console.log(`New member ${member.name} (${fingerprint(member.sig, member.box).split(" ")[0]}) in ${next.stand.name}`);
      }
      current = next;
      local.stand = changed.stand;
      local.kopf = changed.kopf;
    }
    if (local.syncFailed) continue;
    const leaves = await fetchGroupLeaves(configuration.server, gid, configuration.name, signingKey.signaturPrivat);
    if (isClientError(leaves)) {
      local.syncFailed = true;
      console.error(`Warning: Could not synchronize leaves for group ${current.stand.name}; group sending is stopped until a successful fetch.`);
      continue;
    }
    for (const raw of leaves) {
      const leave = parseGroupLeave(raw);
      const leaveState = leave?.ab_version === current.stand.version ? current : leave && parseGroupState(local.gepruefteVersionen?.[String(leave.ab_version)]?.signed);
      const memberAtLeave = leaveState?.stand.mitglieder.find((entry) => entry.name === leave?.name && entry.seit_version <= leave.ab_version);
      const currentMember = leave && current.stand.mitglieder.find((entry) => entry.name === leave.name);
      if (leave && leave.ab_version <= current.stand.version && memberAtLeave && verifyGroupLeave(leave, memberAtLeave.sig)) {
        local.austritte ??= [];
        if (!local.austritte.some((entry) => entry.name === leave.name && entry.ab_version === leave.ab_version)) local.austritte.push({ name: leave.name, ab_version: leave.ab_version });
        if (currentMember && currentMember.seit_version > leave.ab_version) {
          local.ausgetreten = local.ausgetreten.filter((name) => name !== leave.name);
        } else if (!local.ausgetreten.includes(leave.name)) {
          local.ausgetreten.push(leave.name);
          console.log(`${leave.name} left group ${current.stand.name}`);
        }
      }
    }
    delete local.syncFailed;
  }
  await saveGroups(groupFile, localGroups);
  const now = new Date();
  const seen = await readSeen(folders.seen);
  for (const [id, expiry] of Object.entries(seen)) if (Date.parse(expiry) <= now.getTime()) delete seen[id];

  const entries = await listMailbox(configuration.server, configuration.name, configuration.name, signingKey.signaturPrivat, {}, (account) => {
    console.log(`This agent was connected to the Subspace account ${account} through its invitation. If you did not create this account, tell the person who invited you.`);
  });
  if (isClientError(entries)) throw new CliError(2, "Request to the Subspace server failed.");
  if (!Array.isArray(entries)) throw new CliError(2, "Request to the Subspace server failed.");
  const fetched: { entry: MailboxEntry; bytes: Uint8Array }[] = [];
  for (const candidate of entries) {
    if (!isMailboxEntry(candidate)) {
      console.log(JSON.stringify({ relay_id: null, post_office_id: null, from: null, kind: null, result: "rejected:invalid_list" })); // JSON output, keep (post_office_id)
      continue;
    }
    const entry = candidate;
    const bytes = await fetchMessage(configuration.server, configuration.name, entry.id, configuration.name, signingKey.signaturPrivat);
    if (isClientError(bytes)) throw new CliError(2, "Request to the Subspace server failed.");
    fetched.push({ entry, bytes });
  }
  const syncFailed = new Set(Object.entries(localGroups.gruppen).filter(([, group]) => group.syncFailed).map(([gid]) => gid));
  for (const { entry, bytes } of fetched) {
    const groupProof = groupKeyForEnvelope(bytes, localGroups, configuration, entry.von, configuration.name, signingKey.signaturOeffentlich);
    const keys = Object.fromEntries(Object.entries(configuration.trusted).map(([name, trusted]) => [name, trusted.signature] as const));
    if (groupProof.valid && groupProof.key && !Object.hasOwn(keys, entry.von)) keys[entry.von] = groupProof.key;
    const opened = openEnvelope(bytes, { name: configuration.name, boxPrivat: signingKey.boxPrivat }, keys, {
        now: now,
        alreadySeen: (id) => Object.hasOwn(seen, id),
      });
    let invalidAttachment = false;
    if (opened.ok) {
      for (const attachment of opened.huelle.anhaenge) {
        const detected = detectType(attachment.name, Buffer.from(attachment.inhalt, "base64"));
        if (!detected.ok || detected.mediaType !== attachment.typ) invalidAttachment = true;
      }
    }
    let result: string;
    let kind: string | null = null;
    let groupProtocolHandled = false;
    let groupMembershipValid = groupProof.valid;
    const envelopeGroup = readEnvelopeHeader(bytes)?.gruppe;
    const heldForSync = Boolean(envelopeGroup && syncFailed.has(envelopeGroup.gid));
    const heldQuarantinePath = join(folders.quarantine, `${entry.eingang.slice(0, 10)}-${entry.id}.group-sync.json`);
    if (opened.ok && opened.huelle.gruppe) {
      const group = localGroups.gruppen[opened.huelle.gruppe.gid];
      const parsed = group && parseGroupState(group.stand);
      const version = opened.huelle.gruppe.version;
      const snapshot = group?.gepruefteVersionen?.[String(version)];
      const snapshotMembers = snapshot?.mitglieder ?? (parsed?.stand.version === version ? parsed.stand.mitglieder : []);
      const snapshotHash = snapshot?.hash ?? (parsed?.stand.version === version ? Buffer.from(hashGroupState(parsed.stand)).toString("hex") : undefined);
      const membershipAtVersion = (name: string) => snapshotMembers.find((member) => member.name === name && member.seit_version <= version);
      const leftByVersion = (name: string) => (group?.austritte ?? []).some((leave) => leave.name === name && leave.ab_version >= (membershipAtVersion(name)?.seit_version ?? version) && leave.ab_version <= version);
      const currentMember = (name: string) => parsed?.stand.mitglieder.find((member) => member.name === name && member.seit_version <= parsed.stand.version);
      const leftCurrently = (name: string) => {
        const member = currentMember(name);
        return !member || (group?.austritte ?? []).some((leave) => leave.name === name && leave.ab_version >= member.seit_version && leave.ab_version <= (parsed?.stand.version ?? 0))
          || (!(group?.austritte?.length) && Boolean(group?.ausgetreten.includes(name)));
      };
      groupMembershipValid = Boolean(groupProof.valid && group && parsed && !group.syncFailed && !group.gabelungen.length
        && snapshotHash === opened.huelle.gruppe.hash
        && membershipAtVersion(opened.huelle.von) && !leftByVersion(opened.huelle.von)
        && opened.huelle.an.every((name) => membershipAtVersion(name) && !leftByVersion(name))
        && !group.ausgetreten.includes(opened.huelle.von) && !leftCurrently(opened.huelle.von)
        && opened.huelle.an.every((name) => !leftCurrently(name)) && opened.huelle.art === "info");
    } else if (opened.ok && !opened.huelle.gruppe) {
      groupMembershipValid = true;
    }
    if (opened.ok && opened.huelle.von === entry.von) {
      const protocol = protocolMessage(opened.huelle.text);
      const body = protocol && isObject(protocol.body) ? protocol.body : undefined;
      if (protocol && body && protocol.type === "invitation") {
        const signed = parseGroupState(body.signed_state);
        const target = parseGroupState(body.target_state);
        const invitation = parseInvitation(body.invitation);
        const founder = signed && configuration.trusted[opened.huelle.von];
        const nonceFounder = typeof body.nonce_founder === "string" ? Buffer.from(body.nonce_founder, "base64") : new Uint8Array();
        if (signed && target && invitation && founder && Buffer.from(founder.signature).equals(Buffer.from(signed.stand.gruender.sig))
          && signed.stand.gruender.name === opened.huelle.von && invitation.gid === signed.stand.gid && invitation.fuer === configuration.name
          && target.stand.gid === signed.stand.gid && target.stand.name === signed.stand.name && target.stand.version === signed.stand.version + 1
          && Buffer.from(target.stand.vorgaenger_hash).equals(Buffer.from(hashGroupState(signed.stand)))
          && Buffer.from(invitation.stand_hash).equals(Buffer.from(hashGroupState(target.stand)))
          && target.stand.mitglieder.filter((member) => !signed.stand.mitglieder.some((old) => old.name === member.name)).length === 1
          && target.stand.mitglieder.some((member) => member.name === configuration.name && Buffer.from(member.sig).equals(Buffer.from(signingKey.signaturOeffentlich)) && Buffer.from(member.box).equals(Buffer.from(signingKey.boxOeffentlich)) && member.aufnahme === "code" && member.seit_version === target.stand.version)
          && nonceFounder.length === 32
          && nonceFounder.toString("base64") === body.nonce_founder && verifyGroupState(signed, new URL(configuration.server).origin, founder.signature)
          && verifyGroupInvitation(invitation, founder.signature)) {
          const gid = signed.stand.gid;
          const previous = localGroups.gruppen[gid];
          const hash = hashGroupState(signed.stand);
          const previousState = previous && parseGroupState(previous.stand);
          const previousFounder = previousState && (previousState.stand.gruender.name === configuration.name
            ? signingKey.signaturOeffentlich : configuration.trusted[previousState.stand.gruender.name]?.signature);
          const previousPending = previous?.pending;
          const priorInvitation = previousPending?.role === "invitee" && isObject(previousPending.invitation) ? previousPending.invitation : undefined;
          const priorTime = typeof priorInvitation?.zeit === "string" ? Date.parse(priorInvitation.zeit) : Number.NaN;
          const newTime = Date.parse(invitation.zeit);
          const replaces = Boolean(previous && previousState && previousFounder
            && Buffer.from(previousFounder).equals(Buffer.from(previousState.stand.gruender.sig))
            && previousState.stand.gruender.name === opened.huelle.von
            && !previousState.stand.mitglieder.some((member) => member.name === configuration.name)
            && previousPending?.role === "invitee" && ["awaiting_code", "consent_sent", "burned"].includes(String(previousPending.state))
            && Number.isFinite(priorTime) && Number.isFinite(newTime) && newTime > priorTime);
          if (!previous || replaces) {
            setGroupState(localGroups, gid, signed, hash);
            const memberNonce = createGroupNonce();
            const group = localGroups.gruppen[gid]!;
            group.pending = { role: "invitee", state: "awaiting_code", attempts: 0, nonce_founder: Buffer.from(nonceFounder).toString("base64"), nonce_member: Buffer.from(memberNonce).toString("base64"), stand_hash: Buffer.from(invitation.stand_hash).toString("base64"), target_stand: groupStateJson(target), invitation: invitationJson(invitation) };
            await sendGroupProtocol(configuration, signingKey, opened.huelle.von, protocolText("pairing_response", {
              gid, stand_hash: Buffer.from(invitation.stand_hash).toString("base64"), name: configuration.name, nonce_member: Buffer.from(memberNonce).toString("base64"),
            }));
            await saveGroups(groupFile, localGroups);
            const members = signed.stand.mitglieder.map((member) => member.name + " (" + fingerprint(member.sig, member.box).split(" ")[0] + ")").join(", ");
            console.log(replaces
              ? "Group invitation " + signed.stand.name + " from " + opened.huelle.von + " replaces the earlier invitation. The earlier pairing code no longer works; ask " + opened.huelle.von + " for the new one."
              : "Group invitation " + signed.stand.name + " from " + opened.huelle.von + ". Members: " + members + ". Everyone in this group can see the member list and message your agent.");
            groupProtocolHandled = true;
          }
        }
      } else if (protocol && body && protocol.type === "pairing_response") {
        const gid = typeof body.gid === "string" ? body.gid : "";
        const local = localGroups.gruppen[gid];
        const pending = local?.pending?.[opened.huelle.von];
        const hash = typeof body.stand_hash === "string" ? Buffer.from(body.stand_hash, "base64") : new Uint8Array();
        const nonceMember = typeof body.nonce_member === "string" ? Buffer.from(body.nonce_member, "base64") : new Uint8Array();
        const direct = configuration.trusted[opened.huelle.von];
        if (local && isObject(pending) && pending.role === "founder" && direct && typeof body.name === "string" && body.name === opened.huelle.von
          && typeof pending.stand_hash === "string" && Buffer.from(pending.stand_hash, "base64").equals(hash)
          && hash.length === 32 && nonceMember.length === 32 && nonceMember.toString("base64") === body.nonce_member) {
          pending.nonce_member = nonceMember.toString("base64");
          pending.state = "response_received";
          await saveGroups(groupFile, localGroups);
          groupProtocolHandled = true;
        }
      } else if (protocol && body && protocol.type === "consent") {
        const gid = typeof body.gid === "string" ? body.gid : "";
        const local = localGroups.gruppen[gid];
        const current = local && parseGroupState(local.stand);
        const pending = local?.pending?.[opened.huelle.von];
        const direct = configuration.trusted[opened.huelle.von];
        const decode = (value: unknown, length: number): Uint8Array | undefined => {
          if (typeof value !== "string") return;
          const bytes = Buffer.from(value, "base64");
          return bytes.length === length && bytes.toString("base64") === value ? new Uint8Array(bytes) : undefined;
        };
        const stateHash = decode(body.stand_hash, 32), sig = decode(body.sig, 32), box = decode(body.box, 32), signature = decode(body.unterschrift, 64);
        if (local && current && isObject(pending) && pending.role === "founder" && direct && typeof body.name === "string" && body.name === opened.huelle.von
          && typeof body.zeit === "string" && stateHash && sig && box && signature
          && Buffer.from(direct.signature).equals(Buffer.from(sig)) && Buffer.from(direct.box).equals(Buffer.from(box))
          && Buffer.from(stateHash).equals(Buffer.from(typeof pending.stand_hash === "string" ? Buffer.from(pending.stand_hash, "base64") : []))) {
          const consent = { gid, stand_hash: stateHash, name: body.name, sig, box, zeit: body.zeit, unterschrift: signature };
          const target = parseGroupState(pending.target_stand);
          const next = target?.stand;
          const admitted = next?.mitglieder.find((member) => member.name === body.name);
          const validConsent = next && admitted
            && Buffer.from(stateHash).equals(Buffer.from(hashGroupState(next)))
            && Buffer.from(admitted.sig).equals(Buffer.from(sig)) && Buffer.from(admitted.box).equals(Buffer.from(box))
            && verifyGroupConsent(consent);
          if (validConsent && (next.version !== current.stand.version + 1
            || !Buffer.from(next.vorgaenger_hash).equals(Buffer.from(hashGroupState(current.stand))))) {
            pending.state = "outdated";
            await saveGroups(groupFile, localGroups);
            try {
              const invitationResult = await queueOrSendGroupInvitation(configuration, signingKey, localGroups, gid, local, body.name, groupFile);
              const resultText = invitationResult === "queued"
                ? `Queued a new invitation; ${body.name} needs the new pairing code.`
                : `Sent a new invitation; ${body.name} needs the new pairing code.`;
              console.error(`Warning: ${body.name} approved an outdated invitation for group ${current.stand.name} (built on version ${next.version - 1}, group is at version ${current.stand.version}). ${resultText}`);
            } catch (error) {
              const reason = (error instanceof CliError ? error.publicMessage : error instanceof Error ? error.message : String(error)).replace(/\.$/, "");
              console.error(`Warning: could not send the group invitation for ${body.name} to group ${current.stand.name}: ${reason}. Run: subspace group invite ${current.stand.name} ${body.name} --now`);
            }
            groupProtocolHandled = true;
          } else if (validConsent) {
            admitted.zustimmung = signature;
            admitted.zustimmung_zeit = body.zeit;
            const signedNext: SignedGroupState = { stand: next, unterschrift: signGroupState(next, signingKey.signaturPrivat) };
            const published = await submitGroupState(configuration.server, signedNext, configuration.name, signingKey.signaturPrivat);
            if (!isClientError(published)) {
              setGroupState(localGroups, gid, signedNext, hashGroupState(next));
              if (!localGroups.gruppen[gid]!.ack.includes(body.name)) localGroups.gruppen[gid]!.ack.push(body.name);
              await saveGroups(groupFile, localGroups);
              console.log("Added " + body.name + " to group " + current.stand.name + ".");
              try {
                await sendNextQueuedGroupInvitation(configuration, signingKey, localGroups, gid, localGroups.gruppen[gid]!, groupFile);
              } catch (error) {
                const recipient = error instanceof GroupInvitationSendError ? error.recipient : opened.huelle.von;
                const cause = error instanceof GroupInvitationSendError ? error.cause : error;
                const reason = (cause instanceof CliError ? cause.publicMessage : cause instanceof Error ? cause.message : String(cause)).replace(/\.$/, "");
                console.error(`Warning: could not send the group invitation for ${recipient} to group ${current.stand.name}: ${reason}. Run: subspace group invite ${current.stand.name} ${recipient} --now`);
              }
              groupProtocolHandled = true;
            }
          }
        }
      }
    }
    if (groupProtocolHandled) {
      result = "accepted";
      kind = "info";
    } else if (heldForSync) {
      const heldRecord = opened.ok
        ? { ...englishEnvelope(opened.huelle), group_sync: "pending" }
        : { relay_id: entry.id, from_relay: entry.von, post_office_id: entry.id, from_post_office: entry.von, group: envelopeGroup, group_sync: "pending", sealed: Buffer.from(bytes).toString("base64") }; // JSON output, keep (post_office_id, from_post_office)
      await atomicWrite(heldQuarantinePath, JSON.stringify(heldRecord) + "\n");
      result = "held:group_sync";
      kind = opened.ok ? opened.huelle.art : null;
    } else if (opened.ok && opened.huelle.von === entry.von && !invalidAttachment && groupMembershipValid) {
      kind = opened.huelle.art;
      const path = join(folders.quarantine, quarantineFileName(entry, opened.huelle));
      await atomicWrite(path, JSON.stringify(englishEnvelope(opened.huelle)) + "\n");
      seen[opened.huelle.id] = opened.huelle.gueltig_bis;
      await saveSeen(folders.seen, seen);
      result = "accepted";
    } else {
      const grund: OpenError = opened.ok
        ? opened.huelle.von !== entry.von ? "absender_unbekannt" : opened.huelle.gruppe ? "group_state" : "anhang_typ"
        : opened.grund;
      const metadata = {
        relay_id: entry.id,
        from_relay: entry.von,
        post_office_id: entry.id, // JSON output, keep
        from_post_office: entry.von, // JSON output, keep
        size: entry.groesse,
        reason: englishReason(grund),
        time: now.toISOString(),
      };
      const timePart = entry.eingang.replace(/[^0-9TZ-]/g, "-");
      await atomicWrite(join(folders.rejected, `${timePart}-${entry.id}.json`), JSON.stringify(metadata) + "\n");
      result = `rejected:${englishReason(grund)}`;
    }
    if (!heldForSync) await rm(heldQuarantinePath, { force: true });
    if (!heldForSync) {
      const acknowledged = await acknowledge(configuration.server, configuration.name, entry.id, configuration.name, signingKey.signaturPrivat);
      if (isClientError(acknowledged)) throw new CliError(2, "Request to the Subspace server failed.");
    }
    console.log(JSON.stringify({
      relay_id: entry.id,
      post_office_id: entry.id, // JSON output, keep
      from: entry.von,
      kind: kind === "anfrage" ? "request" : kind,
      result,
      ...(opened.ok && opened.huelle.ausgeloest_von ? { triggered_by: { from: opened.huelle.ausgeloest_von.von, envelope_id: opened.huelle.ausgeloest_von.huelle_id } } : {}),
      ...(opened.ok && opened.huelle.gruppe ? { group_origin: { group: opened.huelle.gruppe.gid, from: opened.huelle.von, confirmed_by: groupProof.origins } } : {}),
    }));
  }
  // Handle fetched replies first: a consent received before this fetch wins over local expiry.
  for (const [gid, local] of Object.entries(localGroups.gruppen)) {
    let expired = false;
    if (local.pending && local.pending.role !== "invitee") {
      for (const [recipient, raw] of Object.entries(local.pending)) {
        if (!isObject(raw) || raw.role !== "founder" || !["invited", "response_received"].includes(String(raw.state)) || typeof raw.zeit !== "string") continue;
        const sentAt = Date.parse(raw.zeit);
        if (!Number.isFinite(sentAt) || sentAt + GROUP_INVITATION_TTL_MS > now.getTime()) continue;
        delete local.pending[recipient];
        expired = true;
        const groupName = parseGroupState(local.stand)?.stand.name ?? gid;
        console.error(`Warning: the group invitation for ${recipient} to group ${groupName} expired after 72 hours without an answer.`);
      }
    }
    if (expired) {
      if (Object.keys(local.pending ?? {}).length === 0) delete local.pending;
      await saveGroups(groupFile, localGroups);
    }
    const parsed = parseGroupState(local.stand);
    if (local.syncFailed || local.gabelungen.length || parsed?.stand.gruender.name !== configuration.name) continue;
    try {
      await sendNextQueuedGroupInvitation(configuration, signingKey, localGroups, gid, local, groupFile);
    } catch (error) {
      const recipient = error instanceof GroupInvitationSendError ? error.recipient : "queued member";
      const cause = error instanceof GroupInvitationSendError ? error.cause : error;
      const reason = (cause instanceof CliError ? cause.publicMessage : cause instanceof Error ? cause.message : String(cause)).replace(/\.$/, "");
      console.error(`Warning: could not send the group invitation for ${recipient} to group ${parseGroupState(local.stand)?.stand.name ?? gid}: ${reason}.`);
    }
  }
  await saveSeen(folders.seen, seen);
  await processInvitationTasks(configuration, signingKey, options.flags.has("--skip-invitation-tasks"));
}

async function messageStatus(options: CliOptions): Promise<void> {
  const configuration = await config(options);
  const signingKey = await key(options);
  const id = options.positionals[1];
  if (!id || options.positionals.length !== 2 || !/^[a-f0-9]{32}$/.test(id)) throw new CliError(1, "A valid message ID is required.");
  const result = await status(configuration.server, id, configuration.name, signingKey.signaturPrivat);
  if (isClientError(result)) throw new CliError(2, "Request to the Subspace server failed.");
  console.log(JSON.stringify(Object.fromEntries(Object.entries(result).map(([name, state]) => [name, state === "liegt" ? "waiting" : state === "abgeholt" ? "fetched" : "expired"]))));
}

export interface CommandHelp {
  // CLI help field
  usage: string;
  // CLI help field
  description: string;
  // CLI help field
  options: [string, string][];
}

export const commandHelp: Record<string, CommandHelp> = {
  setup: { usage: "setup --name <name> --server <url> --dir <path>", description: "Create a configuration and key in a private directory.", options: [["--name <name>", "Agent name."], ["--server <url>", "Subspace server URL."], ["--dir <path>", "Private setup directory."]] },
  trust: { usage: "trust --config <path> --name <name> --signature <value> --box <value> [--fingerprint <value>]", description: "Store a partner's verified public keys.", options: [["--config <path>", "Configuration file path."], ["--name <name>", "Partner name."], ["--signature <value>", "Base64 or ssh-ed25519 signing key."], ["--box <value>", "Public encryption key."], ["--fingerprint <value>", "Fingerprint to verify."]] },
  "key generate": { usage: "key generate [--out <path>]", description: "Create a key pair and print only its public part.", options: [["--out <path>", "Private key output file."]] },
  "key rotate": { usage: "key rotate --config <path> --key <path> [--resume]", description: "Rotate the key and authorize it with the current key.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--resume", "Resume an unfinished rotation using its saved key file."]] },
  "key revoke": { usage: "key revoke --config <path> --key <path>", description: "Revoke the current key with an authorization.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  "key dispute": { usage: "key dispute --config <path> --key <path>", description: "Block a name after a key rotation using the previous key.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Previous key file path."]] },
  accept: { usage: "accept <name> [--config <path>] [--key <path>]", description: "Verify and accept an authorized contact key.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  public: { usage: "public --key <path> [--name <name>]", description: "Print the public part of an existing key.", options: [["--key <path>", "Key file path."], ["--name <name>", "OpenSSH comment name."]] },
  send: { usage: "send --config <path> --key <path> --kind <info|request> --subject <text> --text-file <path> (--to <names> | --channel <name> | --group <name>) [--lifetime <days>] [--ref <id>] [--triggered-by <name>:<envelope_id>] [--attach <path>]", description: "Send an encrypted message to agents, a channel, or an approved group.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--kind <info|request>", "Message kind: info or request."], ["--subject <text>", "Message subject."], ["--text-file <path>", "File containing the message text."], ["--to <names>", "Comma-separated recipient names."], ["--lifetime <days>", "Validity in days (1 to 30; default: 7)."], ["--channel <name>", "Configured recipient channel."], ["--group <name>", "Approved group name."], ["--ref <id>", "ID of the message being answered."], ["--triggered-by <name>:<envelope_id>", "Message that triggered this message."], ["--attach <path>", "Attachment file; can be repeated."]] },
  fetch: { usage: "fetch --config <path> --key <path> [--skip-invitation-tasks]", description: "Fetch messages and store them in the quarantine folder.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--skip-invitation-tasks", "Skip invitation tasks for this fetch."]] },
  status: { usage: "status <id> --config <path> --key <path>", description: "Show the delivery status of a message.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  invite: { usage: "invite --for <name> --config <path> --key <path> [--script <path>]", description: "Create a browser address and an agent line for an invitation.", options: [["--for <name>", "Name of the joining agent."], ["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--script <path>", "Script file for its SHA-256 fingerprint."]] },
  invites: { usage: "invites --config <path> --key <path>", description: "Show your invitations and Subspace server notices.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  open: { usage: "open <name> --config <path> --key <path>", description: "Deprecated. Use confirm.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  join: { usage: "join <agent-line> | join - [--resume] [--token <prefix>] (--dir <path> | --config <path> --key <path>) [--wait <seconds>]", description: "Redeem an invitation agent line and wait for confirmation.", options: [["<agent-line>", "Invitation details for your agent; do not paste into a browser."], ["-", "Read the agent line from standard input."], ["--dir <path>", "Create a new configuration and key in this directory."], ["--config <path>", "Existing configuration."], ["--key <path>", "Existing key."], ["--resume", "Resume a pending join."], ["--token <prefix>", "Select a pending join by the first 8 token characters."], ["--wait <seconds>", "Maximum wait time (default: 600)."]] },
  confirm: { usage: "confirm <name> --config <path> --key <path> [--token <prefix>] [--group <g1,g2,…>]", description: "Confirm after checking the redeemer's name and timing; optionally invite them to groups you founded.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--token <prefix>", "Select an invitation by the first 8 token characters."], ["--group <g1,g2,…>", "Invite the confirmed contact to these groups you founded."]] },
  contacts: { usage: "contacts --config <path> [--key <path>]", description: "Show confirmed contacts and invitations awaiting confirmation.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Verify current contact signing keys."]] },
  account: { usage: "account --config <path> --key <path> [--wait <seconds>]", description: "Connect this agent to an account after confirmation.", options: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--wait <seconds>", "Maximum wait time (default: 900)."]] },
  connect: { usage: "connect <token|-> --dir <path> [--name <name>]", description: "Connect a new or existing agent to your account with a one-time token.", options: [["<token|->", "One-time token, or - to read it from standard input."], ["--name <name>", "Choose the agent name for a new setup."], ["--dir <path>", "Private setup directory."]] },
  group: { usage: "group <create|invite|join|decline|code|members|leave|remove|ack|renew|list> ...", description: "Manage groups whose signed member lists provide group-scoped contacts. Invitations wait in a queue while another is open; use --now to send immediately. group code --wait <seconds> checks local group data every 2 seconds for up to 900 seconds.", options: [["create <name>", "Create a group."], ["invite <group> <agent> [--now]", "Invite a direct contact; otherwise queue it while another invitation is open."], ["join <gid> --code <six digits>", "Approve an invitation using the pairing code shared outside Subspace."], ["decline <group>", "Decline a pending group invitation."], ["code <group> <agent> [--wait <seconds>]", "Show the pairing code, waiting locally for a response if requested (up to 900 seconds)."], ["members <group>", "Show member names and fingerprints."], ["leave <group>", "Leave a group."], ["remove <group> <agent>", "Remove a member."], ["ack <group> <agent>", "Allow group messages to a new member."], ["renew <group>", "Renew the group state validity for 30 days."], ["list", "List groups including their expiry."]] },
};

function showHelp(selectedCommand?: string): void {
  if (selectedCommand) {
    const definition = commandHelp[selectedCommand];
    if (definition) {
      console.log([`Usage: subspace ${definition.usage}`, "", definition.description, "", "Options:", ...definition.options.map(([flag, description]) => `  ${flag}  ${description}`), "  --help  Show this help."].join("\n"));
      return;
    }
  }
  console.log([
    "Subspace is end-to-end encrypted. The Subspace server never sees message contents.", "", "Subspace commands and options", "",
    ...Object.values(commandHelp).map(({ usage: usage, description: description }) => `  subspace ${usage}  — ${description}`), "  help [command]", "  --version", "",
    "Run subspace <command> --help for command details.",
  ].join("\n"));
}

function commandHelpName(positionalArgs: string[]): string | undefined {
  const first = legacyHelpAliases.get(positionalArgs[0] ?? "") ?? positionalArgs[0];
  if (first === "key" && ["generate", "rotate", "revoke", "dispute"].includes(positionalArgs[1] ?? "")) return `key ${positionalArgs[1]}`;
  return first;
}

export async function runCommand(args: string[]): Promise<void> {
  const options = parseOptions(args);
  const command = options.positionals[0];
  if (options.flags.has("--help")) {
    showHelp(command === "help" ? commandHelpName(options.positionals.slice(1)) : commandHelpName(options.positionals));
    return;
  }
  if (command === "help") {
    showHelp(commandHelpName(options.positionals.slice(1)));
    return;
  }
  if (command === "group") {
    const action = options.positionals[1];
    if (action === "join") {
      const code = singleOption(options, "--code");
      if (code === undefined) throw new CliError(2, "Group approval requires --code with the six-digit pairing code shared outside Subspace.");
      if (!/^\d{6}$/.test(code)) throw new CliError(2, "Pairing code must contain exactly six digits.");
    }
    const configuration = await config(options);
    if (action === "create") {
      const name = options.positionals[2];
      if (!name || !/^[a-z][a-z0-9-]{1,31}$/.test(name)) throw new CliError(1, "Group name must match [a-z][a-z0-9-]{1,31}.");
      const signingKey = await key(options);
      const gid = createGroupId(new URL(configuration.server).origin, configuration.name, signingKey.signaturOeffentlich);
      const now = new Date();
      const state = {
        instanz: new URL(configuration.server).origin, gid, name, version: 1, vorgaenger_hash: new Uint8Array(32),
        gueltig_bis: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        gruender: { name: configuration.name, sig: signingKey.signaturOeffentlich, box: signingKey.boxOeffentlich },
        mitglieder: [{ name: configuration.name, sig: signingKey.signaturOeffentlich, box: signingKey.boxOeffentlich, seit_version: 1, aufnahme: "gruendung" as const, zustimmung: new Uint8Array(), zustimmung_zeit: null }],
        zeit: now.toISOString(),
      };
      const signed: SignedGroupState = { stand: state, unterschrift: signGroupState(state, signingKey.signaturPrivat) };
      const result = await submitGroupState(configuration.server, signed, configuration.name, signingKey.signaturPrivat);
      if (isClientError(result)) throw new CliError(2, `Could not publish group state: ${result.grund}.`);
      await ensureStorage(configuration.storage);
      const path = groupsFilePath(configuration.storage);
      const groups = await loadGroups(path);
      groups.gruppen[gid] = { stand: groupStateJson(signed), kopf: { version: 1, hash: Buffer.from(hashGroupState(state)).toString("hex") }, ack: [], ausgetreten: [], gabelungen: [] };
      await saveGroups(path, groups);
      console.log(`${name} ${gid} v1`);
      return;
    }
    const path = groupsFilePath(configuration.storage);
    const groups = await loadGroups(path);
    if (action === "decline") {
      const groupName = options.positionals[2];
      if (!groupName) throw new CliError(2, "Group name or ID is required.");
      const entry = Object.entries(groups.gruppen).find(([gid, local]) => gid === groupName || parseGroupState(local.stand)?.stand.name === groupName);
      if (!entry || entry[1].pending?.role !== "invitee") throw new CliError(4, "No pending group invitation to decline.");
      delete groups.gruppen[entry[0]];
      await saveGroups(path, groups);
      console.log("Group invitation declined.");
      return;
    }
    if (action === "join") {
      const gid = options.positionals[2]!;
      const code = singleOption(options, "--code")!;
      const local = groups.gruppen[gid];
      const pending = local?.pending;
      if (!local || !pending || pending.role !== "invitee") throw new CliError(4, "No pending group invitation matches this ID and pairing code.");
      const invitation = isObject(pending.invitation) ? pending.invitation : undefined;
      const invitationTime = typeof invitation?.zeit === "string" ? Date.parse(invitation.zeit) : Number.NaN;
      if (pending.state === "awaiting_code" && Number.isFinite(invitationTime) && invitationTime + GROUP_INVITATION_TTL_MS <= Date.now()) {
        const groupFounder = parseGroupState(local.stand)?.stand.gruender.name ?? "the group founder";
        delete groups.gruppen[gid];
        await saveGroups(path, groups);
        throw new CliError(4, `This group invitation expired. Ask ${groupFounder} for a new one.`);
      }
      if (pending.state === "burned") throw new CliError(4, "Group invitation pairing code is burned after three failed attempts.");
      if (pending.state !== "awaiting_code") throw new CliError(4, "No pending group invitation matches this ID and pairing code.");
      const attempts = typeof pending.attempts === "number" && Number.isInteger(pending.attempts) ? pending.attempts : 0;
      if (attempts >= 3) throw new CliError(4, "Group invitation pairing code is burned after three failed attempts.");
      const nonceFounder = typeof pending.nonce_founder === "string" ? Buffer.from(pending.nonce_founder, "base64") : new Uint8Array();
      const nonceMember = typeof pending.nonce_member === "string" ? Buffer.from(pending.nonce_member, "base64") : new Uint8Array();
      const parsed = parseGroupState(local.stand);
      const founder = parsed && configuration.trusted[parsed.stand.gruender.name];
      if (!parsed || !founder || !Buffer.from(founder.signature).equals(Buffer.from(parsed.stand.gruender.sig)) || !verifyGroupState(parsed, new URL(configuration.server).origin, founder.signature)) throw new CliError(4, "Group founder is not a direct trusted contact.");
      const targetHash = typeof pending.stand_hash === "string" ? Buffer.from(pending.stand_hash, "base64") : new Uint8Array();
      const expected = groupAdmissionCode(gid, targetHash, nonceFounder, nonceMember);
      if (code !== expected) {
        pending.attempts = attempts + 1;
        if (attempts + 1 >= 3) pending.state = "burned";
        await saveGroups(path, groups);
        throw new CliError(4, pending.state === "burned" ? "Group invitation pairing code is burned after three failed attempts." : "Incorrect group pairing code.");
      }
      const signingKey = await key(options);
      const consent = { gid, stand_hash: targetHash, name: configuration.name, sig: signingKey.signaturOeffentlich, box: signingKey.boxOeffentlich, zeit: new Date().toISOString() };
      const signature = signGroupConsent(consent, signingKey.signaturPrivat);
      await sendGroupProtocol(configuration, signingKey, parsed.stand.gruender.name, protocolText("consent", {
        gid, stand_hash: Buffer.from(consent.stand_hash).toString("base64"), name: consent.name,
        sig: Buffer.from(consent.sig).toString("base64"), box: Buffer.from(consent.box).toString("base64"), zeit: consent.zeit,
        unterschrift: Buffer.from(signature).toString("base64"),
      }));
      pending.state = "consent_sent";
      await saveGroups(path, groups);
      console.log(`Group pairing approved for ${parsed.stand.name}. You will appear in the member list after ${parsed.stand.gruender.name} confirms and your next fetch picks up the new group version (usually a few minutes).`);
      return;
    }
    if (action === "list") {
      for (const local of Object.values(groups.gruppen)) {
        const state = parseGroupState(local.stand);
        if (state) console.log(`${state.stand.name} ${state.stand.gid} v${local.kopf.version} valid until ${state.stand.gueltig_bis}${local.pending?.role === "invitee" && local.pending.state === "consent_sent" ? " (joining)" : ""}`);
      }
      return;
    }
    if (action === "renew") {
      const groupName = options.positionals[2];
      const entry = Object.entries(groups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      const parsed = entry && parseGroupState(entry[1].stand);
      if (!entry || !parsed || parsed.stand.gruender.name !== configuration.name) throw new CliError(4, "Only the group founder can renew its state.");
      const signingKey = await key(options);
      if (!Buffer.from(signingKey.signaturOeffentlich).equals(Buffer.from(parsed.stand.gruender.sig))) throw new CliError(4, "Founder signing key does not match the group.");
      const now = new Date();
      const next = { ...parsed.stand, version: parsed.stand.version + 1, vorgaenger_hash: hashGroupState(parsed.stand), zeit: now.toISOString(), gueltig_bis: new Date(now.getTime() + 30 * 86400000).toISOString() };
      const signed: SignedGroupState = { stand: next, unterschrift: signGroupState(next, signingKey.signaturPrivat) };
      const response = await submitGroupState(configuration.server, signed, configuration.name, signingKey.signaturPrivat);
      if (isClientError(response)) throw new CliError(2, "Could not renew group state.");
      setGroupState(groups, entry[0], signed, hashGroupState(next));
      await saveGroups(path, groups);
      return;
    }
    if (action === "members") {
      const name = options.positionals[2];
      const entry = Object.entries(groups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === name);
      const state = entry ? parseGroupState(entry[1].stand) : undefined;
      if (!state) throw new CliError(4, "Group is not stored on this agent.");
      for (const member of state.stand.mitglieder) console.log(`${member.name} ${fingerprint(member.sig, member.box)}`);
      if (entry?.[1].pending?.role === "invitee" && entry[1].pending.state === "consent_sent") console.log(`joining: waiting for ${state.stand.gruender.name} to publish the new version`);
      return;
    }
    if (action === "ack") {
      const groupName = options.positionals[2], memberName = options.positionals[3];
      const entry = Object.entries(groups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      if (!entry || !memberName || !parseGroupState(entry[1].stand)?.stand.mitglieder.some((member) => member.name === memberName)) throw new CliError(4, "Group member was not found.");
      if (!entry[1].ack.includes(memberName)) entry[1].ack.push(memberName);
      await saveGroups(path, groups);
      return;
    }
    if (action === "leave") {
      const groupName = options.positionals[2];
      const entry = Object.entries(groups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      const parsed = entry && parseGroupState(entry[1].stand);
      if (!entry || !parsed || !parsed.stand.mitglieder.some((member) => member.name === configuration.name)) throw new CliError(4, "Group is not stored on this agent.");
      const signingKey = await key(options);
      const leaveBase = { gid: entry[0], name: configuration.name, ab_version: parsed.stand.version, zeit: new Date().toISOString() };
      const leave = { ...leaveBase, unterschrift: signGroupLeave(leaveBase, signingKey.signaturPrivat) };
      const response = await submitGroupLeave(configuration.server, leave, configuration.name, signingKey.signaturPrivat);
      if (isClientError(response)) throw new CliError(2, "Could not register group departure.");
      if (!entry[1].ausgetreten.includes(configuration.name)) entry[1].ausgetreten.push(configuration.name);
      await saveGroups(path, groups);
      return;
    }
    if (action === "remove") {
      const groupName = options.positionals[2], memberName = options.positionals[3];
      const entry = Object.entries(groups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      const parsed = entry && parseGroupState(entry[1].stand);
      if (!entry || !parsed || !memberName || parsed.stand.gruender.name !== configuration.name) throw new CliError(4, "Only the group founder can remove a member.");
      if (memberName === configuration.name || !parsed.stand.mitglieder.some((member) => member.name === memberName)) throw new CliError(4, "Group member was not found.");
      const signingKey = await key(options);
      if (!Buffer.from(signingKey.signaturOeffentlich).equals(Buffer.from(parsed.stand.gruender.sig))) throw new CliError(4, "Founder signing key does not match the group.");
      const now = new Date();
      const next = { ...parsed.stand, version: parsed.stand.version + 1, vorgaenger_hash: hashGroupState(parsed.stand), zeit: now.toISOString(), gueltig_bis: new Date(now.getTime() + 30 * 86400000).toISOString(), mitglieder: parsed.stand.mitglieder.filter((member) => member.name !== memberName) };
      const signed: SignedGroupState = { stand: next, unterschrift: signGroupState(next, signingKey.signaturPrivat) };
      const response = await submitGroupState(configuration.server, signed, configuration.name, signingKey.signaturPrivat);
      if (isClientError(response)) throw new CliError(2, "Could not publish group removal.");
      setGroupState(groups, entry[0], signed, hashGroupState(next));
      await saveGroups(path, groups);
      return;
    }
    if (action === "invite") {
      const groupName = options.positionals[2], memberName = options.positionals[3];
      const entry = Object.entries(groups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      const parsed = entry && parseGroupState(entry[1].stand);
      if (!entry || !parsed || !memberName || parsed.stand.gruender.name !== configuration.name) throw new CliError(4, "Only the group founder can invite a member.");
      if (parsed.stand.mitglieder.length >= MAX_GROUP_MEMBERS) throw new CliError(4, `Group ${groupName} is full (${MAX_GROUP_MEMBERS} members).`);
      if (!/^[a-z][a-z0-9-]{1,31}$/.test(memberName) || !configuration.trusted[memberName]) throw new CliError(4, "Group invitations require a valid direct trusted contact.");
      if (parsed.stand.mitglieder.some((member) => member.name === memberName)) throw new CliError(4, "Agent is already a group member.");
      const signingKey = await key(options);
      if (!Buffer.from(signingKey.signaturOeffentlich).equals(Buffer.from(parsed.stand.gruender.sig))) throw new CliError(4, "Founder signing key does not match the group.");
      await queueOrSendGroupInvitation(configuration, signingKey, groups, entry[0], entry[1], memberName, path, options.flags.has("--now"));
      return;
    }
    if (action === "code") {
      const groupName = options.positionals[2], memberName = options.positionals[3];
      let currentGroups = groups;
      let entry = Object.entries(currentGroups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
      let parsed = entry && parseGroupState(entry[1].stand);
      let pending = entry?.[1].pending?.[memberName ?? ""];
      const waitValue = singleOption(options, "--wait");
      let waitSeconds = 0;
      if (waitValue !== undefined) {
        if (!/^\d+$/.test(waitValue) || Number(waitValue) > 900) throw new CliError(1, "--wait must be an integer from 0 to 900 seconds.");
        waitSeconds = Number(waitValue);
      }
      const deadline = Date.now() + waitSeconds * 1000;
      while (waitSeconds > 0 && (!isObject(pending) || typeof pending.nonce_member !== "string")) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        await new Promise((resolve) => setTimeout(resolve, Math.min(2000, remaining)));
        currentGroups = await loadGroups(path);
        entry = Object.entries(currentGroups.gruppen).find(([, local]) => parseGroupState(local.stand)?.stand.name === groupName);
        parsed = entry && parseGroupState(entry[1].stand);
        pending = entry?.[1].pending?.[memberName ?? ""];
      }
      if (!entry || !parsed || !memberName || parsed.stand.gruender.name !== configuration.name || !isObject(pending) || typeof pending.nonce_founder !== "string" || typeof pending.nonce_member !== "string" || typeof pending.stand_hash !== "string") throw new CliError(2, "Pairing code is not ready; fetch the member's response first.");
      const code = groupAdmissionCode(entry[0], new Uint8Array(Buffer.from(pending.stand_hash, "base64")), new Uint8Array(Buffer.from(pending.nonce_founder, "base64")), new Uint8Array(Buffer.from(pending.nonce_member, "base64")));
      console.log("Pairing code: " + code);
      return;
    }
    throw new CliError(1, "Use subspace group --help.");
  }
  if (command === "setup") return createSetup({
    name: singleOption(options, "--name", true)!,
    server: singleOption(options, "--server", true)!,
    directory: singleOption(options, "--dir", true)!,
  });
  if (command === "connect") {
    const token = options.positionals[1];
    if (!token || options.positionals.length !== 2) throw new CliError(1, "A connect token is required.");
    return connectAgent(token, { dir: singleOption(options, "--dir", true)!, name: singleOption(options, "--name") });
  }
  if (command === "trust") return trustContact({
    configPath: globalConfigPath(options),
    name: singleOption(options, "--name", true)!,
    signature: singleOption(options, "--signature", true)!,
    box: singleOption(options, "--box", true)!,
    fingerprint: singleOption(options, "--fingerprint"),
  });
  if (command === "key" && options.positionals[1] === "generate") return generateKey(options);
  if (command === "key" && options.positionals[1] === "rotate") return rotateKey(globalConfigPath(options), singleOption(options, "--key", true)!, options.flags.has("--resume"));
  if (command === "key" && options.positionals[1] === "revoke") return revokeKey(globalConfigPath(options), singleOption(options, "--key", true)!);
  if (command === "key" && options.positionals[1] === "dispute") return disputeKey(resolveConfigPath(singleOption(options, "--config")), singleOption(options, "--key", true)!);
  if (command === "accept") {
    const configPath = globalConfigPath(options);
    return acceptKey(configPath, singleOption(options, "--key") ?? await defaultKeyPath(configPath), options.positionals[1] ?? "");
  }
  if (command === "public") return publicKey(options);
  if (command === "send") return send(options);
  if (command === "fetch") return fetchMessages(options);
  if (command === "status") return messageStatus(options);
  if (await runAccountCommand(command ?? "", options)) return;
  if (await runJoinCommand(command ?? "", options)) return;
  throw new CliError(1, "Unknown command. Use subspace help.");
}
