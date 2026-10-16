import { chmod, lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { CliError, atomicWrite } from "./shared.ts";
import { hashGroupState, parseGroupState, groupStateJson, type SignedGroupState } from "../group.ts";

export interface LocalGroup {
  stand: Record<string, unknown>;
  // on-disk format, keep
  kopf: { version: number; hash: string };
  ack: string[];
  ausgetreten: string[];
  austritte?: { name: string; ab_version: number }[]; // on-disk format, keep
  gepruefteVersionen?: Record<string, { hash: string; mitglieder: { name: string; seit_version: number; sig: string; box: string }[]; signed?: Record<string, unknown> }>; // on-disk format, keep
  gabelungen: Record<string, unknown>[]; // on-disk format, keep
  pending?: Record<string, unknown>;
  syncFailed?: boolean;
}
export interface GroupsFile { version: 1; gruppen: Record<string, LocalGroup> } // on-disk format, keep

export function groupsFilePath(storage: string): string { return join(storage, "groups.json"); }

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function loadGroups(path: string): Promise<GroupsFile> {
  try {
    const info = await lstat(path).catch(() => undefined);
    if (!info) return { version: 1, gruppen: {} };
    if (!info.isFile() || info.uid !== (process.getuid?.() ?? -1) || (info.mode & 0o777) !== 0o600) throw new Error();
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!isRecord(value)) throw new Error();
    const raw = value;
    if (Object.keys(raw).sort().join(",") !== "gruppen,version" || raw.version !== 1 || !raw.gruppen || typeof raw.gruppen !== "object" || Array.isArray(raw.gruppen)) throw new Error();
    const groups = raw.gruppen;
    if (!isRecord(groups)) throw new Error();
    for (const local of Object.values(groups)) {
      if (!isRecord(local) || !(["ack,ausgetreten,gabelungen,kopf,stand", "ack,ausgetreten,gabelungen,kopf,pending,stand", "ack,ausgetreten,gabelungen,kopf,stand,syncFailed", "ack,ausgetreten,gabelungen,kopf,pending,stand,syncFailed"].includes(Object.keys(local).filter((key) => !["austritte", "gepruefteVersionen"].includes(key)).sort().join(",")))
        || !isRecord(local.kopf) || Object.keys(local.kopf).sort().join(",") !== "hash,version"
        || !Number.isInteger(local.kopf.version) || typeof local.kopf.hash !== "string" || !/^[0-9a-f]{64}$/.test(local.kopf.hash)
        || !Array.isArray(local.ack) || local.ack.some((name) => typeof name !== "string")
        || !Array.isArray(local.ausgetreten) || local.ausgetreten.some((name) => typeof name !== "string")
        || (local.austritte !== undefined && (!Array.isArray(local.austritte) || local.austritte.some((leave) => !isRecord(leave) || typeof leave.name !== "string" || !Number.isInteger(leave.ab_version) || Number(leave.ab_version) < 1)))
        || (local.gepruefteVersionen !== undefined && (!isRecord(local.gepruefteVersionen) || Object.entries(local.gepruefteVersionen).some(([version, state]) => !/^\d+$/.test(version) || !isRecord(state) || typeof state.hash !== "string" || !/^[0-9a-f]{64}$/.test(state.hash) || (state.signed !== undefined && !isRecord(state.signed)) || !Array.isArray(state.mitglieder) || state.mitglieder.some((member) => !isRecord(member) || typeof member.name !== "string" || !Number.isInteger(member.seit_version) || Number(member.seit_version) < 1 || typeof member.sig !== "string" || typeof member.box !== "string"))))
        || !Array.isArray(local.gabelungen) || !isRecord(local.stand) || (local.pending !== undefined && !isRecord(local.pending)) || (local.syncFailed !== undefined && typeof local.syncFailed !== "boolean")) throw new Error();
    }
    return { version: 1, gruppen: groups as GroupsFile["gruppen"] };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(3, "groups.json is invalid or unsafe.");
  }
}

export async function saveGroups(path: string, groups: GroupsFile): Promise<void> {
  await atomicWrite(path, JSON.stringify(groups) + "\n");
  await chmod(path, 0o600);
}

// The server accepts group messages only until expiry; mailbox lifetime is at most 30 days, plus one day for clock skew.
const GROUP_STATE_RETENTION_MS = 31 * 86400000;

export function setGroupState(groups: GroupsFile, gid: string, signed: SignedGroupState, hash: Uint8Array, now = new Date()): void {
  const parsed = parseGroupState(groupStateJson(signed));
  if (!parsed) throw new CliError(3, "Invalid group state.");
  const existing = groups.gruppen[gid];
  if (existing && parsed.stand.version < existing.kopf.version) throw new CliError(3, "Group version rollback rejected.");
  if (existing && parsed.stand.version === existing.kopf.version && Buffer.from(hash).toString("hex") !== existing.kopf.hash) {
    const hashes = new Set([existing.kopf.hash, Buffer.from(hash).toString("hex")]);
    existing.gabelungen.push({ version: parsed.stand.version, hashes: [...hashes] });
    throw new CliError(3, "Group fork detected; sending is stopped.");
  }
  let pending = existing?.pending && structuredClone(existing.pending);
  if (pending && pending.role !== "invitee") {
    for (const name of Object.keys(pending)) {
      const invitation = isRecord(pending[name]) ? pending[name] : undefined;
      const target = invitation && parseGroupState(invitation.target_stand);
      const expected = target?.stand.mitglieder.find((member) => member.name === name);
      const admitted = parsed.stand.mitglieder.find((member) => member.name === name);
      if (expected && admitted && Buffer.from(admitted.sig).equals(Buffer.from(expected.sig)) && Buffer.from(admitted.box).equals(Buffer.from(expected.box))) delete pending[name];
    }
    if (Object.keys(pending).length === 0) pending = undefined;
  } else if (pending?.role === "invitee" && pending.target_stand) {
    const target = parseGroupState(pending.target_stand); // on-disk format, keep
    const invited = target?.stand.mitglieder.find((member) => !existing || !parseGroupState(existing.stand)?.stand.mitglieder.some((old) => old.name === member.name));
    if (invited && parsed.stand.mitglieder.some((member) => member.name === invited.name
      && Buffer.from(member.sig).equals(Buffer.from(invited.sig)) && Buffer.from(member.box).equals(Buffer.from(invited.box)))) pending = undefined;
  }
  const verifiedVersions = { ...(existing?.gepruefteVersionen ?? {}) };
  if (existing && !verifiedVersions[String(existing.kopf.version)]) {
    const oldState = parseGroupState(existing.stand);
    if (oldState && oldState.stand.version === existing.kopf.version && Buffer.from(hashGroupState(oldState.stand)).toString("hex") === existing.kopf.hash) {
      verifiedVersions[String(existing.kopf.version)] = { hash: existing.kopf.hash, signed: groupStateJson(oldState), mitglieder: oldState.stand.mitglieder.map(({ name, seit_version, sig, box }) => ({ name, seit_version, sig: Buffer.from(sig).toString("base64"), box: Buffer.from(box).toString("base64") })) };
    }
  }
  for (const [version, state] of Object.entries(verifiedVersions)) {
    if (version === String(parsed.stand.version) || !state.signed) continue;
    const previousState = parseGroupState(state.signed);
    if (previousState && Date.parse(previousState.stand.gueltig_bis) + GROUP_STATE_RETENTION_MS <= now.getTime()) delete verifiedVersions[version];
  }
  groups.gruppen[gid] = {
    stand: groupStateJson(parsed),
    kopf: { version: parsed.stand.version, hash: Buffer.from(hash).toString("hex") },
    ack: existing?.ack ?? [], ausgetreten: existing?.ausgetreten ?? [], gabelungen: existing?.gabelungen ?? [],
    austritte: existing?.austritte ?? [],
    gepruefteVersionen: { ...verifiedVersions, [String(parsed.stand.version)]: {
      hash: Buffer.from(hash).toString("hex"), signed: groupStateJson(parsed), mitglieder: parsed.stand.mitglieder.map(({ name, seit_version, sig, box }) => ({ name, seit_version, sig: Buffer.from(sig).toString("base64"), box: Buffer.from(box).toString("base64") })),
    } },
    ...(pending ? { pending } : {}),
    ...(existing?.syncFailed ? { syncFailed: true } : {}),
  };
}

export function requireActiveHead(group: LocalGroup, now = new Date()): void {
  if (group.pending?.role === "invitee" && ["awaiting_code", "consent_sent"].includes(String(group.pending.state))) {
    throw new CliError(3, "Group invitation is still pending; group sending is stopped until you join.");
  }
  if (group.syncFailed) throw new CliError(3, "Group synchronization failed; sending is stopped until the next successful fetch.");
  if (group.gabelungen.length) throw new CliError(3, "Group fork detected; sending is stopped.");
  const state = parseGroupState(group.stand);
  if (!state || Date.parse(state.stand.gueltig_bis) <= now.getTime()) throw new CliError(3, "Group state expired; sending is stopped.");
}
