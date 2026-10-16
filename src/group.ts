import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "node:crypto";
import { hashWithPurpose, type ProtocolField } from "./protocol.ts";

const utf8 = new TextEncoder();
const NAME = /^[a-z][a-z0-9-]{1,31}$/;
const ZERO = new Uint8Array(32);
const MAX_AGE = 30 * 24 * 60 * 60 * 1000;
export const MAX_GROUP_MEMBERS = 64;

export interface GroupMember {
  name: string;
  sig: Uint8Array;
  box: Uint8Array;
  seit_version: number;
  // sealed format, keep
  aufnahme: "gruendung" | "code" | "link";
  // sealed format, keep
  zustimmung: Uint8Array;
  // sealed format, keep
  zustimmung_zeit: string | null;
}
export interface GroupState {
  instanz: string;
  gid: string;
  name: string;
  version: number;
  vorgaenger_hash: Uint8Array;
  // sealed format, keep
  gueltig_bis: string;
  // sealed format, keep
  gruender: { name: string; sig: Uint8Array; box: Uint8Array };
  // sealed format, keep
  mitglieder: GroupMember[];
  zeit: string;
}
export interface SignedGroupState {
  // sealed format, keep
  stand: GroupState;
  unterschrift: Uint8Array;
}
export interface GroupConsent { gid: string;
  // wire format, keep
  stand_hash: Uint8Array; name: string; sig: Uint8Array; box: Uint8Array; zeit: string; unterschrift: Uint8Array }
export interface GroupLeave { gid: string; name: string; ab_version: number; zeit: string; unterschrift: Uint8Array }
export interface GroupInvitation { gid: string; stand_hash: Uint8Array; fuer: string; zeit: string; unterschrift: Uint8Array }

function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}
function validDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
  if (!match) return false;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return false;
  const parsed = new Date(timestamp);
  return parsed.getUTCFullYear() === Number(match[1]) && parsed.getUTCMonth() + 1 === Number(match[2])
    && parsed.getUTCDate() === Number(match[3]) && parsed.getUTCHours() === Number(match[4])
    && parsed.getUTCMinutes() === Number(match[5]) && parsed.getUTCSeconds() === Number(match[6])
    && parsed.getUTCMilliseconds() === Number((match[7] ?? "0").padEnd(3, "0"));
}
export function validateNames(...names: string[]): boolean { return names.every((name) => NAME.test(name)); }

export function createGroupId(instanz: string, founder: string, key: Uint8Array, randomness: Uint8Array = new Uint8Array(randomBytes(16))): string {
  if (!validateNames(founder) || key.length !== 32 || randomness.length !== 16) throw new RangeError("Invalid group identifier inputs.");
  return Buffer.from(hashWithPurpose("subspace-gruppe-v1", "gid", [["instanz", utf8.encode(instanz)], ["gruender", utf8.encode(founder)], ["schluessel", key], ["zufall", randomness]])).toString("hex");
}

export function groupStateFields(s: GroupState): ProtocolField[] {
  if (!Number.isInteger(s.version) || s.version < 1 || s.version > 0xffffffff) throw new RangeError("Group version must be uint32 starting at one.");
  if (s.vorgaenger_hash.length !== 32) throw new RangeError("Previous hash must be 32 bytes.");
  const members = utf8.encode(JSON.stringify(s.mitglieder.map((m) => ({ name: m.name, sig: Buffer.from(m.sig).toString("base64"), box: Buffer.from(m.box).toString("base64"), seit_version: m.seit_version, aufnahme: m.aufnahme }))));
  return [["instanz", utf8.encode(s.instanz)], ["gid", utf8.encode(s.gid)], ["name", utf8.encode(s.name)], ["version", uint32(s.version)], ["vorgaenger_hash", s.vorgaenger_hash], ["gueltig_bis", utf8.encode(s.gueltig_bis)], ["gruender_name", utf8.encode(s.gruender.name)], ["gruender_sig", s.gruender.sig], ["gruender_box", s.gruender.box], ["mitglieder", members], ["zeit", utf8.encode(s.zeit)]];
}
export function hashGroupState(s: GroupState): Uint8Array { return hashWithPurpose("subspace-gruppenstand-v1", "gruppenstand", groupStateFields(s)); }
export function signGroupState(s: GroupState, privateKey: Uint8Array): Uint8Array { return ed25519.sign(hashGroupState(s), privateKey); }

function validateState(s: GroupState, instance: string): boolean {
  if (s.instanz !== instance || !/^[0-9a-f]{64}$/.test(s.gid) || !validateNames(s.name, s.gruender.name)) return false;
  if (!Number.isInteger(s.version) || s.version < 1 || s.version > 0xffffffff || s.vorgaenger_hash.length !== 32) return false;
  if (s.version === 1 ? !Buffer.from(s.vorgaenger_hash).equals(Buffer.from(ZERO)) : Buffer.from(s.vorgaenger_hash).equals(Buffer.from(ZERO))) return false;
  if (!validDate(s.zeit) || !validDate(s.gueltig_bis)) return false;
  const delta = Date.parse(s.gueltig_bis) - Date.parse(s.zeit);
  if (delta <= 0 || delta > MAX_AGE || s.mitglieder.length < 1 || s.mitglieder.length > MAX_GROUP_MEMBERS) return false;
  if (s.gruender.sig.length !== 32 || s.gruender.box.length !== 32) return false;
  const names = new Set<string>();
  for (const m of s.mitglieder) {
    if (!validateNames(m.name) || names.has(m.name) || m.sig.length !== 32 || m.box.length !== 32
      || !Number.isInteger(m.seit_version) || m.seit_version < 1 || m.seit_version > s.version
      || !["gruendung", "code", "link"].includes(m.aufnahme) || (m.name === s.gruender.name ? m.aufnahme !== "gruendung" : m.aufnahme === "gruendung")
      || (m.name === s.gruender.name ? m.zustimmung.length !== 0 || m.zustimmung_zeit !== null : m.zustimmung.length !== 64 || typeof m.zustimmung_zeit !== "string" || !validDate(m.zustimmung_zeit))) return false;
    names.add(m.name);
  }
  const founder = s.mitglieder.find((m) => m.name === s.gruender.name);
  return Boolean(founder && Buffer.from(founder.sig).equals(Buffer.from(s.gruender.sig)) && Buffer.from(founder.box).equals(Buffer.from(s.gruender.box)));
}
export function verifyGroupState(value: SignedGroupState, instance: string, pinnedFounder: Uint8Array): boolean {
  try { return Boolean(value.unterschrift.length === 64 && validateState(value.stand, instance)
    && Buffer.from(value.stand.gruender.sig).equals(Buffer.from(pinnedFounder))
    && ed25519.verify(value.unterschrift, hashGroupState(value.stand), pinnedFounder)
    && value.stand.mitglieder.filter((member) => member.name !== value.stand.gruender.name && member.seit_version === value.stand.version).every((member) => verifyGroupConsent({
      gid: value.stand.gid, stand_hash: hashGroupState(value.stand), name: member.name, sig: member.sig, box: member.box,
      zeit: member.zustimmung_zeit!, unterschrift: member.zustimmung,
    }))); } catch { return false; }
}

export type GroupRevisionResult = {
  status: "aktuell" | "neu" | "zurueck" | "fork" | "ungueltig";
  head: { version: number; hash: Uint8Array };
  proofs?: SignedGroupState[];
};
export function validateRevision(incoming: SignedGroupState, current: SignedGroupState, instance: string, founder: Uint8Array): GroupRevisionResult {
  const currentHash = hashGroupState(current.stand);
  const incomingHash = hashGroupState(incoming.stand);
  const head = { version: current.stand.version, hash: currentHash };
  if (!verifyGroupState(incoming, instance, founder)) return { status: "ungueltig", head };
  if (incoming.stand.version < current.stand.version) return { status: "zurueck", head };
  if (incoming.stand.version === current.stand.version) {
    if (Buffer.from(incomingHash).equals(Buffer.from(currentHash))) return { status: "aktuell", head };
    if (Buffer.from(incoming.stand.vorgaenger_hash).equals(Buffer.from(current.stand.vorgaenger_hash))) return { status: "fork", head, proofs: [current, incoming] };
    return { status: "ungueltig", head };
  }
  if (incoming.stand.version !== current.stand.version + 1 || !Buffer.from(incoming.stand.vorgaenger_hash).equals(Buffer.from(currentHash))) return { status: "ungueltig", head };
  const incomingByName = new Map(incoming.stand.mitglieder.map((member) => [member.name, member]));
  for (const prior of current.stand.mitglieder) {
    const updated = incomingByName.get(prior.name);
    const readmitted = Boolean(updated && Buffer.from(updated.sig).equals(Buffer.from(prior.sig)) && Buffer.from(updated.box).equals(Buffer.from(prior.box))
      && updated.aufnahme === prior.aufnahme && updated.seit_version > prior.seit_version && updated.seit_version === incoming.stand.version);
    if (updated && (!Buffer.from(updated.sig).equals(Buffer.from(prior.sig)) || !Buffer.from(updated.box).equals(Buffer.from(prior.box))
      || updated.seit_version !== prior.seit_version || updated.aufnahme !== prior.aufnahme
      || !Buffer.from(updated.zustimmung).equals(Buffer.from(prior.zustimmung)) || updated.zustimmung_zeit !== prior.zustimmung_zeit) && !readmitted) {
      return { status: "ungueltig", head };
    }
  }
  if (incoming.stand.mitglieder.some((member) => !current.stand.mitglieder.some((prior) => prior.name === member.name) && member.seit_version !== incoming.stand.version)) return { status: "ungueltig", head };
  return { status: "neu", head: { version: incoming.stand.version, hash: incomingHash } };
}

const required = ["instanz","gid","name","version","vorgaenger_hash","gueltig_bis","gruender","mitglieder","zeit"];
function object(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function decode(value: unknown, length: number): Uint8Array | undefined {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return;
  const bytes = Buffer.from(value, "base64");
  return bytes.length === length && bytes.toString("base64") === value ? new Uint8Array(bytes) : undefined;
}
export function groupStateJson(value: SignedGroupState): Record<string, unknown> {
  const s = value.stand;
  return { stand: { ...s, vorgaenger_hash: Buffer.from(s.vorgaenger_hash).toString("base64"), gruender: { ...s.gruender, sig: Buffer.from(s.gruender.sig).toString("base64"), box: Buffer.from(s.gruender.box).toString("base64") }, mitglieder: s.mitglieder.map((m) => ({ ...m, sig: Buffer.from(m.sig).toString("base64"), box: Buffer.from(m.box).toString("base64"), zustimmung: Buffer.from(m.zustimmung).toString("base64") })) }, unterschrift: Buffer.from(value.unterschrift).toString("base64") };
}
export function parseGroupState(raw: unknown): SignedGroupState | undefined {
  if (!object(raw) || Object.keys(raw).length !== 2 || !object(raw.stand) || typeof raw.unterschrift !== "string") return;
  const s = raw.stand;
  if (Object.keys(s).length !== required.length || required.some((key) => !Object.hasOwn(s, key)) || typeof s.instanz !== "string" || typeof s.gid !== "string" || typeof s.name !== "string" || typeof s.version !== "number" || typeof s.gueltig_bis !== "string" || typeof s.zeit !== "string" || !object(s.gruender) || !Array.isArray(s.mitglieder)) return;
  if (Object.keys(s.gruender).length !== 3 || Object.keys(s.gruender).sort().join(",") !== "box,name,sig" || typeof s.gruender.name !== "string") return;
  const prev = decode(s.vorgaenger_hash, 32), founderSig = decode(s.gruender.sig, 32), founderBox = decode(s.gruender.box, 32), signature = decode(raw.unterschrift, 64);
  if (!prev || !founderSig || !founderBox || !signature) return;
  const members: GroupMember[] = [];
  for (const entry of s.mitglieder) {
    if (!object(entry) || Object.keys(entry).sort().join(",") !== "aufnahme,box,name,seit_version,sig,zustimmung,zustimmung_zeit" || typeof entry.name !== "string" || typeof entry.seit_version !== "number" || (entry.aufnahme !== "gruendung" && entry.aufnahme !== "code" && entry.aufnahme !== "link") || (entry.zustimmung_zeit !== null && typeof entry.zustimmung_zeit !== "string")) return;
    const sig = decode(entry.sig, 32), box = decode(entry.box, 32), consent = entry.zustimmung === "" ? new Uint8Array() : decode(entry.zustimmung, 64);
    if (!sig || !box || !consent) return;
    members.push({ name: entry.name, sig, box, seit_version: entry.seit_version, aufnahme: entry.aufnahme, zustimmung: consent, zustimmung_zeit: entry.zustimmung_zeit as string | null });
  }
  return { stand: { instanz: s.instanz, gid: s.gid, name: s.name, version: s.version, vorgaenger_hash: prev, gueltig_bis: s.gueltig_bis, gruender: { name: s.gruender.name, sig: founderSig, box: founderBox }, mitglieder: members, zeit: s.zeit }, unterschrift: signature };
}

export function groupCode(transcript: Uint8Array): string {
  const digest = hashWithPurpose("subspace-gruppe-code-v1", "code", [["transkript", transcript]]);
  let value = 0n;
  for (const byte of digest.subarray(0, 8)) value = (value << 8n) | BigInt(byte);
  return (value % 1_000_000n).toString().padStart(6, "0");
}

export function createGroupNonce(): Uint8Array { return new Uint8Array(randomBytes(32)); }

export function groupAdmissionCode(gid: string, stateHash: Uint8Array, founderNonce: Uint8Array, memberNonce: Uint8Array): string {
  if (!/^[0-9a-f]{64}$/.test(gid) || stateHash.length !== 32 || founderNonce.length !== 32 || memberNonce.length !== 32) {
    throw new RangeError("Invalid group code transcript.");
  }
  return groupCode(hashWithPurpose("subspace-gruppe-code-transkript-v1", "aufnahme", [
    ["gid", utf8.encode(gid)], ["stand_hash", stateHash], ["nonce_gruender", founderNonce], ["nonce_mitglied", memberNonce],
  ]));
}

function objectHash(purpose: string, fields: ProtocolField[]): Uint8Array { return hashWithPurpose("subspace-gruppe-v1", purpose, fields); }
export function hashGroupConsent(value: Omit<GroupConsent, "unterschrift">): Uint8Array {
  if (value.stand_hash.length !== 32) throw new RangeError("Group state hash must be 32 bytes.");
  return objectHash("zustimmung", [["gid", utf8.encode(value.gid)], ["stand_hash", value.stand_hash], ["name", utf8.encode(value.name)], ["sig", value.sig], ["box", value.box], ["zeit", utf8.encode(value.zeit)]]);
}
export function signGroupConsent(value: Omit<GroupConsent, "unterschrift">, privateKey: Uint8Array): Uint8Array { return ed25519.sign(hashGroupConsent(value), privateKey); }
export function verifyGroupConsent(value: GroupConsent): boolean {
  try { return validateNames(value.name) && /^[0-9a-f]{64}$/.test(value.gid) && value.stand_hash.length === 32 && value.sig.length === 32 && value.box.length === 32 && validDate(value.zeit) && value.unterschrift.length === 64 && ed25519.verify(value.unterschrift, hashGroupConsent(value), value.sig); } catch { return false; }
}
export function hashGroupLeave(value: Omit<GroupLeave, "unterschrift">): Uint8Array {
  return objectHash("austritt", [["gid", utf8.encode(value.gid)], ["name", utf8.encode(value.name)], ["ab_version", uint32(value.ab_version)], ["zeit", utf8.encode(value.zeit)]]);
}
export function signGroupLeave(value: Omit<GroupLeave, "unterschrift">, privateKey: Uint8Array): Uint8Array { return ed25519.sign(hashGroupLeave(value), privateKey); }
export function verifyGroupLeave(value: GroupLeave, memberSig: Uint8Array): boolean {
  try { return /^[0-9a-f]{64}$/.test(value.gid) && validateNames(value.name) && Number.isInteger(value.ab_version) && value.ab_version >= 1 && validDate(value.zeit) && value.unterschrift.length === 64 && ed25519.verify(value.unterschrift, hashGroupLeave(value), memberSig); } catch { return false; }
}
export function groupLeaveJson(value: GroupLeave): Record<string, unknown> {
  return { ...value, unterschrift: Buffer.from(value.unterschrift).toString("base64") };
}
export function parseGroupLeave(raw: unknown): GroupLeave | undefined {
  if (!object(raw) || Object.keys(raw).sort().join(",") !== "ab_version,gid,name,unterschrift,zeit"
    || typeof raw.gid !== "string" || typeof raw.name !== "string" || typeof raw.ab_version !== "number" || typeof raw.zeit !== "string") return;
  const signature = decode(raw.unterschrift, 64);
  if (!signature) return;
  return { gid: raw.gid, name: raw.name, ab_version: raw.ab_version, zeit: raw.zeit, unterschrift: signature };
}
export function hashGroupInvitation(value: Omit<GroupInvitation, "unterschrift">): Uint8Array {
  if (value.stand_hash.length !== 32) throw new RangeError("Group state hash must be 32 bytes.");
  return objectHash("einladung", [["gid", utf8.encode(value.gid)], ["stand_hash", value.stand_hash], ["fuer", utf8.encode(value.fuer)], ["zeit", utf8.encode(value.zeit)]]);
}
export function signGroupInvitation(value: Omit<GroupInvitation, "unterschrift">, privateKey: Uint8Array): Uint8Array { return ed25519.sign(hashGroupInvitation(value), privateKey); }
export function verifyGroupInvitation(value: GroupInvitation, founderSig: Uint8Array): boolean {
  try { return /^[0-9a-f]{64}$/.test(value.gid) && value.stand_hash.length === 32 && validateNames(value.fuer) && validDate(value.zeit) && value.unterschrift.length === 64 && ed25519.verify(value.unterschrift, hashGroupInvitation(value), founderSig); } catch { return false; }
}
