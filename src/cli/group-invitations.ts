import { randomBytes } from "node:crypto";
import { sealEnvelope } from "../seal.ts";
import { submitMessage, type ClientError } from "../client.ts";
import { createGroupNonce, hashGroupState, signGroupInvitation, groupStateJson, parseGroupState, MAX_GROUP_MEMBERS, type GroupInvitation } from "../group.ts";
import type { Envelope } from "../envelope.ts";
import { CliError, type Configuration } from "./shared.ts";
import { saveGroups, type GroupsFile, type LocalGroup } from "./group.ts";
import type { KeyPair } from "../seal.ts";

export const GROUP_INVITATION_TTL_MS = 72 * 60 * 60 * 1000;

function isClientError<T extends object>(value: T | ClientError): value is ClientError {
  return typeof value === "object" && value !== null && "grund" in value;
}

export function protocolText(type: string, body: Record<string, unknown>): string {
  return "subspace-group-protocol-v1\n" + JSON.stringify({ version: 1, type, body });
}

export function invitationJson(value: GroupInvitation): Record<string, unknown> {
  return { gid: value.gid, stand_hash: Buffer.from(value.stand_hash).toString("base64"), fuer: value.fuer, zeit: value.zeit, unterschrift: Buffer.from(value.unterschrift).toString("base64") };
}

export async function sendGroupProtocol(configuration: Configuration, signingKey: KeyPair, recipient: string, message: string): Promise<void> {
  const trusted = configuration.trusted[recipient];
  if (!trusted) throw new CliError(4, "Group pairing requires a direct trusted contact.");
  const now = new Date();
  const envelope: Envelope = {
    v: 1, id: randomBytes(16).toString("hex"), von: configuration.name, an: [recipient], kanal: null,
    erstellt: now.toISOString(), gueltig_bis: new Date(now.getTime() + 7 * 86400000).toISOString(),
    art: "info", bezug: null, betreff: "Group pairing", text: message, anhaenge: [],
  };
  const result = await submitMessage(configuration.server, sealEnvelope(envelope, signingKey, { [recipient]: trusted.box }), configuration.name, signingKey.signaturPrivat);
  if (isClientError(result)) throw new CliError(2, "Could not send the group pairing message.");
}

export async function sendGroupInvitation(
  configuration: Configuration,
  signingKey: KeyPair,
  groups: GroupsFile,
  gid: string,
  local: LocalGroup,
  recipient: string,
  groupsPath: string,
  queued = false,
): Promise<void> {
  const parsed = parseGroupState(local.stand);
  if (!parsed) throw new CliError(4, "Group state is invalid.");
  const current = parsed.stand;
  const invitedKeys = configuration.trusted[recipient];
  if (!invitedKeys) throw new CliError(4, "Group invitations require a valid direct trusted contact.");
  if (current.mitglieder.some((member: { name: string }) => member.name === recipient)) throw new CliError(4, "Agent is already a group member.");
  if (current.mitglieder.length >= MAX_GROUP_MEMBERS) throw new CliError(4, `Group ${current.name} is full (${MAX_GROUP_MEMBERS} members).`);

  const now = new Date();
  const targetState = {
    ...current, version: current.version + 1, vorgaenger_hash: hashGroupState(current),
    zeit: now.toISOString(), gueltig_bis: new Date(now.getTime() + 30 * 86400000).toISOString(),
    mitglieder: [...current.mitglieder, { name: recipient, sig: invitedKeys.signature, box: invitedKeys.box, seit_version: current.version + 1, aufnahme: "code" as const, zustimmung: new Uint8Array(64), zustimmung_zeit: now.toISOString() }],
  };
  const invitationBase = { gid, stand_hash: hashGroupState(targetState), fuer: recipient, zeit: now.toISOString() };
  const invitation: GroupInvitation = { ...invitationBase, unterschrift: signGroupInvitation(invitationBase, signingKey.signaturPrivat) };
  const nonceFounder = createGroupNonce();
  local.pending ??= {};
  const previous = local.pending[recipient];
  local.pending[recipient] = {
    role: "founder", state: "invited", zeit: now.toISOString(),
    stand_hash: Buffer.from(invitationBase.stand_hash).toString("base64"),
    nonce_founder: Buffer.from(nonceFounder).toString("base64"),
    target_stand: groupStateJson({ stand: targetState, unterschrift: new Uint8Array(64) }),
    invitation: invitationJson(invitation),
  };
  await saveGroups(groupsPath, groups);
  try {
    await sendGroupProtocol(configuration, signingKey, recipient, protocolText("invitation", {
    signed_state: local.stand,
    target_state: groupStateJson({ stand: targetState, unterschrift: new Uint8Array(64) }),
    invitation: invitationJson(invitation),
    nonce_founder: Buffer.from(nonceFounder).toString("base64"),
    }));
  } catch (error) {
    if (queued) {
      const old = isFounderPending(previous) && previous.state === "queued" ? previous : undefined;
      local.pending[recipient] = { role: "founder", state: "queued", ...(old?.zeit ? { zeit: old.zeit } : {}) };
    } else {
      delete local.pending[recipient];
    }
    await saveGroups(groupsPath, groups);
    throw error;
  }
  console.log(`Group invitation sent to ${recipient}${queued ? " (queued)" : ""}.`);
}

export async function sendNextQueuedGroupInvitation(configuration: Configuration, signingKey: KeyPair, groups: GroupsFile, gid: string, local: LocalGroup, groupsPath: string): Promise<void> {
  while (local.pending) {
    const now = Date.now();
    const invitationStillOpen = Object.values(local.pending).some((item) => isOpenFounderInvitation(item, now));
    if (invitationStillOpen) return;
    const queued = Object.entries(local.pending).filter(([, item]) => isFounderPending(item) && item.state === "queued")
      .sort((left, right) => {
        const leftTime = isFounderPending(left[1]) ? left[1].zeit ?? "" : "";
        const rightTime = isFounderPending(right[1]) ? right[1].zeit ?? "" : "";
        return leftTime.localeCompare(rightTime);
      })[0];
    if (!queued) return;
    const [recipient] = queued;
    const parsed = parseGroupState(local.stand);
    const current = parsed?.stand;
    const reason = !current ? "the group state is invalid"
      : !configuration.trusted[recipient] ? "no longer a direct trusted contact"
        : current.mitglieder.some((member) => member.name === recipient) ? "already a group member"
          : current.mitglieder.length >= MAX_GROUP_MEMBERS ? "the group is full" : undefined;
    if (reason) {
      delete local.pending[recipient];
      await saveGroups(groupsPath, groups);
      console.error(`Warning: queued invitation for ${recipient} was dropped because they are ${reason}.`);
      continue;
    }
    try {
      await sendGroupInvitation(configuration, signingKey, groups, gid, local, recipient, groupsPath, true);
    } catch (error) {
      throw new GroupInvitationSendError(recipient, error);
    }
    return;
  }
}

function isFounderPending(item: unknown): item is { role: "founder"; state: string; zeit?: string } {
  return typeof item === "object" && item !== null && "role" in item && item.role === "founder"
    && "state" in item && typeof item.state === "string"
    && (!("zeit" in item) || typeof item.zeit === "string");
}

function isOpenFounderInvitation(item: unknown, now: number): boolean {
  if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
  const pending = item as Record<string, unknown>;
  if (pending.role !== "founder" || !["invited", "response_received"].includes(String(pending.state))) return false;
  if (typeof pending.zeit !== "string") return true;
  const sentAt = Date.parse(pending.zeit);
  return !Number.isFinite(sentAt) || sentAt + GROUP_INVITATION_TTL_MS > now;
}

export class GroupInvitationSendError extends Error {
  constructor(readonly recipient: string, readonly cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
  }
}

export async function queueOrSendGroupInvitation(configuration: Configuration, signingKey: KeyPair, groups: GroupsFile, gid: string, local: LocalGroup, recipient: string, groupsPath: string, now = false): Promise<"queued" | "sent"> {
  const current = parseGroupState(local.stand)?.stand;
  if (!current) throw new CliError(4, "Group state is invalid.");
  if (!configuration.trusted[recipient]) throw new CliError(4, "Group invitations require a valid direct trusted contact.");
  if (current.mitglieder.some((member) => member.name === recipient)) throw new CliError(4, "Agent is already a group member.");
  if (current.mitglieder.length >= MAX_GROUP_MEMBERS) throw new CliError(4, `Group ${current.name} is full (${MAX_GROUP_MEMBERS} members).`);
  const currentTime = Date.now();
  const open = Object.entries(local.pending ?? {}).find(([name, item]) => name !== recipient && isOpenFounderInvitation(item, currentTime));
  if (open && !now) {
    local.pending ??= {};
    local.pending[recipient] = { role: "founder", state: "queued", zeit: new Date().toISOString() };
    await saveGroups(groupsPath, groups);
    const pending = isFounderPending(open[1]) ? open[1] : undefined;
    const expires = new Date(Date.parse(pending?.zeit ?? "") + GROUP_INVITATION_TTL_MS);
    const expiryText = Number.isFinite(expires.getTime()) ? ` or ${open[0]}'s invitation expires (${expires.toISOString().slice(0, 16).replace("T", " ")} UTC)` : "";
    console.log(`Queued: the invitation for ${recipient} will be sent after ${open[0]} has joined group ${current.name}${expiryText}.`);
    return "queued";
  }
  if (open) console.log(`Note: the invitation for ${open[0]} is still open. Only one invitation per group version can complete; invite the next member after ${open[0]} has joined.`);
  await sendGroupInvitation(configuration, signingKey, groups, gid, local, recipient, groupsPath);
  return "sent";
}
