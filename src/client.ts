import { signRequest } from "./request.ts";
import { retryOnRateLimit } from "./cli/network.ts";
import * as cliShared from "./cli/shared.ts";
import { groupLeaveJson as groupLeaveJson, groupStateJson as groupStateJson, parseGroupState as parseGroupState, type GroupLeave as GroupLeave, type SignedGroupState as SignedGroupState } from "./group.ts";

const CliError = cliShared.CliError;

export interface ClientOptions {
  now?: Date;
  nonce?: string;
}

export interface ClientError {
  status: number;
  // wire format, keep
  grund: string;
}

export interface MailboxEntry {
  id: string;
  von: string;
  // wire format, keep
  groesse: number;
  // wire format, keep
  eingang: string;
}

interface MailboxPage {
  // wire format, keep
  eintraege: MailboxEntry[];
  // wire format, keep
  naechster: string | null;
}

function baseUrl(base: string): string {
  return base.replace(/\/$/, "");
}

async function request(
  base: string,
  path: string,
  method: string,
  body: Uint8Array,
  name: string,
  privateKey: Uint8Array,
  opt: ClientOptions,
): Promise<Response> {
  const url = `${baseUrl(base)}${path}`;
  try {
    return await retryOnRateLimit(() => {
      const headers = signRequest({ method: method, url, body: body, name, privateKey: privateKey, now: opt.now, nonce: opt.nonce });
      return fetch(url, { method, headers, body: body.length ? Buffer.from(body) : undefined, redirect: "error", signal: AbortSignal.timeout(30_000) });
    });
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError(2, "Request to the Subspace server failed.");
  }
}

async function clientError(response: Response): Promise<ClientError> {
  let reason = "unbekannt";
  try { reason = (await response.json() as { grund?: string }).grund ?? reason; } catch { /* The body is not JSON. */ }
  return { status: response.status, grund: reason };
}

export async function submitMessage(base: string, bytes: Uint8Array, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<{ status: number; id: string } | ClientError> {
  const response = await request(base, "/v1/einliefern", "POST", bytes, name, privateKey, opt);
  if (!response.ok) return clientError(response);
  return { status: response.status, ...(await response.json() as { id: string }) };
}

export async function listMailbox(base: string, mailbox: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}, invitationNotice?: (account: string) => void): Promise<MailboxEntry[] | ClientError> {
  const path = `/v1/postfach/${encodeURIComponent(mailbox)}`;
  const first = await request(base, path, "GET", new Uint8Array(), name, privateKey, opt);
  if (!first.ok) return clientError(first);
  const linkedAccount = first.headers.get("x-subspace-invitation-account");
  if (linkedAccount && /^[a-z][a-z0-9-]{1,31}$/.test(linkedAccount)) invitationNotice?.(linkedAccount);
  const firstBody = await first.json() as MailboxEntry[] | MailboxPage;
  const entries = Array.isArray(firstBody) ? firstBody : firstBody?.eintraege;
  if (!Array.isArray(entries) || (!Array.isArray(firstBody) && (firstBody.naechster !== null && typeof firstBody.naechster !== "string"))) {
    return { status: 502, grund: "format" };
  }
  let cursor = Array.isArray(firstBody) ? linkCursor(first.headers.get("link")) : firstBody.naechster;
  const followUpOptions = { ...opt };
  delete followUpOptions.nonce;
  while (cursor) {
    const response = await request(base, `${path}?nach=${encodeURIComponent(cursor)}`, "GET", new Uint8Array(), name, privateKey, followUpOptions);
    if (!response.ok) return clientError(response);
    const page = await response.json() as MailboxPage;
    if (!Array.isArray(page.eintraege) || (page.naechster !== null && typeof page.naechster !== "string")) return { status: 502, grund: "format" };
    entries.push(...page.eintraege);
    cursor = page.naechster;
  }
  return entries;
}

function linkCursor(link: string | null): string | null {
  const match = link?.match(/<[^>]*[?&]nach=([^>;]+)>;\s*rel="next"/);
  return match ? decodeURIComponent(match[1]!) : null;
}

export async function fetchMessage(base: string, mailbox: string, id: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<Uint8Array | ClientError> {
  const response = await request(base, `/v1/postfach/${encodeURIComponent(mailbox)}/${encodeURIComponent(id)}`, "GET", new Uint8Array(), name, privateKey, opt);
  if (!response.ok) return clientError(response);
  return new Uint8Array(await response.arrayBuffer());
}

export async function acknowledge(base: string, mailbox: string, id: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<{ status: number } | ClientError> {
  const response = await request(base, `/v1/postfach/${encodeURIComponent(mailbox)}/${encodeURIComponent(id)}`, "DELETE", new Uint8Array(), name, privateKey, opt);
  return response.ok ? { status: response.status } : clientError(response);
}

export async function status(base: string, id: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<Record<string, "abgeholt" | "liegt" | "verfallen"> | ClientError> {
  const response = await request(base, `/v1/status/${encodeURIComponent(id)}`, "GET", new Uint8Array(), name, privateKey, opt);
  if (!response.ok) return clientError(response);
  return response.json() as Promise<Record<string, "abgeholt" | "liegt" | "verfallen">>;
}

export async function submitGroupState(base: string, signed: SignedGroupState, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<{ status: number } | ClientError> {
  const state = JSON.stringify(groupStateJson(signed));
  const response = await request(base, "/v1/group", "POST", new TextEncoder().encode(state), name, privateKey, opt);
  return response.ok ? { status: response.status } : clientError(response);
}

export async function fetchGroupState(base: string, gid: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<unknown | ClientError> {
  const response = await request(base, `/v1/group/${encodeURIComponent(gid)}`, "GET", new Uint8Array(), name, privateKey, opt);
  if (!response.ok) return clientError(response);
  const raw: unknown = await response.json();
  return parseGroupState(raw) ? raw : { status: 502, grund: "format" };
}

export async function listGroups(base: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<unknown[] | ClientError> {
  const response = await request(base, "/v1/groups", "GET", new Uint8Array(), name, privateKey, opt);
  if (!response.ok) return clientError(response);
  const raw: unknown = await response.json();
  return Array.isArray(raw) ? raw : { status: 502, grund: "format" };
}

export async function fetchGroupHistory(base: string, gid: string, nachVersion: number, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<unknown[] | ClientError> {
  const response = await request(base, `/v1/group/${encodeURIComponent(gid)}?after=${nachVersion}`, "GET", new Uint8Array(), name, privateKey, opt);
  if (!response.ok) return clientError(response);
  const raw: unknown = await response.json();
  return Array.isArray(raw) ? raw : { status: 502, grund: "format" };
}

export async function submitGroupLeave(base: string, leave: GroupLeave, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<{ status: number } | ClientError> {
  const body = new TextEncoder().encode(JSON.stringify(groupLeaveJson(leave)));
  const response = await request(base, `/v1/group/${encodeURIComponent(leave.gid)}/leave`, "POST", body, name, privateKey, opt);
  return response.ok ? { status: response.status } : clientError(response);
}

export async function fetchGroupLeaves(base: string, gid: string, name: string, privateKey: Uint8Array, opt: ClientOptions = {}): Promise<unknown[] | ClientError> {
  const response = await request(base, `/v1/group/${encodeURIComponent(gid)}/leaves`, "GET", new Uint8Array(), name, privateKey, opt);
  if (!response.ok) return clientError(response);
  const raw: unknown = await response.json();
  return Array.isArray(raw) ? raw : { status: 502, grund: "format" };
}
