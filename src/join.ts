// A malicious server can prevent a join, but cannot take it over.
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeFields, type ProtocolField } from "./protocol.ts";

export const VERSION = "subspace-join-v2";
const utf8 = new TextEncoder();

export function deriveInvitationKey(secret: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  if (secret.length !== 32) throw new TypeError("Invitation secret must be 32 bytes.");
  const secretKey = hkdf(sha256, secret, new Uint8Array(), utf8.encode("subspace-join-v2 invitation signing key"), 32);
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export interface JoinTranscript {
  // wire format, keep
  instanz: string;
  token: Uint8Array;
  name_I: string;
  name_J: string;
  sig_I: Uint8Array;
  box_I: Uint8Array;
  sig_J: Uint8Array;
  box_J: Uint8Array;
  c_I: Uint8Array;
  n_J: Uint8Array;
  n_I: Uint8Array;
}

function origin(instance: string): string {
  return new URL(instance).origin;
}

function hash(fields: ProtocolField[]): Uint8Array {
  return sha256(encodeFields(fields));
}

export function createJoinCommitment(instance: string, token: Uint8Array, name_I: string, sig_I: Uint8Array, box_I: Uint8Array, n_I: Uint8Array, pk_s: Uint8Array<ArrayBufferLike>): Uint8Array {
  return hash([
    ["ctx", utf8.encode(VERSION)], ["instanz", utf8.encode(origin(instance))], ["token", token],
    ["name_I", utf8.encode(name_I)], ["sig_I", sig_I], ["box_I", box_I], ["n_I", n_I], ["pk_s", pk_s],
  ]);
}

export function transcriptFields(p: JoinTranscript): ProtocolField[] {
  return [
    ["ctx", utf8.encode(VERSION)], ["instanz", utf8.encode(origin(p.instanz))], ["token", p.token],
    ["name_I", utf8.encode(p.name_I)], ["name_J", utf8.encode(p.name_J)], ["sig_I", p.sig_I],
    ["box_I", p.box_I], ["sig_J", p.sig_J], ["box_J", p.box_J], ["c_I", p.c_I], ["n_J", p.n_J], ["n_I", p.n_I],
  ];
}

export function transcriptHash(p: JoinTranscript): Uint8Array {
  return hash(transcriptFields(p));
}

export function code(p: JoinTranscript): string {
  const digest = hash([["zweck", utf8.encode("code")], ["protokoll", transcriptHash(p)]]);
  let value = 0n;
  for (const byte of digest.subarray(0, 8)) value = (value << 8n) | BigInt(byte);
  return (value % 1_000_000n).toString().padStart(6, "0");
}

export function checkCodeAttempt(input: string, expected: string, priorFailures = 0): { accepted: boolean; failures: number; burned: boolean } {
  if (!Number.isInteger(priorFailures) || priorFailures < 0 || priorFailures > 3) throw new RangeError("Invalid code failure count.");
  if (priorFailures >= 3) return { accepted: false, failures: 3, burned: true };
  if (input.length === 0) return { accepted: false, failures: priorFailures, burned: false };
  if (input === expected) return { accepted: true, failures: priorFailures, burned: false };
  const failures = priorFailures + 1;
  return { accepted: false, failures, burned: failures === 3 };
}

export interface RedemptionData {
  // wire format, keep
  instanz: string;
  token: Uint8Array;
  name_J: string;
  sig_J: Uint8Array;
  box_J: Uint8Array;
  c_I: Uint8Array;
  n_J: Uint8Array;
}

export function redemptionMessage(p: RedemptionData): Uint8Array {
  return hash([
    ["ctx", utf8.encode(VERSION)], ["instanz", utf8.encode(origin(p.instanz))], ["token", p.token],
    ["name_J", utf8.encode(p.name_J)], ["sig_J", p.sig_J], ["box_J", p.box_J], ["c_I", p.c_I], ["n_J", p.n_J],
  ]);
}

function message(purpose: "oeffnung" | "bestaetigung", p: JoinTranscript): Uint8Array {
  return hash([["zweck", utf8.encode(purpose)], ["protokoll", transcriptHash(p)]]);
}

export function openingMessage(p: JoinTranscript): Uint8Array {
  return message("oeffnung", p);
}

export function confirmationMessage(p: JoinTranscript): Uint8Array {
  return message("bestaetigung", p);
}
