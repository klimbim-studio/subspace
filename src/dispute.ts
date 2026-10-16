import { ed25519 } from "@noble/curves/ed25519.js";
import { hashWithPurpose, type ProtocolField } from "./protocol.ts";

const utf8 = new TextEncoder();

export interface Dispute {
  name: string;
  // wire format, keep
  alter_schluessel: Uint8Array;
  // wire format, keep
  zeit: string;
  // wire format, keep
  unterschrift: Uint8Array;
}

function disputeFields(instance: string, value: Pick<Dispute, "name" | "alter_schluessel" | "zeit">): ProtocolField[] {
  return [
    ["instanz", utf8.encode(instance)],
    ["name", utf8.encode(value.name)],
    ["alter_schluessel", value.alter_schluessel],
    ["zeit", utf8.encode(value.zeit)],
  ];
}

export function hashDispute(instance: string, value: Pick<Dispute, "name" | "alter_schluessel" | "zeit">): Uint8Array {
  return hashWithPurpose("cartridge-widerspruch-v1", "widerspruch", disputeFields(instance, value)); // wire format, keep
}

export function signDispute(instance: string, value: Pick<Dispute, "name" | "alter_schluessel" | "zeit">, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(hashDispute(instance, value), privateKey);
}

export function verifyDispute(instance: string, value: Dispute): boolean {
  try {
    return value.alter_schluessel.length === 32 && value.unterschrift.length === 64
      && ed25519.verify(value.unterschrift, hashDispute(instance, value), value.alter_schluessel);
  } catch {
    return false;
  }
}

export function parseDispute(raw: unknown): Dispute | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).length !== 4 || !["name", "alter_schluessel", "zeit", "unterschrift"].every((field) => Object.hasOwn(value, field))) return undefined;
  if (typeof value.name !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(value.name)
    || typeof value.zeit !== "string" || typeof value.alter_schluessel !== "string" || typeof value.unterschrift !== "string") return undefined;
  const decode = (encoded: string, length: number): Uint8Array | undefined => {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) return undefined;
    const bytes = Buffer.from(encoded, "base64");
    return bytes.length === length && bytes.toString("base64") === encoded ? new Uint8Array(bytes) : undefined;
  };
  const oldPublicKey = decode(value.alter_schluessel, 32);
  const signature = decode(value.unterschrift, 64);
  const date = new Date(value.zeit);
  if (!oldPublicKey || !signature || !Number.isFinite(date.getTime()) || date.toISOString() !== value.zeit) return undefined;
  return { name: value.name, alter_schluessel: oldPublicKey, zeit: value.zeit, unterschrift: signature };
}

export function disputeJson(value: Dispute): Record<string, string> {
  return {
    name: value.name,
    alter_schluessel: Buffer.from(value.alter_schluessel).toString("base64"),
    zeit: value.zeit,
    unterschrift: Buffer.from(value.unterschrift).toString("base64"),
  };
}
