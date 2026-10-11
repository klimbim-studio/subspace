import { ed25519 } from "@noble/curves/ed25519.js";
import { hashMitZweck, type Protokollfeld } from "./protokoll.ts";

const utf8 = new TextEncoder();

export interface Widerspruch {
  name: string;
  alter_schluessel: Uint8Array;
  zeit: string;
  unterschrift: Uint8Array;
}

function felderWiderspruch(instanz: string, value: Pick<Widerspruch, "name" | "alter_schluessel" | "zeit">): Protokollfeld[] {
  return [
    ["instanz", utf8.encode(instanz)],
    ["name", utf8.encode(value.name)],
    ["alter_schluessel", value.alter_schluessel],
    ["zeit", utf8.encode(value.zeit)],
  ];
}

export function hashWiderspruch(instanz: string, value: Pick<Widerspruch, "name" | "alter_schluessel" | "zeit">): Uint8Array {
  return hashMitZweck("cartridge-widerspruch-v1", "widerspruch", felderWiderspruch(instanz, value));
}

export function signiereWiderspruch(instanz: string, value: Pick<Widerspruch, "name" | "alter_schluessel" | "zeit">, privaterSchluessel: Uint8Array): Uint8Array {
  return ed25519.sign(hashWiderspruch(instanz, value), privaterSchluessel);
}

export function pruefeWiderspruch(instanz: string, value: Widerspruch): boolean {
  try {
    return value.alter_schluessel.length === 32 && value.unterschrift.length === 64
      && ed25519.verify(value.unterschrift, hashWiderspruch(instanz, value), value.alter_schluessel);
  } catch {
    return false;
  }
}

export function parseWiderspruch(raw: unknown): Widerspruch | undefined {
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
  const alter_schluessel = decode(value.alter_schluessel, 32);
  const unterschrift = decode(value.unterschrift, 64);
  const date = new Date(value.zeit);
  if (!alter_schluessel || !unterschrift || !Number.isFinite(date.getTime()) || date.toISOString() !== value.zeit) return undefined;
  return { name: value.name, alter_schluessel, zeit: value.zeit, unterschrift };
}

export function widerspruchJson(value: Widerspruch): Record<string, string> {
  return {
    name: value.name,
    alter_schluessel: Buffer.from(value.alter_schluessel).toString("base64"),
    zeit: value.zeit,
    unterschrift: Buffer.from(value.unterschrift).toString("base64"),
  };
}
