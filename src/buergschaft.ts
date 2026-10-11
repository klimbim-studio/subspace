import { ed25519 } from "@noble/curves/ed25519.js";
import { hashMitZweck, type Protokollfeld } from "./protokoll.ts";

const utf8 = new TextEncoder();

export interface Buergschaft {
  instanz: string;
  art: "nachfolger" | "widerruf";
  buerge_name: string;
  buerge_sig: Uint8Array;
  buerge_box: Uint8Array;
  neu_name: string;
  neu_sig: Uint8Array;
  neu_box: Uint8Array;
  folgenummer: number;
  vorgaenger_hash: Uint8Array;
  zeit: string;
}

export interface SignierteBuergschaft {
  buergschaft: Buergschaft;
  unterschrift: Uint8Array;
}

function u32(wert: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, wert, false);
  return bytes;
}

export function felderBuergschaft(b: Buergschaft): Protokollfeld[] {
  if (!Number.isInteger(b.folgenummer) || b.folgenummer < 0 || b.folgenummer > 0xffffffff) throw new RangeError("Folgenummer muss uint32 sein.");
  if (b.vorgaenger_hash.length !== 32) throw new RangeError("Vorgänger-Hash muss 32 Byte lang sein.");
  return [
    ["instanz", utf8.encode(b.instanz)],
    ["art", utf8.encode(b.art)],
    ["buerge_name", utf8.encode(b.buerge_name)],
    ["buerge_sig", b.buerge_sig],
    ["buerge_box", b.buerge_box],
    ["neu_name", utf8.encode(b.neu_name)],
    ["neu_sig", b.neu_sig],
    ["neu_box", b.neu_box],
    ["folgenummer", u32(b.folgenummer)],
    ["vorgaenger_hash", b.vorgaenger_hash],
    ["zeit", utf8.encode(b.zeit)],
  ];
}

export function hashBuergschaft(b: Buergschaft): Uint8Array {
  return hashMitZweck("cartridge-buergschaft-v1", "buergschaft", felderBuergschaft(b));
}

export function signiereBuergschaft(b: Buergschaft, privaterSchluessel: Uint8Array): Uint8Array {
  return ed25519.sign(hashBuergschaft(b), privaterSchluessel);
}

export function pruefeBuergschaft(b: Buergschaft, unterschrift: Uint8Array): boolean {
  try {
    return unterschrift.length === 64 && ed25519.verify(unterschrift, hashBuergschaft(b), b.buerge_sig);
  } catch {
    return false;
  }
}

export function buergschaftJson(value: SignierteBuergschaft): Record<string, unknown> {
  return {
    buergschaft: {
      ...value.buergschaft,
      buerge_sig: Buffer.from(value.buergschaft.buerge_sig).toString("base64"),
      buerge_box: Buffer.from(value.buergschaft.buerge_box).toString("base64"),
      neu_sig: Buffer.from(value.buergschaft.neu_sig).toString("base64"),
      neu_box: Buffer.from(value.buergschaft.neu_box).toString("base64"),
      vorgaenger_hash: Buffer.from(value.buergschaft.vorgaenger_hash).toString("base64"),
    },
    unterschrift: Buffer.from(value.unterschrift).toString("base64"),
  };
}

export function parseBuergschaft(raw: unknown): SignierteBuergschaft | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const wrapper = raw as Record<string, unknown>;
  if (!wrapper.buergschaft || typeof wrapper.buergschaft !== "object" || Array.isArray(wrapper.buergschaft) || typeof wrapper.unterschrift !== "string") return undefined;
  const value = wrapper.buergschaft as Record<string, unknown>;
  const fields = ["instanz", "art", "buerge_name", "buerge_sig", "buerge_box", "neu_name", "neu_sig", "neu_box", "folgenummer", "vorgaenger_hash", "zeit"];
  if (Object.keys(value).length !== fields.length || fields.some((field) => !Object.hasOwn(value, field))) return undefined;
  if (typeof value.instanz !== "string" || (value.art !== "nachfolger" && value.art !== "widerruf")
    || typeof value.buerge_name !== "string" || typeof value.neu_name !== "string"
    || typeof value.folgenummer !== "number" || !Number.isInteger(value.folgenummer) || value.folgenummer < 0 || value.folgenummer > 0xffffffff
    || typeof value.zeit !== "string") return undefined;
  const decode = (encoded: unknown, length: number): Uint8Array | undefined => {
    if (typeof encoded !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) return undefined;
    const bytes = Buffer.from(encoded, "base64");
    return bytes.length === length && bytes.toString("base64") === encoded ? new Uint8Array(bytes) : undefined;
  };
  const buerge_sig = decode(value.buerge_sig, 32);
  const buerge_box = decode(value.buerge_box, 32);
  const neu_sig = decode(value.neu_sig, 32);
  const neu_box = decode(value.neu_box, 32);
  const vorgaenger_hash = decode(value.vorgaenger_hash, 32);
  const unterschrift = decode(wrapper.unterschrift, 64);
  if (!buerge_sig || !buerge_box || !neu_sig || !neu_box || !vorgaenger_hash || !unterschrift) return undefined;
  return {
    buergschaft: {
      instanz: value.instanz,
      art: value.art,
      buerge_name: value.buerge_name,
      buerge_sig,
      buerge_box,
      neu_name: value.neu_name,
      neu_sig,
      neu_box,
      folgenummer: value.folgenummer,
      vorgaenger_hash,
      zeit: value.zeit,
    },
    unterschrift,
  };
}
