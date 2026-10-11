// Ein bösartiges Postamt kann den Beitritt verhindern, aber nicht übernehmen.
import { sha256 } from "@noble/hashes/sha2.js";
import { kodiere, type Protokollfeld } from "./protokoll.ts";

export const VERSION = "cartridge-beitritt-v1";
const utf8 = new TextEncoder();

export interface Beitrittsprotokoll {
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

function ursprung(instanz: string): string {
  return new URL(instanz).origin;
}

function hash(felder: Protokollfeld[]): Uint8Array {
  return sha256(kodiere(felder));
}

export function festlegung(instanz: string, token: Uint8Array, name_I: string, sig_I: Uint8Array, box_I: Uint8Array, n_I: Uint8Array): Uint8Array {
  return hash([
    ["ctx", utf8.encode(VERSION)], ["instanz", utf8.encode(ursprung(instanz))], ["token", token],
    ["name_I", utf8.encode(name_I)], ["sig_I", sig_I], ["box_I", box_I], ["n_I", n_I],
  ]);
}

export function protokoll(p: Beitrittsprotokoll): Protokollfeld[] {
  return [
    ["ctx", utf8.encode(VERSION)], ["instanz", utf8.encode(ursprung(p.instanz))], ["token", p.token],
    ["name_I", utf8.encode(p.name_I)], ["name_J", utf8.encode(p.name_J)], ["sig_I", p.sig_I],
    ["box_I", p.box_I], ["sig_J", p.sig_J], ["box_J", p.box_J], ["c_I", p.c_I], ["n_J", p.n_J], ["n_I", p.n_I],
  ];
}

export function protokollHash(p: Beitrittsprotokoll): Uint8Array {
  return hash(protokoll(p));
}

export function code(p: Beitrittsprotokoll): string {
  const digest = hash([["zweck", utf8.encode("code")], ["protokoll", protokollHash(p)]]);
  let wert = 0n;
  for (const byte of digest.subarray(0, 8)) wert = (wert << 8n) | BigInt(byte);
  return (wert % 1_000_000n).toString().padStart(6, "0");
}

export interface Einloesungsdaten {
  instanz: string;
  token: Uint8Array;
  name_J: string;
  sig_J: Uint8Array;
  box_J: Uint8Array;
  c_I: Uint8Array;
  n_J: Uint8Array;
}

export function einloesungsNachricht(p: Einloesungsdaten): Uint8Array {
  return hash([
    ["ctx", utf8.encode(VERSION)], ["instanz", utf8.encode(ursprung(p.instanz))], ["token", p.token],
    ["name_J", utf8.encode(p.name_J)], ["sig_J", p.sig_J], ["box_J", p.box_J], ["c_I", p.c_I], ["n_J", p.n_J],
  ]);
}

function nachricht(zweck: "oeffnung" | "bestaetigung", p: Beitrittsprotokoll): Uint8Array {
  return hash([["zweck", utf8.encode(zweck)], ["protokoll", protokollHash(p)]]);
}

export function oeffnungsNachricht(p: Beitrittsprotokoll): Uint8Array {
  return nachricht("oeffnung", p);
}

export function bestaetigungsNachricht(p: Beitrittsprotokoll): Uint8Array {
  return nachricht("bestaetigung", p);
}
