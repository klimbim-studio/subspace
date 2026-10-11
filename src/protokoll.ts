import { sha256 } from "@noble/hashes/sha2.js";

const utf8 = new TextEncoder();

export type Protokollfeld = [string, Uint8Array];

export function kodiere(felder: Protokollfeld[]): Uint8Array {
  const kodiert: Uint8Array[] = [];
  let gesamt = 0;
  for (const [bezeichnung, wert] of felder) {
    const name = utf8.encode(bezeichnung);
    if (name.length > 0xffff) throw new RangeError("Feldbezeichnung ist zu lang.");
    if (wert.length > 0xffffffff) throw new RangeError("Feldwert ist zu lang.");
    const laengen = new Uint8Array(6);
    new DataView(laengen.buffer).setUint16(0, name.length, false);
    new DataView(laengen.buffer).setUint32(2, wert.length, false);
    kodiert.push(laengen, name, wert);
    gesamt += laengen.length + name.length + wert.length;
  }
  const ergebnis = new Uint8Array(gesamt);
  let offset = 0;
  for (const teil of kodiert) {
    ergebnis.set(teil, offset);
    offset += teil.length;
  }
  return ergebnis;
}

export function hashMitZweck(version: string, zweck: string, felder: Protokollfeld[]): Uint8Array {
  return sha256(kodiere([["version", utf8.encode(version)], ["zweck", utf8.encode(zweck)], ...felder]));
}
