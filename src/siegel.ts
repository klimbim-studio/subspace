import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { pruefeHuelle, type Huelle } from "./huelle.ts";

export interface Schluessel {
  signaturPrivat: Uint8Array;
  signaturOeffentlich: Uint8Array;
  boxPrivat: Uint8Array;
  boxOeffentlich: Uint8Array;
}

export type Grund =
  | "zu_gross"
  | "format"
  | "nicht_an_mich"
  | "entschluesselung"
  | "schema"
  | "umschlag_passt_nicht"
  | "absender_unbekannt"
  | "unterschrift"
  | "wiederholung"
  | "abgelaufen"
  | "zukunft"
  | "anhang_typ";

export const MAX_BYTES = 5 * 1024 * 1024;

interface Eintrag {
  epk: string;
  nonce: string;
  box: string;
}

interface Umschlag {
  v: 1;
  von: string;
  an: string[];
  nonce: string;
  inhalt: string;
  schluessel: Record<string, Eintrag>;
  laufzeit?: number;
  laufzeit_signatur?: string;
}

interface Innen {
  huelle: unknown;
  sig: string;
}

const VORSPANN = "agentenpost-v1-huelle\n";
const LAUFZEIT_VORSPANN = "agentenpost-v1-laufzeit\n";
const INFO = "agentenpost-v1-schluessel";
const TAG_MS = 24 * 60 * 60 * 1000;
const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const NAMENSMUSTER = /^[a-z][a-z0-9-]{1,31}$/;
const BASE64MUSTER = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function kanonisch(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(kanonisch).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const eintrag = value as Record<string, unknown>;
    return `{${Object.keys(eintrag).sort().map((key) => `${JSON.stringify(key)}:${kanonisch(eintrag[key])}`).join(",")}}`;
  }
  const kodiert = JSON.stringify(value);
  if (kodiert === undefined) throw new TypeError("Wert ist nicht als JSON darstellbar.");
  return kodiert;
}

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function dekodiereBase64(value: string): Uint8Array {
  if (!BASE64MUSTER.test(value)) throw new TypeError("Ungültiges Base64.");
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (base64(bytes) !== value) throw new TypeError("Nicht-kanonisches Base64.");
  return bytes;
}

function istObjekt(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exakteFelder(value: Record<string, unknown>, felder: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...felder].sort();
  return actual.length === expected.length && actual.every((feld, index) => feld === expected[index]);
}

function header(von: string, an: string[]): { v: 1; von: string; an: string[] } {
  return { v: 1, von, an: [...an].sort() };
}

function pruefeEmpfaenger(an: string[], empfaenger: Record<string, Uint8Array>): void {
  const names = Object.keys(empfaenger).sort();
  const expected = [...an].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    throw new TypeError("Empfängerschlüssel müssen genau den Namen aus der Hülle entsprechen.");
  }
  for (const name of names) {
    const key = empfaenger[name];
    if (!NAMENSMUSTER.test(name) || !(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError(`Ungültiger X25519-Empfängerschlüssel für ${name}.`);
    }
  }
}

function baueUmschlag(
  innen: Uint8Array,
  von: string,
  an: string[],
  empfaenger: Record<string, Uint8Array>,
  exakteEmpfaenger = true,
  laufzeit?: { tage: number; signaturPrivat: Uint8Array },
): Uint8Array {
  if (exakteEmpfaenger) {
    pruefeEmpfaenger(an, empfaenger);
  } else {
    for (const [name, key] of Object.entries(empfaenger)) {
      if (!NAMENSMUSTER.test(name) || !(key instanceof Uint8Array) || key.length !== 32) {
        throw new TypeError(`Ungültiger X25519-Empfängerschlüssel für ${name}.`);
      }
    }
  }
  const aad = utf8.encode(kanonisch(header(von, an)));
  const inhaltsschluessel = randomBytes(32);
  const nonce = randomBytes(24);
  const inhalt = xchacha20poly1305(inhaltsschluessel, nonce, aad).encrypt(innen);
  const schluessel: Record<string, Eintrag> = {};
  for (const name of Object.keys(empfaenger).sort()) {
    const ephemeral = x25519.keygen();
    const epk = ephemeral.publicKey;
    const recipientPublic = empfaenger[name]!;
    const geteilt = x25519.getSharedSecret(ephemeral.secretKey, recipientPublic);
    const salt = new Uint8Array(epk.length + recipientPublic.length);
    salt.set(epk);
    salt.set(recipientPublic, epk.length);
    const kek = hkdf(sha256, geteilt, salt, utf8.encode(INFO), 32);
    const wrappingNonce = randomBytes(24);
    const box = xchacha20poly1305(kek, wrappingNonce, aad).encrypt(inhaltsschluessel);
    schluessel[name] = { epk: base64(epk), nonce: base64(wrappingNonce), box: base64(box) };
  }
  const envelope: Umschlag = { v: 1, von, an: [...an], nonce: base64(nonce), inhalt: base64(inhalt), schluessel };
  if (laufzeit) {
    envelope.laufzeit = laufzeit.tage;
    const signaturBasis = `${LAUFZEIT_VORSPANN}${Buffer.from(sha256(utf8.encode(kanonisch(envelope)))).toString("hex")}`;
    envelope.laufzeit_signatur = base64(ed25519.sign(utf8.encode(signaturBasis), laufzeit.signaturPrivat));
  }
  const bytes = utf8.encode(JSON.stringify(envelope));
  if (bytes.length > MAX_BYTES) throw new RangeError("Der Umschlag überschreitet MAX_BYTES.");
  return bytes;
}

function parseUmschlag(bytes: Uint8Array): Umschlag | undefined {
  try {
    const parsed: unknown = JSON.parse(utf8Decoder.decode(bytes));
    if (!istObjekt(parsed)) return undefined;
    const basisFelder = ["v", "von", "an", "nonce", "inhalt", "schluessel"];
    const mitLaufzeit = exakteFelder(parsed, [...basisFelder, "laufzeit", "laufzeit_signatur"]);
    if (!mitLaufzeit && !exakteFelder(parsed, basisFelder)) return undefined;
    if (parsed.v !== 1 || typeof parsed.von !== "string" || !NAMENSMUSTER.test(parsed.von)) return undefined;
    if (!Array.isArray(parsed.an) || parsed.an.some((name) => typeof name !== "string" || !NAMENSMUSTER.test(name))) return undefined;
    if (typeof parsed.nonce !== "string" || typeof parsed.inhalt !== "string" || !istObjekt(parsed.schluessel)) return undefined;
    if (mitLaufzeit && (typeof parsed.laufzeit !== "number" || !Number.isFinite(parsed.laufzeit) || parsed.laufzeit < 1 || parsed.laufzeit > 30
      || typeof parsed.laufzeit_signatur !== "string" || dekodiereBase64(parsed.laufzeit_signatur).length !== 64)) return undefined;
    const nonce = dekodiereBase64(parsed.nonce);
    const inhalt = dekodiereBase64(parsed.inhalt);
    if (nonce.length !== 24 || inhalt.length < 16) return undefined;
    const schluessel: Record<string, Eintrag> = {};
    for (const [name, value] of Object.entries(parsed.schluessel)) {
      if (!NAMENSMUSTER.test(name) || !istObjekt(value) || !exakteFelder(value, ["epk", "nonce", "box"])) return undefined;
      if (typeof value.epk !== "string" || typeof value.nonce !== "string" || typeof value.box !== "string") return undefined;
      if (dekodiereBase64(value.epk).length !== 32 || dekodiereBase64(value.nonce).length !== 24 || dekodiereBase64(value.box).length < 16) return undefined;
      schluessel[name] = { epk: value.epk, nonce: value.nonce, box: value.box };
    }
    return {
      v: 1,
      von: parsed.von,
      an: [...parsed.an] as string[],
      nonce: parsed.nonce,
      inhalt: parsed.inhalt,
      schluessel,
      ...(mitLaufzeit ? { laufzeit: parsed.laufzeit as number, laufzeit_signatur: parsed.laufzeit_signatur as string } : {}),
    };
  } catch {
    return undefined;
  }
}

export function leseUmschlagKopf(bytes: Uint8Array): { von: string; an: string[]; empfaenger: string[]; laufzeit: number } | undefined {
  const umschlag = parseUmschlag(bytes);
  if (!umschlag) return undefined;
  return { von: umschlag.von, an: [...umschlag.an], empfaenger: Object.keys(umschlag.schluessel), laufzeit: umschlag.laufzeit ?? 7 };
}

export function pruefeUmschlagLaufzeit(bytes: Uint8Array, signaturOeffentlich: Uint8Array): boolean {
  const umschlag = parseUmschlag(bytes);
  if (!umschlag) return false;
  if (umschlag.laufzeit === undefined || umschlag.laufzeit_signatur === undefined) return true;
  const ohneSignatur: Umschlag = { ...umschlag };
  delete ohneSignatur.laufzeit_signatur;
  const signaturBasis = `${LAUFZEIT_VORSPANN}${Buffer.from(sha256(utf8.encode(kanonisch(ohneSignatur)))).toString("hex")}`;
  try {
    return ed25519.verify(dekodiereBase64(umschlag.laufzeit_signatur), utf8.encode(signaturBasis), signaturOeffentlich);
  } catch {
    return false;
  }
}

export function erzeugeSchluessel(): Schluessel {
  const signing = ed25519.keygen();
  const box = x25519.keygen();
  return {
    signaturPrivat: signing.secretKey,
    signaturOeffentlich: signing.publicKey,
    boxPrivat: box.secretKey,
    boxOeffentlich: box.publicKey,
  };
}

export function fingerabdruck(signaturOeffentlich: Uint8Array, boxOeffentlich: Uint8Array): string {
  const combined = new Uint8Array(signaturOeffentlich.length + boxOeffentlich.length);
  combined.set(signaturOeffentlich);
  combined.set(boxOeffentlich, signaturOeffentlich.length);
  const hex = Buffer.from(sha256(combined)).toString("hex");
  return hex.match(/.{4}/g)!.join(" ");
}

export function versiegeln(huelle: Huelle, absender: Schluessel, empfaenger: Record<string, Uint8Array>): Uint8Array {
  const pruefung = pruefeHuelle(huelle);
  if (!pruefung.ok) throw new TypeError(`Ungültige Hülle: ${pruefung.detail}`);
  pruefeEmpfaenger(pruefung.huelle.an, empfaenger);
  const signatur = ed25519.sign(utf8.encode(`${VORSPANN}${kanonisch(pruefung.huelle)}`), absender.signaturPrivat);
  const innen = utf8.encode(kanonisch({ huelle: pruefung.huelle, sig: base64(signatur) }));
  const tage = Math.max(1, Math.ceil((Date.parse(pruefung.huelle.gueltig_bis) - Date.parse(pruefung.huelle.erstellt)) / TAG_MS));
  return baueUmschlag(innen, pruefung.huelle.von, pruefung.huelle.an, empfaenger, true, { tage, signaturPrivat: absender.signaturPrivat });
}

export function verschluesselnRoh(
  innen: Uint8Array,
  von: string,
  an: string[],
  empfaenger: Record<string, Uint8Array>,
): Uint8Array {
  if (!NAMENSMUSTER.test(von) || an.length < 1 || an.length > 20 || an.some((name) => !NAMENSMUSTER.test(name))) {
    throw new TypeError("Ungültiger Kopf.");
  }
  if (new Set(an).size !== an.length) throw new TypeError("Doppelte Empfänger im Kopf.");
  return baueUmschlag(innen, von, an, empfaenger, false);
}

export function oeffnen(
  umschlagBytes: Uint8Array,
  ich: { name: string; boxPrivat: Uint8Array },
  vertraut: Record<string, Uint8Array>,
  opt: { jetzt: Date; schonGesehen: (id: string) => boolean; maxBytes?: number },
): { ok: true; huelle: Huelle } | { ok: false; grund: Grund } {
  try {
    if (umschlagBytes.length > (opt.maxBytes ?? MAX_BYTES)) return { ok: false, grund: "zu_gross" };
    const envelope = parseUmschlag(umschlagBytes);
    if (!envelope) return { ok: false, grund: "format" };
    if (!Object.hasOwn(envelope.schluessel, ich.name)) return { ok: false, grund: "nicht_an_mich" };
    let innenBytes: Uint8Array;
    try {
      const eintrag = envelope.schluessel[ich.name]!;
      const epk = dekodiereBase64(eintrag.epk);
      const recipientPublic = x25519.getPublicKey(ich.boxPrivat);
      const geteilt = x25519.getSharedSecret(ich.boxPrivat, epk);
      const salt = new Uint8Array(epk.length + recipientPublic.length);
      salt.set(epk);
      salt.set(recipientPublic, epk.length);
      const kek = hkdf(sha256, geteilt, salt, utf8.encode(INFO), 32);
      const aad = utf8.encode(kanonisch(header(envelope.von, envelope.an)));
      const contentKey = xchacha20poly1305(kek, dekodiereBase64(eintrag.nonce), aad).decrypt(dekodiereBase64(eintrag.box));
      innenBytes = xchacha20poly1305(contentKey, dekodiereBase64(envelope.nonce), aad).decrypt(dekodiereBase64(envelope.inhalt));
    } catch {
      return { ok: false, grund: "entschluesselung" };
    }
    let innen: unknown;
    try {
      innen = JSON.parse(utf8Decoder.decode(innenBytes));
    } catch {
      return { ok: false, grund: "schema" };
    }
    if (!istObjekt(innen) || !exakteFelder(innen, ["huelle", "sig"]) || typeof innen.sig !== "string") {
      return { ok: false, grund: "schema" };
    }
    const pruefung = pruefeHuelle(innen.huelle);
    if (!pruefung.ok) return { ok: false, grund: "schema" };
    const huelle = pruefung.huelle;
    if (huelle.von !== envelope.von || huelle.an.length !== envelope.an.length || huelle.an.some((name) => !envelope.an.includes(name))) {
      return { ok: false, grund: "umschlag_passt_nicht" };
    }
    if (!Object.hasOwn(vertraut, huelle.von)) return { ok: false, grund: "absender_unbekannt" };
    let gueltigeSignatur = false;
    try {
      gueltigeSignatur = ed25519.verify(
        dekodiereBase64(innen.sig),
        utf8.encode(`${VORSPANN}${kanonisch(huelle)}`),
        vertraut[huelle.von]!,
      );
    } catch {
      gueltigeSignatur = false;
    }
    if (!gueltigeSignatur) return { ok: false, grund: "unterschrift" };
    if (envelope.laufzeit !== undefined) {
      const tage = Math.max(1, Math.ceil((Date.parse(huelle.gueltig_bis) - Date.parse(huelle.erstellt)) / TAG_MS));
      if (tage !== envelope.laufzeit || !pruefeUmschlagLaufzeit(umschlagBytes, vertraut[huelle.von]!)) return { ok: false, grund: "unterschrift" };
    }
    if (!huelle.an.includes(ich.name)) return { ok: false, grund: "nicht_an_mich" };
    if (opt.schonGesehen(huelle.id)) return { ok: false, grund: "wiederholung" };
    const jetzt = opt.jetzt.getTime();
    if (Date.parse(huelle.gueltig_bis) <= jetzt) return { ok: false, grund: "abgelaufen" };
    if (Date.parse(huelle.erstellt) > jetzt + 5 * 60 * 1000) return { ok: false, grund: "zukunft" };
    return { ok: true, huelle };
  } catch {
    return { ok: false, grund: "format" };
  }
}
