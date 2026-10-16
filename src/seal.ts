import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { validateEnvelope, type Envelope } from "./envelope.ts";

export interface KeyPair {
  // on-disk format, keep
  signaturPrivat: Uint8Array;
  // on-disk format, keep
  signaturOeffentlich: Uint8Array;
  // on-disk format, keep
  boxPrivat: Uint8Array;
  // on-disk format, keep
  boxOeffentlich: Uint8Array;
}

export type OpenError =
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
  | "anhang_typ"
  | "group_state";

export const MAX_BYTES = 5 * 1024 * 1024;

interface RecipientKeyEntry {
  epk: string;
  nonce: string;
  box: string;
}

interface EncryptedEnvelope {
  v: 1;
  von: string;
  an: string[];
  nonce: string;
  inhalt: string;
  // wire format, keep
  schluessel: Record<string, RecipientKeyEntry>;
  // sealed format, keep
  laufzeit?: number;
  // wire format, keep
  laufzeit_signatur?: string;
  // sealed format, keep
  gruppe?: { gid: string; version: number; hash: string };
}

interface EncryptedBody {
  // sealed format, keep
  huelle: unknown;
  sig: string;
}

const ENVELOPE_PREFIX = "agentenpost-v1-huelle\n"; // wire format, keep
const LIFETIME_PREFIX = "agentenpost-v1-laufzeit\n"; // wire format, keep
const INFO = "agentenpost-v1-schluessel"; // wire format, keep
const TAG_MS = 24 * 60 * 60 * 1000;
const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const NAME_PATTERN = /^[a-z][a-z0-9-]{1,31}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entry = value as Record<string, unknown>;
    return `{${Object.keys(entry).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(entry[key])}`).join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError("Value cannot be represented as JSON.");
  return serialized;
}

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function decodeBase64(value: string): Uint8Array {
  if (!BASE64_PATTERN.test(value)) throw new TypeError("Invalid base64.");
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (base64(bytes) !== value) throw new TypeError("Non-canonical base64.");
  return bytes;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactFields(value: Record<string, unknown>, fields: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function header(von: string, an: string[]): { v: 1; von: string; an: string[] } {
  return { v: 1, von, an: [...an].sort() };
}

function validateRecipients(an: string[], empfaenger: Record<string, Uint8Array>): void {
  const names = Object.keys(empfaenger).sort();
  const expected = [...an].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    throw new TypeError("Recipient keys must match exactly the names in the envelope.");
  }
  for (const name of names) {
    const key = empfaenger[name];
    if (!NAME_PATTERN.test(name) || !(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError(`Invalid X25519 recipient key for ${name}.`);
    }
  }
}

function buildEnvelope(
  plaintextBytes: Uint8Array,
  von: string,
  an: string[],
  empfaenger: Record<string, Uint8Array>,
  requireExactRecipients = true,
  laufzeit?: { days: number; signaturPrivat: Uint8Array },
  gruppe?: { gid: string; version: number; hash: string },
  randomSource: (length: number) => Uint8Array = randomBytes,
): Uint8Array {
  if (requireExactRecipients) {
    validateRecipients(an, empfaenger);
  } else {
    for (const [name, key] of Object.entries(empfaenger)) {
      if (!NAME_PATTERN.test(name) || !(key instanceof Uint8Array) || key.length !== 32) {
        throw new TypeError(`Invalid X25519 recipient key for ${name}.`);
      }
    }
  }
  const aad = utf8.encode(canonicalize(header(von, an)));
  const contentKey = randomSource(32);
  const nonce = randomSource(24);
  const inhalt = xchacha20poly1305(contentKey, nonce, aad).encrypt(plaintextBytes);
  const schluessel: Record<string, RecipientKeyEntry> = {};
  for (const name of Object.keys(empfaenger).sort()) {
    const ephemeral = x25519.keygen(randomSource(32));
    const epk = ephemeral.publicKey;
    const recipientPublic = empfaenger[name]!;
    const sharedSecret = x25519.getSharedSecret(ephemeral.secretKey, recipientPublic);
    const salt = new Uint8Array(epk.length + recipientPublic.length);
    salt.set(epk);
    salt.set(recipientPublic, epk.length);
    const kek = hkdf(sha256, sharedSecret, salt, utf8.encode(INFO), 32);
    const wrappingNonce = randomSource(24);
    const box = xchacha20poly1305(kek, wrappingNonce, aad).encrypt(contentKey);
    schluessel[name] = { epk: base64(epk), nonce: base64(wrappingNonce), box: base64(box) };
  }
  const envelope: EncryptedEnvelope = { v: 1, von, an: [...an], nonce: base64(nonce), inhalt: base64(inhalt), schluessel, ...(gruppe ? { gruppe } : {}) };
  if (laufzeit) {
    envelope.laufzeit = laufzeit.days;
    const signatureBase = `${LIFETIME_PREFIX}${Buffer.from(sha256(utf8.encode(canonicalize(envelope)))).toString("hex")}`;
    envelope.laufzeit_signatur = base64(ed25519.sign(utf8.encode(signatureBase), laufzeit.signaturPrivat));
  }
  const bytes = utf8.encode(JSON.stringify(envelope));
  if (bytes.length > MAX_BYTES) throw new RangeError("The envelope exceeds MAX_BYTES.");
  return bytes;
}

function parseEnvelope(bytes: Uint8Array): EncryptedEnvelope | undefined {
  try {
    const parsed: unknown = JSON.parse(utf8Decoder.decode(bytes));
    if (!isObject(parsed)) return undefined;
    const requiredFields = ["v", "von", "an", "nonce", "inhalt", "schluessel"];
    const hasGroup = Object.hasOwn(parsed, "gruppe");
    const withLifetime = Object.hasOwn(parsed, "laufzeit") || Object.hasOwn(parsed, "laufzeit_signatur");
    const expected = [...requiredFields, ...(hasGroup ? ["gruppe"] : []), ...(withLifetime ? ["laufzeit", "laufzeit_signatur"] : [])];
    if (!hasExactFields(parsed, expected)) return undefined;
    if (parsed.v !== 1 || typeof parsed.von !== "string" || !NAME_PATTERN.test(parsed.von)) return undefined;
    if (!Array.isArray(parsed.an) || parsed.an.some((name) => typeof name !== "string" || !NAME_PATTERN.test(name))) return undefined;
    if (typeof parsed.nonce !== "string" || typeof parsed.inhalt !== "string" || !isObject(parsed.schluessel)) return undefined;
    let gruppe: EncryptedEnvelope["gruppe"];
    if (hasGroup) {
      if (!isObject(parsed.gruppe) || !hasExactFields(parsed.gruppe, ["gid", "version", "hash"])
        || typeof parsed.gruppe.gid !== "string" || !/^[0-9a-f]{64}$/.test(parsed.gruppe.gid)
        || typeof parsed.gruppe.version !== "number" || !Number.isInteger(parsed.gruppe.version) || parsed.gruppe.version < 1 || parsed.gruppe.version > 0xffffffff
        || typeof parsed.gruppe.hash !== "string" || !/^[0-9a-f]{64}$/.test(parsed.gruppe.hash)) return undefined;
      gruppe = { gid: parsed.gruppe.gid, version: parsed.gruppe.version, hash: parsed.gruppe.hash };
    }
    if (withLifetime && (typeof parsed.laufzeit !== "number" || !Number.isFinite(parsed.laufzeit) || parsed.laufzeit < 1 || parsed.laufzeit > 30
      || typeof parsed.laufzeit_signatur !== "string" || decodeBase64(parsed.laufzeit_signatur).length !== 64)) return undefined;
    const nonce = decodeBase64(parsed.nonce);
    const inhalt = decodeBase64(parsed.inhalt);
    if (nonce.length !== 24 || inhalt.length < 16) return undefined;
    const schluessel: Record<string, RecipientKeyEntry> = {};
    for (const [name, value] of Object.entries(parsed.schluessel)) {
      if (!NAME_PATTERN.test(name) || !isObject(value) || !hasExactFields(value, ["epk", "nonce", "box"])) return undefined;
      if (typeof value.epk !== "string" || typeof value.nonce !== "string" || typeof value.box !== "string") return undefined;
      if (decodeBase64(value.epk).length !== 32 || decodeBase64(value.nonce).length !== 24 || decodeBase64(value.box).length < 16) return undefined;
      schluessel[name] = { epk: value.epk, nonce: value.nonce, box: value.box };
    }
    return {
      v: 1,
      von: parsed.von,
      an: [...parsed.an] as string[],
      nonce: parsed.nonce,
      inhalt: parsed.inhalt,
      schluessel,
      ...(withLifetime ? { laufzeit: parsed.laufzeit as number, laufzeit_signatur: parsed.laufzeit_signatur as string } : {}),
      ...(gruppe ? { gruppe } : {}),
    };
  } catch {
    return undefined;
  }
}

export function readEnvelopeHeader(bytes: Uint8Array): {
  von: string;
  an: string[];
  // sealed format, keep
  empfaenger: string[];
  // sealed format, keep
  laufzeit: number;
  // sealed format, keep
  gruppe?: { gid: string; version: number; hash: string };
} | undefined {
  const encryptedEnvelope = parseEnvelope(bytes);
  if (!encryptedEnvelope) return undefined;
  return { von: encryptedEnvelope.von, an: [...encryptedEnvelope.an], empfaenger: Object.keys(encryptedEnvelope.schluessel), laufzeit: encryptedEnvelope.laufzeit ?? 7, ...(encryptedEnvelope.gruppe ? { gruppe: encryptedEnvelope.gruppe } : {}) };
}

export function verifyEnvelopeLifetime(bytes: Uint8Array, signaturOeffentlich: Uint8Array): boolean {
  const encryptedEnvelope = parseEnvelope(bytes);
  if (!encryptedEnvelope) return false;
  if (encryptedEnvelope.laufzeit === undefined || encryptedEnvelope.laufzeit_signatur === undefined) return true;
  const unsignedEnvelope: EncryptedEnvelope = { ...encryptedEnvelope };
  delete unsignedEnvelope.laufzeit_signatur;
  const signatureBase = `${LIFETIME_PREFIX}${Buffer.from(sha256(utf8.encode(canonicalize(unsignedEnvelope)))).toString("hex")}`;
  try {
    return ed25519.verify(decodeBase64(encryptedEnvelope.laufzeit_signatur), utf8.encode(signatureBase), signaturOeffentlich);
  } catch {
    return false;
  }
}

export function createKey(): KeyPair {
  const signing = ed25519.keygen();
  const box = x25519.keygen();
  return {
    signaturPrivat: signing.secretKey,
    signaturOeffentlich: signing.publicKey,
    boxPrivat: box.secretKey,
    boxOeffentlich: box.publicKey,
  };
}

export function fingerprint(signaturOeffentlich: Uint8Array, boxOeffentlich: Uint8Array): string {
  const combined = new Uint8Array(signaturOeffentlich.length + boxOeffentlich.length);
  combined.set(signaturOeffentlich);
  combined.set(boxOeffentlich, signaturOeffentlich.length);
  const hex = Buffer.from(sha256(combined)).toString("hex");
  return hex.match(/.{4}/g)!.join(" ");
}

export function sealEnvelope(
  huelle: Envelope,
  sender: KeyPair,
  empfaenger: Record<string, Uint8Array>,
  randomSource: (length: number) => Uint8Array = randomBytes,
): Uint8Array {
  const validationResult = validateEnvelope(huelle);
  if (!validationResult.ok) throw new TypeError(`Invalid envelope: ${validationResult.detail}`);
  validateRecipients(validationResult.envelope.an, empfaenger);
  const signature = ed25519.sign(utf8.encode(`${ENVELOPE_PREFIX}${canonicalize(validationResult.envelope)}`), sender.signaturPrivat);
  const plaintextBytes = utf8.encode(canonicalize({ huelle: validationResult.envelope, sig: base64(signature) }));
  const days = Math.max(1, Math.ceil((Date.parse(validationResult.envelope.gueltig_bis) - Date.parse(validationResult.envelope.erstellt)) / TAG_MS));
  return buildEnvelope(plaintextBytes, validationResult.envelope.von, validationResult.envelope.an, empfaenger, true, { days, signaturPrivat: sender.signaturPrivat }, validationResult.envelope.gruppe, randomSource);
}

export function encryptRaw(
  plaintextBytes: Uint8Array,
  von: string,
  an: string[],
  empfaenger: Record<string, Uint8Array>,
): Uint8Array {
  if (!NAME_PATTERN.test(von) || an.length < 1 || an.length > 20 || an.some((name) => !NAME_PATTERN.test(name))) {
    throw new TypeError("Invalid header.");
  }
  if (new Set(an).size !== an.length) throw new TypeError("Duplicate recipients in the header.");
  return buildEnvelope(plaintextBytes, von, an, empfaenger, false);
}

export function openEnvelope(
  envelopeBytes: Uint8Array,
  self: { name: string; boxPrivat: Uint8Array },
  trustedKeys: Record<string, Uint8Array>,
  opt: {
    now: Date;
    alreadySeen: (id: string) => boolean;
    maxBytes?: number;
  },
): { ok: true; huelle: Envelope } | { ok: false;
  grund: OpenError;
} {
  try {
    if (envelopeBytes.length > (opt.maxBytes ?? MAX_BYTES)) return { ok: false, grund: "zu_gross" };
    const envelope = parseEnvelope(envelopeBytes);
    if (!envelope) return { ok: false, grund: "format" };
    if (!Object.hasOwn(envelope.schluessel, self.name)) return { ok: false, grund: "nicht_an_mich" };
    let plaintextBytes: Uint8Array;
    try {
      const recipientEntry = envelope.schluessel[self.name]!;
      const epk = decodeBase64(recipientEntry.epk);
      const recipientPublic = x25519.getPublicKey(self.boxPrivat);
      const sharedSecret = x25519.getSharedSecret(self.boxPrivat, epk);
      const salt = new Uint8Array(epk.length + recipientPublic.length);
      salt.set(epk);
      salt.set(recipientPublic, epk.length);
      const kek = hkdf(sha256, sharedSecret, salt, utf8.encode(INFO), 32);
      const aad = utf8.encode(canonicalize(header(envelope.von, envelope.an)));
      const contentKey = xchacha20poly1305(kek, decodeBase64(recipientEntry.nonce), aad).decrypt(decodeBase64(recipientEntry.box));
      plaintextBytes = xchacha20poly1305(contentKey, decodeBase64(envelope.nonce), aad).decrypt(decodeBase64(envelope.inhalt));
    } catch {
      return { ok: false, grund: "entschluesselung" };
    }
    let parsedPlaintext: unknown;
    try {
      parsedPlaintext = JSON.parse(utf8Decoder.decode(plaintextBytes));
    } catch {
      return { ok: false, grund: "schema" };
    }
    if (!isObject(parsedPlaintext) || !hasExactFields(parsedPlaintext, ["huelle", "sig"]) || typeof parsedPlaintext.sig !== "string") {
      return { ok: false, grund: "schema" };
    }
    const validationResult = validateEnvelope(parsedPlaintext.huelle);
    if (!validationResult.ok) return { ok: false, grund: "schema" };
    const huelle = validationResult.envelope;
    if (JSON.stringify(envelope.gruppe ?? null) !== JSON.stringify(huelle.gruppe ?? null)) return { ok: false, grund: "umschlag_passt_nicht" };
    if (huelle.von !== envelope.von || huelle.an.length !== envelope.an.length || huelle.an.some((name) => !envelope.an.includes(name))) {
      return { ok: false, grund: "umschlag_passt_nicht" };
    }
    if (!Object.hasOwn(trustedKeys, huelle.von)) return { ok: false, grund: "absender_unbekannt" };
    let validSignature = false;
    try {
      validSignature = ed25519.verify(
        decodeBase64(parsedPlaintext.sig),
        utf8.encode(`${ENVELOPE_PREFIX}${canonicalize(huelle)}`),
        trustedKeys[huelle.von]!,
      );
    } catch {
      validSignature = false;
    }
    if (!validSignature) return { ok: false, grund: "unterschrift" };
    if (envelope.laufzeit !== undefined) {
      const days = Math.max(1, Math.ceil((Date.parse(huelle.gueltig_bis) - Date.parse(huelle.erstellt)) / TAG_MS));
      if (days !== envelope.laufzeit || !verifyEnvelopeLifetime(envelopeBytes, trustedKeys[huelle.von]!)) return { ok: false, grund: "unterschrift" };
    }
    if (!huelle.an.includes(self.name)) return { ok: false, grund: "nicht_an_mich" };
    if (opt.alreadySeen(huelle.id)) return { ok: false, grund: "wiederholung" };
    const currentTime = opt.now.getTime();
    if (Date.parse(huelle.gueltig_bis) <= currentTime) return { ok: false, grund: "abgelaufen" };
    if (Date.parse(huelle.erstellt) > currentTime + 5 * 60 * 1000) return { ok: false, grund: "zukunft" };
    return { ok: true, huelle };
  } catch {
    return { ok: false, grund: "format" };
  }
}
