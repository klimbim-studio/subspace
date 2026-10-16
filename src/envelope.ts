export type Art = "info" | "anfrage";

export interface EnvelopeAttachment {
  name: string;
  // sealed format, keep
  typ: string;
  // wire format, keep
  inhalt: string;
}

export interface Envelope {
  v: 1;
  id: string;
  von: string;
  an: string[];
  // sealed format, keep
  kanal: string | null;
  // sealed format, keep
  erstellt: string;
  // sealed format, keep
  gueltig_bis: string;
  art: Art;
  // sealed format, keep
  bezug: string | null;
  // sealed format, keep
  betreff: string;
  text: string;
  // sealed format, keep
  anhaenge: EnvelopeAttachment[];
  // sealed format, keep
  ausgeloest_von?: {
    von: string;
    // sealed format, keep
    huelle_id: string;
  };
  // sealed format, keep
  gruppe?: { gid: string; version: number; hash: string };
}

export type EnvelopeValidation =
  | { ok: true; envelope: Envelope }
  | { ok: false; reason: "schema"; detail: string };

const ENVELOPE_FIELDS = [
  "v", "id", "von", "an", "kanal", "erstellt", "gueltig_bis", "art", "bezug", "betreff", "text", "anhaenge",
];
const ATTACHMENT_FIELDS = ["name", "typ", "inhalt"];
const NAME_PATTERN = /^[a-z][a-z0-9-]{1,31}$/;
const ID_PATTERN = /^[0-9a-f]{32}$/;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactFields(value: Record<string, unknown>, fields: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function isDate(value: string): boolean {
  if (!DATE_PATTERN.test(value)) return false;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return false;
  const parsed = new Date(timestamp);
  const [date, time] = value.slice(0, -1).split("T");
  const [year, month, day] = date!.split("-").map(Number);
  const [hour, minute, second] = time!.split(":");
  const [wholeSeconds, milliseconds = "0"] = second!.split(".");
  const millis = Number(`0.${milliseconds}`) * 1000;
  return parsed.getUTCFullYear() === year
    && parsed.getUTCMonth() + 1 === month
    && parsed.getUTCDate() === day
    && parsed.getUTCHours() === Number(hour)
    && parsed.getUTCMinutes() === Number(minute)
    && parsed.getUTCSeconds() === Number(wholeSeconds)
    && parsed.getUTCMilliseconds() === Math.floor(millis);
}

function schemaError(detail: string): EnvelopeValidation {
  return { ok: false, reason: "schema", detail };
}

export function validateEnvelope(x: unknown): EnvelopeValidation {
  if (!isObject(x)) return schemaError("The envelope must be an object.");
  const fields = [...ENVELOPE_FIELDS, ...(Object.hasOwn(x, "ausgeloest_von") ? ["ausgeloest_von"] : []), ...(Object.hasOwn(x, "gruppe") ? ["gruppe"] : [])];
  if (!hasExactFields(x, fields)) return schemaError("The envelope has missing or unknown fields.");
  if (x.v !== 1) return schemaError("v must be 1.");
  if (typeof x.id !== "string" || !ID_PATTERN.test(x.id)) return schemaError("id must consist of 32 lowercase hex characters.");
  if (typeof x.von !== "string" || !NAME_PATTERN.test(x.von)) return schemaError("von is not a valid participant name.");
  if (!Array.isArray(x.an) || x.an.length < 1 || x.an.length > 20) return schemaError("an must contain 1 to 20 participants.");
  const recipients = new Set<string>();
  for (const name of x.an) {
    if (typeof name !== "string" || !NAME_PATTERN.test(name)) return schemaError("an contains an invalid participant name.");
    if (name === x.von) return schemaError("von must not appear in an.");
    if (recipients.has(name)) return schemaError("an must not contain duplicates.");
    recipients.add(name);
  }
  if (x.kanal !== null && (typeof x.kanal !== "string" || !NAME_PATTERN.test(x.kanal))) return schemaError("kanal is not a valid channel name."); // wire format, keep
  if (typeof x.erstellt !== "string" || !isDate(x.erstellt)) return schemaError("erstellt must be a valid ISO-8601 UTC date."); // wire format, keep
  if (typeof x.gueltig_bis !== "string" || !isDate(x.gueltig_bis)) return schemaError("gueltig_bis must be a valid ISO-8601 UTC date."); // wire format, keep
  const erstellt = Date.parse(x.erstellt);
  const validUntil = Date.parse(x.gueltig_bis);
  if (validUntil <= erstellt || validUntil - erstellt > 30 * 24 * 60 * 60 * 1000) {
    return schemaError("gueltig_bis must be after erstellt and at most thirty days later."); // wire format, keep
  }
  if (x.art !== "info" && x.art !== "anfrage") return schemaError("art must be info or anfrage."); // wire format, keep
  if (x.bezug !== null && (typeof x.bezug !== "string" || !ID_PATTERN.test(x.bezug))) return schemaError("bezug must be an id or null."); // wire format, keep
  if (Object.hasOwn(x, "ausgeloest_von")) {
    const triggerSource = x.ausgeloest_von;
    if (!isObject(triggerSource) || !hasExactFields(triggerSource, ["von", "huelle_id"])) {
      return schemaError("ausgeloest_von must contain exactly von and huelle_id."); // wire format, keep
    }
    if (typeof triggerSource.von !== "string" || !NAME_PATTERN.test(triggerSource.von)) {
      return schemaError("ausgeloest_von.von is not a valid participant name."); // wire format, keep
    }
    if (typeof triggerSource.huelle_id !== "string" || !ID_PATTERN.test(triggerSource.huelle_id)) {
      return schemaError("ausgeloest_von.huelle_id must consist of 32 lowercase hex characters."); // wire format, keep
    }
  }
  if (Object.hasOwn(x, "gruppe")) {
    const group = x.gruppe;
    if (!isObject(group) || !hasExactFields(group, ["gid", "version", "hash"])) return schemaError("gruppe must contain exactly gid, version and hash."); // wire format, keep
    if (typeof group.gid !== "string" || !/^[0-9a-f]{64}$/.test(group.gid)
      || typeof group.version !== "number" || !Number.isInteger(group.version) || group.version < 1 || group.version > 0xffffffff
      || typeof group.hash !== "string" || !/^[0-9a-f]{64}$/.test(group.hash)) return schemaError("gruppe has invalid group state metadata."); // wire format, keep
  }
  if (typeof x.betreff !== "string" || x.betreff.length < 1 || x.betreff.length > 200) return schemaError("betreff must have 1 to 200 characters."); // wire format, keep
  if (typeof x.text !== "string" || x.text.length > 100_000) return schemaError("text must have at most 100000 characters.");
  if (!Array.isArray(x.anhaenge) || x.anhaenge.length > 10) return schemaError("anhaenge must have at most ten entries."); // wire format, keep
  for (const [index, attachment] of x.anhaenge.entries()) {
    if (!isObject(attachment) || !hasExactFields(attachment, ATTACHMENT_FIELDS)) return schemaError(`anhaenge[${index}] has missing or unknown fields.`); // wire format, keep
    if (typeof attachment.name !== "string" || typeof attachment.typ !== "string" || typeof attachment.inhalt !== "string") {
      return schemaError(`anhaenge[${index}] contains a field of the wrong type.`); // wire format, keep
    }
    if (!BASE64_PATTERN.test(attachment.inhalt)) return schemaError(`anhaenge[${index}].inhalt is not base64.`); // wire format, keep
  }
  const trigger = Object.hasOwn(x, "ausgeloest_von") ? x.ausgeloest_von : undefined;
  const group = Object.hasOwn(x, "gruppe") ? x.gruppe : undefined;
  const envelope: Envelope = {
    v: 1,
    id: x.id as string,
    von: x.von as string,
    an: [...recipients],
    kanal: x.kanal as string | null,
    erstellt: x.erstellt as string,
    gueltig_bis: x.gueltig_bis as string,
    art: x.art,
    bezug: x.bezug as string | null,
    betreff: x.betreff as string,
    text: x.text as string,
    anhaenge: x.anhaenge.map((attachment) => {
      const checked = attachment as Record<string, unknown>;
      return { name: checked.name as string, typ: checked.typ as string, inhalt: checked.inhalt as string };
    }),
    ...(isObject(trigger) ? { ausgeloest_von: { von: trigger.von as string, huelle_id: trigger.huelle_id as string } } : {}),
    ...(isObject(group) ? { gruppe: { gid: group.gid as string, version: group.version as number, hash: group.hash as string } } : {}),
  };
  return { ok: true, envelope: envelope };
}
