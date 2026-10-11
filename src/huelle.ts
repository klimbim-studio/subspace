export type Art = "info" | "anfrage";

export interface Anhang {
  name: string;
  typ: string;
  inhalt: string;
}

export interface Huelle {
  v: 1;
  id: string;
  von: string;
  an: string[];
  kanal: string | null;
  erstellt: string;
  gueltig_bis: string;
  art: Art;
  bezug: string | null;
  betreff: string;
  text: string;
  anhaenge: Anhang[];
  ausgeloest_von?: { von: string; huelle_id: string };
}

export type HuellePruefung =
  | { ok: true; huelle: Huelle }
  | { ok: false; grund: "schema"; detail: string };

const HUELLENFELDER = [
  "v", "id", "von", "an", "kanal", "erstellt", "gueltig_bis", "art", "bezug", "betreff", "text", "anhaenge",
];
const ANHANGFELDER = ["name", "typ", "inhalt"];
const NAMENSMUSTER = /^[a-z][a-z0-9-]{1,31}$/;
const IDMUSTER = /^[0-9a-f]{32}$/;
const DATUMSMUSTER = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const BASE64MUSTER = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function istObjekt(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hatExakteFelder(value: Record<string, unknown>, felder: string[]): boolean {
  const tatsaechlich = Object.keys(value).sort();
  const erwartet = [...felder].sort();
  return tatsaechlich.length === erwartet.length && tatsaechlich.every((feld, index) => feld === erwartet[index]);
}

function istDatum(value: string): boolean {
  if (!DATUMSMUSTER.test(value)) return false;
  const zeit = Date.parse(value);
  if (!Number.isFinite(zeit)) return false;
  const parsed = new Date(zeit);
  const [datum, uhr] = value.slice(0, -1).split("T");
  const [jahr, monat, tag] = datum!.split("-").map(Number);
  const [stunde, minute, sekunde] = uhr!.split(":");
  const [ganzSekunden, millisekunden = "0"] = sekunde!.split(".");
  const millis = Number(`0.${millisekunden}`) * 1000;
  return parsed.getUTCFullYear() === jahr
    && parsed.getUTCMonth() + 1 === monat
    && parsed.getUTCDate() === tag
    && parsed.getUTCHours() === Number(stunde)
    && parsed.getUTCMinutes() === Number(minute)
    && parsed.getUTCSeconds() === Number(ganzSekunden)
    && parsed.getUTCMilliseconds() === Math.floor(millis);
}

function schemaFehler(detail: string): HuellePruefung {
  return { ok: false, grund: "schema", detail };
}

export function pruefeHuelle(x: unknown): HuellePruefung {
  if (!istObjekt(x)) return schemaFehler("Die Hülle muss ein Objekt sein.");
  const felder = Object.hasOwn(x, "ausgeloest_von") ? [...HUELLENFELDER, "ausgeloest_von"] : HUELLENFELDER;
  if (!hatExakteFelder(x, felder)) return schemaFehler("Die Hülle hat fehlende oder unbekannte Felder.");
  if (x.v !== 1) return schemaFehler("v muss 1 sein.");
  if (typeof x.id !== "string" || !IDMUSTER.test(x.id)) return schemaFehler("id muss aus 32 Kleinbuchstaben-Hexzeichen bestehen.");
  if (typeof x.von !== "string" || !NAMENSMUSTER.test(x.von)) return schemaFehler("von ist kein gültiger Teilnehmername.");
  if (!Array.isArray(x.an) || x.an.length < 1 || x.an.length > 20) return schemaFehler("an muss 1 bis 20 Teilnehmer enthalten.");
  const empfaenger = new Set<string>();
  for (const name of x.an) {
    if (typeof name !== "string" || !NAMENSMUSTER.test(name)) return schemaFehler("an enthält einen ungültigen Teilnehmernamen.");
    if (name === x.von) return schemaFehler("von darf nicht in an stehen.");
    if (empfaenger.has(name)) return schemaFehler("an darf keine Dubletten enthalten.");
    empfaenger.add(name);
  }
  if (x.kanal !== null && (typeof x.kanal !== "string" || !NAMENSMUSTER.test(x.kanal))) return schemaFehler("kanal ist kein gültiger Verteilername.");
  if (typeof x.erstellt !== "string" || !istDatum(x.erstellt)) return schemaFehler("erstellt muss ein gültiges ISO-8601-UTC-Datum sein.");
  if (typeof x.gueltig_bis !== "string" || !istDatum(x.gueltig_bis)) return schemaFehler("gueltig_bis muss ein gültiges ISO-8601-UTC-Datum sein.");
  const erstellt = Date.parse(x.erstellt);
  const gueltigBis = Date.parse(x.gueltig_bis);
  if (gueltigBis <= erstellt || gueltigBis - erstellt > 30 * 24 * 60 * 60 * 1000) {
    return schemaFehler("gueltig_bis muss nach erstellt und höchstens dreißig Tage später liegen.");
  }
  if (x.art !== "info" && x.art !== "anfrage") return schemaFehler("art muss info oder anfrage sein.");
  if (x.bezug !== null && (typeof x.bezug !== "string" || !IDMUSTER.test(x.bezug))) return schemaFehler("bezug muss eine id oder null sein.");
  if (Object.hasOwn(x, "ausgeloest_von")) {
    const ausgeloestVon = x.ausgeloest_von;
    if (!istObjekt(ausgeloestVon) || !hatExakteFelder(ausgeloestVon, ["von", "huelle_id"])) {
      return schemaFehler("ausgeloest_von muss genau von und huelle_id enthalten.");
    }
    if (typeof ausgeloestVon.von !== "string" || !NAMENSMUSTER.test(ausgeloestVon.von)) {
      return schemaFehler("ausgeloest_von.von ist kein gültiger Teilnehmername.");
    }
    if (typeof ausgeloestVon.huelle_id !== "string" || !IDMUSTER.test(ausgeloestVon.huelle_id)) {
      return schemaFehler("ausgeloest_von.huelle_id muss aus 32 Kleinbuchstaben-Hexzeichen bestehen.");
    }
  }
  if (typeof x.betreff !== "string" || x.betreff.length < 1 || x.betreff.length > 200) return schemaFehler("betreff muss 1 bis 200 Zeichen haben.");
  if (typeof x.text !== "string" || x.text.length > 100_000) return schemaFehler("text darf höchstens 100000 Zeichen haben.");
  if (!Array.isArray(x.anhaenge) || x.anhaenge.length > 10) return schemaFehler("anhaenge darf höchstens zehn Einträge haben.");
  for (const [index, anhang] of x.anhaenge.entries()) {
    if (!istObjekt(anhang) || !hatExakteFelder(anhang, ANHANGFELDER)) return schemaFehler(`anhaenge[${index}] hat fehlende oder unbekannte Felder.`);
    if (typeof anhang.name !== "string" || typeof anhang.typ !== "string" || typeof anhang.inhalt !== "string") {
      return schemaFehler(`anhaenge[${index}] enthält einen falschen Feldtyp.`);
    }
    if (!BASE64MUSTER.test(anhang.inhalt)) return schemaFehler(`anhaenge[${index}].inhalt ist kein base64.`);
  }
  const huelle: Huelle = {
    v: 1,
    id: x.id as string,
    von: x.von as string,
    an: [...empfaenger],
    kanal: x.kanal as string | null,
    erstellt: x.erstellt as string,
    gueltig_bis: x.gueltig_bis as string,
    art: x.art,
    bezug: x.bezug as string | null,
    betreff: x.betreff as string,
    text: x.text as string,
    anhaenge: x.anhaenge.map((anhang) => {
      const geprueft = anhang as Record<string, unknown>;
      return { name: geprueft.name as string, typ: geprueft.typ as string, inhalt: geprueft.inhalt as string };
    }),
    ...(Object.hasOwn(x, "ausgeloest_von") ? {
      ausgeloest_von: {
        von: (x.ausgeloest_von as Record<string, unknown>).von as string,
        huelle_id: (x.ausgeloest_von as Record<string, unknown>).huelle_id as string,
      },
    } : {}),
  };
  return { ok: true, huelle };
}
