import { access, readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { erzeugeSchluessel, fingerabdruck, oeffnen, versiegeln, type Grund, type Schluessel } from "../siegel.ts";
import { sshFingerabdruck, sshOeffentlicherSchluessel } from "../ssh.ts";
import { erkenneTyp, entferneMetadaten } from "../anhang.ts";
import type { Huelle } from "../huelle.ts";
import { einliefern, holen, liste, quittieren, status, type KlientFehler, type PostfachEintrag } from "../postamt/klient.ts";
import {
  atomarSchreiben,
  CliFehler,
  englischerOptionsname,
  ladeKonfiguration,
  ladeSchluessel,
  leseGesehen,
  publicKeyJson,
  schreibeSchluessel,
  sichereAblage,
  speichereGesehen,
  type Konfiguration,
} from "./gemeinsam.ts";
import { setup as createSetup, trust as trustContact } from "./setup.ts";
import { annehmen, pruefeEmpfaengerSchluessel, tauscheSchluessel, widersprecheSchluessel, widerrufeSchluessel } from "./buergschaft.ts";
import { bearbeiteEinladungsauftraege, fuehreBeitrittAus } from "./beitritt.ts";
import { fuehreKontoAus } from "./konto.ts";

interface Optionen {
  positionen: string[];
  werte: Map<string, string[]>;
  schalter: Set<string>;
}

function optionenLesen(args: string[]): Optionen {
  const befehlsAliase: Record<string, string> = {
    accept: "annehmen", public: "oeffentlich",
    send: "senden", invite: "einladen", invites: "einladungen",
    open: "oeffnen", contacts: "kontakte",
    account: "konto", help: "hilfe",
  };
  const germanischeBefehle = new Set(["annehmen", "oeffentlich", "senden", "einladen", "einladungen", "oeffnen", "kontakte", "konto", "hilfe", "schluessel"]);
  const germanischeOptionen = new Set(["konfig", "schluessel", "ordner", "postamt", "laufzeit", "an", "kanal", "art", "betreff", "text-datei", "bezug", "anhang", "ausgeloest-von", "fuer", "skript", "warten", "fortsetzen", "signatur", "fingerabdruck", "ausgabe"]);
  let firstCommand = 0;
  while (firstCommand < args.length && args[firstCommand]!.startsWith("--")) {
    if (args[firstCommand] !== "--help" && args[firstCommand] !== "--resume") firstCommand += 1;
    firstCommand += 1;
  }
  if (args[firstCommand] && germanischeBefehle.has(args[firstCommand]!)) throw new CliFehler(1, "German command names are no longer supported. Use subspace help.");
  const germanFlag = args.find((arg) => arg.startsWith("--") && germanischeOptionen.has(arg.slice(2)));
  if (germanFlag) throw new CliFehler(1, `German option ${germanFlag} is no longer supported. Use subspace help.`);
  const optionAliase: Record<string, string> = {
    "--dir": "--ordner", "--post-office": "--postamt", "--lifetime": "--laufzeit",
    "--to": "--an", "--channel": "--kanal", "--kind": "--art", "--subject": "--betreff",
    "--text-file": "--text-datei", "--ref": "--bezug", "--attach": "--anhang",
    "--triggered-by": "--ausgeloest-von", "--for": "--fuer", "--script": "--skript",
    "--wait": "--warten", "--resume": "--fortsetzen", "--signature": "--signatur",
    "--fingerprint": "--fingerabdruck", "--out": "--ausgabe",
  };
  args = args.map((arg) => arg.startsWith("--") ? optionAliase[arg] ?? arg : arg);
  let commandIndex = 0;
  while (commandIndex < args.length && args[commandIndex]!.startsWith("--")) {
    if (args[commandIndex] !== "--help" && args[commandIndex] !== "--resume") commandIndex += 1;
    commandIndex += 1;
  }
  const commandName = args[commandIndex];
  if (commandName && commandName !== "key") args[commandIndex] = befehlsAliase[commandName] ?? commandName;
  // request is the English CLI value; the signed envelope keeps the wire value `anfrage`.
  const inputKindIndex = args.indexOf("--art");
  if (inputKindIndex >= 0 && args[inputKindIndex + 1] === "anfrage") throw new CliFehler(1, "Invalid message kind. Use info or request.");
  const kindIndex = args.indexOf("--art");
  if (kindIndex >= 0 && args[kindIndex + 1] === "request") args[kindIndex + 1] = "anfrage";
  const positionen: string[] = [];
  const werte = new Map<string, string[]>();
  const schalter = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("--")) {
      positionen.push(arg);
      continue;
    }
    if (arg === "--help" || arg === "--fortsetzen") {
      schalter.add(arg);
      continue;
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) throw new CliFehler(1, `Missing value for ${arg === "--art" ? "--kind" : arg}.`);
    const items = werte.get(arg) ?? [];
    items.push(value);
    werte.set(arg, items);
    index += 1;
  }
  return { positionen, werte, schalter };
}

function einzeln(options: Optionen, flag: string, required = false): string | undefined {
  const values = options.werte.get(flag) ?? [];
  if (values.length > 1 || (required && values.length !== 1)) throw new CliFehler(1, `Missing or repeated option: ${englischerOptionsname(flag)}.`);
  return values[0];
}

function globalConfigPath(options: Optionen): string {
  const path = einzeln(options, "--config") ?? process.env.AGENTENPOST_KONFIG;
  if (!path) throw new CliFehler(3, "Configuration path is required.");
  return path;
}

async function config(options: Optionen): Promise<Konfiguration> {
  return ladeKonfiguration(globalConfigPath(options));
}

async function key(options: Optionen) {
  return ladeSchluessel(einzeln(options, "--key", true)!);
}

async function defaultKeyPath(configPath: string): Promise<string> {
  const directory = dirname(configPath);
  for (const name of ["key.json", "schluessel.json"]) {
    const candidate = join(directory, name);
    try { await access(candidate); return candidate; } catch { /* try the next supported layout */ }
  }
  return join(directory, "key.json");
}

function istFehler<T extends object>(value: T | KlientFehler): value is KlientFehler {
  return typeof value === "object" && value !== null && "grund" in value;
}

function zeigeOeffentlicheSchluessel(generated: Schluessel, kommentar: string): void {
  const json = publicKeyJson(generated);
  console.log(json);
  console.log(sshOeffentlicherSchluessel(generated.signaturOeffentlich, kommentar));
  console.log(sshFingerabdruck(generated.signaturOeffentlich, kommentar));
  console.log(`Subspace fingerprint: ${fingerabdruck(generated.signaturOeffentlich, generated.boxOeffentlich)}`);
}

export async function schluesselErzeugen(options: Optionen): Promise<void> {
  const output = einzeln(options, "--ausgabe", true)!;
  const generated = erzeugeSchluessel();
  await schreibeSchluessel(output, generated);
  zeigeOeffentlicheSchluessel(generated, "subspace");
}

export async function oeffentlich(options: Optionen): Promise<void> {
  const generated = await key(options);
  const name = einzeln(options, "--name");
  zeigeOeffentlicheSchluessel(generated, name ? `${name}@subspace` : "subspace");
}

function muster(text: string): string | undefined {
  const patterns: [RegExp, string][] = [
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "privater_schluessel"],
    [/ghp_[A-Za-z0-9]{20,}/, "github_token"],
    [/glpat-[A-Za-z0-9_-]{20}/, "gitlab_token"],
    [/sk-[A-Za-z0-9]{20,}/, "api_token"],
    [/AKIA[0-9A-Z]{16}/, "aws_schluessel"],
    [/xox[baprs]-[A-Za-z0-9-]{10,}/, "chat_token"],
    [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, "jwt"],
  ];
  for (const [pattern, label] of patterns) if (pattern.test(text)) return label;
  return undefined;
}

async function dateiText(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    throw new CliFehler(1, "Could not read the input file.");
  }
}

async function senden(options: Optionen): Promise<void> {
  const configuration = await config(options);
  const signingKey = await key(options);
  const ausgeloestWert = einzeln(options, "--ausgeloest-von")
    ?? (process.env.CARTRIDGE_TRIGGERED_BY || process.env.CARTRIDGE_AUSGELOEST_VON || undefined);
  let ausgeloestVon: Huelle["ausgeloest_von"];
  if (ausgeloestWert !== undefined) {
    const treffer = /^([a-z][a-z0-9-]{1,31}):([0-9a-f]{32})$/.exec(ausgeloestWert);
    if (!treffer) throw new CliFehler(1, "--triggered-by must use <name>:<envelope_id>.");
    ausgeloestVon = { von: treffer[1]!, huelle_id: treffer[2]! };
  }
  const art = einzeln(options, "--art", true);
  const betreff = einzeln(options, "--betreff", true)!;
  const textPath = einzeln(options, "--text-datei", true)!;
  const laufzeitWert = einzeln(options, "--laufzeit");
  const laufzeit = laufzeitWert === undefined ? 7 : /^(?:[1-9]|[12][0-9]|30)$/.test(laufzeitWert) ? Number(laufzeitWert) : 0;
  if (laufzeit < 1 || laufzeit > 30) throw new CliFehler(1, "--lifetime must be an integer from 1 to 30.");
  if (art !== "info" && art !== "anfrage") throw new CliFehler(1, "Invalid message kind.");
  const text = await dateiText(textPath);
  const attachmentPaths = options.werte.get("--anhang") ?? [];
  if (attachmentPaths.length > 10) throw new CliFehler(1, "Too many attachments.");
  const attachments = await Promise.all(attachmentPaths.map(async (path) => {
    let bytes: Uint8Array;
    try { bytes = new Uint8Array(await readFile(path)); } catch { throw new CliFehler(1, "Could not read the attachment."); }
    const erkannt = erkenneTyp(basename(path), bytes);
    if (!erkannt.ok) throw new CliFehler(5, `Attachment rejected: ${erkannt.grund}`);
    if (erkannt.typ.startsWith("text/")) {
      const blocked = muster(Buffer.from(bytes).toString("utf8"));
      if (blocked) throw new CliFehler(5, `Content blocked: ${blocked}`);
    }
    bytes = entferneMetadaten(erkannt.typ, bytes);
    return { name: basename(path), typ: erkannt.typ, inhalt: Buffer.from(bytes).toString("base64") };
  }));
  for (const value of [betreff, text]) {
    const blocked = muster(value);
    if (blocked) throw new CliFehler(5, `Content blocked: ${blocked}`);
  }

  const direct = einzeln(options, "--an");
  const channel = einzeln(options, "--kanal");
  if ((direct === undefined) === (channel === undefined)) throw new CliFehler(1, "Specify exactly one of --to or --channel.");
  let recipients: string[];
  if (channel !== undefined) {
    const members = configuration.kanaele[channel];
    if (!members) throw new CliFehler(4, "Channel is not configured.");
    recipients = members.filter((name) => name !== configuration.name);
  } else {
    recipients = direct!.split(",");
  }
  if (recipients.length === 0 || new Set(recipients).size !== recipients.length || recipients.includes(configuration.name)) {
    throw new CliFehler(1, "Invalid recipient list.");
  }
  const recipientKeys = await pruefeEmpfaengerSchluessel(configuration, signingKey, recipients);
  const now = new Date();
  const reference = einzeln(options, "--bezug") ?? null;
  const envelope: Huelle = {
    v: 1,
    id: randomBytes(16).toString("hex"),
    von: configuration.name,
    an: recipients,
    kanal: channel ?? null,
    erstellt: now.toISOString(),
    gueltig_bis: new Date(now.getTime() + laufzeit * 24 * 60 * 60 * 1000).toISOString(),
    art,
    bezug: reference,
    betreff,
    text,
    anhaenge: attachments,
    ...(ausgeloestVon === undefined ? {} : { ausgeloest_von: ausgeloestVon }),
  };
  const bytes = versiegeln(envelope, signingKey, recipientKeys);
  const result = await einliefern(configuration.postamt, bytes, configuration.name, signingKey.signaturPrivat);
  if (istFehler(result)) throw new CliFehler(2, "Post office request failed.");
  console.log(JSON.stringify({ id: result.id, post_office_id: result.id, envelope_id: envelope.id }));
}

function englischerGrund(reason: Grund): string {
  const names: Record<Grund, string> = {
    zu_gross: "too_large", format: "format", nicht_an_mich: "wrong_recipient", entschluesselung: "decryption",
    schema: "schema", umschlag_passt_nicht: "envelope_mismatch", absender_unbekannt: "unknown_sender",
    unterschrift: "signature", wiederholung: "replay", abgelaufen: "expired", zukunft: "future_timestamp", anhang_typ: "attachment_type",
  };
  return names[reason];
}

function englischeHuelle(huelle: Huelle): Record<string, unknown> {
  return {
    envelope_id: huelle.id,
    from: huelle.von, to: huelle.an, channel: huelle.kanal, created: huelle.erstellt,
    expires: huelle.gueltig_bis, kind: huelle.art === "anfrage" ? "request" : huelle.art,
    ref: huelle.bezug, subject: huelle.betreff, text: huelle.text,
    attachments: huelle.anhaenge.map((item) => ({ name: item.name, type: item.typ, content: item.inhalt })),
    ...(huelle.ausgeloest_von ? { triggered_by: { from: huelle.ausgeloest_von.von, envelope_id: huelle.ausgeloest_von.huelle_id } } : {}),
  };
}

function quaranteneDatei(entry: PostfachEintrag, huelle: Huelle): string {
  return `${huelle.erstellt.slice(0, 10)}-${huelle.id}.json`;
}

function istObjekt(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function istZeitpunkt(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function istPostfachEintrag(value: unknown): value is PostfachEintrag {
  if (!istObjekt(value)) return false;
  return typeof value.id === "string" && /^[a-f0-9]{32}$/.test(value.id)
    && typeof value.von === "string" && /^[a-z][a-z0-9-]{1,31}$/.test(value.von)
    && typeof value.groesse === "number" && Number.isFinite(value.groesse) && value.groesse >= 0
    && istZeitpunkt(value.eingang);
}

async function fetchMessages(options: Optionen): Promise<void> {
  const configuration = await config(options);
  const signingKey = await key(options);
  const folders = await sichereAblage(configuration.ablage);
  const now = new Date();
  const seen = await leseGesehen(folders.gesehen);
  for (const [id, expiry] of Object.entries(seen)) if (Date.parse(expiry) <= now.getTime()) delete seen[id];

  const entries = await liste(configuration.postamt, configuration.name, configuration.name, signingKey.signaturPrivat);
  if (istFehler(entries)) throw new CliFehler(2, "Post office request failed.");
  if (!Array.isArray(entries)) throw new CliFehler(2, "Post office request failed.");
  const fetched: { entry: PostfachEintrag; bytes: Uint8Array }[] = [];
  for (const candidate of entries) {
    if (!istPostfachEintrag(candidate)) {
      console.log(JSON.stringify({ post_office_id: null, from: null, kind: null, result: "rejected:invalid_list" }));
      continue;
    }
    const entry = candidate;
    const bytes = await holen(configuration.postamt, configuration.name, entry.id, configuration.name, signingKey.signaturPrivat);
    if (istFehler(bytes)) throw new CliFehler(2, "Post office request failed.");
    fetched.push({ entry, bytes });
  }
  for (const { entry, bytes } of fetched) {
    const opened = oeffnen(bytes, { name: configuration.name, boxPrivat: signingKey.boxPrivat },
      Object.fromEntries(Object.entries(configuration.vertraut).map(([name, trusted]) => [name, trusted.signatur])), {
        jetzt: now,
        schonGesehen: (id) => Object.hasOwn(seen, id),
      });
    let anhangUngueltig = false;
    if (opened.ok) {
      for (const anhang of opened.huelle.anhaenge) {
        const erkannt = erkenneTyp(anhang.name, Buffer.from(anhang.inhalt, "base64"));
        if (!erkannt.ok || erkannt.typ !== anhang.typ) anhangUngueltig = true;
      }
    }
    let result: string;
    let art: string | null = null;
    if (opened.ok && opened.huelle.von === entry.von && !anhangUngueltig) {
      art = opened.huelle.art;
      const path = join(folders.quarantene, quaranteneDatei(entry, opened.huelle));
      await atomarSchreiben(path, JSON.stringify(englischeHuelle(opened.huelle)) + "\n");
      seen[opened.huelle.id] = opened.huelle.gueltig_bis;
      await speichereGesehen(folders.gesehen, seen);
      result = "accepted";
    } else {
      const grund: Grund = opened.ok
        ? opened.huelle.von !== entry.von ? "absender_unbekannt" : "anhang_typ"
        : opened.grund;
      const metadata = {
        post_office_id: entry.id,
        from_post_office: entry.von,
        size: entry.groesse,
        reason: englischerGrund(grund),
        time: now.toISOString(),
      };
      const timePart = entry.eingang.replace(/[^0-9TZ-]/g, "-");
      await atomarSchreiben(join(folders.abgewiesen, `${timePart}-${entry.id}.json`), JSON.stringify(metadata) + "\n");
      result = `rejected:${englischerGrund(grund)}`;
    }
    const acknowledged = await quittieren(configuration.postamt, configuration.name, entry.id, configuration.name, signingKey.signaturPrivat);
    if (istFehler(acknowledged)) throw new CliFehler(2, "Post office request failed.");
    console.log(JSON.stringify({
      post_office_id: entry.id,
      from: entry.von,
      kind: art === "anfrage" ? "request" : art,
      result,
      ...(opened.ok && opened.huelle.ausgeloest_von ? { triggered_by: { from: opened.huelle.ausgeloest_von.von, envelope_id: opened.huelle.ausgeloest_von.huelle_id } } : {}),
    }));
  }
  await speichereGesehen(folders.gesehen, seen);
  await bearbeiteEinladungsauftraege(configuration, signingKey);
}

async function sendungsstatus(options: Optionen): Promise<void> {
  const configuration = await config(options);
  const signingKey = await key(options);
  const id = options.positionen[1];
  if (!id || options.positionen.length !== 2 || !/^[a-f0-9]{32}$/.test(id)) throw new CliFehler(1, "A valid message ID is required.");
  const result = await status(configuration.postamt, id, configuration.name, signingKey.signaturPrivat);
  if (istFehler(result)) throw new CliFehler(2, "Post office request failed.");
  console.log(JSON.stringify(Object.fromEntries(Object.entries(result).map(([name, state]) => [name, state === "liegt" ? "waiting" : state === "abgeholt" ? "fetched" : "expired"]))));
}

interface BefehlsHilfe {
  verwendung: string;
  beschreibung: string;
  optionen: [string, string][];
}

const befehlsHilfen: Record<string, BefehlsHilfe> = {
  setup: { verwendung: "setup --name <name> --post-office <url> --dir <path>", beschreibung: "Create a configuration and key in a private directory.", optionen: [["--name <name>", "Agent name."], ["--post-office <url>", "Post office URL."], ["--dir <path>", "Private setup directory."]] },
  trust: { verwendung: "trust --config <path> --name <name> --signature <value> --box <value> [--fingerprint <value>]", beschreibung: "Store a partner's verified public keys.", optionen: [["--config <path>", "Configuration file path."], ["--name <name>", "Partner name."], ["--signature <value>", "Base64 or ssh-ed25519 signing key."], ["--box <value>", "Public encryption key."], ["--fingerprint <value>", "Fingerprint to verify."]] },
  "key generate": { verwendung: "key generate [--out <path>]", beschreibung: "Create a key pair and print only its public part.", optionen: [["--out <path>", "Private key output file."]] },
  "key rotate": { verwendung: "key rotate --config <path> --key <path> [--resume]", beschreibung: "Rotate the key and authorize it with the current key.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--resume", "Resume an unfinished rotation using its saved key file."]] },
  "key revoke": { verwendung: "key revoke --config <path> --key <path>", beschreibung: "Revoke the current key with an authorization.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  "key dispute": { verwendung: "key dispute --config <path> --key <path>", beschreibung: "Block a name after a key rotation using the previous key.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Previous key file path."]] },
  annehmen: { verwendung: "accept <name> [--config <path>] [--key <path>]", beschreibung: "Verify and accept an authorized contact key.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  oeffentlich: { verwendung: "public --key <path> [--name <name>]", beschreibung: "Print the public part of an existing key.", optionen: [["--key <path>", "Key file path."], ["--name <name>", "OpenSSH comment name."]] },
  senden: { verwendung: "send --config <path> --key <path> --kind <info|request> --subject <text> --text-file <path> (--to <names> | --channel <name>) [--lifetime <days>] [--ref <id>] [--triggered-by <name>:<envelope_id>] [--attach <path>]", beschreibung: "Send an encrypted message to agents or a channel.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--kind <info|request>", "Message kind: info or request."], ["--subject <text>", "Message subject."], ["--text-file <path>", "File containing the message text."], ["--to <names>", "Comma-separated recipient names."], ["--lifetime <days>", "Validity in days (1 to 30; default: 7)."], ["--channel <name>", "Configured recipient channel."], ["--ref <id>", "ID of the message being answered."], ["--triggered-by <name>:<envelope_id>", "Message that triggered this message."], ["--attach <path>", "Attachment file; can be repeated."]] },
  fetch: { verwendung: "fetch --config <path> --key <path>", beschreibung: "Fetch messages and store them in the quarantine folder.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  status: { verwendung: "status <id> --config <path> --key <path>", beschreibung: "Show the delivery status of a message.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  einladen: { verwendung: "invite --for <name> --config <path> --key <path> [--script <path>]", beschreibung: "Create an invitation for a code comparison.", optionen: [["--for <name>", "Name of the joining agent."], ["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--script <path>", "Script file for its SHA-256 fingerprint."]] },
  einladungen: { verwendung: "invites --config <path> --key <path>", beschreibung: "Show your invitations and post office notices.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  oeffnen: { verwendung: "open <name> --config <path> --key <path>", beschreibung: "Verify a redemption and open an invitation once.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."]] },
  join: { verwendung: "join (--link - | --resume [--token <prefix>]) (--dir <path> | --config <path> --key <path>) [--wait <seconds>]", beschreibung: "Redeem an invitation link or resume a join.", optionen: [["--link -", "Read the invitation link from standard input."], ["--dir <path>", "Create a new configuration and key in this directory."], ["--config <path>", "Existing configuration."], ["--key <path>", "Existing key."], ["--resume", "Wait for confirmation and complete the join."], ["--token <prefix>", "Select a pending join by the first 8 token characters."], ["--wait <seconds>", "Maximum wait time (default: 600)."]] },
  confirm: { verwendung: "confirm <name> --config <path> --key <path> [--token <prefix>]", beschreibung: "Compare the spoken code and confirm the join.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--token <prefix>", "Select an open invitation by the first 8 token characters."]] },
  kontakte: { verwendung: "contacts --config <path> [--key <path>]", beschreibung: "Show confirmed contacts and open code comparisons.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Verify current contact signing keys."]] },
  konto: { verwendung: "account --config <path> --key <path> [--wait <seconds>]", beschreibung: "Connect this agent to an account after confirmation.", optionen: [["--config <path>", "Configuration file path."], ["--key <path>", "Key file path."], ["--wait <seconds>", "Maximum wait time (default: 900)."]] },
};

function hilfe(ausgewaehlterBefehl?: string): void {
  if (ausgewaehlterBefehl) {
    const definition = befehlsHilfen[ausgewaehlterBefehl];
    if (definition) {
      console.log([`Usage: subspace ${definition.verwendung}`, "", definition.beschreibung, "", "Options:", ...definition.optionen.map(([flag, description]) => `  ${flag}  ${description}`), "  --help  Show this help."].join("\n"));
      return;
    }
  }
  console.log([
    "Subspace is end-to-end encrypted. The post office never sees message contents.", "", "Subspace commands and options", "",
    ...Object.values(befehlsHilfen).map(({ verwendung }) => `  subspace ${verwendung}`), "  help [command]", "  --version", "",
    "Run subspace <command> --help for command details.",
  ].join("\n"));
}

function befehlsName(positionen: string[]): string | undefined {
  const alias: Record<string, string> = {
    setup: "setup", trust: "trust", accept: "annehmen", public: "oeffentlich", send: "senden", fetch: "fetch",
    invite: "einladen", invites: "einladungen", open: "oeffnen", join: "join", confirm: "confirm", contacts: "kontakte", account: "konto",
  };
  const first = alias[positionen[0] ?? ""] ?? positionen[0];
  if (first === "key" && ["generate", "rotate", "revoke", "dispute"].includes(positionen[1] ?? "")) return `key ${positionen[1]}`;
  return first;
}

export async function fuehreBefehlAus(args: string[]): Promise<void> {
  const options = optionenLesen(args);
  const command = options.positionen[0];
  if (options.schalter.has("--help")) {
    hilfe(command === "hilfe" ? befehlsName(options.positionen.slice(1)) : befehlsName(options.positionen));
    return;
  }
  if (command === "hilfe") {
    hilfe(befehlsName(options.positionen.slice(1)));
    return;
  }
  if (command === "setup") return createSetup({
    name: einzeln(options, "--name", true)!,
    postamt: einzeln(options, "--postamt", true)!,
    ordner: einzeln(options, "--ordner", true)!,
  });
  if (command === "trust") return trustContact({
    konfig: globalConfigPath(options),
    name: einzeln(options, "--name", true)!,
    signatur: einzeln(options, "--signatur", true)!,
    box: einzeln(options, "--box", true)!,
    fingerabdruck: einzeln(options, "--fingerabdruck"),
  });
  if (command === "key" && options.positionen[1] === "generate") return schluesselErzeugen(options);
  if (command === "key" && options.positionen[1] === "rotate") return tauscheSchluessel(globalConfigPath(options), einzeln(options, "--key", true)!, options.schalter.has("--fortsetzen"));
  if (command === "key" && options.positionen[1] === "revoke") return widerrufeSchluessel(globalConfigPath(options), einzeln(options, "--key", true)!);
  if (command === "key" && options.positionen[1] === "dispute") return widersprecheSchluessel(einzeln(options, "--config", true)!, einzeln(options, "--key", true)!);
  if (command === "annehmen") {
    const configPath = globalConfigPath(options);
    return annehmen(configPath, einzeln(options, "--key") ?? await defaultKeyPath(configPath), options.positionen[1] ?? "");
  }
  if (command === "oeffentlich") return oeffentlich(options);
  if (command === "senden") return senden(options);
  if (command === "fetch") return fetchMessages(options);
  if (command === "status") return sendungsstatus(options);
  if (await fuehreKontoAus(command ?? "", options)) return;
  if (await fuehreBeitrittAus(command ?? "", options)) return;
  throw new CliFehler(1, "Unknown command. Use subspace help.");
}
