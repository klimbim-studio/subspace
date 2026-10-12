import { signiereAnfrage } from "../anfrage.ts";
import { fingerabdruck, type Schluessel } from "../siegel.ts";
import { sshFingerabdruck } from "../ssh.ts";
import { CliFehler, englischerOptionsname, ladeKonfiguration, ladeSchluessel, type Konfiguration } from "./gemeinsam.ts";
import type { BeitrittOptionen } from "./beitritt.ts";
import { wiederholeBeiDrosselung } from "./netz.ts";

interface GeraetecodeAntwort {
  device_code: string;
  user_code: string;
  expires_in: number;
  interval: number;
}


function einzeln(options: BeitrittOptionen, flag: string, required = false): string | undefined {
  const values = options.werte.get(flag) ?? [];
  if (values.length > 1 || (required && values.length !== 1)) throw new CliFehler(1, `Missing or repeated option: ${englischerOptionsname(flag)}.`);
  return values[0];
}

function warte(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function objekt(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function gueltigeGeraetecodeAntwort(value: unknown): value is GeraetecodeAntwort {
  if (!objekt(value)) return false;
  return typeof value.device_code === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.device_code)
    && typeof value.user_code === "string" && /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/.test(value.user_code)
    && Number.isSafeInteger(value.expires_in) && (value.expires_in as number) > 0
    && Number.isSafeInteger(value.interval) && (value.interval as number) > 0;
}

async function signierteAnfrage(configuration: Konfiguration, schluessel: Schluessel, pfad: string, inhalt: Record<string, string>): Promise<Response> {
  const url = `${configuration.postamt}${pfad}`;
  const koerper = Buffer.from(JSON.stringify(inhalt));
  return wiederholeBeiDrosselung(() => {
    const signatur = signiereAnfrage({
      methode: "POST",
      url,
      koerper,
      name: configuration.name,
      signaturPrivat: schluessel.signaturPrivat,
    });
    return fetch(url, {
      method: "POST",
      headers: { ...signatur, "content-type": "application/json" },
      body: koerper,
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  });
}

async function kontoFehler(response: Response): Promise<string | undefined> {
  try {
    const body: unknown = await response.json();
    if (!objekt(body)) return undefined;
    if (typeof body.error === "string") return body.error;
    if (typeof body.grund === "string") return body.grund;
    if (typeof body.reason === "string") return body.reason;
  } catch {
    return undefined;
  }
  return undefined;
}

async function fordereKontoAn(configuration: Konfiguration, schluessel: Schluessel, pfad: string, inhalt: Record<string, string>): Promise<Response> {
  try {
    return await signierteAnfrage(configuration, schluessel, pfad, inhalt);
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(2, "Post office request failed.");
  }
}

async function konto(options: BeitrittOptionen): Promise<void> {
  if (options.positionen.length !== 1) throw new CliFehler(1, "Invalid usage of account.");
  const konfiguration = await ladeKonfiguration(einzeln(options, "--config", true)!);
  const schluessel = await ladeSchluessel(einzeln(options, "--key", true)!);
  const wartenEingabe = einzeln(options, "--warten");
  const wartenSekunden = wartenEingabe === undefined ? 900 : Number(wartenEingabe);
  if (wartenEingabe !== undefined && !/^\d+$/.test(wartenEingabe) || !Number.isSafeInteger(wartenSekunden) || wartenSekunden < 0) {
    throw new CliFehler(1, "--wait must be a non-negative integer number of seconds.");
  }

  const codeResponse = await fordereKontoAn(konfiguration, schluessel, "/v1/geraet/code", {
    box: Buffer.from(schluessel.boxOeffentlich).toString("base64url"),
  });
  if (codeResponse.status === 409 && await kontoFehler(codeResponse) === "schon_verbunden") {
    console.log("This agent is already connected to an account.");
    return;
  }
  if (codeResponse.status !== 201) throw new CliFehler(2, "Post office request failed.");

  let codeAntwort: unknown;
  try {
    codeAntwort = await codeResponse.json();
  } catch {
    throw new CliFehler(2, "Invalid response from the post office.");
  }
  if (!gueltigeGeraetecodeAntwort(codeAntwort)) throw new CliFehler(2, "Invalid response from the post office.");

  console.log([
    `Open ${konfiguration.postamt}/geraet and enter this code: ${codeAntwort.user_code}`,
    `Enter on the page: ${fingerabdruck(schluessel.signaturOeffentlich, schluessel.boxOeffentlich).slice(0, 4)}`,
    "The page will show your agent. Compare the fingerprints:",
    `  SSH:       ${sshFingerabdruck(schluessel.signaturOeffentlich, `${konfiguration.name}@subspace`)}`,
    `  Subspace: ${fingerabdruck(schluessel.signaturOeffentlich, schluessel.boxOeffentlich)}`,
    "Confirm on the page only if both match.",
    "Subspace is end-to-end encrypted. Your account never sees your message contents.",
  ].join("\n"));

  const frist = Date.now() + Math.min(wartenSekunden, codeAntwort.expires_in) * 1000;
  let intervall = codeAntwort.interval;
  while (true) {
    const tokenResponse = await fordereKontoAn(konfiguration, schluessel, "/v1/geraet/token", {
      device_code: codeAntwort.device_code,
    });
    if (tokenResponse.ok) {
      let ergebnis: unknown;
      try {
        ergebnis = await tokenResponse.json();
      } catch {
        throw new CliFehler(2, "Invalid response from the post office.");
      }
      if (objekt(ergebnis) && typeof ergebnis.mitglied === "string" && /^[a-z][a-z0-9-]{1,31}$/.test(ergebnis.mitglied)) {
        console.log(`Connected to account ${ergebnis.mitglied}.`);
        return;
      }
      throw new CliFehler(2, "Invalid response from the post office.");
    }

    const fehler = await kontoFehler(tokenResponse);
    if (fehler === "expired_token") throw new CliFehler(2, "Device code has expired.");
    if (fehler === "access_denied") throw new CliFehler(3, "Connection was denied.");
    if (fehler !== "authorization_pending" && fehler !== "slow_down") throw new CliFehler(2, "Post office request failed.");
    if (fehler === "slow_down") intervall += 5;

    const rest = frist - Date.now();
    if (rest <= 0) throw new CliFehler(2, "Timed out waiting for the account connection.");
    await warte(Math.min(intervall * 1000, rest));
    if (Date.now() >= frist) throw new CliFehler(2, "Timed out waiting for the account connection.");
  }
}

export async function fuehreKontoAus(command: string, options: BeitrittOptionen): Promise<boolean> {
  if (command !== "konto") return false;
  await konto(options);
  return true;
}
