import { signiereAnfrage } from "../anfrage.ts";
import { wiederholeBeiDrosselung } from "../cli/netz.ts";
import { CliFehler } from "../cli/gemeinsam.ts";

export interface KlientOptionen {
  jetzt?: Date;
  nonce?: string;
}

export interface KlientFehler {
  status: number;
  grund: string;
}

export interface PostfachEintrag {
  id: string;
  von: string;
  groesse: number;
  eingang: string;
}

interface PostfachSeite {
  eintraege: PostfachEintrag[];
  naechster: string | null;
}

function basisUrl(base: string): string {
  return base.replace(/\/$/, "");
}

async function request(
  base: string,
  path: string,
  method: string,
  body: Uint8Array,
  name: string,
  signaturPrivat: Uint8Array,
  opt: KlientOptionen,
): Promise<Response> {
  const url = `${basisUrl(base)}${path}`;
  try {
    return await wiederholeBeiDrosselung(() => {
      const headers = signiereAnfrage({ methode: method, url, koerper: body, name, signaturPrivat, jetzt: opt.jetzt, nonce: opt.nonce });
      return fetch(url, { method, headers, body: body.length ? Buffer.from(body) : undefined });
    });
  } catch (error) {
    if (error instanceof CliFehler) throw error;
    throw new CliFehler(2, "Post office request failed.");
  }
}

async function fehler(response: Response): Promise<KlientFehler> {
  let grund = "unbekannt";
  try { grund = (await response.json() as { grund?: string }).grund ?? grund; } catch { /* body ist nicht JSON */ }
  return { status: response.status, grund };
}

export async function einliefern(base: string, bytes: Uint8Array, name: string, signaturPrivat: Uint8Array, opt: KlientOptionen = {}): Promise<{ status: number; id: string } | KlientFehler> {
  const response = await request(base, "/v1/einliefern", "POST", bytes, name, signaturPrivat, opt);
  if (!response.ok) return fehler(response);
  return { status: response.status, ...(await response.json() as { id: string }) };
}

export async function liste(base: string, postfach: string, name: string, signaturPrivat: Uint8Array, opt: KlientOptionen = {}): Promise<PostfachEintrag[] | KlientFehler> {
  const path = `/v1/postfach/${encodeURIComponent(postfach)}`;
  const first = await request(base, path, "GET", new Uint8Array(), name, signaturPrivat, opt);
  if (!first.ok) return fehler(first);
  const firstBody = await first.json() as PostfachEintrag[] | PostfachSeite;
  const entries = Array.isArray(firstBody) ? firstBody : firstBody?.eintraege;
  if (!Array.isArray(entries) || (!Array.isArray(firstBody) && (firstBody.naechster !== null && typeof firstBody.naechster !== "string"))) {
    return { status: 502, grund: "format" };
  }
  let cursor = Array.isArray(firstBody) ? linkCursor(first.headers.get("link")) : firstBody.naechster;
  const followUpOptions = { ...opt };
  delete followUpOptions.nonce;
  while (cursor) {
    const response = await request(base, `${path}?nach=${encodeURIComponent(cursor)}`, "GET", new Uint8Array(), name, signaturPrivat, followUpOptions);
    if (!response.ok) return fehler(response);
    const page = await response.json() as PostfachSeite;
    if (!Array.isArray(page.eintraege) || (page.naechster !== null && typeof page.naechster !== "string")) return { status: 502, grund: "format" };
    entries.push(...page.eintraege);
    cursor = page.naechster;
  }
  return entries;
}

function linkCursor(link: string | null): string | null {
  const match = link?.match(/<[^>]*[?&]nach=([^>;]+)>;\s*rel="next"/);
  return match ? decodeURIComponent(match[1]!) : null;
}

export async function holen(base: string, postfach: string, id: string, name: string, signaturPrivat: Uint8Array, opt: KlientOptionen = {}): Promise<Uint8Array | KlientFehler> {
  const response = await request(base, `/v1/postfach/${encodeURIComponent(postfach)}/${encodeURIComponent(id)}`, "GET", new Uint8Array(), name, signaturPrivat, opt);
  if (!response.ok) return fehler(response);
  return new Uint8Array(await response.arrayBuffer());
}

export async function quittieren(base: string, postfach: string, id: string, name: string, signaturPrivat: Uint8Array, opt: KlientOptionen = {}): Promise<{ status: number } | KlientFehler> {
  const response = await request(base, `/v1/postfach/${encodeURIComponent(postfach)}/${encodeURIComponent(id)}`, "DELETE", new Uint8Array(), name, signaturPrivat, opt);
  return response.ok ? { status: response.status } : fehler(response);
}

export async function status(base: string, id: string, name: string, signaturPrivat: Uint8Array, opt: KlientOptionen = {}): Promise<Record<string, "abgeholt" | "liegt" | "verfallen"> | KlientFehler> {
  const response = await request(base, `/v1/status/${encodeURIComponent(id)}`, "GET", new Uint8Array(), name, signaturPrivat, opt);
  if (!response.ok) return fehler(response);
  return response.json() as Promise<Record<string, "abgeholt" | "liegt" | "verfallen">>;
}
