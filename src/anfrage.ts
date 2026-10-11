import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

const utf8 = new TextEncoder();
const KOMPONENTEN = ["@method", "@path", "@authority", "content-digest"] as const;
const TAG = "agentenpost-v1";
const NAMENSMUSTER = /^[a-z][a-z0-9-]{1,31}$/;

export interface SignaturKomponente {
  name: string;
  wert: string;
}

export function signaturBasis(komponenten: readonly SignaturKomponente[], signaturInput: string): string {
  return [
    ...komponenten.map(({ name, wert }) => `"${name.toLowerCase()}": ${wert}`),
    `"@signature-params": ${signaturInput}`,
  ].join("\n");
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function digest(koerper: Uint8Array): string {
  return `sha-256=:${Buffer.from(sha256(koerper)).toString("base64")}:`;
}

function signaturInput(created: number, nonce: string, name: string): string {
  return `("@method" "@path" "@authority" "content-digest");created=${created};nonce="${nonce}";keyid="${name}";alg="ed25519";tag="${TAG}"`;
}

function basisKomponenten(methode: string, path: string, authority: string, contentDigest: string): SignaturKomponente[] {
  return [
    { name: "@method", wert: methode.toUpperCase() },
    { name: "@path", wert: path },
    { name: "@authority", wert: authority.toLowerCase() },
    { name: "content-digest", wert: contentDigest },
  ];
}

export function signiereAnfrage(input: {
  methode: string;
  url: string | URL;
  koerper: Uint8Array;
  name: string;
  signaturPrivat: Uint8Array;
  jetzt?: Date;
  nonce?: string;
}): Record<string, string> {
  if (!NAMENSMUSTER.test(input.name)) throw new TypeError("Ungültiger Teilnehmername.");
  const url = new URL(input.url);
  const created = Math.floor((input.jetzt ?? new Date()).getTime() / 1000);
  const nonce = input.nonce ?? base64url(randomBytes(16));
  if (!/^[A-Za-z0-9_-]{22}$/.test(nonce) || Buffer.from(nonce, "base64url").length !== 16 || base64url(Buffer.from(nonce, "base64url")) !== nonce) {
    throw new TypeError("Nonce muss aus 16 kanonischen Base64url-Bytes bestehen.");
  }
  const contentDigest = digest(input.koerper);
  const params = signaturInput(created, nonce, input.name);
  const basis = signaturBasis(basisKomponenten(input.methode, `${url.pathname}${url.search}`, url.host, contentDigest), params);
  const signature = ed25519.sign(utf8.encode(basis), input.signaturPrivat);
  return {
    "Content-Digest": contentDigest,
    "Signature-Input": `ap=${params}`,
    Signature: `ap=:${Buffer.from(signature).toString("base64")}:`,
  };
}

type PruefErgebnis = { ok: true; name: string; nonce: string }
  | { ok: false; grund: "signatur_fehlt" | "format" | "digest" | "unbekannt" | "unterschrift" | "zeit" | "wiederholung" | "tag" };

export function pruefeAnfrage(
  req: Request,
  koerper: Uint8Array,
  schluesselVon: (name: string) => Uint8Array | undefined,
  opt: { jetzt: Date; nonceSchonGesehen: (n: string) => boolean },
): PruefErgebnis {
  const signatureHeader = req.headers.get("signature");
  const inputHeader = req.headers.get("signature-input");
  if (!signatureHeader || !inputHeader) return { ok: false, grund: "signatur_fehlt" };

  const inputMatch = /^ap=\("@method" "@path" "@authority" "content-digest"\);created=(0|[1-9][0-9]*);nonce="([A-Za-z0-9_-]+)";keyid="([a-z][a-z0-9-]{1,31})";alg="([^"]+)";tag="([^"]+)"$/.exec(inputHeader);
  if (!inputMatch) return { ok: false, grund: "format" };
  const created = Number(inputMatch[1]);
  const nonce = inputMatch[2]!;
  const name = inputMatch[3]!;
  const alg = inputMatch[4]!;
  const tag = inputMatch[5]!;
  if (tag !== TAG) return { ok: false, grund: "tag" };
  if (alg !== "ed25519") return { ok: false, grund: "format" };
  if (!Number.isSafeInteger(created) || !/^[A-Za-z0-9_-]{22}$/.test(nonce)) return { ok: false, grund: "format" };
  let nonceBytes: Buffer;
  try {
    nonceBytes = Buffer.from(nonce, "base64url");
  } catch {
    return { ok: false, grund: "format" };
  }
  if (nonceBytes.length !== 16 || base64url(nonceBytes) !== nonce) return { ok: false, grund: "format" };

  const signatureMatch = /^ap=:([A-Za-z0-9+/]+={0,2}):$/.exec(signatureHeader);
  if (!signatureMatch) return { ok: false, grund: "format" };
  const digestHeader = req.headers.get("content-digest");
  if (!digestHeader || digestHeader !== digest(koerper)) return { ok: false, grund: "digest" };

  const createdMillis = created * 1000;
  const nowMillis = opt.jetzt.getTime();
  if (createdMillis < nowMillis - 300_000 || createdMillis > nowMillis + 300_000) return { ok: false, grund: "zeit" };

  const publicKey = schluesselVon(name);
  if (!publicKey) return { ok: false, grund: "unbekannt" };

  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    return { ok: false, grund: "format" };
  }
  const authority = (req.headers.get("host") ?? url.host).toLowerCase();
  const params = signaturInput(created, nonce, name);
  const basis = signaturBasis(basisKomponenten(req.method, `${url.pathname}${url.search}`, authority, digestHeader), params);
  let valid = false;
  try {
    const signature = Buffer.from(signatureMatch[1]!, "base64");
    valid = Buffer.from(signature).toString("base64") === signatureMatch[1] && ed25519.verify(signature, utf8.encode(basis), publicKey);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, grund: "unterschrift" };
  if (opt.nonceSchonGesehen(nonce)) return { ok: false, grund: "wiederholung" };
  return { ok: true, name, nonce };
}
