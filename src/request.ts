import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

const utf8 = new TextEncoder();
const COMPONENTS = ["@method", "@path", "@authority", "content-digest"] as const;
const TAG = "agentenpost-v1"; // wire format, keep
const NAME_PATTERN = /^[a-z][a-z0-9-]{1,31}$/;

export interface SignatureComponent {
  name: string;
  value: string;
}

export function signatureBase(components: readonly SignatureComponent[], signatureInput: string): string {
  return [
    ...components.map(({ name, value }) => `"${name.toLowerCase()}": ${value}`),
    `"@signature-params": ${signatureInput}`,
  ].join("\n");
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function digest(body: Uint8Array): string {
  return `sha-256=:${Buffer.from(sha256(body)).toString("base64")}:`;
}

function signatureInput(created: number, nonce: string, name: string): string {
  return `("@method" "@path" "@authority" "content-digest");created=${created};nonce="${nonce}";keyid="${name}";alg="ed25519";tag="${TAG}"`;
}

function baseComponents(method: string, path: string, authority: string, contentDigest: string): SignatureComponent[] {
  return [
    { name: "@method", value: method.toUpperCase() },
    { name: "@path", value: path },
    { name: "@authority", value: authority.toLowerCase() },
    { name: "content-digest", value: contentDigest },
  ];
}

export function signRequest(input: {
  method: string;
  url: string | URL;
  body: Uint8Array;
  name: string;
  privateKey: Uint8Array;
  now?: Date;
  nonce?: string;
}): Record<string, string> {
  if (!NAME_PATTERN.test(input.name)) throw new TypeError("Invalid participant name.");
  const url = new URL(input.url);
  const created = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const nonce = input.nonce ?? base64url(randomBytes(16));
  if (!/^[A-Za-z0-9_-]{22}$/.test(nonce) || Buffer.from(nonce, "base64url").length !== 16 || base64url(Buffer.from(nonce, "base64url")) !== nonce) {
    throw new TypeError("Nonce must consist of 16 canonical base64url bytes.");
  }
  const contentDigest = digest(input.body);
  const params = signatureInput(created, nonce, input.name);
  const basis = signatureBase(baseComponents(input.method, `${url.pathname}${url.search}`, url.host, contentDigest), params);
  const signature = ed25519.sign(utf8.encode(basis), input.privateKey);
  return {
    "Content-Digest": contentDigest,
    "Signature-Input": `ap=${params}`,
    Signature: `ap=:${Buffer.from(signature).toString("base64")}:`,
  };
}

type VerifyResult = { ok: true; name: string; nonce: string }
  | { ok: false; reason: "signatur_fehlt" | "format" | "digest" | "unbekannt" | "unterschrift" | "zeit" | "wiederholung" | "tag" };

export function verifyRequest(
  req: Request,
  body: Uint8Array,
  getPublicKey: (name: string) => Uint8Array | undefined,
  opt: { now: Date; nonceAlreadySeen: (n: string) => boolean },
): VerifyResult {
  const signatureHeader = req.headers.get("signature");
  const inputHeader = req.headers.get("signature-input");
  if (!signatureHeader || !inputHeader) return { ok: false, reason: "signatur_fehlt" };

  const inputMatch = /^ap=\("@method" "@path" "@authority" "content-digest"\);created=(0|[1-9][0-9]*);nonce="([A-Za-z0-9_-]+)";keyid="([a-z][a-z0-9-]{1,31})";alg="([^"]+)";tag="([^"]+)"$/.exec(inputHeader);
  if (!inputMatch) return { ok: false, reason: "format" };
  const created = Number(inputMatch[1]);
  const nonce = inputMatch[2]!;
  const name = inputMatch[3]!;
  const alg = inputMatch[4]!;
  const tag = inputMatch[5]!;
  if (tag !== TAG) return { ok: false, reason: "tag" };
  if (alg !== "ed25519") return { ok: false, reason: "format" };
  if (!Number.isSafeInteger(created) || !/^[A-Za-z0-9_-]{22}$/.test(nonce)) return { ok: false, reason: "format" };
  let nonceBytes: Buffer;
  try {
    nonceBytes = Buffer.from(nonce, "base64url");
  } catch {
    return { ok: false, reason: "format" };
  }
  if (nonceBytes.length !== 16 || base64url(nonceBytes) !== nonce) return { ok: false, reason: "format" };

  const signatureMatch = /^ap=:([A-Za-z0-9+/]+={0,2}):$/.exec(signatureHeader);
  if (!signatureMatch) return { ok: false, reason: "format" };
  const digestHeader = req.headers.get("content-digest");
  if (!digestHeader || digestHeader !== digest(body)) return { ok: false, reason: "digest" };

  const createdMillis = created * 1000;
  const nowMillis = opt.now.getTime();
  if (createdMillis < nowMillis - 300_000 || createdMillis > nowMillis + 300_000) return { ok: false, reason: "zeit" };

  const publicKey = getPublicKey(name);
  if (!publicKey) return { ok: false, reason: "unbekannt" };

  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    return { ok: false, reason: "format" };
  }
  const authority = (req.headers.get("host") ?? url.host).toLowerCase();
  const params = signatureInput(created, nonce, name);
  const basis = signatureBase(baseComponents(req.method, `${url.pathname}${url.search}`, authority, digestHeader), params);
  let valid = false;
  try {
    const signature = Buffer.from(signatureMatch[1]!, "base64");
    valid = Buffer.from(signature).toString("base64") === signatureMatch[1] && ed25519.verify(signature, utf8.encode(basis), publicKey);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "unterschrift" };
  if (opt.nonceAlreadySeen(nonce)) return { ok: false, reason: "wiederholung" };
  return { ok: true, name, nonce };
}
