import { describe, expect, test } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createKey } from "../src/seal.ts";
import { verifyRequest, signatureBase, signRequest } from "../src/request.ts";

const utf8 = new TextEncoder();
const RFC_PUBLIC = Buffer.from("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs", "base64url");
const RFC_SIGNATURE = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
const RFC_BASIS = [
  '"date": Tue, 20 Apr 2021 02:07:55 GMT',
  '"@method": POST',
  '"@path": /foo',
  '"@authority": example.com',
  '"content-type": application/json',
  '"content-length": 18',
  '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
].join("\n");
const RFC_PARAMS = '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"';

function verify(headers: Record<string, string>, body: Uint8Array, publicKey: Uint8Array, url = "http://example.test/v1/einliefern") {
  return verifyRequest(new Request(url, { method: "POST", headers }), body, () => publicKey, {
    now: new Date("2026-10-07T12:00:00Z"),
    nonceAlreadySeen: () => false,
  });
}

describe("HTTP request verification", () => {
  test("RFC 9421: Appendix B.2.6 matches exactly and verification succeeds only for /foo", () => {
    const components = [
      { name: "date", value: "Tue, 20 Apr 2021 02:07:55 GMT" },
      { name: "@method", value: "POST" },
      { name: "@path", value: "/foo" },
      { name: "@authority", value: "example.com" },
      { name: "content-type", value: "application/json" },
      { name: "content-length", value: "18" },
    ];
    expect(signatureBase(components, RFC_PARAMS)).toBe(RFC_BASIS);
    const signature = Buffer.from(RFC_SIGNATURE, "base64");
    expect(ed25519.verify(signature, utf8.encode(RFC_BASIS), RFC_PUBLIC)).toBe(true);
    expect(ed25519.verify(signature, utf8.encode(RFC_BASIS.replace("/foo", "/bar")), RFC_PUBLIC)).toBe(false);
  });

  test("signed request: success and digest, path, tag, time, and replay token errors", () => {
    const keys = createKey();
    const body = utf8.encode("umschlag");
    const now = new Date("2026-10-07T12:00:00Z");
    const headers = signRequest({ method: "POST", url: "http://example.test/v1/einliefern", body: body, name: "alpha", privateKey: keys.signaturPrivat, now: now, nonce: "AAECAwQFBgcICQoLDA0ODw" });
    expect(verify(headers, body, keys.signaturOeffentlich)).toMatchObject({ ok: true, name: "alpha" });
    expect(verify(headers, body, keys.signaturOeffentlich, "http://example.test/anders")).toEqual({ ok: false, reason: "unterschrift" });
    expect(verify(headers, utf8.encode("geändert"), keys.signaturOeffentlich)).toEqual({ ok: false, reason: "digest" });

    const wrongTag = { ...headers, "Signature-Input": headers["Signature-Input"]!.replace("agentenpost-v1", "fremd") }; // wire format, keep
    expect(verify(wrongTag, body, keys.signaturOeffentlich)).toEqual({ ok: false, reason: "tag" });

    const alt = signRequest({ method: "POST", url: "http://example.test/v1/einliefern", body: body, name: "alpha", privateKey: keys.signaturPrivat, now: new Date(now.getTime() - 301_000), nonce: "AQECAwQFBgcICQoLDA0ODw" });
    expect(verify(alt, body, keys.signaturOeffentlich)).toEqual({ ok: false, reason: "zeit" });
    expect(verifyRequest(new Request("http://example.test/v1/einliefern", { method: "POST", headers }), body, () => keys.signaturOeffentlich, {
      now: now,
      nonceAlreadySeen: (nonce) => nonce === "AAECAwQFBgcICQoLDA0ODw",
    })).toEqual({ ok: false, reason: "wiederholung" });
  });
});
