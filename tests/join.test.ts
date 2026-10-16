import { describe, expect, test } from "bun:test";
import { encodeFields } from "../src/protocol.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { checkCodeAttempt, code, deriveInvitationKey, redemptionMessage, createJoinCommitment, transcriptHash, type JoinTranscript } from "../src/join.ts";

const utf8 = new TextEncoder();
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

describe("join encoding", () => {
  test("code attempt check keeps the three-failure limit for group joins", () => {
    expect(checkCodeAttempt("", "123456", 0)).toEqual({ accepted: false, failures: 0, burned: false });
    expect(checkCodeAttempt("000000", "123456", 0)).toEqual({ accepted: false, failures: 1, burned: false });
    expect(checkCodeAttempt("000000", "123456", 1)).toEqual({ accepted: false, failures: 2, burned: false });
    expect(checkCodeAttempt("000000", "123456", 2)).toEqual({ accepted: false, failures: 3, burned: true });
    expect(checkCodeAttempt("123456", "123456", 2)).toEqual({ accepted: true, failures: 2, burned: false });
  });

  test("two-step protocol: secret keys derive consistently and protect commitment and redemption", () => {
    const secret = new Uint8Array(32).fill(71);
    const derived = deriveInvitationKey(secret);
    expect(derived.publicKey).toEqual(deriveInvitationKey(secret).publicKey);
    expect(deriveInvitationKey(new Uint8Array(32).fill(72)).publicKey).not.toEqual(derived.publicKey);
    const instance = "https://relay.example";
    const token = new Uint8Array(16).fill(1);
    const sigI = new Uint8Array(32).fill(2);
    const boxI = new Uint8Array(32).fill(3);
    const nI = new Uint8Array(32).fill(4);
    expect(createJoinCommitment(instance, token, "alpha", sigI, boxI, nI, derived.publicKey))
      .not.toEqual(createJoinCommitment(instance, token, "alpha", sigI, boxI, nI, deriveInvitationKey(new Uint8Array(32).fill(72)).publicKey));
    const redemption = { instanz: instance, token, name_J: "beta", sig_J: new Uint8Array(32).fill(5), box_J: new Uint8Array(32).fill(6), c_I: new Uint8Array(32).fill(7), n_J: new Uint8Array(32).fill(8) };
    const message = redemptionMessage(redemption);
    const signature = ed25519.sign(message, derived.secretKey);
    expect(ed25519.verify(signature, redemptionMessage(redemption), derived.publicKey)).toBe(true);
    expect(ed25519.verify(signature, redemptionMessage({ ...redemption, sig_J: new Uint8Array(32).fill(9) }), derived.publicKey)).toBe(false);
  });

  test("encoding is unambiguous and produces fixed protocol vectors", () => {
    expect(hex(encodeFields([["a", utf8.encode("ab")], ["b", utf8.encode("c")]])))
      .not.toBe(hex(encodeFields([["a", utf8.encode("a")], ["b", utf8.encode("bc")]])));

    const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
    const fest = createJoinCommitment("https://postamt.example", bytes(16, 1), "alpha", bytes(32, 2), bytes(32, 3), bytes(32, 4), bytes(32, 8)); // wire format, keep
    const p = {
      instanz: "https://postamt.example", token: bytes(16, 1), name_I: "alpha", name_J: "beta", // wire format, keep
      sig_I: bytes(32, 2), box_I: bytes(32, 3), sig_J: bytes(32, 5), box_J: bytes(32, 6),
      c_I: fest, n_J: bytes(32, 7), n_I: bytes(32, 4),
    };
    expect(hex(fest)).toBe("7e97db10e5a5654f38f2345fd881c292166ca03f27835b5ac565433781cd2e34");
    expect(hex(transcriptHash(p))).toBe("b66359958056e608ebfbbf1b431ffaf30e4d12dc9e120f91e946d9487e2f7cc2");
    expect(code(p)).toBe("936159");
  });

  test("intermediary: changing each join field changes the code", () => {
    const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
    const instance = "https://relay.example";
    const token = bytes(16, 1);
    const nI = bytes(32, 4);
    const sigI = bytes(32, 2);
    const boxI = bytes(32, 3);
    const cI = createJoinCommitment(instance, token, "alpha", sigI, boxI, nI, bytes(32, 8));
    const original: JoinTranscript = {
      instanz: instance, token, name_I: "alpha", name_J: "beta", sig_I: sigI, box_I: boxI,
      sig_J: bytes(32, 5), box_J: bytes(32, 6), c_I: cI, n_J: bytes(32, 7), n_I: nI,
    };
    const mediated: JoinTranscript[] = [
      { ...original, box_I: bytes(32, 8) },
      { ...original, sig_J: bytes(32, 9) },
      { ...original, box_J: bytes(32, 10) },
      { ...original, n_J: bytes(32, 11) },
      { ...original, name_J: "mallory" },
    ];
    for (const transcript of mediated) expect(code(transcript)).not.toBe(code(original));
  });
});
