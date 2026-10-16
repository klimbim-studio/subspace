import { describe, expect, test } from "bun:test";
import { sshPublicKeyFingerprint, sshPublicKey } from "../src/ssh.ts";

describe("OpenSSH output", () => {
  test("vector matches ssh-keygen", () => {
    const key = Buffer.from("jNsLz3XSvIq6tY2X/tmD+HRdkTyc7ccfAGYqJcnGjTM=", "base64");
    expect(sshPublicKey(key, "phai@subspace")).toBe(
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIzbC8910ryKurWNl/7Zg/h0XZE8nO3HHwBmKiXJxo0z phai@subspace",
    );
    expect(sshPublicKeyFingerprint(key, "phai@subspace")).toBe(
      "256 SHA256:nfYh7Mgf67HQYqo4TASfl3SokQxt18l5vKmZl3cSNlY phai@subspace (ED25519)",
    );
  });
});
