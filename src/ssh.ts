import { createHash } from "node:crypto";

const SSH_ED25519 = "ssh-ed25519";
const KEY_LENGTH = 32;

function sshBlob(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== KEY_LENGTH) throw new TypeError("Ed25519 key must be exactly 32 bytes long.");
  const keyType = Buffer.from(SSH_ED25519, "ascii");
  const blob = Buffer.alloc(4 + keyType.length + 4 + KEY_LENGTH);
  blob.writeUInt32BE(keyType.length, 0);
  keyType.copy(blob, 4);
  blob.writeUInt32BE(KEY_LENGTH, 4 + keyType.length);
  Buffer.from(publicKey).copy(blob, 8 + keyType.length);
  return blob;
}

export function sshPublicKey(publicKey: Uint8Array, comment: string): string {
  return `${SSH_ED25519} ${Buffer.from(sshBlob(publicKey)).toString("base64")} ${comment}`;
}

export function sshPublicKeyFingerprint(publicKey: Uint8Array, comment: string): string {
  const fingerprint = createHash("sha256").update(sshBlob(publicKey)).digest("base64").replace(/=+$/, "");
  return `256 SHA256:${fingerprint} ${comment} (ED25519)`;
}

export function decodeSshPublicKey(value: string): Uint8Array | undefined {
  const parts = value.trim().split(/\s+/);
  if (parts.length < 2 || parts[0] !== SSH_ED25519 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(parts[1]!)) {
    return undefined;
  }
  const blob = Buffer.from(parts[1]!, "base64");
  if (blob.toString("base64") !== parts[1] || blob.length !== 4 + SSH_ED25519.length + 4 + KEY_LENGTH
    || blob.readUInt32BE(0) !== SSH_ED25519.length
    || blob.toString("ascii", 4, 4 + SSH_ED25519.length) !== SSH_ED25519
    || blob.readUInt32BE(4 + SSH_ED25519.length) !== KEY_LENGTH) {
    return undefined;
  }
  return new Uint8Array(blob.subarray(8 + SSH_ED25519.length));
}
