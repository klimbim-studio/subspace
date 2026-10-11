import { createHash } from "node:crypto";

const SSH_ED25519 = "ssh-ed25519";
const SCHLUESSELLAENGE = 32;

function sshBlob(oeffentlicherSchluessel: Uint8Array): Uint8Array {
  if (oeffentlicherSchluessel.length !== SCHLUESSELLAENGE) throw new TypeError("Ed25519-Schlüssel muss genau 32 Byte lang sein.");
  const typ = Buffer.from(SSH_ED25519, "ascii");
  const blob = Buffer.alloc(4 + typ.length + 4 + SCHLUESSELLAENGE);
  blob.writeUInt32BE(typ.length, 0);
  typ.copy(blob, 4);
  blob.writeUInt32BE(SCHLUESSELLAENGE, 4 + typ.length);
  Buffer.from(oeffentlicherSchluessel).copy(blob, 8 + typ.length);
  return blob;
}

export function sshOeffentlicherSchluessel(oeffentlicherSchluessel: Uint8Array, kommentar: string): string {
  return `${SSH_ED25519} ${Buffer.from(sshBlob(oeffentlicherSchluessel)).toString("base64")} ${kommentar}`;
}

export function sshFingerabdruck(oeffentlicherSchluessel: Uint8Array, kommentar: string): string {
  const fingerprint = createHash("sha256").update(sshBlob(oeffentlicherSchluessel)).digest("base64").replace(/=+$/, "");
  return `256 SHA256:${fingerprint} ${kommentar} (ED25519)`;
}

export function sshSchluesselDekodieren(value: string): Uint8Array | undefined {
  const parts = value.trim().split(/\s+/);
  if (parts.length < 2 || parts[0] !== SSH_ED25519 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(parts[1]!)) {
    return undefined;
  }
  const blob = Buffer.from(parts[1]!, "base64");
  if (blob.toString("base64") !== parts[1] || blob.length !== 4 + SSH_ED25519.length + 4 + SCHLUESSELLAENGE
    || blob.readUInt32BE(0) !== SSH_ED25519.length
    || blob.toString("ascii", 4, 4 + SSH_ED25519.length) !== SSH_ED25519
    || blob.readUInt32BE(4 + SSH_ED25519.length) !== SCHLUESSELLAENGE) {
    return undefined;
  }
  return new Uint8Array(blob.subarray(8 + SSH_ED25519.length));
}
