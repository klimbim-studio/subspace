import { sha256 } from "@noble/hashes/sha2.js";

const utf8 = new TextEncoder();

export type ProtocolField = [string, Uint8Array];

export function encodeFields(fields: ProtocolField[]): Uint8Array {
  const encoded: Uint8Array[] = [];
  let totalLength = 0;
  for (const [fieldName, value] of fields) {
    const name = utf8.encode(fieldName);
    if (name.length > 0xffff) throw new RangeError("Field name is too long.");
    if (value.length > 0xffffffff) throw new RangeError("Field value is too long.");
    const lengths = new Uint8Array(6);
    new DataView(lengths.buffer).setUint16(0, name.length, false);
    new DataView(lengths.buffer).setUint32(2, value.length, false);
    encoded.push(lengths, name, value);
    totalLength += lengths.length + name.length + value.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of encoded) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function hashWithPurpose(version: string, purpose: string, fields: ProtocolField[]): Uint8Array {
  return sha256(encodeFields([["version", utf8.encode(version)], ["zweck", utf8.encode(purpose)], ...fields]));
}
