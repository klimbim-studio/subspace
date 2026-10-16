export type AttachmentType =
  | "image/png"
  | "image/jpeg"
  | "application/pdf"
  | "text/plain"
  | "text/markdown"
  | "text/csv"
  | "text/html";

export type AttachmentDetection = { ok: true; mediaType: AttachmentType } | { ok: false; reason: string };

const PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const FORBIDDEN_PDF_TOKENS = ["/JavaScript", "/Launch", "/EmbeddedFile", "/OpenAction", "/AA", "/ObjStm"];

function startsWithBytes(bytes: Uint8Array, prefix: Uint8Array): boolean {
  return bytes.length >= prefix.length && prefix.every((byte, index) => bytes[index] === byte);
}

function endsWithBytes(bytes: Uint8Array, suffix: Uint8Array): boolean {
  return bytes.length >= suffix.length && suffix.every((byte, index) => bytes[bytes.length - suffix.length + index] === byte);
}

function asciiBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function findBytes(bytes: Uint8Array, needle: Uint8Array, start = 0, end = bytes.length): number {
  outer: for (let index = start; index <= end - needle.length; index += 1) {
    for (let offset = 0; offset < needle.length; offset += 1) {
      if (bytes[index + offset] !== needle[offset]) continue outer;
    }
    return index;
  }
  return -1;
}

function decodePdfNames(bytes: Uint8Array): Uint8Array {
  const decoded = new Uint8Array(bytes.length);
  let writeIndex = 0;
  const delimiters = new Set([0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20, 0x28, 0x29, 0x3c, 0x3e, 0x5b, 0x5d, 0x7b, 0x7d, 0x2f, 0x25]);
  const hexDigit = (byte: number | undefined): number => {
    if (byte === undefined) return -1;
    if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;
    if (byte >= 0x41 && byte <= 0x46) return byte - 0x41 + 10;
    if (byte >= 0x61 && byte <= 0x66) return byte - 0x61 + 10;
    return -1;
  };

  for (let index = 0; index < bytes.length; index += 1) {
    decoded[writeIndex++] = bytes[index]!;
    if (bytes[index] !== 0x2f) continue;
    while (index + 1 < bytes.length && !delimiters.has(bytes[index + 1]!)) {
      if (bytes[index + 1] === 0x23) {
        const high = hexDigit(bytes[index + 2]);
        const low = hexDigit(bytes[index + 3]);
        if (high !== -1 && low !== -1) {
          decoded[writeIndex++] = (high << 4) | low;
          index += 3;
          continue;
        }
      }
      index += 1;
      decoded[writeIndex++] = bytes[index]!;
    }
  }
  return decoded.subarray(0, writeIndex);
}

function isActivePdf(bytes: Uint8Array): boolean {
  const pdfText = decodePdfNames(bytes);
  for (const word of FORBIDDEN_PDF_TOKENS) if (findBytes(pdfText, asciiBytes(word)) !== -1) return true;
  const javascriptToken = asciiBytes("/JS");
  let position = findBytes(pdfText, javascriptToken);
  while (position !== -1) {
    const next = pdfText[position + javascriptToken.length];
    if (next !== undefined && !((next >= 0x41 && next <= 0x5a) || (next >= 0x61 && next <= 0x7a))) return true;
    position = findBytes(pdfText, javascriptToken, position + 1);
  }
  return false;
}

function textType(name: string): AttachmentType {
  const suffix = name.toLowerCase();
  if (suffix.endsWith(".md")) return "text/markdown";
  if (suffix.endsWith(".csv")) return "text/csv";
  if (suffix.endsWith(".html") || suffix.endsWith(".htm")) return "text/html";
  return "text/plain";
}

export function detectType(name: string, bytes: Uint8Array): AttachmentDetection {
  if (name.toLowerCase().endsWith(".svg")) return { ok: false, reason: "svg" };
  if (startsWithBytes(bytes, new Uint8Array([0x50, 0x4b, 0x03, 0x04]))) return { ok: false, reason: "format" };
  if (startsWithBytes(bytes, asciiBytes("RIFF")) && bytes.length >= 12 && String.fromCharCode(...bytes.subarray(8, 12)) === "WEBP") {
    return { ok: false, reason: "format" };
  }
  if (startsWithBytes(bytes, PNG_SIGNATURE)) {
    const iend = new Uint8Array([0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44]);
    return bytes.length >= 20 && findBytes(bytes, iend, bytes.length - 12, bytes.length) === bytes.length - 12
      ? { ok: true, mediaType: "image/png" }
      : { ok: false, reason: "format" };
  }
  if (startsWithBytes(bytes, new Uint8Array([0xff, 0xd8, 0xff]))) {
    return endsWithBytes(bytes, new Uint8Array([0xff, 0xd9]))
      ? { ok: true, mediaType: "image/jpeg" }
      : { ok: false, reason: "format" };
  }
  if (startsWithBytes(bytes, asciiBytes("%PDF-"))) {
    if (findBytes(bytes, asciiBytes("%%EOF"), Math.max(0, bytes.length - 1024)) === -1) return { ok: false, reason: "format" };
    if (isActivePdf(bytes)) return { ok: false, reason: "pdf_aktiv" };
    return { ok: true, mediaType: "application/pdf" };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, reason: "format" };
  }
  if (bytes.includes(0)) return { ok: false, reason: "format" };
  if (text.toLowerCase().includes("<svg")) return { ok: false, reason: "svg" };
  return { ok: true, mediaType: textType(name) };
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function stripJpegMetadata(bytes: Uint8Array): Uint8Array {
  if (!startsWithBytes(bytes, new Uint8Array([0xff, 0xd8]))) return bytes;
  const parts: Uint8Array[] = [bytes.subarray(0, 2)];
  let offset = 2;
  let removed = false;
  while (offset < bytes.length) {
    const markerStart = offset;
    if (bytes[offset] !== 0xff) {
      parts.push(bytes.subarray(offset));
      break;
    }
    while (bytes[offset] === 0xff) offset += 1;
    const marker = bytes[offset];
    if (marker === undefined || marker === 0x00) {
      parts.push(bytes.subarray(markerStart));
      break;
    }
    offset += 1;
    if (marker === 0xda) {
      parts.push(bytes.subarray(markerStart));
      break;
    }
    if (marker === 0xd8 || marker === 0xd9 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      parts.push(bytes.subarray(markerStart, offset));
      continue;
    }
    if (offset + 2 > bytes.length) {
      parts.push(bytes.subarray(markerStart));
      break;
    }
    const length = (bytes[offset]! << 8) | bytes[offset + 1]!;
    if (length < 2 || offset + length > bytes.length) {
      parts.push(bytes.subarray(markerStart));
      break;
    }
    const end = offset + length;
    if (marker === 0xe1 || marker === 0xed) removed = true;
    else parts.push(bytes.subarray(markerStart, end));
    offset = end;
  }
  return removed ? concatBytes(parts) : bytes;
}

function stripPngMetadata(bytes: Uint8Array): Uint8Array {
  if (!startsWithBytes(bytes, PNG_SIGNATURE)) return bytes;
  const parts: Uint8Array[] = [bytes.subarray(0, PNG_SIGNATURE.length)];
  const metadataChunks = new Set(["tEXt", "iTXt", "zTXt", "eXIf", "tIME"]);
  let offset = PNG_SIGNATURE.length;
  let removed = false;
  while (offset + 12 <= bytes.length) {
    const length = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
    if (length > bytes.length - offset - 12) {
      parts.push(bytes.subarray(offset));
      offset = bytes.length;
      break;
    }
    const chunkType = String.fromCharCode(...bytes.subarray(offset + 4, offset + 8));
    const end = offset + length + 12;
    if (metadataChunks.has(chunkType)) removed = true;
    else parts.push(bytes.subarray(offset, end));
    offset = end;
  }
  if (offset < bytes.length) parts.push(bytes.subarray(offset));
  return removed ? concatBytes(parts) : bytes;
}

export function stripMetadata(mediaType: AttachmentType | string, bytes: Uint8Array): Uint8Array {
  if (mediaType === "image/jpeg") return stripJpegMetadata(bytes);
  if (mediaType === "image/png") return stripPngMetadata(bytes);
  return bytes;
}
