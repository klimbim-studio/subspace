import { describe, expect, test } from "bun:test";
import { detectType, stripMetadata } from "../src/attachment.ts";

const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function pngChunk(mediaType: string, data = new Uint8Array()): Uint8Array {
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  chunk.write(mediaType, 4, "ascii");
  chunk.set(data, 8);
  return chunk;
}

function png(...chunks: Uint8Array[]): Uint8Array {
  return Buffer.concat([pngSignature, ...chunks]);
}

function jpegSegment(marker: number, data: Uint8Array): Uint8Array {
  const segment = Buffer.alloc(data.length + 4);
  segment[0] = 0xff;
  segment[1] = marker;
  segment.writeUInt16BE(data.length + 2, 2);
  segment.set(data, 4);
  return segment;
}

const jpegHeader = Buffer.from([0xff, 0xd8, 0xff]);

describe("attachment detection", () => {
  test("pdf-5mb: a large PDF with many encoded names is accepted and the work grows linearly", () => {
    // Every "/#41" is a name whose escape the scan decodes. Wall-clock limits flake on shared CI runners, so the
    // test compares two sizes on the same machine: a linear scan needs about five times as long for five times the
    // data, a quadratic one about twenty-five times. The best of several runs filters out scheduler noise.
    const pdfWithEncodedNames = (size: number): Uint8Array => {
      const body = Buffer.alloc(size - 15);
      for (let index = 0; index + 3 < body.length; index += 4) body.set([0x2f, 0x23, 0x34, 0x31], index);
      return Buffer.concat([Buffer.from("%PDF-1.7\n"), body, Buffer.from("\n%%EOF")]).subarray(0, size);
    };
    const bestOf = (runs: number, work: () => void): number => {
      let best = Number.POSITIVE_INFINITY;
      for (let run = 0; run < runs; run += 1) {
        const start = performance.now();
        work();
        best = Math.min(best, performance.now() - start);
      }
      return best;
    };
    const small = pdfWithEncodedNames(1024 * 1024);
    const large = pdfWithEncodedNames(5 * 1024 * 1024);
    expect(detectType("pdf-1mb.pdf", small)).toEqual({ ok: true, mediaType: "application/pdf" });
    expect(detectType("pdf-5mb.pdf", large)).toEqual({ ok: true, mediaType: "application/pdf" });
    const smallTime = bestOf(3, () => detectType("pdf-1mb.pdf", small));
    const largeTime = bestOf(3, () => detectType("pdf-5mb.pdf", large));
    expect(largeTime).toBeLessThan(Math.max(smallTime, 2) * 15);
  });

  test("PDF name decoding hides neither padding nor escaped tokens from the scan", () => {
    const verdict = (content: string) => detectType("probe.pdf", Buffer.from(`%PDF-1.7\n%%EOF\n${content}`, "ascii"));
    const accepted = { ok: true, mediaType: "application/pdf" } as const;
    // "/JS" as the very last bytes has no following character, so it is no token. Decoding "/A#42C" shortens the
    // text by two bytes; the verdict must not change because of the unused rest of the decode buffer.
    expect(verdict("/JS")).toEqual(accepted);
    expect(verdict("/A#42C /JS")).toEqual(accepted);
    expect(verdict("/A#42C#43D /JS")).toEqual(accepted);
    expect(verdict("/JS ")).toEqual({ ok: false, reason: "pdf_aktiv" });
    expect(verdict("/A#42C /JS ")).toEqual({ ok: false, reason: "pdf_aktiv" });
    // An escape cannot smuggle a forbidden token past the scan.
    expect(verdict("/Java#53cript")).toEqual({ ok: false, reason: "pdf_aktiv" });
  });

  test("detects all allowed formats by content and text by extension", () => {
    const samples: [string, Uint8Array, string][] = [
      ["bild.png", png(pngChunk("IEND")), "image/png"],
      ["bild.jpg", Buffer.concat([jpegHeader, Buffer.from([0xff, 0xd9])]), "image/jpeg"],
      ["bericht.pdf", Buffer.from("%PDF-1.7\n%%EOF", "ascii"), "application/pdf"],
      ["notiz.txt", Buffer.from("Text", "utf8"), "text/plain"],
      ["notiz.md", Buffer.from("# Text", "utf8"), "text/markdown"],
      ["daten.csv", Buffer.from("a,b\n1,2", "utf8"), "text/csv"],
      ["seite.htm", Buffer.from("<h1>Hallo</h1>", "utf8"), "text/html"],
    ];
    for (const [name, bytes, mediaType] of samples) expect(detectType(name, bytes)).toMatchObject({ ok: true, mediaType });
  });

  test("rejects SVG, archives, invalid text, and active PDFs", () => {
    for (const [name, bytes] of [
      ["vektor.svg", Buffer.from("harmlos")],
      ["datei.txt", Buffer.from("<SVG viewBox='0 0 1 1'>")],
      ["archiv.zip", Buffer.from([0x50, 0x4b, 0x03, 0x04])],
      ["bild.webp", Buffer.from("RIFF\0\0\0\0WEBPVP8 ")],
      ["nul.txt", Buffer.from([0x61, 0x00, 0x62])],
      ["utf8.txt", Buffer.from([0xff])],
      ...["/JavaScript", "/JS /Page", "/Launch", "/EmbeddedFile", "/OpenAction", "/AA"].map((word) => [
        "aktiv.pdf",
        Buffer.from(`%PDF-1.7\n${word}\n%%EOF`),
      ] as [string, Uint8Array]),
    ] as [string, Uint8Array][]) expect(detectType(name, bytes).ok).toBe(false);
    expect(detectType("normal.pdf", Buffer.from("%PDF-1.7\n/JSON /JSomething\n%%EOF"))).toEqual({ ok: true, mediaType: "application/pdf" });
    expect(detectType("bild.png", png(pngChunk("IDAT", Buffer.from("x"))))).toMatchObject({ ok: false });
  });

  test("rejects encoded active PDF names and allows encoded JSON", () => {
    for (const word of ["/J#61vaScript", "/J#53", "/Open#41ction", "/#41A", "/#4Caunch"]) {
      expect(detectType("aktiv.pdf", Buffer.from(`%PDF-1.7\n${word}\n%%EOF`))).toEqual({ ok: false, reason: "pdf_aktiv" });
    }
    expect(detectType("normal.pdf", Buffer.from("%PDF-1.7\n/J#53ON\n%%EOF"))).toEqual({ ok: true, mediaType: "application/pdf" });
  });

  test("rejects object stream PDFs even with an escaped name", () => {
    for (const word of ["/Type /ObjStm", "/Type /Obj#53tm"]) {
      expect(detectType("objektstrom.pdf", Buffer.from(`%PDF-1.7\n${word}\n%%EOF`))).toEqual({ ok: false, reason: "pdf_aktiv" });
    }
  });
});

describe("attachment metadata", () => {
  test("JPEG metadata: removes APP1 and APP13 and preserves all remaining bytes", () => {
    const app0 = jpegSegment(0xe0, Buffer.from("JFIF"));
    const app1 = jpegSegment(0xe1, Buffer.from("Exif GPS XMP"));
    const app13 = jpegSegment(0xed, Buffer.from("IPTC"));
    const scan = Buffer.from([0xff, 0xda, 0x00, 0x02, 0x11, 0xff, 0xd9]);
    const original = Buffer.concat([jpegHeader, app0, app1, app13, scan]);
    const expected = Buffer.concat([jpegHeader, app0, scan]);
    expect(stripMetadata("image/jpeg", original)).toEqual(expected);
    expect(Buffer.from(stripMetadata("image/jpeg", original)).toString("latin1")).not.toMatch(/Exif|GPS|IPTC/);
    expect(stripMetadata("image/jpeg", expected)).toEqual(expected);
  });

  test("PNG metadata: removes metadata chunks and preserves image data", () => {
    const ihdr = pngChunk("IHDR", Buffer.from("header"));
    const metadata = [
      pngChunk("tEXt", Buffer.from("Comment\0GPS")),
      pngChunk("iTXt", Buffer.from("GPS")),
      pngChunk("zTXt", Buffer.from("GPS")),
      pngChunk("eXIf", Buffer.from("Exif")),
      pngChunk("tIME", Buffer.from("time")),
    ];
    const imageData = pngChunk("IDAT", Buffer.from([0, 1, 2, 255]));
    const end = pngChunk("IEND");
    const original = png(ihdr, ...metadata, imageData, end);
    const expected = png(ihdr, imageData, end);
    expect(stripMetadata("image/png", original)).toEqual(expected);
    expect(stripMetadata("image/png", expected)).toEqual(expected);
  });
});
