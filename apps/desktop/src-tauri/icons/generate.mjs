// Generates the bundle icon set referenced by tauri.conf.json.
//
// Checked in as source rather than left as opaque binaries: the icons are
// derived artifacts, and a reviewer should be able to re-derive them. Run
// `node generate.mjs` from this directory; it rewrites every PNG listed in
// SIZES plus icon.ico.
//
// Deliberately dependency-free. Node's zlib is enough to emit a PNG, so the
// icon set costs the project no new package, no image toolchain, and no
// install step in CI.

import { deflateSync } from "node:zlib";
import { writeFileSync } from "node:fs";

// `128x128@2x` is Tauri's name for the 256px variant, not a separate design.
const SIZES = [
  ["32x32.png", 32],
  ["128x128.png", 128],
  ["128x128@2x.png", 256],
];

const SUPERSAMPLE = 4; // Cheap antialiasing: render big, box-filter down.

// Deep slate tile, warm core. Legible at 32px because the mark is three
// concentric shapes with wide gaps, not fine detail.
const TILE_TOP = [37, 43, 66];
const TILE_BOTTOM = [22, 26, 42];
const RING = [232, 236, 245];
const CORE = [242, 168, 73];

const clamp01 = (value) => Math.min(1, Math.max(0, value));

/** Signed distance to a rounded square centred on the unit box. */
function roundedSquareDistance(x, y, half, radius) {
  const dx = Math.abs(x) - (half - radius);
  const dy = Math.abs(y) - (half - radius);
  const outside = Math.hypot(Math.max(dx, 0), Math.max(dy, 0));
  return outside + Math.min(Math.max(dx, dy), 0) - radius;
}

function mix(from, to, amount) {
  return from.map((channel, index) => channel + (to[index] - channel) * amount);
}

/**
 * Colour one supersampled pixel. Coordinates are normalised to [-1, 1] so the
 * same geometry serves every output size.
 */
function shade(x, y) {
  const tile = roundedSquareDistance(x, y, 0.94, 0.28);
  if (tile > 0) return null; // Transparent corner.

  const gradient = clamp01((y + 0.94) / 1.88);
  let colour = mix(TILE_TOP, TILE_BOTTOM, gradient);

  // Ring with a gap in the upper right: a boundary that is opened
  // deliberately, which is the whole permission model in one glyph. Rows run
  // top to bottom, so negative angles are the upper half.
  const radius = Math.hypot(x, y);
  const angle = Math.atan2(y, x);
  const inRing = radius > 0.4 && radius < 0.58;
  const inGap = angle > -1.29 && angle < -0.28;
  if (inRing && !inGap) colour = RING;

  if (radius < 0.2) colour = CORE;

  return colour;
}

function renderPixels(size) {
  const pixels = new Uint8Array(size * size * 4);
  const step = 2 / (size * SUPERSAMPLE);
  for (let row = 0; row < size; row += 1) {
    for (let column = 0; column < size; column += 1) {
      let red = 0;
      let green = 0;
      let blue = 0;
      let alpha = 0;
      for (let sy = 0; sy < SUPERSAMPLE; sy += 1) {
        for (let sx = 0; sx < SUPERSAMPLE; sx += 1) {
          const x = -1 + (column * SUPERSAMPLE + sx + 0.5) * step;
          const y = -1 + (row * SUPERSAMPLE + sy + 0.5) * step;
          const colour = shade(x, y);
          if (colour === null) continue;
          red += colour[0];
          green += colour[1];
          blue += colour[2];
          alpha += 255;
        }
      }
      const samples = SUPERSAMPLE * SUPERSAMPLE;
      const offset = (row * size + column) * 4;
      // Un-premultiply so edge pixels keep their colour at low alpha.
      const covered = alpha / 255;
      if (covered > 0) {
        pixels[offset] = Math.round(red / covered);
        pixels[offset + 1] = Math.round(green / covered);
        pixels[offset + 2] = Math.round(blue / covered);
      }
      pixels[offset + 3] = Math.round(alpha / samples);
    }
  }
  return pixels;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function encodePng(size, pixels) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // 8 bits per channel
  header[9] = 6; // truecolour with alpha
  // Rows are filter type 0 (None): the shapes are smooth, so the filters that
  // would help are not worth the code.
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let row = 0; row < size; row += 1) {
    const start = row * (size * 4 + 1);
    raw[start] = 0;
    Buffer.from(pixels.buffer, row * size * 4, size * 4).copy(raw, start + 1);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/** ICO holding PNG-compressed entries, which every supported Windows accepts. */
function encodeIco(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2); // 1 = icon
  header.writeUInt16LE(entries.length, 4);
  let offset = 6 + entries.length * 16;
  const directory = [];
  for (const [size, png] of entries) {
    const entry = Buffer.alloc(16);
    entry[0] = size >= 256 ? 0 : size; // 0 means 256 in the ICO format.
    entry[1] = size >= 256 ? 0 : size;
    entry.writeUInt16LE(1, 4); // colour planes
    entry.writeUInt16LE(32, 6); // bits per pixel
    entry.writeUInt32LE(png.length, 8);
    entry.writeUInt32LE(offset, 12);
    directory.push(entry);
    offset += png.length;
  }
  return Buffer.concat([header, ...directory, ...entries.map(([, png]) => png)]);
}

const icoEntries = [];
for (const [name, size] of SIZES) {
  const png = encodePng(size, renderPixels(size));
  writeFileSync(new URL(name, import.meta.url), png);
  console.log(`${name} ${size}x${size} ${png.length} bytes`);
  icoEntries.push([size, png]);
}

// Windows needs 16px too; the resource step reads only icon.ico.
icoEntries.unshift([16, encodePng(16, renderPixels(16))]);
const ico = encodeIco(icoEntries);
writeFileSync(new URL("icon.ico", import.meta.url), ico);
console.log(`icon.ico ${icoEntries.length} entries ${ico.length} bytes`);
