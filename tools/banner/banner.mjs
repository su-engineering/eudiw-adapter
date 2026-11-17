#!/usr/bin/env node
// Renders a README banner in the su.engineering look from a JSON config:
//   node tools/banner/banner.mjs tools/banner/eudiw-adapter.json docs/assets/banner.svg
// Charcoal field with a 28px dot grid, a 12px inset hairline frame, the su.engineering ASCII logo as its original
// text, a lowercase title ending in a signal-orange full stop, and an optional flow diagram whose boxes share one
// height and whose arrows sit on one centre line. Only the standard library; copy this file to reuse it elsewhere.
import { readFileSync, writeFileSync } from 'node:fs';

const C = { paper: '#10110f', ink: '#eeeade', muted: '#aaa79d', line: '#4d4c43', fire: '#ff6538', raised: '#171815' };
const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
const W = 1280;
const H = 400;
const CHAR = 0.6; // JetBrains Mono advance width per font-size unit

// The su.engineering logo, verbatim. Never redraw or restyle it; it is placed as text only.
const LOGO = [
  '                       _                 _',
  ' ___ _ _   ___ ___ ___|_|___ ___ ___ ___|_|___ ___',
  '|_ -| | |_| -_|   | . | |   | -_| -_|  _| |   | . |',
  '|___|___|_|___|_|_|_  |_|_|_|___|___|_| |_|_|_|_  |',
  '                  |___|                       |___|',
];

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const text = (x, y, size, fill, body, extra = '') =>
  `<text x="${x}" y="${y}" font-size="${size}" fill="${fill}"${extra}>${body}</text>`;

/** Glyphs drawn inside a flow box of width w and height h, centred. */
const GLYPHS = {
  wallet(w, h) {
    const cw = w - 36;
    const x = 18;
    return [
      `<rect x="${x}" y="22" width="${cw}" height="${Math.round(cw * 0.58)}" fill="${C.raised}" stroke="${C.line}"/>`,
      `<rect x="${x + 10}" y="32" width="8" height="8" fill="${C.fire}"/>`,
      `<rect x="${x + 10}" y="${22 + Math.round(cw * 0.58) - 18}" width="${Math.round(cw * 0.5)}" height="4" fill="${C.line}"/>`,
      ...[0, 1, 2].map((i) => `<rect x="${x}" y="${h - 56 + i * 14}" width="${[cw, cw * 0.7, cw * 0.85][i]}" height="4" fill="${C.line}"/>`),
    ].join('');
  },
  verify(w, h) {
    const cx = w / 2;
    const cy = h / 2 - 6;
    return [
      `<rect x="${cx - 30}" y="${cy - 30}" width="60" height="60" fill="none" stroke="${C.fire}" stroke-width="1.5"/>`,
      `<path d="M${cx - 15} ${cy + 1}l10 10l20 -22" fill="none" stroke="${C.fire}" stroke-width="5" stroke-linecap="square"/>`,
      text(cx, h - 18, 11, C.muted, 'verified', ' text-anchor="middle" letter-spacing="2"'),
    ].join('');
  },
  code(w, h, lines = []) {
    const size = 13;
    const top = h / 2 - ((lines.length - 1) * 20) / 2 + 4;
    return [
      `<line x1="0" y1="26" x2="${w}" y2="26" stroke="${C.line}"/>`,
      `<rect x="12" y="10" width="6" height="6" fill="${C.fire}"/>`,
      ...lines.map((l, i) => {
        const body = esc(l).replace(/\b(true|false)\b/g, `<tspan fill="${C.fire}">$1</tspan>`);
        return text(16, top + 8 + i * 20, size, C.ink, body, ' xml:space="preserve"');
      }),
    ].join('');
  },
};

function flow(diagram) {
  const { boxes, arrows = [], height = 150 } = diagram;
  const gap = 88; // room for an arrow and its label between boxes
  const total = boxes.reduce((s, b) => s + b.width, 0) + gap * (boxes.length - 1);
  const right = W - 64;
  let x = right - total;
  const top = 150; // centres the boxes on the text column (label to chips)
  const mid = top + height / 2;
  const out = [];
  boxes.forEach((b, i) => {
    out.push(`<g transform="translate(${x} ${top})">`);
    out.push(`<rect width="${b.width}" height="${height}" fill="${C.paper}" stroke="${b.accent ? C.fire : C.line}" stroke-width="${b.accent ? 1.5 : 1}"/>`);
    out.push(GLYPHS[b.glyph]?.(b.width, height, b.lines) ?? '');
    out.push(text(b.width / 2, height + 30, 13, C.muted, esc(b.caption), ' text-anchor="middle"'));
    out.push('</g>');
    if (i < boxes.length - 1) {
      const a = arrows[i] ?? {};
      const x1 = x + b.width + 10;
      const x2 = x + b.width + gap - 10;
      out.push(`<line x1="${x1}" y1="${mid}" x2="${x2 - 2}" y2="${mid}" stroke="${C.muted}" stroke-width="1.5"${a.dashed ? ' stroke-dasharray="5 5"' : ''}/>`);
      out.push(`<path d="M${x2 - 9} ${mid - 6}L${x2} ${mid}L${x2 - 9} ${mid + 6}" fill="none" stroke="${C.muted}" stroke-width="1.5"/>`);
      if (a.label) {
        out.push(text((x1 + x2) / 2, mid - 12, 11, C.muted, esc(a.label), ' text-anchor="middle"'));
      }
    }
    x += b.width + gap;
  });
  return out.join('\n    ');
}

function chips(list, x, y) {
  const size = 13;
  let cx = x;
  return list
    .map((c) => {
      const w = Math.ceil(c.length * size * CHAR) + 24;
      const s = `<rect x="${cx}" y="${y}" width="${w}" height="30" fill="none" stroke="${C.line}"/>` +
        text(cx + w / 2, y + 20, size, C.ink, esc(c), ' text-anchor="middle"');
      cx += w + 8;
      return s;
    })
    .join('');
}

export function banner(cfg) {
  const dots = `<pattern id="dots" width="28" height="28" patternUnits="userSpaceOnUse"><rect x="13" y="13" width="1.5" height="1.5" fill="${C.line}"/></pattern>`;
  const logo = LOGO.map((l, i) => text(48, 52 + i * 9.5, 9, C.ink, esc(l), ' xml:space="preserve"')).join('');
  const title = `${esc(cfg.title)}<tspan fill="${C.fire}">.</tspan>`;
  const tagline = (cfg.tagline ?? []).map((l, i) => text(48, 246 + i * 26, 18, i === 0 ? C.ink : C.muted, esc(l))).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(cfg.alt)}">
  <defs>${dots}</defs>
  <rect width="${W}" height="${H}" fill="${C.paper}"/>
  <rect width="${W}" height="${H}" fill="url(#dots)"/>
  <rect x="12.5" y="12.5" width="${W - 25}" height="${H - 25}" fill="none" stroke="${C.line}"/>
  <g font-family="${MONO}">
    ${logo}
    ${text(W - 48, 64, 12, C.muted, esc(cfg.meta ?? ''), ' text-anchor="end" letter-spacing="1.5"')}
    <rect x="48" y="${cfg.label ? 140 : 0}" width="7" height="7" fill="${C.fire}"/>
    ${text(64, 147, 12, C.muted, esc((cfg.label ?? '').toUpperCase()), ' letter-spacing="2.5"')}
    ${text(46, 206, 52, C.ink, title, ' font-weight="700" letter-spacing="-1"')}
    ${tagline}
    ${chips(cfg.chips ?? [], 48, 318)}
    ${cfg.diagram ? flow(cfg.diagram) : ''}
  </g>
</svg>
`;
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  const [config, out] = process.argv.slice(2);
  if (!config || !out) {
    console.error('usage: node banner.mjs <config.json> <out.svg>');
    process.exit(2);
  }
  writeFileSync(out, banner(JSON.parse(readFileSync(config, 'utf8'))));
  console.log(`wrote ${out}`);
}
