/*
 * Copyright 2026 su-engineering
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * <eudiw-request>: shows an EUDI Wallet request as a QR code and an "open wallet" link, says what is asked and
 * that nothing else leaves the wallet, counts down to expiry, and follows the session through a status URL on your
 * own backend.
 *
 *   <eudiw-request launch-uri="openid4vp://?client_id=..." status-url="/verifications/abc/status"
 *                  request-label="over 18" expires-at="2026-11-17T10:05:00Z"></eudiw-request>
 *
 * Attributes
 *   launch-uri     wallet_launch.launch_uri from the session your backend created
 *   status-url     a URL on your backend answering {"status": "...", "expires_at"?: "..."} (same origin, cookies sent)
 *   request-label  what is asked, in the user's words, for example "over 18"
 *   expires-at     the session's expires_at (ISO 8601); shows a countdown and ends the request locally at zero
 *   mode           "cross_device" (default: QR code and link) or "same_device" (link only)
 *   theme          "dark" (default), "light", or "auto" (follows prefers-color-scheme)
 *   credit         "off" hides the "eudiw-adapter · su.engineering" line
 *   poll-interval  milliseconds between status checks, default 2000
 *
 * Events (bubbling, composed)
 *   eudiw-status   detail: {status, response}  when the status changes; response is the status URL's JSON body
 *   eudiw-done     detail: {status, response}  once, when the session ends
 *   eudiw-restart  when the user asks for a new request after it ended without a verification
 *
 * The component never talks to the adapter. It loads JetBrains Mono from ./fonts next to this file (same origin)
 * and makes no other request than the status URL.
 */
import { qrcode } from './vendor/qrcode.mjs';

const TERMINAL = new Set(['verified', 'rejected', 'denied', 'expired', 'cancelled', 'consumed']);
const BLOCKED_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'blob:', 'file:']);
const SVG = 'http://www.w3.org/2000/svg';
const FAMILY = 'eudiw-jetbrains-mono';

const COPY = {
  scan: 'Scan with your EU Digital Identity Wallet',
  open: 'Open your EU Digital Identity Wallet to continue',
  waiting: 'Waiting for your wallet',
  verified: 'verified',
  rejected: 'this could not be verified',
  denied: 'declined in your wallet',
  expired: 'this request expired',
  cancelled: 'this request was cancelled',
  retrying: 'Connection lost, retrying',
  invalid: 'This wallet request is not valid',
};

/** Registers the vendored JetBrains Mono once per document (@font-face does not work inside a shadow root). */
function registerFont() {
  if (document[`__${FAMILY}`]) {
    return;
  }
  document[`__${FAMILY}`] = true;
  const latin = new URL('./fonts/jetbrains-mono-latin-wght-normal.woff2', import.meta.url);
  const latinExt = new URL('./fonts/jetbrains-mono-latin-ext-wght-normal.woff2', import.meta.url);
  const css = `
@font-face { font-family: "${FAMILY}"; font-style: normal; font-weight: 100 800; font-display: swap;
  src: url("${latin}") format("woff2");
  unicode-range: U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD; }
@font-face { font-family: "${FAMILY}"; font-style: normal; font-weight: 100 800; font-display: swap;
  src: url("${latinExt}") format("woff2");
  unicode-range: U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF; }`;
  if ('adoptedStyleSheets' in document && 'replaceSync' in CSSStyleSheet.prototype) {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  } else {
    const style = document.createElement('style');
    style.textContent = css;
    document.head.append(style);
  }
}

const STYLE = `
:host {
  --eudiw-bg: #10110f;
  --eudiw-fg: #eeeade;
  --eudiw-muted: #aaa79d;
  --eudiw-line: #4d4c43;
  --eudiw-signal: #ff6538;
  --eudiw-signal-text: #ff6538;
  --eudiw-qr-bg: #eeeade;
  --eudiw-qr-fg: #10110f;
  --eudiw-font: "${FAMILY}", "JetBrains Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  display: inline-block;
  width: min(100%, 360px);
  color: var(--eudiw-fg);
  font: 400 14px/1.6 var(--eudiw-font);
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
}
:host([theme="light"]) {
  --eudiw-bg: #eeeade;
  --eudiw-fg: #10110f;
  --eudiw-muted: #5c5a51;
  --eudiw-line: #bdb8a8;
  --eudiw-signal: #ff6538;
  --eudiw-signal-text: #b23a14;
  --eudiw-qr-bg: #f7f4ec;
  --eudiw-qr-fg: #10110f;
}
@media (prefers-color-scheme: light) {
  :host([theme="auto"]) {
    --eudiw-bg: #eeeade;
    --eudiw-fg: #10110f;
    --eudiw-muted: #5c5a51;
    --eudiw-line: #bdb8a8;
    --eudiw-signal-text: #b23a14;
    --eudiw-qr-bg: #f7f4ec;
  }
}
* { box-sizing: border-box; }
::selection { background: var(--eudiw-signal); color: #10110f; }
.panel { position: relative; background: var(--eudiw-bg); border: 1px solid var(--eudiw-line); }
.bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px;
  border-bottom: 1px solid var(--eudiw-line); font-size: 11px; letter-spacing: .12em; text-transform: uppercase;
  color: var(--eudiw-muted); }
.bar .tag { display: inline-flex; align-items: center; gap: 8px; }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--eudiw-signal); flex: none; }
.clock { font-size: 12px; letter-spacing: .04em; color: var(--eudiw-fg); }
.clock[data-low] { color: var(--eudiw-signal-text); }
.body { display: grid; gap: 18px; padding: 22px 20px 20px; }
.ask { margin: 0; font-size: 22px; line-height: 1.15; font-weight: 500; letter-spacing: -.035em; color: var(--eudiw-fg);
  text-wrap: balance; }
.ask span { color: var(--eudiw-muted); font-size: 11px; letter-spacing: .12em; text-transform: uppercase;
  display: block; margin-bottom: 8px; font-weight: 400; }
.ask b { font-weight: 500; }
.ask i { font-style: normal; color: var(--eudiw-signal-text); }
.code { position: relative; margin: 4px auto 0; width: min(268px, 100%); padding: 14px; }
.code::before, .code::after, .code > i::before, .code > i::after { content: ""; position: absolute; width: 14px; height: 14px;
  border-color: var(--eudiw-fg); border-style: solid; border-width: 0; }
.code::before { top: 0; left: 0; border-top-width: 1px; border-left-width: 1px; }
.code::after { top: 0; right: 0; border-top-width: 1px; border-right-width: 1px; }
.code > i::before { bottom: 0; left: 0; border-bottom-width: 1px; border-left-width: 1px; }
.code > i::after { bottom: 0; right: 0; border-bottom-width: 1px; border-right-width: 1px; }
.code svg { display: block; width: 100%; height: auto; }
.hint { margin: -6px 0 0; text-align: center; font-size: 11px; color: var(--eudiw-muted); }
.open { display: flex; align-items: center; justify-content: space-between; gap: 12px; min-height: 48px; padding: 0 16px;
  background: var(--eudiw-fg); color: var(--eudiw-bg); text-decoration: none; font-weight: 500; font-size: 13px;
  letter-spacing: -.01em; border: 1px solid var(--eudiw-fg); transition: background-color 160ms, color 160ms; }
.open:hover { background: transparent; color: var(--eudiw-fg); }
.open svg, .again svg { width: 12px; height: 12px; flex: none; color: var(--eudiw-signal); }
a:focus-visible, button:focus-visible { outline: 2px solid var(--eudiw-signal-text); outline-offset: 6px; }
.status { display: flex; align-items: center; gap: 10px; margin: 0; font-size: 12px; color: var(--eudiw-muted); }
.cursor { width: 7px; height: 13px; background: var(--eudiw-signal); flex: none; animation: blink 1.1s steps(1, end) infinite; }
.privacy { margin: 0; padding-top: 14px; border-top: 1px dashed var(--eudiw-line); font-size: 11px; line-height: 1.6;
  color: var(--eudiw-muted); }
.privacy b { color: var(--eudiw-fg); font-weight: 400; }
.credit { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 10px 16px;
  border-top: 1px solid var(--eudiw-line); font-size: 11px; letter-spacing: .06em; color: var(--eudiw-muted); }
.credit a { color: inherit; text-decoration: none; border-bottom: 1px solid var(--eudiw-line); }
.credit a:hover { color: var(--eudiw-signal-text); border-color: var(--eudiw-signal); }
:host([credit="off"]) .credit { display: none; }
.result { display: grid; gap: 14px; padding: 6px 0 2px; }
.stamp { justify-self: start; display: inline-flex; align-items: center; gap: 10px; padding: 7px 12px;
  border: 1px solid var(--eudiw-signal); color: var(--eudiw-signal-text); font-size: 11px; letter-spacing: .14em;
  text-transform: uppercase; }
.stamp[data-tone="bad"] { border-color: var(--eudiw-line); color: var(--eudiw-muted); }
.stamp[data-tone="bad"] .dot { background: transparent; border: 1px solid currentColor; }
.big { margin: 0; font-size: 34px; line-height: 1; font-weight: 500; letter-spacing: -.045em; }
.big i { font-style: normal; color: var(--eudiw-signal-text); }
.again { display: inline-flex; align-items: center; gap: 10px; justify-self: start; padding: 10px 0 7px; font: inherit;
  font-size: 13px; color: var(--eudiw-fg); background: none; border: 0; border-bottom: 1px solid var(--eudiw-fg);
  cursor: pointer; }
.again:hover { color: var(--eudiw-signal-text); border-color: var(--eudiw-signal); }
.enter { animation: enter 520ms cubic-bezier(.16,1,.3,1) both; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
@keyframes enter { from { opacity: 0; transform: translateY(6px); clip-path: inset(0 0 100% 0); }
  to { opacity: 1; transform: none; clip-path: inset(0); } }
@media (prefers-reduced-motion: reduce) {
  .cursor, .enter { animation: none; }
  .open, .credit a, .again { transition: none; }
}
`;

function arrow() {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 12 12');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.4');
  const path = document.createElementNS(SVG, 'path');
  path.setAttribute('d', 'M3 9 9 3M4.2 3H9v4.8');
  svg.append(path);
  return svg;
}

function safeLaunchUri(value) {
  if (!value) {
    return null;
  }
  let scheme;
  try {
    scheme = new URL(value).protocol.toLowerCase();
  } catch {
    return null;
  }
  return BLOCKED_SCHEMES.has(scheme) ? null : value;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text != null) {
    node.textContent = text;
  }
  return node;
}

/** An SVG QR code (error correction M, quiet zone of four modules) built with DOM calls, no markup strings. */
export function qrSvg(text, title) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const size = count + 8;
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('shape-rendering', 'crispEdges');
  const label = document.createElementNS(SVG, 'title');
  label.textContent = title;
  svg.append(label);
  const background = document.createElementNS(SVG, 'rect');
  background.setAttribute('width', String(size));
  background.setAttribute('height', String(size));
  background.setAttribute('fill', 'var(--eudiw-qr-bg, #ffffff)');
  svg.append(background);
  let d = '';
  for (let row = 0; row < count; row += 1) {
    for (let col = 0; col < count; col += 1) {
      if (qr.isDark(row, col)) {
        d += `M${col + 4} ${row + 4}h1v1h-1z`;
      }
    }
  }
  const path = document.createElementNS(SVG, 'path');
  path.setAttribute('d', d);
  path.setAttribute('fill', 'var(--eudiw-qr-fg, #000000)');
  svg.append(path);
  return svg;
}

export class EudiwRequest extends HTMLElement {
  static observedAttributes = ['launch-uri', 'status-url', 'mode', 'request-label', 'expires-at'];

  #status = null;
  #response = null;
  #timer = null;
  #clock = null;
  #failures = 0;
  #controller = null;
  #expiresAt = null;

  constructor() {
    super();
    registerFont();
    const root = this.attachShadow({ mode: 'open' });
    if ('adoptedStyleSheets' in root && 'replaceSync' in CSSStyleSheet.prototype) {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(STYLE);
      root.adoptedStyleSheets = [sheet];
    } else {
      root.append(el('style', null, STYLE));
    }
    this.panel = el('section', 'panel');
    this.panel.setAttribute('part', 'panel');
    this.panel.setAttribute('aria-label', 'EU Digital Identity Wallet request');
    root.append(this.panel);
  }

  connectedCallback() {
    this.#reset();
    document.addEventListener('visibilitychange', this.#onVisibility);
  }

  disconnectedCallback() {
    this.#stop();
    clearInterval(this.#clock);
    document.removeEventListener('visibilitychange', this.#onVisibility);
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      this.#reset();
    }
  }

  /** The last status the backend reported, or null. */
  get status() {
    return this.#status;
  }

  #reset() {
    this.#status = null;
    this.#response = null;
    this.#failures = 0;
    const expires = Date.parse(this.getAttribute('expires-at') ?? '');
    this.#expiresAt = Number.isFinite(expires) ? expires : null;
    this.#renderPending();
    this.#startClock();
    this.#schedule(0);
  }

  #onVisibility = () => {
    if (document.visibilityState === 'visible' && !TERMINAL.has(this.#status)) {
      this.#schedule(0);
    }
  };

  #bar(label) {
    const bar = el('div', 'bar');
    const tag = el('span', 'tag');
    tag.append(el('span', 'dot'), el('span', null, label));
    this.clockEl = el('span', 'clock');
    this.clockEl.setAttribute('aria-label', 'time left');
    bar.append(tag, this.clockEl);
    return bar;
  }

  #credit() {
    const credit = el('div', 'credit');
    credit.setAttribute('part', 'credit');
    const name = el('span', null, 'eudiw-adapter');
    const link = el('a', null, 'su.engineering');
    link.href = 'https://su.engineering';
    link.target = '_blank';
    link.rel = 'noopener';
    credit.append(name, link);
    return credit;
  }

  #ask() {
    const label = this.getAttribute('request-label');
    const ask = el('p', 'ask');
    ask.append(el('span', null, 'this service asks for'));
    if (label) {
      const b = el('b', null, label);
      ask.append(b, el('i', null, '.'));
    } else {
      ask.append(document.createTextNode('one fact from your wallet'), el('i', null, '.'));
    }
    return ask;
  }

  #renderPending() {
    const launch = safeLaunchUri(this.getAttribute('launch-uri'));
    const sameDevice = this.getAttribute('mode') === 'same_device';
    this.panel.replaceChildren();
    this.panel.append(this.#bar('EU Digital Identity Wallet'));
    const body = el('div', 'body');
    this.panel.append(body);
    if (!launch) {
      body.append(el('p', 'status', COPY.invalid));
      this.panel.append(this.#credit());
      return;
    }
    body.append(this.#ask());
    if (!sameDevice) {
      const code = el('div', 'code');
      code.setAttribute('part', 'qr');
      code.append(qrSvg(launch, 'QR code for your EU Digital Identity Wallet'), el('i'));
      body.append(code, el('p', 'hint', COPY.scan));
    }
    const open = el('a', 'open');
    open.setAttribute('part', 'open');
    open.href = launch;
    open.append(el('span', null, sameDevice ? 'open wallet' : 'open wallet on this phone'), arrow());
    body.append(open);
    this.statusLine = el('p', 'status');
    this.statusLine.setAttribute('role', 'status');
    this.statusLine.setAttribute('aria-live', 'polite');
    this.statusLine.append(el('span', 'cursor'), el('span', null, sameDevice ? COPY.open : COPY.waiting));
    body.append(this.statusLine);
    const privacy = el('p', 'privacy');
    privacy.setAttribute('part', 'privacy');
    privacy.append(
      el('b', null, 'Nothing else leaves your wallet. '),
      document.createTextNode('You see the request in your wallet and decide there.'),
    );
    body.append(privacy);
    this.panel.append(this.#credit());
  }

  #renderDone(status) {
    const ok = status === 'verified' || status === 'consumed';
    this.panel.replaceChildren();
    this.panel.append(this.#bar('EU Digital Identity Wallet'));
    this.clockEl.textContent = '';
    const body = el('div', 'body');
    const result = el('div', 'result enter');
    result.setAttribute('role', 'status');
    const stamp = el('span', 'stamp');
    stamp.dataset.tone = ok ? 'ok' : 'bad';
    stamp.append(el('span', 'dot'), el('span', null, ok ? 'verified' : status));
    const big = el('p', 'big');
    big.append(document.createTextNode(ok ? 'done' : COPY[status] ?? status), el('i', null, '.'));
    result.append(stamp, big);
    if (ok) {
      const label = this.getAttribute('request-label');
      result.append(el('p', 'privacy', label
        ? `Your wallet confirmed ${label}. Nothing else left it.`
        : 'Your wallet confirmed what was asked. Nothing else left it.'));
    } else {
      const again = el('button', 'again');
      again.type = 'button';
      again.append(el('span', null, 'start a new request'), arrow());
      again.addEventListener('click', () => {
        this.dispatchEvent(new CustomEvent('eudiw-restart', { bubbles: true, composed: true }));
      });
      result.append(again);
    }
    body.append(result);
    this.panel.append(body, this.#credit());
  }

  #startClock() {
    clearInterval(this.#clock);
    const tick = () => {
      if (!this.clockEl || this.#expiresAt == null || TERMINAL.has(this.#status)) {
        return;
      }
      const left = Math.max(0, Math.round((this.#expiresAt - Date.now()) / 1000));
      this.clockEl.textContent = `${String(Math.floor(left / 60)).padStart(2, '0')}:${String(left % 60).padStart(2, '0')}`;
      this.clockEl.setAttribute('aria-label', `${left} seconds left`);
      if (left <= 30) {
        this.clockEl.dataset.low = '';
      }
      if (left === 0) {
        this.#update('expired', this.#response);
      }
    };
    tick();
    this.#clock = setInterval(tick, 1000);
  }

  #schedule(delay) {
    this.#stop();
    if (!this.getAttribute('status-url')
        || !safeLaunchUri(this.getAttribute('launch-uri'))
        || TERMINAL.has(this.#status)) {
      return;
    }
    this.#timer = setTimeout(() => this.#poll(), delay);
  }

  #stop() {
    clearTimeout(this.#timer);
    this.#timer = null;
    if (this.#controller) {
      this.#controller.abort();
      this.#controller = null;
    }
  }

  async #poll() {
    const interval = Math.max(500, Number(this.getAttribute('poll-interval')) || 2000);
    if (document.visibilityState === 'hidden') {
      return; // resumed by visibilitychange
    }
    this.#controller = new AbortController();
    try {
      const response = await fetch(this.getAttribute('status-url'), {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
        cache: 'no-store',
        signal: this.#controller.signal,
      });
      if (!response.ok) {
        throw new Error(`status ${response.status}`);
      }
      const body = await response.json();
      this.#failures = 0;
      if (this.#expiresAt == null && typeof body.expires_at === 'string' && Number.isFinite(Date.parse(body.expires_at))) {
        this.#expiresAt = Date.parse(body.expires_at);
      }
      if (typeof body.status === 'string') {
        this.#update(body.status, body);
      }
      this.#schedule(interval);
    } catch (e) {
      if (e && e.name === 'AbortError') {
        return;
      }
      this.#failures += 1;
      if (this.statusLine && this.#failures >= 3) {
        this.statusLine.lastChild.textContent = COPY.retrying;
      }
      this.#schedule(Math.min(30000, interval * 2 ** Math.min(this.#failures, 4)));
    }
  }

  #update(status, response) {
    this.#response = response ?? this.#response;
    const changed = status !== this.#status;
    const detail = { detail: { status, response: this.#response }, bubbles: true, composed: true };
    if (!changed) {
      if (response) {
        this.dispatchEvent(new CustomEvent('eudiw-poll', detail));
      }
      return;
    }
    this.#status = status;
    this.dispatchEvent(new CustomEvent('eudiw-status', detail));
    if (TERMINAL.has(status)) {
      this.#stop();
      clearInterval(this.#clock);
      this.#renderDone(status);
      this.dispatchEvent(new CustomEvent('eudiw-done', detail));
    }
  }
}

if (!customElements.get('eudiw-request')) {
  customElements.define('eudiw-request', EudiwRequest);
}
