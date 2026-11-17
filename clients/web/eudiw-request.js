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
 * <eudiw-request>: shows an EUDI Wallet request as a QR code and an "open wallet" link, and follows the session
 * through a status URL on your own backend.
 *
 *   <eudiw-request launch-uri="openid4vp://?client_id=..." status-url="/verifications/abc/status"></eudiw-request>
 *
 * Attributes
 *   launch-uri     wallet_launch.launch_uri from the session your backend created
 *   status-url     a URL on your backend that answers {"status": "..."} for this session (same origin, cookies sent)
 *   mode           "cross_device" (default: QR code and link) or "same_device" (link only)
 *   poll-interval  milliseconds between status checks, default 2000
 *
 * Events (bubbling, composed)
 *   eudiw-status   detail: {status}  whenever the status changes
 *   eudiw-done     detail: {status}  once, when the session ends: verified, rejected, denied, expired, cancelled
 *
 * The component never talks to the adapter: your backend holds the client credentials, starts the session and
 * fetches the result. No dependencies besides the vendored QR encoder.
 */
import { qrcode } from './vendor/qrcode.mjs';

const TERMINAL = new Set(['verified', 'rejected', 'denied', 'expired', 'cancelled', 'consumed']);
const MESSAGES = {
  waiting: 'Scan the code with your EU Digital Identity Wallet',
  waitingSameDevice: 'Open your EU Digital Identity Wallet to continue',
  verified: 'Verified',
  rejected: 'The presentation could not be verified',
  denied: 'The request was declined in the wallet',
  expired: 'The request expired',
  cancelled: 'The request was cancelled',
  consumed: 'Verified',
  error: 'Checking the status failed; retrying',
};
const BLOCKED_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'blob:', 'file:']);
const SVG = 'http://www.w3.org/2000/svg';

const STYLE = `
:host {
  --eudiw-fg: #10131a;
  --eudiw-bg: #ffffff;
  --eudiw-muted: #5b6475;
  --eudiw-accent: #1f4fd8;
  --eudiw-accent-fg: #ffffff;
  --eudiw-ok: #137a3a;
  --eudiw-bad: #b42318;
  --eudiw-radius: 12px;
  display: inline-block;
  color-scheme: light dark;
  font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
  color: var(--eudiw-fg);
}
@media (prefers-color-scheme: dark) {
  :host { --eudiw-fg: #e8ebf1; --eudiw-bg: #161a22; --eudiw-muted: #9aa3b5; --eudiw-accent: #6b8cff;
    --eudiw-accent-fg: #0b0e14; --eudiw-ok: #4cc27a; --eudiw-bad: #ff7a6b; }
}
.card { display: grid; min-width: 220px; box-sizing: border-box; justify-items: center; gap: 14px; padding: 20px; background: var(--eudiw-bg);
  border: 1px solid color-mix(in srgb, var(--eudiw-fg) 14%, transparent); border-radius: var(--eudiw-radius);
  max-width: 320px; }
svg { width: min(260px, 70vw); height: auto; display: block; border-radius: 6px; }
.status { margin: 0; text-align: center; color: var(--eudiw-muted); min-height: 1.45em; }
.status[data-tone="ok"] { color: var(--eudiw-ok); font-weight: 600; }
.status[data-tone="bad"] { color: var(--eudiw-bad); }
a.open { display: inline-block; padding: 10px 18px; border-radius: 999px; background: var(--eudiw-accent);
  color: var(--eudiw-accent-fg); text-decoration: none; font-weight: 600; }
a.open:focus-visible { outline: 3px solid color-mix(in srgb, var(--eudiw-accent) 45%, transparent); outline-offset: 2px; }
.done svg, .done a.open { display: none; }
`;

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
  background.setAttribute('fill', '#ffffff');
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
  path.setAttribute('fill', '#000000');
  svg.append(path);
  return svg;
}

export class EudiwRequest extends HTMLElement {
  static observedAttributes = ['launch-uri', 'status-url', 'mode'];

  #status = null;
  #timer = null;
  #failures = 0;
  #controller = null;

  constructor() {
    super();
    const root = this.attachShadow({ mode: 'open' });
    if ('adoptedStyleSheets' in root && typeof CSSStyleSheet === 'function' && 'replaceSync' in CSSStyleSheet.prototype) {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(STYLE);
      root.adoptedStyleSheets = [sheet];
    } else {
      const style = document.createElement('style');
      style.textContent = STYLE;
      root.append(style);
    }
    this.card = document.createElement('div');
    this.card.className = 'card';
    this.card.setAttribute('part', 'card');
    root.append(this.card);
  }

  connectedCallback() {
    this.#render();
    this.#schedule(0);
    document.addEventListener('visibilitychange', this.#onVisibility);
  }

  disconnectedCallback() {
    this.#stop();
    document.removeEventListener('visibilitychange', this.#onVisibility);
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      this.#status = null;
      this.#failures = 0;
      this.#render();
      this.#schedule(0);
    }
  }

  /** The last status the backend reported, or null. */
  get status() {
    return this.#status;
  }

  #onVisibility = () => {
    if (document.visibilityState === 'visible' && !TERMINAL.has(this.#status)) {
      this.#schedule(0);
    }
  };

  #render() {
    const launch = safeLaunchUri(this.getAttribute('launch-uri'));
    const sameDevice = this.getAttribute('mode') === 'same_device';
    this.card.replaceChildren();
    if (!launch) {
      this.card.append(this.#message('This wallet request is not valid.', 'bad'));
      this.statusLine = null;
      return;
    }
    if (!sameDevice) {
      const svg = qrSvg(launch, 'QR code for your EU Digital Identity Wallet');
      svg.setAttribute('part', 'qr');
      this.card.append(svg);
    }
    const open = document.createElement('a');
    open.className = 'open';
    open.setAttribute('part', 'open');
    open.href = launch;
    open.textContent = sameDevice ? 'Open wallet' : 'Open wallet on this device';
    this.card.append(open);
    this.statusLine = this.#message(sameDevice ? MESSAGES.waitingSameDevice : MESSAGES.waiting, null);
    this.statusLine.setAttribute('role', 'status');
    this.statusLine.setAttribute('aria-live', 'polite');
    this.card.append(this.statusLine);
  }

  #message(text, tone) {
    const p = document.createElement('p');
    p.className = 'status';
    p.setAttribute('part', 'status');
    if (tone) {
      p.dataset.tone = tone;
    }
    p.textContent = text;
    return p;
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
      if (typeof body.status === 'string') {
        this.#update(body.status);
      }
      this.#schedule(interval);
    } catch (e) {
      if (e && e.name === 'AbortError') {
        return;
      }
      this.#failures += 1;
      if (this.statusLine && this.#failures >= 3) {
        this.statusLine.textContent = MESSAGES.error;
      }
      this.#schedule(Math.min(30000, interval * 2 ** Math.min(this.#failures, 4)));
    }
  }

  #update(status) {
    if (status === this.#status) {
      return;
    }
    this.#status = status;
    const options = { detail: { status }, bubbles: true, composed: true };
    this.dispatchEvent(new CustomEvent('eudiw-status', options));
    if (this.statusLine && MESSAGES[status]) {
      this.statusLine.textContent = MESSAGES[status];
      this.statusLine.dataset.tone = status === 'verified' || status === 'consumed' ? 'ok' : TERMINAL.has(status) ? 'bad' : '';
    }
    if (TERMINAL.has(status)) {
      this.card.classList.add('done');
      this.#stop();
      this.dispatchEvent(new CustomEvent('eudiw-done', options));
    }
  }
}

if (!customElements.get('eudiw-request')) {
  customElements.define('eudiw-request', EudiwRequest);
}
