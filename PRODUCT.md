# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- Relying-party engineers (banks, shops, public services, identity teams) who add EU Digital Identity Wallet presentation to an existing product and must not implement OpenID4VP, HAIP, SD-JWT VC and ETSI trust lists themselves.
- Their end users, on a desktop page scanning a QR code with a phone wallet, or on a phone opening the wallet directly, who are asked to share one or a few facts (for example "over 18").

## Product Purpose

eudiw-adapter is an open-source (Apache-2.0) EUDI Wallet verifier for relying parties. A backend asks for a policy-defined set of claims through a small REST API; the adapter talks to the wallet, verifies everything, and returns only the approved claims. The browser-facing pieces (`clients/web/eudiw-request.js` and the example pages in `examples/`) show the wallet request and follow the session.

## Positioning

Built by su.engineering from the specifications, with data minimization and fail-closed verification as defaults, tested against independent wallets and the OpenID Foundation HAIP test plan (run locally, not certified).

## Capabilities and Constraints

- The web component never talks to the adapter; it renders a launch URI and polls a status URL on the integrator's backend.
- The component is embedded on third-party sites: it must work under strict CSP, make no third-party requests, and be themeable.
- v0.1.0 was the first release: image and chart on ghcr.io, the component on npm as `@su-engineering/eudiw-request`. v0.2.0 added ISO mdoc.
- mdoc and the Digital Credentials API are not implemented.

## Brand Commitments

- su.engineering branding on every frontend element, matching the su.engineering website (visual authority: the su.engineering website design system, "The Typographic Canvas", in the su-landing repository).
- The component ships in the su.engineering look by default with a small "eudiw-adapter · su.engineering" credit line; integrators can retheme it with CSS custom properties and hide the credit (user decision, 2026-11-17).
- Dark (charcoal) by default, plus a warm-ivory light variant chosen by attribute or the host's color scheme (user decision, 2026-11-17).
- JetBrains Mono vendored as woff2 (OFL) and loaded from the integrator's origin; no Google Fonts (user decision, 2026-11-17).
- The su.engineering ASCII logo is never redrawn, converted or restyled; render only the original text in a `<pre>`.
- No em-dashes or AI-slop phrasing in public copy.

## Evidence on Hand

- Interop evidence: `interop/oidf/README.md`, `docs/standards-matrix.md`.
- No customers, testimonials, deployments or certifications exist; never imply them.

## Product Principles

1. The user's attention is the scarce resource: one clear action (scan or open wallet) and an honest status.
2. Nothing leaves the user's wallet that the policy does not need; say so plainly.
3. Fail visibly and honestly: rejected, declined and expired states are first-class, never hidden.
4. Integrators own their pages: the component must sit well inside someone else's design.

## Accessibility & Inclusion

WCAG 2.2 AA: visible focus, live status announcements, reduced motion respected, contrast in both variants, usable at 320px width.
