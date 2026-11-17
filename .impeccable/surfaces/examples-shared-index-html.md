---
version: 1
slug: "examples-shared-index-html"
primary_target: "examples/shared/index.html"
related_targets: ["clients/web/eudiw-request.js"]
---

# Surface: example showcase page and <eudiw-request>

Scope: `examples/shared/index.html` (developer showcase, Persuade for engineers evaluating the adapter) and `clients/web/eudiw-request.js` (embeddable component, Operate for end users). World inherited from the su.engineering website design system (su-landing repository): charcoal #10110f, ivory #eeeade, signal orange #ff6538, stone #aaa79d, olive hairline #4d4c43, JetBrains Mono only, square, hairlines, no shadows or gradients, original ASCII logo in a `<pre>`.

Audience: engineers running the example against the demo; end users scanning a QR. Job: run a real age check and see exactly what crossed the wire. Constraints: component themeable, dark default plus ivory light variant, vendored JetBrains Mono, CSP-safe, privacy line and expiry countdown in the component.

## Direction contract

THESIS: The check and its evidence side by side: request on the left, a live protocol trace on the right. Refuses the centred card-with-spinner demo page.

OWN-WORLD: su.engineering canvas: charcoal field with the 28px dotted grid and 12px inset hairline frame, ivory lowercase display type ending in an orange full stop, 11px tracked uppercase labels led by an orange dot, square outlined panels, northeast arrows, orange only for live signal.

STORY: The visitor reads what is asked (over 18, nothing else), scans or opens the wallet, watches each step land in the trace with timestamps, and ends on the returned JSON beside the attributes that stayed in the wallet.

FIRST VIEWPORT: Top bar: ASCII logo left, "eudiw-adapter / example" and GitHub link right. Left column (6/12): kicker, headline "prove you are over 18. share nothing else." at ~56px, one paragraph, then the request panel (QR 240px, countdown, privacy line, open-wallet link, primary "start a check" button before a session). Right column: ruled trace with column header, step rows (time, actor, event), orange dot on the live row.

FORM: Request and trace, third on my ordered list, seed key e4517232.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

Signature interaction: each trace row arrives with a short left-to-right hairline draw and the QR panel collapses into a verified stamp; reduced motion shows final states.
