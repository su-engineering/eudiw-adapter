---
name: eudiw-adapter on the su.engineering canvas
description: The su.engineering typographic world applied to a wallet request component and its developer showcase.
colors:
  fire: "#ff6538"
  paper: "#10110f"
  ink: "#eeeade"
  muted: "#aaa79d"
  line: "#4d4c43"
  faint: "#2a2a25"
  fire-text-light: "#b23a14"
  muted-light: "#5c5a51"
  line-light: "#bdb8a8"
  qr-paper-light: "#f7f4ec"
typography:
  display:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "clamp(36px, 3.9vw, 54px)"
    fontWeight: 500
    lineHeight: 1.02
    letterSpacing: "-0.045em"
  result:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "34px"
    fontWeight: 500
    lineHeight: 1
    letterSpacing: "-0.045em"
  headline:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "30px"
    fontWeight: 500
    lineHeight: 1.02
    letterSpacing: "-0.04em"
  title:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "22px"
    fontWeight: 500
    lineHeight: 1.15
    letterSpacing: "-0.035em"
  body:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.75
    fontFeature: "tnum"
  body-component:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.6
    fontFeature: "tnum"
  data:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "12px"
    fontWeight: 400
    fontFeature: "tnum"
  label:
    fontFamily: "JetBrains Mono, ui-monospace, Menlo, monospace"
    fontSize: "11px"
    fontWeight: 400
    letterSpacing: "0.14em"
  logo:
    fontFamily: "JetBrains Mono, monospace"
    fontSize: "10px"
    fontWeight: 400
    lineHeight: 1
    letterSpacing: "-0.025em"
rounded:
  square: "0px"
  dot: "50%"
spacing:
  frame: "12px"
  row: "13px"
  cell: "20px"
  gutter: "24px"
  grid: "28px"
  section: "56px"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    rounded: "{rounded.square}"
    padding: "0 16px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
  text-link:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    typography: "{typography.data}"
    padding: "10px 0 7px"
  text-link-hover:
    textColor: "{colors.fire}"
  request-panel:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    typography: "{typography.body-component}"
    rounded: "{rounded.square}"
    width: "360px"
  request-panel-light:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
  verified-stamp:
    backgroundColor: "transparent"
    textColor: "{colors.fire}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "7px 12px"
  trace-row:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    padding: "13px 0"
  returned-cell:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.square}"
    padding: "20px"
---

# Design System: eudiw-adapter on the su.engineering canvas

## Overview

**Creative North Star: "The Typographic Canvas" (inherited)**

This repository does not own a visual world. It extends the su.engineering canvas recorded in `~/Developer/su-landing/DESIGN.md`, which stays the brand authority and is not edited from here. What this file records is how that world landed in two shipped surfaces: the embeddable `<eudiw-request>` web component (`clients/web/eudiw-request.js`) and the developer showcase page (`examples/shared/index.html`), where the request sits on the left and a live protocol trace on the right.

The inherited material is intact: charcoal field, warm ivory type, signal orange used in small points, JetBrains Mono as the only family, square outlined panels, one-pixel rules, a 28px dotted grid with a 12px inset hairline frame, northeast arrows, and the original ASCII logo in a `<pre>`. The page reads like a technical print spread: large lowercase statements beside compact tracked annotations and tabular data.

Where this repo differs from su-landing: the component has a warm-ivory light variant beside the charcoal default; its tokens are exposed as `--eudiw-*` custom properties so integrators can retheme it; body copy is sentence case while display headings stay lowercase; waiting is shown by a blinking orange block cursor; and the trace shows inferred rows for steps the backend cannot observe directly.

**Key Characteristics:**

- Inherited su.engineering world, unchanged in palette, family and logo.
- Large lowercase headings that end in an orange full stop.
- Evidence beside action: a ruled, timestamped trace next to the request.
- Square panels, hairlines and pattern fills; no shadows, no colour-blend gradients.
- A themeable component that keeps the brand look by default and can recede into a host page.

## Colors

A warm, mineral, mostly neutral palette with one hot signal colour.

### Primary
- **Signal Orange** (`fire`): status dots, the full stop that closes each heading, interpuncts in trace details, northeast arrows, the live trace row's actor and dot, the JSON value returned to the backend, error text, hover text and rules, focus outlines, the waiting cursor, and text selection. In the component it is `--eudiw-signal`.
- **Signal Orange, text on ivory** (`fire-text-light`): the readable orange for words in the light variant (stamp text, low-time countdown, link hover). In the component it is `--eudiw-signal-text`; on charcoal it equals `fire`.

### Neutral
- **Charcoal** (`paper`): page field, opaque panels, the dark component background (`--eudiw-bg`), and QR modules in both themes (`--eudiw-qr-fg`).
- **Warm Ivory** (`ink`): primary text, the primary button fill, QR corner brackets, the light component background, and the QR quiet zone on charcoal (`--eudiw-qr-bg`).
- **Stone** (`muted`): supporting copy, labels, timestamps, actor names, credit line (`--eudiw-muted`).
- **Olive Hairline** (`line`): panel outlines, column rules, dashed separators, link underlines (`--eudiw-line`).
- **Faint Rule** (`faint`): the quietest rules on the page: header and footer separators and the bottom rule of each trace row.
- **Light variant neutrals** (`muted-light`, `line-light`, `qr-paper-light`): stone, hairline and QR quiet zone for the ivory component, chosen so muted text and the QR keep contrast on ivory.

### Named Rules

**The Signal Rule.** Orange marks small points of attention, live state and interaction. In this repo's surfaces it fills nothing larger than the 7px dot and the cursor.

**The Two Oranges Rule.** On ivory, any orange word a person must read uses `fire-text-light`.

**The Retheme Rule.** Component colours are `--eudiw-*` custom properties on `:host`. The defaults are the su.engineering values; `theme="light"` and `theme="auto"` swap them, and integrators may override them. New component colours must be added as `--eudiw-*` properties, never hardcoded.

## Typography

**Display Font:** JetBrains Mono (vendored woff2, with ui-monospace, SF Mono, Menlo, Consolas, monospace)
**Body Font:** JetBrains Mono
**Label/Mono Font:** JetBrains Mono

**Character:** One monospace family carries everything. The scale is deliberately irregular: tight, heavy-ish (500) lowercase statements with negative tracking beside small, wide-tracked uppercase annotations and tabular numerals.

The font is vendored in `clients/web/fonts` and loaded from the integrator's origin. Because `@font-face` does not work inside a shadow root, the component registers the family once on the document under the name `eudiw-jetbrains-mono`. No Google Fonts, no third-party requests.

### Hierarchy
- **Display** (500, clamp(36px, 3.9vw, 54px), 1.02): the page's single headline, lowercase, ending in an orange full stop.
- **Result** (500, 34px, 1): the component's end-state word ("done.", "this request expired.").
- **Headline** (500, 30px, 1.02): section headings beside the display, such as the trace heading.
- **Title** (500, 22px, 1.15): the component's ask line ("over 18."), with balanced wrapping.
- **Body** (400, 15px, 1.75): page base. Lead paragraphs drop to 14px in stone with a 54ch measure; footer text is 12px at 34ch.
- **Body, component** (400, 14px, 1.6): the component's base; its supporting lines step down to 12px and 11px.
- **Data** (400, 12px): trace rows, definition lists, status line, nav links. Tabular numerals throughout.
- **Label** (400, 11px, 0.14em, uppercase): structural headers: trace column headers, the component's top bar, cell headings in the returned panel, the verified stamp, the actor column.
- **Logo** (400, 10px, 1, -0.025em; 7px below 560px): the original ASCII art only.

### Named Rules

**The Lowercase Statement Rule.** Display, headline and result type is lowercase and closes with an orange full stop. Body copy, hints and status messages are sentence case.

**The Tabular Rule.** Numerals are tabular everywhere, so timestamps and the countdown never jitter.

## Layout

The page is a centred column `min(100% - 48px, 1320px)` (16px gutters below 560px) over a fixed charcoal field with a faint dotted grid every 28px and a fixed one-pixel ivory frame inset 12px from the viewport.

A top bar holds the ASCII logo on the left and a muted nav on the right, closed by a faint rule. The main area is a two-column split: request on the left, trace on the right, divided by a one-pixel olive rule, with 56px above and fluid inner padding (clamp(24px, 5vw, 80px) on the request side, clamp(24px, 4vw, 56px) on the trace side). A three-column footer with a signature cell closes the page.

The trace is a three-column grid (92px time, 76px actor, flexible event) with 16px gaps and 13px row padding, under a header row of tracked labels.

Below 900px the split stacks: the trace moves under the request, its side rule becomes a top rule, and the live-row dot in the gutter is hidden. Below 560px the trace rows reflow to time and actor on one line with the event underneath, column headers are hidden, the returned panel stacks, and the component goes full width.

The component is an inline block `min(100%, 360px)` wide with 20px inner padding and an 18px gap between its parts. It must work at 320px.

## Elevation & Depth

Flat. No drop shadows, no blur, no colour-blend gradients. Depth comes from one-pixel rules, opaque charcoal panels over the dotted field, and the fixed frame above the page. Pattern fills are part of the world: the dotted grid and the 45 degree hatch that marks the "stayed in the wallet" cell are both drawn with CSS gradient functions but read as texture, not as shading.

**The Hairline Rule.** Structure is drawn with one-pixel lines: solid olive for outlines and column rules, dashed for separators inside a panel and for rows not yet reached, faint for the quietest row and page rules.

## Shapes

Square everywhere. The only round form is the 7px status dot. The QR code is framed by four 14px ivory corner brackets instead of a box. Arrows are a single 12px northeast stroke (1.4px) in orange. The logo is the original ASCII text, set in a `<pre>` and never redrawn.

**The Square Rule.** No rounded corners on panels, buttons, cells or stamps. The 7px dot is the single exception.

## Components

### Buttons
Solid, quiet and flat.
- **Shape:** square (0px).
- **Primary:** ivory fill, charcoal text, 13px at weight 500, 46 to 48px tall, 16px side padding, label left and orange northeast arrow right ("start a check", "open wallet on this phone").
- **Hover / Focus:** fill drains to transparent with ivory text over 160ms; focus is a 2px orange outline.
- **Disabled:** 60% opacity with a progress cursor.
- **Text button:** "start a new request" is a bare 13px line with an ivory underline rule and an arrow; hover turns text orange and the rule to signal.

### Links
Muted 12px text with a transparent bottom rule and an orange arrow for outbound links. Hover turns text and rule orange over 160ms. Inline links in the footer and credit carry a permanent olive underline that turns orange on hover.

### Request panel (`<eudiw-request>`)
The signature component.
- **Top bar:** orange dot plus "EU Digital Identity Wallet" as a label on the left, the mm:ss countdown on the right; the countdown turns to the text orange in the last 30 seconds.
- **Body:** the ask line (the requested label as a title, closed by an orange full stop), the QR in corner brackets with a centred hint, the primary open-wallet button, a status line led by a 7x13px orange block cursor that blinks on a 1.1s step, and a privacy line above a dashed rule ("Nothing else leaves your wallet.").
- **Credit:** "eudiw-adapter" and an underlined "su.engineering" link under a solid rule. `credit="off"` hides it.
- **End state:** the body swaps for a stamp, a result word and either a confirmation line or the restart button, revealed with a 520ms clip from the top on `cubic-bezier(.16,1,.3,1)`.
- **Themes:** `dark` (default), `light`, `auto` (follows `prefers-color-scheme`). Parts exposed: `panel`, `qr`, `open`, `privacy`, `credit`.

### Verified stamp
Square outline in signal orange with an orange dot and tracked uppercase text. For any outcome other than verified, the outline turns olive, the text stone, and the dot becomes a hollow ring.

### Start panel
Shares the request panel's 360px outline. A definition list (policy, asks for, returns) with a 96px key column and dashed row rules, then the primary button. Errors appear below as 12px orange text.

### Protocol trace
- **Real row:** timestamp (HH:MM:SS.mmm), actor in tracked uppercase stone, event in ivory with an optional stone detail line whose separators are orange interpuncts. A faint bottom rule.
- **Inferred row:** a step derived from the session status rather than observed by the backend. The time column reads "inferred" in place of a timestamp; otherwise it looks like a real row. The detail line says which status it came from.
- **Ghost row:** a planned step not reached yet. Time reads `--:--:--`, text greyed, bottom rule dashed olive.
- **Live row:** the step being waited for, or the last real one. Actor turns orange and a 7px orange dot sits in the gutter on the column rule.
- **Arrival:** a new non-ghost row (real or inferred) wipes in left to right over 560ms, while an orange rule draws under it over 900ms and fades.

### Returned panel
Two cells in one olive outline: the JSON returned to the backend (keys in stone, values in orange) and "stayed in the wallet" on the hatched fill. Cell headings use the label role. Stacks below 560px.

### Motion
Entrances (row wipe, row rule, end-state reveal) use `cubic-bezier(.16,1,.3,1)`; hover colour changes are plain 160ms transitions; the cursor blinks on a stepped 1.1s cycle. Under `prefers-reduced-motion: reduce` the cursor stops blinking, rows and the end state appear in their final state, and hover transitions are removed.

**The Focus Rule.** Every link and button has a visible 2px orange outline with offset; the inherited offset is 6px.

## Do's and Don'ts

### Do:
- **Do** render the su.engineering ASCII logo as the original text in a `<pre>`, at line-height 1, linked to su.engineering and hidden from assistive technology.
- **Do** close lowercase headings and result words with an orange full stop.
- **Do** expose every component colour as a `--eudiw-*` property and keep su.engineering values as the defaults.
- **Do** use `fire-text-light` (#b23a14 via `--eudiw-signal-text`) for any orange word on ivory.
- **Do** keep tabular numerals for timestamps and the countdown.
- **Do** show planned steps as ghost rows and unobserved steps as inferred rows; never print a timestamp the backend did not record.
- **Do** keep rejected, declined, expired and cancelled outcomes as full end states with a restart action.
- **Do** load JetBrains Mono from the vendored woff2 files on the integrator's origin.

### Don't:
- **Don't** redraw, convert, trace, recolour or restyle the ASCII logo, or replace it with a wordmark or image.
- **Don't** add drop shadows, blur, rounded corners or colour-blend gradients.
- **Don't** load fonts or any other asset from a third party inside the component.
- **Don't** add a second typeface.
