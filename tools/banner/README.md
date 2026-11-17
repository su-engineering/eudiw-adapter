# README banner

`banner.mjs` renders a 1280×400 README banner in the su.engineering look from a JSON config: a charcoal field with a 28px dot grid, a 12px inset hairline frame, the su.engineering logo as its original ASCII text, a lowercase title ending in a signal-orange full stop, a two-line tagline, chips, and an optional flow diagram. Every box in the diagram has the same height, and every arrow sits on the same centre line.

```sh
node tools/banner/banner.mjs tools/banner/eudiw-adapter.json docs/assets/banner.svg
```

To use it in another repository, copy `banner.mjs` (standard library only, Node 18 or later) and write a config:

| Field | Meaning |
| --- | --- |
| `alt` | Accessible description of the image |
| `meta` | Small text at the top right, for example the license |
| `label` | Eyebrow above the title, shown in capitals after an orange square |
| `title` | Repository name; the orange full stop is added |
| `tagline` | One or two lines; the first in ivory, the second muted |
| `chips` | Short standard or feature names |
| `diagram` | Optional. `boxes` (each `glyph`: `wallet`, `verify` or `code` with `lines`; `width`; `caption`; `accent` for the orange outline), `arrows` (`label`, `dashed`), and a shared `height` |

The logo is never redrawn or restyled: it is placed verbatim as text. GitHub shows SVG images without web fonts, so the text renders in the viewer's monospace font; leave some slack in widths.
