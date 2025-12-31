# DEDSEC / Cyberpunk Visual System

## 1. Palette
- **Core Canvas**: `#030509`, `#070B12`, `#0C121E` layered with low-opacity noise.
- **Structural Grays**: `#1A212F` (rails), `#252C3F` (panels), `#3B455E` (dividers), `#D5DFF0` (body text).
- **Neon Accents** (sparingly): `#25F4FF` (primary action), `#4C79FF` (info), `#FF2AD0` (exploit), `#5CFF6D` (success), `#FF365A` (breach), `#FFB347` (caution).
- **Rules**: No more than 3 neon hues visible at once; ensure ≥7:1 contrast for text-on-background; use gradients only for attention states.

## 2. Typography
- **Headers**: Orbitron / Neue Machina, uppercase, 20–28px, letter-spacing 0.08em.
- **Body & UI Copy**: IBM Plex Mono / Space Mono, 16–18px, line-height 1.55 for legibility.
- **Data / Metrics**: Roboto Mono Tabular, 14px for dashboards.
- **Usage**: Reserve display font for hero labels, badges, telemetry headings. Keep long-form content in mono for focus + parity with CLI heritage.

## 3. Layout & Components
- **Grid**: 8px modular grid, 24px gutters for main panels. Panels = stacked terminals with asymmetric corner cuts and 1px neon border.
- **Navigation Rail**: Vertical lane on left; modules listed as IDs (`NODE 04`, `OPS.Δ`). Active item uses cyan bar + waveform glyph.
- **Panels**: `rgba(7,11,18,0.92)` background, scanline overlay, noise mask (1–2%). Add status ribbon (e.g., `INTRUSION FEED`) with glitch dither.
- **Tables**: Alternating row fills (#0E1321 / #11182A), monospace headings, inline sparklines. Selected row uses subtle cyan glow.
- **Forms**: Terminal-style prompts. Labels shown as tokens (`> target_url`). Inputs highlight with cyan border + caret animation on focus.
- **Buttons**: Angular pill with diagonal notch. Default = ghost outline; hover = cyan→magenta gradient fill + bloom. Idle icons are thin-line polygonal glyphs; active icons fill solid neon.
- **Alerts / Logs**: Render as breach banners—red tint, glitch icon jitter, stack-trace typography. Success notices = green pulse trail. Provide severity badges (INFO, WARN, CRIT) using neon outlines.

## 4. Motion & Effects
- **Animations**: Keep durations 150–250ms, easing resembling electrical discharge (`cubic-bezier(0.4,0,0.2,1)`).
- **Noise / Glitch**: Background grain loops at ultra-low opacity; trigger burst on context switch. Panel borders emit quick static when data refreshes. Add optional "calm mode" to reduce amplitude.
- **Streams**: Terminal text caret blinks irregularly (450–650ms). Connection lines pulse at 1Hz to suggest signal flow. Use parallax drift for holographic grids.

## 5. Branding & Tone
- **Persona**: Anonymous hacktivist collective, anti-establishment. Voice is terse, declarative ("TRACE JAMMED", "LINK ESTABLISHED").
- **Iconography**: Angular linework, waveform/glitch motifs, intersecting triangles. Replace avatars with glyph IDs to preserve anonymity.
- **Status Colors**: Recon (cyan), Exploit (magenta), Maintain (green), Breach (red). Documented in CSS tokens.
- **Accessibility**: Provide high-contrast fallback (reduced noise, disabled glow). All interactive targets ≥44px, text never drops below 14px.

## 6. Implementation Notes
1. Centralize theme tokens in CSS variables (see `ui/dedsec_theme.css`).
2. Attach scanline/noise layers via pseudo-elements to avoid DOM clutter.
3. Apply accent glows only on hover/focus to keep baseline restful.
4. Offer `data-theme="calm"` attribute to dampen animations for marathon pentest sessions.
5. Keep CLI output aligned by using same palette references (Colorama codes) where possible.
