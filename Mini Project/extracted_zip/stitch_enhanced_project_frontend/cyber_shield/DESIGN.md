---
name: Cyber Shield
colors:
  surface: '#10131a'
  surface-dim: '#10131a'
  surface-bright: '#363940'
  surface-container-lowest: '#0b0e14'
  surface-container-low: '#191c22'
  surface-container: '#1d2026'
  surface-container-high: '#272a31'
  surface-container-highest: '#32353c'
  on-surface: '#e0e2eb'
  on-surface-variant: '#bdc8d1'
  inverse-surface: '#e0e2eb'
  inverse-on-surface: '#2d3037'
  outline: '#87929a'
  outline-variant: '#3e484f'
  surface-tint: '#7bd0ff'
  primary: '#8ed5ff'
  on-primary: '#00354a'
  primary-container: '#38bdf8'
  on-primary-container: '#004965'
  inverse-primary: '#00668a'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffbcbf'
  on-tertiary: '#67001b'
  tertiary-container: '#ff929a'
  on-tertiary-container: '#8c0028'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c4e7ff'
  primary-fixed-dim: '#7bd0ff'
  on-primary-fixed: '#001e2c'
  on-primary-fixed-variant: '#004c69'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffdadb'
  tertiary-fixed-dim: '#ffb2b7'
  on-tertiary-fixed: '#40000d'
  on-tertiary-fixed-variant: '#92002a'
  background: '#10131a'
  on-background: '#e0e2eb'
  surface-variant: '#32353c'
  bg-obsidian: '#080b11'
  bg-surface: '#121929'
  bg-console: '#05070a'
  accent-amber: '#fbbf24'
  accent-orange: '#f97316'
  text-primary: '#f3f4f6'
  text-secondary: '#9ca3af'
  text-muted: '#6b7280'
typography:
  display-lg:
    fontFamily: Outfit
    fontSize: 32px
    fontWeight: '800'
    lineHeight: '1.2'
  headline-md:
    fontFamily: Outfit
    fontSize: 24px
    fontWeight: '700'
    lineHeight: '1.2'
  headline-sm:
    fontFamily: Outfit
    fontSize: 18px
    fontWeight: '600'
    lineHeight: '1.4'
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: '1.5'
  label-mono:
    fontFamily: Fira Code
    fontSize: 12px
    fontWeight: '450'
    lineHeight: '1.6'
    letterSpacing: -0.02em
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: '1'
    letterSpacing: 0.05em
  headline-md-mobile:
    fontFamily: Outfit
    fontSize: 20px
    fontWeight: '700'
    lineHeight: '1.2'
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 4px
  xs: 8px
  sm: 12px
  md: 16px
  lg: 24px
  xl: 32px
  gutter: 20px
  margin-mobile: 16px
  margin-desktop: 32px
---

## Brand & Style
The design system for this Android Malware Detection app is engineered to feel like a **Premium Security Command Center**. It targets security researchers and power users who require high information density without sacrificing aesthetic sophistication.

The style is a fusion of **Glassmorphism** and **Corporate Modern**, utilizing deep obsidian surfaces, frosted textures, and vibrant neon accents to evoke a sense of high-tech vigilance. The interface should feel "live," "pulsing," and "impenetrable." 

Key attributes:
- **Technical Authority:** Precise, data-heavy, and unapologetically professional.
- **Cybernetic Depth:** Layered translucent surfaces that suggest a complex digital ecosystem.
- **Vibrant Alertness:** A dark environment where color is used exclusively for state and hierarchy.

## Colors
This system operates exclusively in **Dark Mode**. The color strategy utilizes a "Vantablack" foundation to make vibrant semantic accents pop.

- **Primary (Electric Blue):** Used for navigation, active states, and informative data visualization.
- **Secondary (Emerald Green):** Reserved for "Safe" states, system health, and successful scan results.
- **Tertiary (Alert Red):** Strictly for malware detection, high-risk threats, and critical errors.
- **Neutral (Obsidian):** The background hierarchy ranges from deep `#080b11` for the base to `#121929` for interactive surfaces.

**Semantic Logic:** Color is information. Use `accent-amber` for moderate warnings and `accent-orange` for suspicious activity. Text uses a tiered grayscale to maintain readability against dark backgrounds.

## Typography
The typographic system balances the approachability of **Outfit** (Headlines) with the clarity of **Inter** (Body) and the technical rigor of **Fira Code** (Monospace).

- **Headlines:** Use Outfit for all titles and brand elements. It provides a modern, geometric feel that differentiates the app from standard system tools.
- **Data & Logs:** Any technical output, package names, or code snippets must use Fira Code. This signals to the user that they are looking at "raw" system data.
- **Scale:** Maintain a strict hierarchy. Large display sizes (32px+) are reserved for critical risk scores and high-level dashboard metrics. Use `label-caps` for table headers and section metadata to maximize space efficiency.

## Layout & Spacing
The layout follows a **Fluid Grid** model designed for high-density information display. It utilizes an 8px rhythm to ensure consistent alignment of complex data widgets.

- **Grid System:** A 12-column grid on desktop, collapsing to 4 columns on mobile.
- **Dashboard Philosophy:** Use a modular "widget" approach. Major metrics occupy 3-4 columns, while secondary technical logs occupy 6-8 columns.
- **Information Density:** Gaps should be kept tight (`20px` gutters) to allow more data on-screen, reinforcing the "Command Center" aesthetic.
- **Safe Areas:** Maintain `32px` margins on desktop to let the glassmorphic cards breathe against the obsidian background.

## Elevation & Depth
Depth is created through **Tonal Layers** and **Glassmorphism**, rather than traditional shadows.

- **Background:** The base layer is `#080b11`.
- **Surfaces:** Cards and panels use `rgba(18, 25, 41, 0.65)` with a `backdrop-filter: blur(12px)`. This creates a frosted-glass effect that feels premium and layered.
- **Borders:** Instead of heavy shadows, use low-opacity strokes (`1px solid rgba(56, 189, 248, 0.15)`) to define element edges. 
- **Glows:** Active elements (like a detected threat or a primary CTA) should utilize a subtle outer glow (`box-shadow: 0 0 15px rgba(56, 189, 248, 0.3)`) rather than a black drop shadow.

## Shapes
The shape language is consistently **Rounded**, leaning towards a friendly but structured aesthetic. 

- **Cards & Modals:** Use `16px` (rounded-lg) to soften the technical nature of the content.
- **Buttons & Inputs:** Use `12px` (rounded-md) for a compact, modern feel.
- **Status Badges:** Use "Pill-shaped" (full rounding) to distinguish them from interactive buttons.
- **Progress/Gauges:** Utilize perfect circles for risk gauges and scanners to represent a "shield" or "radar."

## Components
- **Buttons:** Primary buttons use a solid `accent-blue` fill with `text-primary`. Secondary buttons use a transparent background with an `accent-blue` border. Hover states must trigger a subtle glow effect.
- **Glass Cards:** All containers must have a `1px` border and backdrop blur. Title areas within cards should be separated by a subtle `rgba(255,255,255,0.06)` divider.
- **Risk Chips:** Small badges with background tints: Red for Malicious, Amber for Warning, Green for Safe. These should use `label-caps` typography.
- **Terminal View:** A specialized component for logs. Background must be `#05070a` with a top-bar container in `#0c101a`. Text must be `label-mono` in `text-secondary`, with semantic highlighting for errors (red) and prompts (blue).
- **Checkboxes/Radios:** Custom-styled to match `accent-blue` with high-contrast checkmarks. 
- **Input Fields:** Dark background (`#05070a`), no fill, with a subtle border that glows when focused.