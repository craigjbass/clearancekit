---
title: ClearanceKit Website De-AI Redesign
date: 2026-05-23
status: Approved
scope: docs/index.html, docs/documentation.html, docs/update.html
---

# ClearanceKit Website De-AI Redesign

## Goal

Replace the current ClearanceKit marketing site visual + voice with a pure terminal / brutalist aesthetic so that the site no longer reads as AI-generated SaaS-template output. All three pages in `docs/` are in scope.

The current site exhibits the standard AI-generated SaaS landing-page tells: gradient hero with radial glows, glass-blur fixed nav, eyebrow / title / subtitle triplet on every section, six-card feature grid with icons, big-number stats bar, "Stop X before Y" headline pattern, "Everything you need to..." section titles, em-dash-heavy benefit prose, Inter + JetBrains Mono web-font combo, purple brand palette. The replacement is a single-font monospace dark site whose entire visual vocabulary is "terminal output".

## Non-goals

- No new functional features.
- No information-architecture changes (all 8 landing-page sections remain, in the same order).
- No build-system introduction. Pages stay as self-contained HTML with embedded `<style>` blocks.
- No theme toggle. Single dark theme only.
- No animation. The only hover affordance for links is a colour change (link text to `--green`, or bracket characters around bracketed links to `--green`). No transitions, no transforms, no opacity fades.
- No replacement of the dropped marketing assets with new ones (no replacement screenshots, no new gif).
- Google Analytics `gtag` blocks are preserved unchanged on all three pages.

## Visual system

### Palette (single dark theme)

```
--bg:     #0a0a0a   (near-black)
--fg:     #e7e7e7   (off-white)
--dim:    #888888   (comments, metadata)
--faint:  #555555   (separators, secondary metadata)
--green:  #9fef00   (terminal accent: code, allow, prompt)
--red:    #ef4444   (deny)
--border: #222222
```

No light variant. No accent colour beyond green + red.

### Typography

- Single font stack: `ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace`.
- The Google Fonts `<link>` is removed from all three pages. No web fonts are loaded at all; the system monospace stack renders immediately and consistently on macOS/Windows/Linux without a network request.
- Font sizes: 11px (metadata), 12px (secondary), 13px (body), 15px (headings). No marketing-scale sizes (no 32px+, no `clamp()` fluid headlines).
- Line-height: 1.5 for body, 1.4 for ASCII diagrams.

### Layout

- Content column: max-width 80 characters (~720px at 13px font), left-aligned, page-centered.
- No fixed nav. Top nav is a plain text bar that scrolls with the page.
- No glass-blur, no radial gradients, no drop shadows, no `backdrop-filter`.
- No SVG / icon decorations.

### ASCII conventions

- Section headers rendered as `// section-name` — lowercase, dimmed (`--dim`), no bold.
- Box drawing for diagrams uses `┌─┐ │ │ └─┘ ▶ ↳`.
- Lists use `-` as the bullet character.
- Bracketed links substitute for marketing buttons: `[ download ]`, `[ docs ]`, `[ source ]`. Hover state: bracket characters change colour to `--green`.
- Inline metadata uses `key=value` pairs separated by two spaces, e.g. `clients=3  events=10  deps=0`.

## Shell

### Top nav (all three pages)

```
clearancekit  ·  home  ·  docs  ·  download  ·  source
```

Plain text, single line. Active page link is dimmed (not bold). No logo image. No CTA button.

### Footer (all three pages)

Single terminal-style block, e.g.:

```
// license: MIT    source: github.com/craigjbass/clearancekit    version: 0.x
```

## Landing page (`docs/index.html`)

All 8 current sections are kept in order. Each is restyled per the table below.

| # | Section | New treatment |
|---|---|---|
| 1 | Hero | ASCII title box (`┌─...─┐` framing `CLEARANCEKIT`), one declarative synopsis line, three bracketed links: `[ download ]` `[ docs ]` `[ source ]`. No `hero-badge`, no radial gradient. |
| 2 | Stats bar | One monospace line: `clients=3  events=10  deps=0  net=0  mdm=yes`. No big-number cards. |
| 3 | How it works | ASCII flow diagram (`process → opfilter → policy → ALLOW/DENY`), followed by 4 numbered prose lines. No numbered circles, no two-column grid. |
| 4 | Features | Bullet list, no card grid. Each item: `- code-signature policies` on one line, 1-2 lines of description below indented. No icons. |
| 5 | What's at risk | Definition-list style: path on its own line in `--green`, description below in `--fg`. No card chrome. |
| 6 | Why code signing | Two columns of monospace text — `path/hash MAC` on the left, `clearancekit` on the right. No table chrome, no decorative split. Below 768px viewport width the two columns stack vertically, left column first. |
| 7 | Installation | Numbered steps rendered as shell prompts: `$ open ClearanceKit.dmg`, `$ ...`. No step circles, no card grid. |
| 8 | Download CTA | Single block: `download: latest.dmg  source: github.com/craigjbass/clearancekit  license: MIT`. No giant CTA button. |

### Assets removed from the page

- `Screenshots/recording.gif`
- All `Screenshots/*.png` references
- The DEFCON YouTube thumbnail embed (kept as a single text link instead: `[ DEFCON talk on macOS Endpoint Security ]`)

### Hero headline (replacement copy)

Current: `Stop supply chain attacks before they read your secrets`

New: `Kernel-level file access control for macOS, bound to code-signing identity.`

## Documentation page (`docs/documentation.html`)

- Same shell, palette, type, and layout as the landing page.
- A TOC is rendered at the top of the page as bracketed jump links, e.g. `[ overview ]  [ setup ]  [ rules ]  [ jail ]  [ allowlist ]  [ mdm ]  [ mcp ]`.
- Wide reading column for prose, still capped at 80ch.
- Markdown-rendered tables collapse to aligned monospace text when they fit within 80ch; tables wider than 80ch keep table chrome but use the new palette (no purple borders).
- Code blocks are unchanged structurally; they pick up the new palette automatically (`--green` for prompt prefixes, `--fg` for code).
- The existing client-side markdown-to-HTML rendering logic (around line 891) is preserved.

## Update page (`docs/update.html`)

- Same shell, palette, type, layout.
- Functional content (version selector, response output area) is preserved. The version selector becomes a bracketed list of versions; selecting one renders the update path output below in terminal-output style.
- No marketing copy is added or kept.

## Copy rewrite principles (full voice rewrite)

Applied across all three pages where prose exists:

- Short declarative sentences, active voice, present tense.
- No benefit-statement framing. Drop all "Stop X before Y" / "Everything you need to" / "in under a minute" / "lock down your workstation" patterns.
- Drop all `section-eyebrow` micro-labels.
- Em-dashes are used only for clarification, never for dramatic emphasis. If a sentence's em-dash could be replaced with a period or a comma, replace it.
- Second-person ("you", "your") is rationed — describe behaviour rather than addressing the reader.
- `clearancekit` is rendered lowercase as a brand mark in body copy (matching existing usage in several places); the title is `ClearanceKit` (normal capitalisation) only.
- Section titles describe content factually: `Features`, not `Everything you need to lock down your workstation`. `Threat model`, not `What's at risk`. `Install`, not `Up and running in under a minute`.
- If a sentence could open a SaaS landing page, rewrite it.

## Tech approach

- Each of the three HTML files retains its own embedded `<style>` block. No external CSS file, no shared CSS link, no build system.
- A single canonical visual-system stylesheet (~150 lines) is pasted verbatim into each of the three `<style>` blocks. The same block of CSS lives in three places. This duplication is accepted to keep the deployment model unchanged (plain GitHub Pages, no Jekyll plugins, no preprocessor).
- The Google Fonts `<link>` is removed from all three pages.
- Google Analytics `gtag` script blocks are preserved verbatim on all three pages.
- No JavaScript changes are required beyond removing CSS hooks for animations that no longer exist.
- The existing `documentation.html` client-side markdown rendering remains.

## QA

- Visual QA in a browser at three widths: 375px (mobile), 768px (tablet), 1440px (desktop).
- Check all internal anchor links still resolve after section restructure.
- Check the page renders correctly with web fonts blocked (sanity-check the system monospace fallback).
- Check that the `wc -l` of each file does not balloon — the redesign should net to fewer lines of HTML per page than the current state, not more.

## Implementation order

1. Build the visual system as a single reference HTML page that exercises every component (nav, footer, headers, lists, bracketed links, ASCII diagram, two-column comparison, stats line, code block). This is the source of truth for the CSS that will be pasted into the three real pages.
2. Apply the redesign to `docs/index.html` (largest, highest-value change).
3. Apply the redesign to `docs/documentation.html`.
4. Apply the redesign to `docs/update.html`.
5. Manual visual QA at the three widths listed above.
6. Commit and push.

## Out-of-scope follow-ups (not in this change)

- A real `favicon.ico` matched to the new aesthetic.
- Open Graph / Twitter card images matched to the new aesthetic (the existing meta image references will be updated only if they 404; otherwise they stay until separately redesigned).
- A README.md restyle to match the website. The README lives in a different surface (GitHub) and has its own rendering constraints.
