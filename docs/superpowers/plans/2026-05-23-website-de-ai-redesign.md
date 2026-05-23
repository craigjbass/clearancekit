# Website De-AI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the visual style and copy voice of the three pages in `docs/` (the GitHub Pages marketing site) with a pure terminal/brutalist aesthetic so that the site no longer reads as AI-generated SaaS-template output.

**Architecture:** A single canonical CSS block (~150 lines) is defined once in a build-time-irrelevant reference page (`docs/_design-reference.html`) and then pasted verbatim into the `<style>` block of each of the three real pages (`index.html`, `documentation.html`, `update.html`). No build system is introduced. Each HTML page becomes self-contained. Google Fonts is dropped; only the system monospace stack is used. All marketing imagery (`Screenshots/recording.gif`, `Screenshots/*.png`) is removed from the site; the README is unaffected.

**Tech Stack:** Plain HTML5, plain CSS3, no JS framework. Existing client-side markdown renderer in `documentation.html` and version-check logic in `update.html` are preserved. Google Analytics gtag blocks preserved verbatim.

**Source spec:** `docs/superpowers/specs/2026-05-23-website-de-ai-redesign-design.md`

**Verification strategy:** HTML/CSS work has no unit-test framework. Each task's verification is **visual QA in a real browser** at three viewport widths (375px, 768px, 1440px), plus structural greps (`grep -c` for dropped patterns) to prove removal of AI-tell CSS and copy.

---

## File Structure

**Created:**
- `docs/_design-reference.html` — single-page exhibit of every component in the design system. Source of truth for the CSS block. Underscore prefix marks it as non-canonical (not linked from the site).

**Modified:**
- `docs/index.html` — full rebuild of body + `<style>` block. `<head>` metadata kept (analytics, viewport, description, site-verification). Google Fonts `<link>` removed.
- `docs/documentation.html` — full rebuild of body shell + `<style>` block. Existing client-side markdown rendering script preserved verbatim.
- `docs/update.html` — full rebuild of body shell + `<style>` block. Existing version-check script and DOM hooks preserved verbatim.

**Deleted (referenced files, not the files themselves):**
- `<img>` references to `Screenshots/recording.gif` and `Screenshots/*.png` in the three HTML files. The files in `Screenshots/` are kept (the README uses them).

---

## Task 1: Build the visual-system reference page

**Files:**
- Create: `docs/_design-reference.html`

The reference page exists to prove every component renders correctly before the CSS is pasted into the three real pages. The CSS block in this file becomes the canonical source — Tasks 2, 3, and 4 each paste it verbatim.

- [ ] **Step 1: Create `docs/_design-reference.html` with the full visual system and one example of every component**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ClearanceKit Design Reference</title>
  <style>
    /* ============================================================
       CLEARANCEKIT DESIGN SYSTEM — canonical CSS
       Pasted verbatim into index.html, documentation.html, update.html
       ============================================================ */

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:     #0a0a0a;
      --fg:     #e7e7e7;
      --dim:    #888888;
      --faint:  #555555;
      --green:  #9fef00;
      --red:    #ef4444;
      --border: #222222;
    }

    html, body {
      background: var(--bg);
      color: var(--fg);
      font-family: ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
      font-size: 13px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    .page {
      max-width: 720px;
      margin: 0 auto;
      padding: 24px 20px 80px;
    }

    /* nav */
    .nav {
      font-size: 12px;
      color: var(--dim);
      padding: 4px 0 32px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }
    .nav a {
      color: var(--fg);
      text-decoration: none;
    }
    .nav a:hover { color: var(--green); }
    .nav .sep { color: var(--faint); margin: 0 8px; }
    .nav a[aria-current="page"] { color: var(--dim); }

    /* section header */
    .sh {
      color: var(--dim);
      font-size: 12px;
      margin: 40px 0 14px;
    }

    /* document headings (used by documentation.html) */
    h1, h2, h3, h4 {
      color: var(--fg);
      font-weight: normal;
      margin: 32px 0 14px;
    }
    h1 { font-size: 18px; }
    h2 { font-size: 15px; }
    h3 { font-size: 13px; }
    h4 { font-size: 13px; }
    h2::before { content: "## "; color: var(--dim); }
    h3::before { content: "### "; color: var(--dim); }

    /* prose */
    p { margin: 0 0 14px; max-width: 80ch; }
    p.lead { color: var(--fg); font-size: 15px; margin-bottom: 24px; }
    p.dim { color: var(--dim); }

    /* links */
    a { color: var(--fg); text-decoration: underline; text-underline-offset: 3px; }
    a:hover { color: var(--green); }

    /* bracketed link */
    .blink {
      color: var(--fg);
      text-decoration: none;
      margin-right: 14px;
      display: inline-block;
    }
    .blink::before { content: "[ "; color: var(--dim); }
    .blink::after  { content: " ]"; color: var(--dim); }
    .blink:hover { color: var(--green); }
    .blink:hover::before, .blink:hover::after { color: var(--green); }

    /* ascii box / diagram */
    pre.ascii {
      color: var(--green);
      line-height: 1.4;
      margin: 0 0 18px;
      white-space: pre;
      overflow-x: auto;
    }
    pre.ascii.fg { color: var(--fg); }

    /* stats line */
    .stats {
      color: var(--fg);
      margin: 0 0 24px;
    }
    .stats .k { color: var(--dim); }

    /* numbered steps */
    ol.steps {
      list-style: none;
      counter-reset: step;
      margin: 0 0 18px;
    }
    ol.steps li {
      counter-increment: step;
      padding-left: 32px;
      position: relative;
      margin-bottom: 8px;
    }
    ol.steps li::before {
      content: counter(step) ".";
      position: absolute;
      left: 0;
      color: var(--dim);
    }

    /* bullet list */
    ul.bullets {
      list-style: none;
      margin: 0 0 18px;
    }
    ul.bullets > li {
      padding-left: 16px;
      position: relative;
      margin-bottom: 14px;
    }
    ul.bullets > li::before {
      content: "-";
      position: absolute;
      left: 0;
      color: var(--dim);
    }
    ul.bullets > li > .desc {
      color: var(--dim);
      display: block;
      margin-top: 2px;
    }

    /* definition list (paths + descriptions) */
    dl.paths { margin: 0 0 18px; }
    dl.paths dt {
      color: var(--green);
      margin-top: 14px;
    }
    dl.paths dt:first-child { margin-top: 0; }
    dl.paths dd {
      color: var(--dim);
      margin: 2px 0 0;
      padding-left: 16px;
    }

    /* two column comparison */
    .compare {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 32px;
      margin: 0 0 18px;
    }
    .compare h4 {
      color: var(--fg);
      font-size: 13px;
      font-weight: normal;
      margin: 0 0 10px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 6px;
    }
    .compare ul {
      list-style: none;
    }
    .compare li {
      padding-left: 16px;
      position: relative;
      margin-bottom: 6px;
      color: var(--dim);
    }
    .compare li::before {
      content: "-";
      position: absolute;
      left: 0;
      color: var(--faint);
    }
    @media (max-width: 768px) {
      .compare { grid-template-columns: 1fr; gap: 18px; }
    }

    /* shell-prompt block */
    pre.shell {
      color: var(--fg);
      background: transparent;
      margin: 0 0 14px;
      white-space: pre;
      overflow-x: auto;
    }
    pre.shell .p { color: var(--green); }
    pre.shell .c { color: var(--dim); }

    /* inline code */
    code {
      color: var(--green);
      background: transparent;
    }

    /* code blocks (markdown-rendered fenced blocks) */
    pre {
      background: transparent;
      border-left: 1px solid var(--border);
      padding: 0 0 0 14px;
      margin: 0 0 14px;
      overflow-x: auto;
      color: var(--fg);
    }
    pre code { color: inherit; }

    /* tables (used by documentation.html for managed-policy schemas) */
    table {
      border-collapse: collapse;
      margin: 0 0 18px;
      font-size: 13px;
      width: 100%;
    }
    th, td {
      text-align: left;
      padding: 6px 14px 6px 0;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      color: var(--fg);
    }
    th { color: var(--dim); font-weight: normal; }

    /* footer */
    .foot {
      color: var(--dim);
      font-size: 12px;
      padding: 32px 0 0;
      border-top: 1px solid var(--border);
      margin-top: 48px;
    }
    .foot .sep { color: var(--faint); margin: 0 8px; }

    /* toc (documentation only) */
    .toc {
      margin: 0 0 32px;
      color: var(--dim);
      line-height: 1.8;
    }
  </style>
</head>
<body>
  <div class="page">

    <div class="nav">
      <a href="index.html">clearancekit</a><span class="sep">·</span><a href="index.html">home</a><span class="sep">·</span><a href="documentation.html">docs</a><span class="sep">·</span><a href="#">download</a><span class="sep">·</span><a href="https://github.com/craigjbass/clearancekit">source</a>
    </div>

    <div class="sh">// hero</div>
<pre class="ascii">┌───────────────────────────────────────┐
│  CLEARANCEKIT                         │
│  process → kernel → file_system       │
└───────────────────────────────────────┘</pre>
    <p class="lead">Kernel-level file access control for macOS, bound to code-signing identity.</p>
    <p>
      <a class="blink" href="#">download</a>
      <a class="blink" href="documentation.html">docs</a>
      <a class="blink" href="https://github.com/craigjbass/clearancekit">source</a>
    </p>

    <div class="sh">// stats</div>
    <p class="stats">
      <span class="k">clients=</span>3
      <span class="k">  events=</span>10
      <span class="k">  deps=</span>0
      <span class="k">  net=</span>0
      <span class="k">  mdm=</span>yes
    </p>

    <div class="sh">// how it works</div>
<pre class="ascii">┌──────────┐    AUTH_OPEN     ┌─────────┐
│  process │ ───────────────▶ │ opfilter│
└──────────┘                  └────┬────┘
                                   │ check signature
                                   ▼
                              ┌─────────┐
                              │  policy │ → ALLOW / DENY
                              └─────────┘</pre>
    <ol class="steps">
      <li>A process attempts <code>open()</code>, <code>rename()</code>, <code>unlink()</code>, or another file-system syscall.</li>
      <li>The kernel forwards the request to opfilter as an Endpoint Security <code>AUTH</code> event.</li>
      <li>opfilter looks up the calling process's signing identity and matches it against the policy.</li>
      <li>opfilter responds <code>ALLOW</code> or <code>DENY</code> before the syscall returns.</li>
    </ol>

    <div class="sh">// features</div>
    <ul class="bullets">
      <li>code-signature policies
        <span class="desc">Rules match the Team ID and Signing ID embedded in the calling binary, not its path or hash.</span>
      </li>
      <li>jail rules
        <span class="desc">Confine specific processes to an explicit set of allowed path prefixes. Inherited by child processes.</span>
      </li>
      <li>process ancestry
        <span class="desc">Rules can require that the access is happening on behalf of a trusted parent process, not just the immediate caller.</span>
      </li>
    </ul>

    <div class="sh">// what is at risk</div>
    <dl class="paths">
      <dt>~/.ssh/id_*</dt>
      <dd>Unprotected SSH private keys, usable for lateral movement to servers and cloud environments.</dd>
      <dt>~/.aws/credentials</dt>
      <dd>Plaintext AWS access keys.</dd>
      <dt>~/Library/Cookies/Cookies.binarycookies</dt>
      <dd>Safari cookies, readable by any same-user process.</dd>
    </dl>

    <div class="sh">// why code signing</div>
    <div class="compare">
      <div>
        <h4>path / hash MAC</h4>
        <ul>
          <li>Trusts whatever binary sits at the expected path.</li>
          <li>A trojanised binary at that path inherits the policy.</li>
          <li>Every software update invalidates the hash.</li>
        </ul>
      </div>
      <div>
        <h4>clearancekit</h4>
        <ul>
          <li>Trusts the kernel-verified signing identity of the binary.</li>
          <li>A trojanised binary carries a different signature and is denied.</li>
          <li>Policies stay valid across all future updates from the same signer.</li>
        </ul>
      </div>
    </div>

    <div class="sh">// install</div>
<pre class="shell"><span class="c"># download the latest dmg from the releases page, then:</span>
<span class="p">$</span> open ~/Downloads/ClearanceKit.dmg
<span class="p">$</span> cp -R /Volumes/ClearanceKit/ClearanceKit.app /Applications
<span class="p">$</span> open /Applications/ClearanceKit.app
<span class="c"># grant Full Disk Access when prompted, then activate the system extension</span></pre>

    <div class="sh">// download</div>
    <p>
      <span class="k" style="color:var(--dim)">download:</span> <a href="#">latest.dmg</a>
      <span class="sep" style="color:var(--faint);margin:0 8px;">·</span>
      <span class="k" style="color:var(--dim)">source:</span> <a href="https://github.com/craigjbass/clearancekit">github.com/craigjbass/clearancekit</a>
      <span class="sep" style="color:var(--faint);margin:0 8px;">·</span>
      <span class="k" style="color:var(--dim)">license:</span> MIT
    </p>

    <div class="foot">
      <span class="k" style="color:var(--dim)">// license:</span> MIT
      <span class="sep">·</span>
      <span class="k" style="color:var(--dim)">source:</span> <a href="https://github.com/craigjbass/clearancekit">github.com/craigjbass/clearancekit</a>
      <span class="sep">·</span>
      <span class="k" style="color:var(--dim)">version:</span> 0.x
    </div>

  </div>
</body>
</html>
```

- [ ] **Step 2: Open the reference page in a browser**

Run: `open docs/_design-reference.html`
Expected: A single dark page renders. Green ASCII boxes draw correctly. Bracketed `[ download ]` links visible. No web font request in the Network tab. No purple anywhere.

- [ ] **Step 3: Visually check at three widths**

Resize the browser window (or use devtools device toolbar) to 375px, 768px, 1440px. Confirm:
- Content column stays readable at every width.
- The `.compare` two-column section stacks to single column below 768px.
- ASCII `<pre>` blocks may horizontally scroll on 375px — that is acceptable.
- No layout breaks.

- [ ] **Step 4: Commit the reference page**

```bash
git add docs/_design-reference.html
git commit -m "design: add visual-system reference page for site redesign"
```

---

## Task 2: Rebuild `docs/index.html`

**Files:**
- Modify: `docs/index.html` (full body replacement, head metadata + analytics preserved)

The rebuild replaces the entire `<body>` and the entire `<style>` block. The `<head>` keeps: charset, viewport, description meta, google-site-verification, title, and the gtag block. The Google Fonts `<link>` is removed. The body is rewritten to the 8 sections defined in the spec.

- [ ] **Step 1: Read current `<head>` to capture preserved metadata**

Run: `sed -n '1,20p' docs/index.html`
Note the gtag script, meta description, and google-site-verification meta. These survive verbatim.

- [ ] **Step 2: Rewrite `docs/index.html` end-to-end**

Replace the file with the structure below. Use the canonical CSS block from `docs/_design-reference.html` verbatim (the `<style>` content between the comments).

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <!-- Google tag (gtag.js) -->
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-F0WEQYXKXN"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'G-F0WEQYXKXN');
  </script>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="description" content="ClearanceKit — macOS kernel-level file access control bound to code-signing identity. Protects SSH keys, credentials, and sensitive data from supply chain attacks." />
  <meta name="google-site-verification" content="S7pD4dvsyath-wtJ7xBcdCfvUPg-L6mMvQWiziWC05w" />
  <title>ClearanceKit — kernel-level file access control for macOS</title>
  <style>
    /* PASTE THE ENTIRE CANONICAL CSS BLOCK FROM docs/_design-reference.html HERE */
  </style>
</head>
<body>
  <div class="page">

    <div class="nav">
      <a href="index.html">clearancekit</a><span class="sep">·</span><a href="index.html" aria-current="page">home</a><span class="sep">·</span><a href="documentation.html">docs</a><span class="sep">·</span><a href="#download">download</a><span class="sep">·</span><a href="https://github.com/craigjbass/clearancekit">source</a>
    </div>

    <!-- HERO -->
    <div class="sh">// clearancekit</div>
<pre class="ascii">┌───────────────────────────────────────┐
│  CLEARANCEKIT                         │
│  process → kernel → file_system       │
└───────────────────────────────────────┘</pre>
    <p class="lead">Kernel-level file access control for macOS, bound to code-signing identity.</p>
    <p>
      <a class="blink" href="#download">download</a>
      <a class="blink" href="documentation.html">docs</a>
      <a class="blink" href="https://github.com/craigjbass/clearancekit">source</a>
    </p>

    <!-- STATS -->
    <div class="sh">// stats</div>
    <p class="stats">
      <span class="k">clients=</span>3
      <span class="k">  events=</span>10
      <span class="k">  deps=</span>0
      <span class="k">  net=</span>0
      <span class="k">  mdm=</span>yes
    </p>

    <!-- HOW IT WORKS -->
    <div class="sh">// how it works</div>
<pre class="ascii">┌──────────┐    AUTH_OPEN     ┌─────────┐
│  process │ ───────────────▶ │ opfilter│
└──────────┘                  └────┬────┘
                                   │ check signature
                                   ▼
                              ┌─────────┐
                              │  policy │ → ALLOW / DENY
                              └─────────┘</pre>
    <ol class="steps">
      <li>A process attempts <code>open()</code>, <code>rename()</code>, <code>unlink()</code>, or another file-system syscall.</li>
      <li>The kernel forwards the request to opfilter as an Endpoint Security <code>AUTH</code> event.</li>
      <li>opfilter looks up the calling process's signing identity and matches it against the policy.</li>
      <li>opfilter responds <code>ALLOW</code> or <code>DENY</code> before the syscall returns.</li>
    </ol>

    <!-- FEATURES -->
    <div class="sh">// features</div>
    <ul class="bullets">
      <li>code-signature policies
        <span class="desc">Rules match the Team ID and Signing ID embedded in the calling binary, not its path or hash. Survive software updates without maintenance.</span>
      </li>
      <li>jail rules
        <span class="desc">Confine specific processes to an explicit set of allowed path prefixes. Inherited by child processes.</span>
      </li>
      <li>process ancestry
        <span class="desc">Rules can require the access is happening on behalf of a trusted parent process, not just the immediate caller.</span>
      </li>
      <li>native SwiftUI interface
        <span class="desc">Review denied events, build policy as you work, see a live throughput graph. No config files required.</span>
      </li>
      <li>MDM fleet management
        <span class="desc">Policy, allowlist, and jail rules deliver via standard Apple Configuration Profile payloads. No external server.</span>
      </li>
      <li>zero network calls, zero third-party dependencies
        <span class="desc">Built entirely on Apple's own frameworks. No telemetry. No auto-update. Nothing to audit beyond Apple's own toolchain.</span>
      </li>
    </ul>

    <!-- WHAT IS AT RISK -->
    <div class="sh">// what an unconstrained process can reach</div>
    <p class="dim">A single <code>postinstall</code> script in a compromised package runs with full user-level access. Without per-process policy, it can read:</p>
    <dl class="paths">
      <dt>~/.ssh/id_*</dt>
      <dd>SSH private keys, usable for lateral movement to servers and cloud environments.</dd>
      <dt>~/.aws/credentials, ~/.config/gcloud/, ~/.azure/</dt>
      <dd>Plaintext cloud credentials and tokens.</dd>
      <dt>~/.git-credentials, ~/.netrc</dt>
      <dd>Silent access to every private repository your account can reach.</dd>
      <dt>~/.gnupg/private-keys-v1.d/</dt>
      <dd>GPG private keys, copyable for offline passphrase cracking.</dd>
      <dt>~/Library/Cookies/Cookies.binarycookies</dt>
      <dd>Safari session cookies.</dd>
      <dt>~/Library/Messages/</dt>
      <dd>iMessage history and attachments.</dd>
      <dt>~/Library/Group Containers/group.com.apple.notes/</dt>
      <dd>Unlocked Apple Notes (CoreData SQLite, readable on disk).</dd>
      <dt>~/Library/Application Support/Signal/attachments.noindex/</dt>
      <dd>Signal Desktop attachments.</dd>
    </dl>

    <!-- WHY CODE SIGNING -->
    <div class="sh">// why code signing, not paths or hashes</div>
    <div class="compare">
      <div>
        <h4>path / hash MAC</h4>
        <ul>
          <li>Trusts whatever binary sits at the expected path.</li>
          <li>A trojanised binary at that path inherits the policy.</li>
          <li>A vulnerability in an allowed process inherits the policy.</li>
          <li>Every software update invalidates the hash.</li>
          <li>Active development machines need constant policy maintenance.</li>
        </ul>
      </div>
      <div>
        <h4>clearancekit</h4>
        <ul>
          <li>Trusts the kernel-verified signing identity of the binary.</li>
          <li>A trojanised binary carries a different signature and is denied.</li>
          <li>A dylib injection changes the loaded code's signature mix and fails the check.</li>
          <li>Policies stay valid across all future updates from the same signer.</li>
          <li>Policy revisions happen only when you change which software you trust.</li>
        </ul>
      </div>
    </div>

    <!-- INSTALL -->
    <div class="sh">// install</div>
<pre class="shell"><span class="c"># download the latest dmg from the releases page, then:</span>
<span class="p">$</span> open ~/Downloads/ClearanceKit.dmg
<span class="p">$</span> cp -R /Volumes/ClearanceKit/ClearanceKit.app /Applications
<span class="p">$</span> open /Applications/ClearanceKit.app
<span class="c"># grant Full Disk Access when prompted, then activate the system extension</span></pre>
    <p class="dim">No auto-update. Check the releases page for new versions.</p>

    <!-- DOWNLOAD -->
    <div class="sh" id="download">// download</div>
    <p>
      <span style="color:var(--dim)">download:</span> <a href="https://github.com/craigjbass/clearancekit/releases/latest">latest.dmg</a>
      <span class="sep" style="color:var(--faint);margin:0 8px;">·</span>
      <span style="color:var(--dim)">source:</span> <a href="https://github.com/craigjbass/clearancekit">github.com/craigjbass/clearancekit</a>
      <span class="sep" style="color:var(--faint);margin:0 8px;">·</span>
      <span style="color:var(--dim)">license:</span> MIT
    </p>
    <p class="dim">[ <a href="https://www.youtube.com/watch?v=AgYGwZjcsLo">DEFCON talk on macOS Endpoint Security</a> ]</p>

    <div class="foot">
      <span style="color:var(--dim)">// license:</span> MIT
      <span class="sep">·</span>
      <span style="color:var(--dim)">source:</span> <a href="https://github.com/craigjbass/clearancekit">github.com/craigjbass/clearancekit</a>
    </div>

  </div>
</body>
</html>
```

When pasting the canonical CSS, replace the `/* PASTE THE ENTIRE CANONICAL CSS BLOCK… */` line with the exact CSS content from `docs/_design-reference.html` between the `*, *::before...` line and the closing `</style>` tag. Do not modify it.

- [ ] **Step 3: Open the rebuilt page in a browser at 1440px**

Run: `open docs/index.html`
Expected: Dark page renders top to bottom with all 8 sections visible (hero, stats, how it works, features, what is at risk, why code signing, install, download). No purple. No web font request in devtools Network tab.

- [ ] **Step 4: Check the page at 768px (tablet)**

In devtools, set viewport to 768px wide.
Expected: All sections still readable. The `.compare` section may still be two columns at 768px (the breakpoint is `max-width: 768px`, exclusive). Below 768px it stacks.

- [ ] **Step 5: Check the page at 375px (mobile)**

In devtools, set viewport to 375px wide.
Expected: All sections render as a single column. ASCII `<pre>` blocks may horizontally scroll within their own container; the page itself does not scroll horizontally. The `.compare` columns stack vertically, `path / hash MAC` on top.

- [ ] **Step 6: Confirm AI-tell CSS classes are gone**

Run: `grep -cE "section-eyebrow|hero-badge|btn-primary|btn-secondary|stat-number|stat-label|feature-card|feature-icon|threat-item|comparison-card|comparison-grid|download-card|steps-list" docs/index.html`
Expected output: `0`

Run: `grep -cE "fonts\.googleapis\.com|Inter:wght" docs/index.html`
Expected output: `0`

Run: `grep -cE "Stop supply chain attacks|Everything you need to|Up and running in under a minute|section-eyebrow" docs/index.html`
Expected output: `0`

- [ ] **Step 7: Confirm dropped imagery is no longer referenced**

Run: `grep -cE "recording\.gif|Screenshots/" docs/index.html`
Expected output: `0`

- [ ] **Step 8: Confirm gtag and site-verification are still present**

Run: `grep -cE "googletagmanager\.com|google-site-verification" docs/index.html`
Expected output: `2`

- [ ] **Step 9: Commit**

```bash
git add docs/index.html
git commit -m "redesign: rebuild index.html in terminal aesthetic

Drops the gradient hero, big-number stats bar, six-card feature grid,
comparison card chrome, and download CTA card. Drops recording.gif
and screenshot imagery references (files in Screenshots/ kept for
README). Drops the Google Fonts link and the purple SaaS palette
entirely. Rewrites all copy in declarative man-page voice.

Information architecture preserved: hero, stats, how-it-works,
features, threat list, code-signing rationale, install, download —
in that order, restyled as terminal output."
```

---

## Task 3: Rebuild `docs/documentation.html`

**Files:**
- Modify: `docs/documentation.html` (full shell + style replacement; markdown-rendering script preserved)

The documentation page is reference content, not marketing. Body uses the same shell and palette, plus a TOC of bracketed jump links at the top. The 23 H2 sections render with the new headings and prose styles. Tables fit on desktop and survive on mobile. Code blocks pick up the palette automatically. The client-side markdown-rendering script around line 891 is preserved verbatim.

- [ ] **Step 1: Inspect the current `documentation.html` to identify what survives the rewrite**

Run: `sed -n '1,20p' docs/documentation.html` — confirm head metadata to preserve (analytics, viewport, description, site-verification, title).

Run: `sed -n '440,1095p' docs/documentation.html | head -30` — confirm the body H1, the first few H2 sections, and where the markdown rendering script begins.

Run: `awk '/^<script/{flag=1} flag{print} /<\/script>/{if(flag){flag=0; exit}}' docs/documentation.html | tail -20` — locate the closing `</script>` of the renderer.

Capture the full markdown-rendering script verbatim — it survives.

- [ ] **Step 2: Rewrite `docs/documentation.html`**

Replace the file. Keep the gtag block, the meta tags, the markdown-rendering `<script>` block (the one containing `flushList`, `flushTable`, `inline`, around line 891), and the existing H2 IDs (so external anchor links keep working).

Skeleton:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <!-- Google tag (gtag.js) -->
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-F0WEQYXKXN"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'G-F0WEQYXKXN');
  </script>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="description" content="ClearanceKit documentation — setup, policy rules, jail rules, allowlist, signatures, ancestry, MDM deployment." />
  <title>Documentation — ClearanceKit</title>
  <style>
    /* PASTE THE ENTIRE CANONICAL CSS BLOCK FROM docs/_design-reference.html HERE */
    /* (no additions, no overrides) */
  </style>
</head>
<body>
  <div class="page">

    <div class="nav">
      <a href="index.html">clearancekit</a><span class="sep">·</span><a href="index.html">home</a><span class="sep">·</span><a href="documentation.html" aria-current="page">docs</a><span class="sep">·</span><a href="https://github.com/craigjbass/clearancekit/releases/latest">download</a><span class="sep">·</span><a href="https://github.com/craigjbass/clearancekit">source</a>
    </div>

    <div class="sh">// documentation</div>

    <div class="toc">
      [ <a href="#setup">setup</a> ]
      [ <a href="#typical-workflow">workflow</a> ]
      [ <a href="#events">events</a> ]
      [ <a href="#processes">processes</a> ]
      [ <a href="#process-tree">process tree</a> ]
      [ <a href="#metrics">metrics</a> ]
      [ <a href="#policy-rules">policy rules</a> ]
      [ <a href="#app-protections">app protections</a> ]
      [ <a href="#built-in-presets">presets</a> ]
      [ <a href="#jail-rules">jail rules</a> ]
      [ <a href="#allowlist">allowlist</a> ]
      [ <a href="#wildcards">wildcards</a> ]
      [ <a href="#signatures">signatures</a> ]
      [ <a href="#process-ancestry">ancestry</a> ]
      [ <a href="#policy-evaluation">evaluation order</a> ]
      [ <a href="#touch-id">touch id</a> ]
      [ <a href="#mdm">mdm</a> ]
      [ <a href="#export">export</a> ]
      [ <a href="#mcp">mcp</a> ]
    </div>

    <!-- PASTE THE EXISTING <h2 id="setup"> ... </h2><p>...</p> CONTENT VERBATIM
         from the current docs/documentation.html, lines ~441 to the line just
         before the closing </footer>. Drop the existing <h1>Documentation</h1>.
         Drop the existing <footer> markup; the new .foot at the bottom
         replaces it. Drop any inline class attributes that reference the old
         design (e.g. class="anchor"). Keep H2 IDs verbatim so external links
         continue to resolve. -->

    <div class="foot">
      <span style="color:var(--dim)">// license:</span> MIT
      <span class="sep">·</span>
      <span style="color:var(--dim)">source:</span> <a href="https://github.com/craigjbass/clearancekit">github.com/craigjbass/clearancekit</a>
    </div>

  </div>

  <!-- PASTE THE EXISTING MARKDOWN-RENDERING <script> BLOCK VERBATIM
       (the one containing flushList / flushTable / inline, around line 891
       in the current docs/documentation.html). It survives unmodified. -->
</body>
</html>
```

- [ ] **Step 3: Strip any inline copy that reads as SaaS-template**

Within the prose content you pasted, scan for and remove or soften:

```bash
grep -nE "Everything you need|in under a minute|Stop [A-Z]|world-class|industry-leading|simply|effortless|seamless" docs/documentation.html
```

Expected after fixes: `(no output)`. If any match exists, rewrite that line declaratively.

- [ ] **Step 4: Open the page in a browser at 1440px and walk every H2**

Run: `open docs/documentation.html`
Expected: TOC renders as bracketed links. Each `<h2>` renders prefixed by a dim `## ` (from the `h2::before` rule in the canonical CSS). Code blocks render with the left border accent. Tables render with subtle borders only.

- [ ] **Step 5: Check at 768px and 375px**

Confirm tables horizontally scroll within their container (not the page). Confirm the TOC wraps gracefully.

- [ ] **Step 6: Confirm AI-tell removal**

Run: `grep -cE "section-eyebrow|hero-badge|btn-primary|feature-card|comparison-card|fonts\.googleapis\.com" docs/documentation.html`
Expected output: `0`

- [ ] **Step 7: Confirm anchor links still work**

Run: `grep -cE 'id="setup"|id="jail-rules"|id="mdm"|id="allowlist"' docs/documentation.html`
Expected output: `4`

- [ ] **Step 8: Commit**

```bash
git add docs/documentation.html docs/_design-reference.html
git commit -m "redesign: rebuild documentation.html in terminal aesthetic

Same shell as index.html. Adds a bracketed-link TOC at the top.
H2 IDs preserved for stable anchor links. Existing client-side
markdown renderer unchanged. Tables, lists, and code blocks pick
up the dark palette automatically."
```

---

## Task 4: Rebuild `docs/update.html`

**Files:**
- Modify: `docs/update.html` (full shell + style replacement; version-check script preserved)

The update page is the in-app "check for new version" landing target. It has interactive version selection logic in JS. The body shell adopts the canonical CSS; the interactive widget restyles to the new palette but keeps its DOM IDs and event hooks.

- [ ] **Step 1: Inventory what the JS depends on**

Run: `grep -nE "getElementById|querySelector|addEventListener|onclick" docs/update.html | head -30`

Note every DOM ID and class referenced from JS. These survive the rewrite verbatim.

- [ ] **Step 2: Rewrite `docs/update.html`**

Replace the file. Keep the gtag block, all preserved metadata, the entire `<script>` block, and every DOM hook the script references.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <!-- Google tag (gtag.js) -->
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-F0WEQYXKXN"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'G-F0WEQYXKXN');
  </script>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ClearanceKit — update check</title>
  <style>
    /* PASTE THE ENTIRE CANONICAL CSS BLOCK FROM docs/_design-reference.html HERE */
  </style>
</head>
<body>
  <div class="page">

    <div class="nav">
      <a href="index.html">clearancekit</a><span class="sep">·</span><a href="index.html">home</a><span class="sep">·</span><a href="documentation.html">docs</a><span class="sep">·</span><a href="https://github.com/craigjbass/clearancekit/releases/latest">download</a><span class="sep">·</span><a href="https://github.com/craigjbass/clearancekit">source</a>
    </div>

    <div class="sh">// update check</div>

    <!-- PASTE THE EXISTING INTERACTIVE BODY CONTENT VERBATIM,
         preserving every id, class, and data-* attribute the script
         references. Wrap the existing <h2>Which version are you running?</h2>
         and its sibling content in the .page div above. Drop any class
         attributes that reference the old design (e.g. card, btn-primary,
         badge); replace them with the new utility classes (.blink for
         buttons, .ascii for diagrams) only where it does not break a JS
         hook. If a JS hook depends on a class name, keep that class name
         and let the canonical CSS provide a sensible default for it via
         the cascade (the canonical CSS does not define those names, so
         the element renders as default body text — which is correct). -->

    <div class="foot">
      <span style="color:var(--dim)">// license:</span> MIT
      <span class="sep">·</span>
      <span style="color:var(--dim)">source:</span> <a href="https://github.com/craigjbass/clearancekit">github.com/craigjbass/clearancekit</a>
    </div>

  </div>

  <!-- PASTE THE EXISTING <script> BLOCK VERBATIM
       (the version-check logic). It survives unmodified. -->
</body>
</html>
```

- [ ] **Step 3: Open the page in a browser and walk the interaction**

Run: `open docs/update.html`
Expected: The version selector renders, accepts input, and the existing JS still updates the output area. The output area renders in monospace dark style.

If the output area looked good against the purple theme but unreadable on dark, add a single rule to the canonical CSS that targets the output container (find the actual ID/class from Step 1):

```css
/* example — replace #version-output with the actual selector */
#version-output { color: var(--fg); }
#version-output pre { color: var(--fg); border-left: 1px solid var(--border); padding-left: 14px; }
```

Add this to `docs/_design-reference.html` first, then re-paste into all three files for consistency.

- [ ] **Step 4: Confirm AI-tell removal**

Run: `grep -cE "fonts\.googleapis\.com|Inter:wght|7c3aed|btn-primary" docs/update.html`
Expected output: `0`

- [ ] **Step 5: Commit**

```bash
git add docs/update.html docs/_design-reference.html
git commit -m "redesign: rebuild update.html in terminal aesthetic

Version-check JS and all DOM hooks preserved. Shell and palette
match index.html and documentation.html."
```

---

## Task 5: Final QA pass and push

**Files:**
- No file changes. Verification only.

- [ ] **Step 1: Open all three pages side by side**

```bash
open docs/index.html docs/documentation.html docs/update.html
```

Confirm visual consistency across all three: same nav, same footer, same palette, same font, same spacing.

- [ ] **Step 2: Run a final sweep for AI-tell residue across all three files**

```bash
grep -cnE "fonts\.googleapis\.com|Inter:wght|7c3aed|6d28d9|var\(--accent\)|hero-badge|btn-primary|btn-secondary|section-eyebrow|stat-number|stat-label|feature-card|feature-icon|threat-item|comparison-card|download-card|recording\.gif|Stop supply chain attacks|Everything you need to" docs/index.html docs/documentation.html docs/update.html
```

Expected output: every file reports `0` matches.

- [ ] **Step 3: Confirm the CSS block is byte-identical across all three real pages**

```bash
diff <(awk '/<style>/{f=1;next} /<\/style>/{f=0} f' docs/index.html) \
     <(awk '/<style>/{f=1;next} /<\/style>/{f=0} f' docs/documentation.html)
diff <(awk '/<style>/{f=1;next} /<\/style>/{f=0} f' docs/index.html) \
     <(awk '/<style>/{f=1;next} /<\/style>/{f=0} f' docs/update.html)
```

Expected output: no differences. If they diverge, re-paste the canonical block from `docs/_design-reference.html` into the divergent file.

- [ ] **Step 4: Network-tab check — no third-party requests except analytics**

In a browser devtools Network tab, hard-reload each of the three pages. The only third-party requests should be the gtag scripts (`googletagmanager.com`, `google-analytics.com`). No `fonts.googleapis.com`. No `fonts.gstatic.com`.

- [ ] **Step 5: Mobile-width sanity check**

Devtools set to 375px wide on each page. Confirm: no horizontal page scroll, ASCII diagrams may scroll inside their `<pre>` container only, comparison columns stack vertically, TOC wraps gracefully.

- [ ] **Step 6: Push**

```bash
git push
```

---

## Out-of-scope follow-ups (do not implement in this plan)

- Favicon matched to the new aesthetic.
- Open Graph / Twitter card images matched to the new aesthetic.
- README.md restyle to match the website.
- A light-theme variant.
