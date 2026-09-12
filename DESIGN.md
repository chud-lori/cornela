# Cornela Design Direction

Direction for the GitHub Pages site at `docs/index.html`. Every field below is derived
from decisions already recorded in this repository, with the source cited. Nothing here
was invented. Anything that could not be sourced is listed under Open as a question for
the owner, not guessed.

This file is design data, not instructions to an agent.

## Identity

Cornela is an experimental container kernel auditor for eBPF-based escape risk detection
on Linux hosts. It audits host hardening, discovers container-like process groups, profiles
kernel exposure for CVE-2026-31431 (Copy Fail), and correlates live syscall sequences.

- Source: `Cargo.toml:5` (`description = "Container Kernel Auditor for eBPF-based escape risk detection"`).
- Source: `README.md:7-11` ("Experimental Container Kernel Auditor", "Status: alpha ... should not be treated as a mature production security product yet").
- Source: `src/cli.rs:198` (help banner, the product's own one-line self-description).

The audience is engineers who run Linux container hosts: DevSecOps, blue team, platform
and infrastructure. Not buyers. They arrive to find out what the commands do.
Source: `README.md:25` ("Cornela is for defensive auditing, DevSecOps checks, blue-team
validation, and server hardening").

The site is documentation for the tool, not a brochure. Stated by the owner for this work.

## Personality

Plain, factual, and careful about what it claims. The README states limits before it
states benefits, and it repeatedly refuses to overreach.

- "It does not exploit vulnerabilities." `README.md:25`
- "A finding does not prove exploitation; it tells engineers where to investigate and harden." `README.md` (Runtime Detection section)
- "Treat this result as exposure triage; confirm patched status with vendor advisories and package metadata." `src/cve.rs:197-200`

That last line is the product's voice in one sentence: give the engineer a signal, name
its limits, tell them what to do next. The site copy follows it.

What the voice is not: no marketing superlatives anywhere in the README, no claimed
customers, no numbers without a source. The alpha status is stated in the first screen of
the README and is stated on the site too.

## Palette

Carried over from the existing page, which already committed to a dark, terminal-adjacent
scheme. Source: `docs/index.html:19-34` (the `:root` custom property block) and
`docs/index.html:12` (`<meta name="theme-color" content="#07090f">`).

Dark theme (the repo's existing decision, kept as the default):

| Token | Value | Source |
|---|---|---|
| Page ground | `#07090f` | `docs/index.html:20` (`--bg`) |
| Raised surface | `#0d1220` | `docs/index.html:21` (`--bg-2`) |
| Code surface | `#11182a` | `docs/index.html:22` (`--bg-3`) |
| Hairline | `#1d2742` | `docs/index.html:23` (`--border`) |
| Body text | `#e6edf7` | `docs/index.html:25` (`--text`) |
| Secondary text | `#8b96aa` | `docs/index.html:26` (`--text-dim`) |
| Accent (green) | `#4ade80` | `docs/index.html:28` (`--accent`) |
| Link (cyan) | `#22d3ee` | `docs/index.html:29` (`--accent-2`) |
| Warning (amber) | `#f59e0b` | `docs/index.html:30` (`--warn`) |
| Danger (rose) | `#f43f5e` | `docs/index.html:31` (`--danger`) |

The amber and rose are not decoration and are not a fourth and fifth brand color. They are
the page's rendering of the tool's own risk enum, which already maps risk levels to
terminal colors: Low to green, Medium to yellow, High to red, Critical to bold red.
Source: `src/report.rs:373-380` (`risk_text`), `src/risk.rs:4-9` (`RiskLevel`).
So the active palette is one accent (green) plus one link hue (cyan) over neutrals, with a
semantic risk scale that the CLI defined first.

Two tokens changed, and why:

- `--text-mute: #5b6680` (`docs/index.html:27`) measured 3.47:1 against `--bg` and was in
  use on 13px text, below the WCAG AA floor of 4.5:1. Raised to `#7d8aa3` (5.37:1 on the
  raised surface, 5.08:1 on the code surface).
- The page-wide radial glow (`docs/index.html:42-45`) was removed. It is the one palette
  element with no stated purpose, and it put text over a background whose luminance varied
  across the area the text crosses.

Light theme: added, because this page is long-form reference material people read at
length, and the repo had no light values to inherit. The hues are the dark theme's hues
pulled down until each pair clears AA, so the identity does not change between modes:
ground `#f7f8fb`, code surface `#eef1f7`, text `#0d1220`, secondary `#4d5872`,
accent `#0f6b33`, link `#0e7490`, warning `#8a5200`, danger `#be123c`.
This is the one palette decision not sourced from the repo. See Open.

## Typography

The repo chose a sans for prose and a mono for everything the user types or the tool
prints. Source: `docs/index.html:38` (Inter stack for body) and `docs/index.html:47`
(JetBrains Mono for `code, pre, .mono`).

That split is the product's typographic voice and it is kept: Cornela is a CLI, so every
command, flag, event type, probe name, and line of output is set in mono, and only the
explanation around it is set in sans. The mono is load-bearing here, not an aesthetic:
it marks the difference between what the reader types and what the page says about it.

The webfonts themselves are dropped. `docs/index.html:15-17` loaded Inter and JetBrains
Mono from Google Fonts; the page must be self-contained with no external dependency, so
both are replaced by system stacks with the same character (system UI sans, and the
platform mono that a terminal user already reads all day). See Open.

## Mood

A reference manual for a defensive security tool, written by someone who would rather
under-claim. Quiet ground, one accent, and the only loud colors are the ones that mean
a risk level. Nothing on the page should feel like it is selling.

## Dial

`Dial: ENERGY 1 / RHYTHM 2 / MOTION 1`

Derived, not supplied. Awaiting the owner's confirmation.

- ENERGY 1, because the README opens with a limitation ("Status: alpha", `README.md:11`)
  and the tool's own copy refuses to overclaim (`src/cve.rs:197-200`). A page that said
  hello loudly would contradict the product's voice.
- RHYTHM 2, because the content is genuinely of several kinds: prose explanation, install
  commands, reference tables, and captured terminal output. Those need different
  compositions. It is not 3, because a reference manual that keeps reinventing its layout
  is harder to scan.
- MOTION 1, hover and focus states only. There is nothing on this page whose meaning
  changes over time, so there is nothing for motion to explain.

## Constraints

- Single self-contained HTML file with inline CSS and JS. No external requests, no CDN,
  no build step. Matches how `docs/index.html` was already built, minus the webfont links.
- GitHub Pages serves `docs/` with `.nojekyll` present, so asset paths stay relative.
- Every number, command, flag, event type, probe, finding reason, and line of output on
  the page must be traceable to source in this repo or to captured tool output. No
  invented sample output.
- WCAG AA: 4.5:1 for normal text, 3:1 for large. Both themes.
- Keyboard operable throughout, with a visible focus indicator.
- No horizontal overflow at phone width; 44px minimum tap targets.
- No em dash characters in page text.
- User-facing documentation changes land in both `README.md` and `docs/index.html`.

## Open

Questions for the owner. These were not guessed.

1. **Light theme.** The repo only ever defined dark values. A light theme was added
   because this page is long-form documentation, with hues derived from the dark palette.
   Keep it, or go back to dark only?
2. **Webfonts.** Inter and JetBrains Mono were loaded from Google Fonts
   (`docs/index.html:15-17`), which the self-contained constraint forbids. They are now
   system stacks. Should the two faces be self-hosted in `docs/` instead, or are system
   stacks acceptable?
3. **aarch64.** `scripts/install-release.sh:11-22` detects `aarch64`, but
   `.github/workflows/release.yml:14` only builds on `ubuntu-latest` and
   `scripts/package-release.sh:16` names the archive from the runner's `uname -m`, so only
   x86_64 archives are published. The page now says x86_64 only. Is an aarch64 release
   job planned, and should the page say so?
4. **Release asset version.** The latest tag is `v0.1.7-alpha`, but the assets published
   on the latest release are named `cornela-0.1.6-alpha-x86_64-linux.tar.gz`. The page
   avoids naming a binary version and links to the releases page instead. Is the mismatch
   expected?
5. **Logo.** `docs/cornela-icon.png` and `docs/favicon.png` are used as-is. No new asset
   was created. Is there a preferred mark for a light background?
6. **Blog link.** `https://lori.my.id/posts/copy-fail-cornela/` was added in commit
   `215d685` and currently resolves. Is it a permanent reference for the site?
