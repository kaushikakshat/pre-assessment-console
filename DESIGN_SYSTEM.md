# Pre-Assessment Console — Design Pattern Library & UI Rules

> **For Claude Code.** This file is the source of truth for every user interface in the Internal Web & API Security Pre-Assessment Platform. Read it in full before creating or changing any screen, component, copy or style. Reference it from `CLAUDE.md` (for example: `See docs/DESIGN_SYSTEM.md for all UI work`).
>
> - **MUST / MUST NOT** are hard rules. Code that breaks one is a defect.
> - **SHOULD** is the default; deviate only with a written reason in the PR.
> - **Precedence:** Product decisions (§1.2) → this file → PRD and other project documents → your own judgement. If this file conflicts with a project document, follow this file and mention the conflict in the PR.
> - Never invent requirements, roles, states, permissions or copy that this file does not define. If something is undefined, use a `TBD` marker (§6.32) and list it in the PR.
>
> Version 1.0 · 02 Nov 2026 · Derived from the approved clickable prototype (Owner + Admin).

---

## Contents

1. Product context and non-negotiables
2. Information architecture and navigation
3. Design tokens
4. Iconography
5. Status vocabularies
6. Component library
7. Interaction patterns
8. Content and copy rules
9. Accessibility rules
10. Responsive rules
11. Roles, permissions and UI enforcement
12. Data contracts (enums and shapes the UI relies on)
13. Review checklist
14. Open decisions

---

## 1. Product context and non-negotiables

### 1.1 What the product is

An internal, authenticated web application for about 30 admin-provisioned users. Users validate a target (website or API), run bounded non-destructive scans (Quick Scan, Pre-Assessment, Deep Scan or individual modules), triage findings, retest fixes, share results read-only and generate reports. Administrators govern users, policies, capacity, approvals, health, audit and emergency controls.

**It is a pre-assessment aid. It is NOT a penetration test, statutory certificate or security clearance.** The UI must never imply otherwise.

### 1.2 Product decisions (override project documents)

| ID | Decision |
|---|---|
| PD-1 | **Two roles only:** Assessment Owner and Platform Administrator. There are no Collaborator, Reviewer or Auditor roles or screens. |
| PD-2 | **Sharing is view-only, whole assessment.** An owner can share an assessment with any active user (owners and admins). The recipient sees the whole assessment read-only under **Shared reports**: overview, findings with redacted evidence, modules, scan history, reports (preview and PDF). No comments, no state changes. |
| PD-3 | **Only the initiator retests.** Retests can be requested only by the owner who ran the scans. Share recipients and administrators cannot retest someone else's assessment. |
| PD-4 | **Owner decides findings directly.** Acknowledge, under review, false positive, accepted risk, reopen — no second approval. Reasons are required for false positive, accepted risk and reopen. A retest that no longer observes a finding marks it Resolved automatically. |
| PD-5 | **Policy versions publish without a separate approval.** Lifecycle: draft → validate → dry run → publish → monitor → rollback, all by an administrator. |
| PD-6 | **Administrators** approve approval-required targets, review interrupted jobs and set job priority. Administrators can also test websites themselves and may **self-approve** their own targets with a mandatory reason that is flagged in the audit log. |
| PD-7 | **No authorization reference and no validity period** on assessments. The user confirms authorization with a checkbox before each scan and each retest. Target validation is unchanged. |
| — | **One MFA prompt per sign-in** for every role. No second "step-up" code for the admin console. |

### 1.3 Non-negotiables (MUST)

1. **No scan traffic before validation returns Allowed** (or an administrator approves an approval-required target). The UI must never offer "Submit scan" otherwise.
2. **Never show a false success.** An interrupted, failed, unavailable or inconclusive module/job is never shown as Completed or passed.
3. **Colour never carries meaning alone.** Every status is colour + icon + word.
4. **Severity and confidence are always separate** fields, badges and columns.
5. **The pre-assessment disclaimer** appears on the dashboard, every assessment overview, every report preview and every PDF.
6. **High-impact actions require confirmation and are audited** (§7.24 list).
7. **Ordinary users never see** other users' targets, internal IPs, worker hostnames, stack traces, secrets, tokens or cookies. Evidence is always redacted (`[REDACTED]`).
8. **UI hiding is not security.** Every permission shown in the UI is also enforced by the backend; denied direct access shows the Denied state (§6.27).
9. **No placeholder buttons.** Every visible control does something real or is disabled with a reason.
10. **Retests never overwrite history.** A retest is a new linked job; earlier evidence stays.

---

## 2. Information architecture and navigation

### 2.1 Assessment Owner

Sidebar (in this order):

| Item | Route | Notes |
|---|---|---|
| Dashboard | `/dashboard` | Default landing page after sign-in |
| My Assessments | `/assessments` | Count badge = number owned |
| Shared reports | `/shared` | Count badge = active shares received |
| Scan Queue | `/queue` | Count badge = own queued + running jobs |
| Reports | `/reports` | Own + shared reports |
| *(section: Account)* Profile & Sessions | `/profile` | |
| Help & Safety Guidance | `/help` | |

Detail routes: `/assessments/new` (wizard), `/assessments/:id?tab=overview|findings|modules|history|reports|sharing|activity`, `/assessments/:id/scan` (new scan, starts at wizard step 2), `/reports/:reportId`.

### 2.2 Platform Administrator

Admins land on **Admin overview**. Sidebar:

| Group | Items |
|---|---|
| (console) | Overview · Users & Roles · Assessments / Jobs · Scan Capacity & Scheduling · Profiles & Modules · Target Policies · Policy Versions · Reports & Retention · System Health · Audit Logs · Notifications · Emergency Controls |
| My testing | My Assessments · Shared reports · Scan Queue · Reports |
| Account | Profile & Sessions · Help & Safety Guidance |

Admins use exactly the same owner screens under **My testing**. Admins can open any assessment from Assessments / Jobs → All assessments in **Administrator view** (read-only + generate report).

### 2.3 Shell layout

```
┌───────────────────────────────────────────────────────────────┐
│ Sidebar 232px │ Top bar 56px: breadcrumbs · bell · [Admin mode] · name/role · sign out │
│ (brand,       ├───────────────────────────────────────────────┤
│  nav groups,  │ Global alert bar (only when paused / emergency stop)                  │
│  footer note) │ Page: max-width 1280px, padding 24px, vertical gap 24px              │
└───────────────────────────────────────────────────────────────┘
```

- Sidebar is sticky, full height, `surface-1`, right border. Brand = product name in type ("Pre-Assessment Console") + sub-label ("Web & API security pre-assessment" or "Admin console"). **No logo exists — do not draw one.**
- Sidebar footer (owner): "Pre-assessment aid only — not a penetration test, certificate or clearance." Admin: "Admin actions are recorded in the audit log."
- Top bar is sticky. Admins show a `warn` badge **Admin mode** with a shield icon.
- Nav item active state: `primary-subtle` background, `primary` text, `aria-current="page"`. Count badges: `surface-2` chip, tabular numbers. Alert count uses `danger-bg`/`danger`.

### 2.4 Breadcrumbs

- Always present in the top bar. Last item is plain text with `aria-current="page"`; others are links.
- Assessment parent: owner → "My Assessments"; share recipient → "Shared reports"; admin view of others' → "Assessments / Jobs".
- Admin console pages: "Admin console › {Page}" (Overview shows only "Admin console").
- Report: "{Parent} › {Assessment name} › {Report ID}".

---

## 3. Design tokens

All colours, sizes and shadows MUST come from these tokens. **No literal hex, rgb or px colour values in components.** Light is the default; dark is a full theme.

### 3.1 CSS (copy as-is)

```css
:root {
  /* surfaces & text */
  --surface-0: #f4f5f6; --surface-1: #ffffff; --surface-2: #eceef0;
  --border: #d3d8dc; --border-strong: #7d8891;
  --ink: #13181c; --ink-muted: #4d5961; --ink-disabled: #8a949b;
  /* action */
  --primary: #0c5a6a; --primary-hover: #08485a; --on-primary: #ffffff; --primary-subtle: #e2f0f2; --focus: #0c5a6a;
  /* severity (findings only) */
  --sev-critical: #8c1232; --sev-critical-bg: #fae4e9; --sev-high: #a13a05; --sev-high-bg: #fcebdd;
  --sev-medium: #735400; --sev-medium-bg: #faf0cd; --sev-low: #1c5687; --sev-low-bg: #e1edf8;
  --sev-info: #4d5961; --sev-info-bg: #eceef0;
  /* status */
  --ok: #1d6636; --ok-bg: #e1f1e6; --warn: #7a4d00; --warn-bg: #fbefd6;
  --danger: #a31d1b; --danger-bg: #fbe4e2; --danger-hover: #861412; --on-danger: #ffffff;
  --neutral: #4d5961; --neutral-bg: #eceef0;
  --scrim: rgba(10, 14, 16, 0.48);
  /* open-decision marker */
  --note: #6a3fb0; --note-bg: #f1eafb;
  /* elevation */
  --shadow-raised: 0 1px 2px rgba(16, 24, 28, 0.06);
  --shadow-overlay: 0 12px 32px rgba(16, 24, 28, 0.18);
  /* type */
  --font-sans: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
  /* radius */
  --r-sm: 3px; --r-md: 6px; --r-lg: 8px; --r-full: 999px;
  /* spacing (4px grid) */
  --space-1: 4px; --space-2: 8px; --space-3: 12px; --space-4: 16px; --space-5: 24px; --space-6: 32px; --space-7: 48px;
}
:root[data-theme="dark"] {
  --surface-0: #0e1113; --surface-1: #171b1e; --surface-2: #20262a; --border: #30383d; --border-strong: #6b767e;
  --ink: #e7ebed; --ink-muted: #a1abb2; --ink-disabled: #626c73;
  --primary: #5fc3d2; --primary-hover: #86d4e0; --on-primary: #0a1b1f; --primary-subtle: #12343a; --focus: #8fdde9;
  --sev-critical: #ff9cb1; --sev-critical-bg: #3d1420; --sev-high: #ffa86f; --sev-high-bg: #3b2110;
  --sev-medium: #f0c954; --sev-medium-bg: #33290a; --sev-low: #90c4f0; --sev-low-bg: #13293c;
  --sev-info: #a1abb2; --sev-info-bg: #252b2f;
  --ok: #7fd59b; --ok-bg: #12301d; --warn: #f2c25a; --warn-bg: #352708;
  --danger: #ff9089; --danger-bg: #3b1513; --danger-hover: #ffb0aa; --on-danger: #2a0807;
  --neutral: #a1abb2; --neutral-bg: #252b2f; --scrim: rgba(0, 0, 0, 0.64);
  --note: #c9a8ff; --note-bg: #2a1f3d;
  --shadow-raised: none; --shadow-overlay: 0 12px 32px rgba(0, 0, 0, 0.5);
  color-scheme: dark;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { /* same values as [data-theme="dark"] */ } }
body { background: var(--surface-0); color: var(--ink); font: 400 14px/20px var(--font-sans); }
```

Fonts: IBM Plex Sans 400/500/600 and IBM Plex Mono 400/500 (Google Fonts, or self-hosted). Always keep the fallback stacks.

### 3.2 Colour roles (MUST)

| Token | Use | Never |
|---|---|---|
| `surface-0` | Page background | Cards |
| `surface-1` | Cards, tables, inputs, dialogs, drawers, sidebar, top bar | — |
| `surface-2` | Table header row, hover row, evidence blocks, disabled controls, chips | Page background |
| `border` | Hairline dividers, card outlines | The only boundary of an input |
| `border-strong` | Input, checkbox, radio, secondary button outlines | Decoration |
| `ink` / `ink-muted` | Primary / secondary text | — |
| `ink-disabled` | Disabled labels only | Any text a user must read |
| `primary` | The only action colour: primary button, links, selected tab, checked controls, running progress, focus | Decoration, headings, status that is not "in progress" |
| `primary-subtle` | Selected row/card, running module row, info badges/banners | — |
| `sev-*` / `sev-*-bg` | Severity only | Anything else |
| `ok`, `warn`, `danger`, `neutral` (+ `-bg`) | Status badges, banners, glyphs | Large decorative fills |
| `note` / `note-bg` | `TBD` markers and annotation pins only | Product UI meaning |

**Contrast:** every text pair is ≥ 4.5:1 in both themes; `border-strong` and `focus` are ≥ 3:1 on every surface. `ok` and `danger` are close in lightness — they are always paired with their icon and word.

### 3.3 Typography scale

| Style | Size / line | Weight | Use |
|---|---|---|---|
| Page title | 24/32 (`letter-spacing -0.01em`) | 600 | One `h1` per page |
| Section | 20/28 | 600 | Dialog titles, drawer titles |
| Card title | 15/22 (cards), 16/24 (sections) | 600 | `h2` in card headers |
| Sub-heading | 14/20 | 600 | Finding sections (Description, Evidence…) |
| Body | 14/20 | 400 | Default |
| Small | 13/18 | 400 | Tables, hints, meta, kv lists |
| Label | 13/18 | 500 | Form labels, buttons, tabs, nav |
| Caption | 12/16 (`letter-spacing 0.02em`) | 500 | Badges, column headers, stat labels |
| Stat numeral | 30/36, tabular | 600 | Stat cards only |
| Mono | 13/20 (12/18 small) | 400 | Targets, hosts, IPs, ports, paths, job/assessment/finding/report IDs, evidence |

Rules: sentence case everywhere; `text-wrap: balance` on headings; `font-variant-numeric: tabular-nums` wherever numbers align.

### 3.4 Spacing, radius, elevation

- **Spacing:** 4px grid only (`--space-1…7`). Card padding 20px (header 14px/20px). Table cells 12px. Gap between page sections 24px; between cards 16–20px; between form fields 18px.
- **Radius:** `r-sm` badges/chips/checkbox; `r-md` buttons, inputs, tabs; `r-lg` cards, banners, dialogs, drawers; `r-full` progress pips only.
- **Elevation:** `shadow-raised` for cards (light only); `shadow-overlay` for dialogs, drawers, popovers, toasts. No other shadows. **No gradients.**

### 3.5 Z-index layers

| Layer | z-index |
|---|---|
| Sticky top bar | 20 |
| Popovers (notifications) | 30 |
| Scrim | 60 |
| Drawer | 61 |
| Modal | 70 |
| Toasts | 80 |

### 3.6 Motion

Only the spinning ring glyph for `running`, `validating`, `cancelling` and in-progress actions (1.2s linear rotation). It MUST stop under `prefers-reduced-motion: reduce`. No layout transitions, no page-load animations.

---

## 4. Iconography

16px stroked glyphs, 1.75px stroke, round caps/joins, `currentColor`, `viewBox 0 0 16 16`. 12px inside badges, 14px inside small buttons and lists. Decorative icons get `aria-hidden="true"`.

| Name | Meaning |
|---|---|
| `check` | Completed, Allowed, Resolved, success |
| `x` | Failed, field error, closed toast |
| `warn` (triangle) | Warnings, Completed with warnings, Reopened |
| `clock` | Queued, Awaiting approval, Under review |
| `arrow` (circle+chevron) | Scheduled |
| `spin` (ring) | Running, Validating, Cancelling, in progress |
| `stop` (octagon) | Blocked, Emergency stop, danger banner |
| `slash` (circle+slash) | Cancelled, False positive, Unavailable, Revoked |
| `pause` | Interrupted · needs review |
| `dot` | New |
| `ring` | Open, Pending, Queued module |
| `skip` (dashed ring) | Skipped, Not tested, Not retested |
| `help` | Inconclusive |
| `info` | Info banner |
| `shield` | Accepted risk, MFA, validate target, admin mode |
| `lock` | Access level badges, Denied state |
| `doc` | Audit line, report, export |
| `flag` | `TBD` marker |
| `retest` (circular arrow) | Request retest |
| `share`, `plus`, `search`, `bell`, `user`, `users`, `folder`, `home`, `queue`, `report`, `book`, `map`, `chevron`, `close`, `logout` | Navigation and actions |

**Severity glyph:** four ascending bars; filled count = level (critical 4, high 3, medium 2, low 1, info 0; unfilled bars at 28% opacity).
**Confidence glyph:** two dots; Confirmed = 2 filled, Suspected = 1 filled.

---

## 5. Status vocabularies

Use these words **exactly**, everywhere (UI, reports, PDFs, exports, notifications). Each status renders as a `StatusBadge` with the given tone and icon.

### 5.1 Job states (PRD FR-10)

| Key | Label | Tone | Icon |
|---|---|---|---|
| `queued` | Queued | neutral | clock |
| `validating` | Validating | info | spin |
| `scheduled` | Scheduled | neutral | arrow |
| `running` | Running | info | spin |
| `cancelling` | Cancelling | warn | spin |
| `completed` | Completed | ok | check |
| `completed-warnings` | Completed with warnings | warn | warn |
| `failed` | Failed | danger | x |
| `cancelled` | Cancelled | neutral | slash |
| `blocked` | Blocked | danger | stop |
| `interrupted` | Interrupted · needs review | warn | pause |

### 5.2 Module run states

| Key | Label | Tone | Icon |
|---|---|---|---|
| `queued` | Queued | neutral | ring |
| `running` | Running | info | spin |
| `completed` | Completed | ok | check |
| `completed-warnings` | Completed with warnings | warn | warn |
| `skipped` | Skipped | neutral | skip |
| `blocked` | Blocked | danger | stop |
| `failed` | Failed | danger | x |
| `cancelled` | Cancelled | neutral | slash |
| `unavailable` | Unavailable | neutral | slash |
| `inconclusive` | Inconclusive | warn | help |
| `interrupted` | Interrupted | warn | pause |

### 5.3 Finding lifecycle (PRD FR-12)

| Key | Label | Tone | Icon |
|---|---|---|---|
| `new` | New | info | dot |
| `open` | Open | neutral | ring |
| `under-review` | Under review | info | clock |
| `false-positive` | False positive | neutral | slash |
| `resolved` | Resolved | ok | check |
| `reopened` | Reopened | danger | warn |
| `not-retested` | Not retested | neutral | skip |
| `accepted-risk` | Accepted risk | warn | shield |

"Needs action" = `new`, `open`, `under-review`, `reopened`.

### 5.4 Target validation outcome

| Key | Badge | Panel heading | Tone | Icon |
|---|---|---|---|---|
| `allowed` | Allowed | Allowed — target may be scanned | ok | check |
| `approval` | Approval required | Approval required — waiting for an approver | warn | clock |
| `blocked` | Blocked | Blocked — no scan traffic will be sent | danger | stop |

Validation check results: `pass` (ok/check), `warn` (warn/warn), `fail` (danger/x), `skip` (neutral/skip, detail "Not evaluated after a blocking result").

### 5.5 Assessment status (when not showing a job state)

`draft` Draft (neutral/doc) · `awaiting-approval` Awaiting approval (warn/clock) · `blocked` Blocked (danger/stop). Otherwise show the latest job's state.

### 5.6 Severity and confidence

Severity: `critical` Critical · `high` High · `medium` Medium · `low` Low · `info` Informational (compact: "Info"). Uses `sev-*` tokens and the bar glyph.

Confidence: `confirmed` Confirmed · `suspected` Suspected. **Neutral** outlined tag (`ink` on `surface-1`, `border-strong` outline) — never severity colours. Level names are open decision OD-1.

### 5.7 Report result categories (always all 7, in this order)

Confirmed · Suspected · False positive · Unresolved · Blocked · Skipped · Not tested. (Blocked, Skipped and Not tested count modules; the others count findings.)

### 5.8 Other vocabularies

- **Share status:** Active (ok/lock "View only") · Expired (warn/clock) · Revoked (neutral/slash).
- **Account status:** Active (ok/check) · Deactivated (neutral/slash). **MFA:** Enrolled (ok/shield) · Enrolment pending (info/clock) · Not enrolled (warn/warn).
- **Worker:** Healthy (ok/check) · Heartbeat lost (danger/x) · Standby (neutral/pause) · Not provisioned (neutral/slash).
- **Service health:** Healthy (ok/check) · Degraded (warn/warn) · Down (danger/x).
- **Report status:** Ready (ok/check) · Generating (info/spin) · Failed (danger/x).
- **Policy rule outcome:** Allow (ok/check) · Deny (danger/stop) · Require approval (warn/clock). **Policy version:** Published (ok/check) · Superseded (neutral/clock).
- **Alert severity:** Critical (danger/x) · Warning (warn/warn) · Info (info/info).

---

## 6. Component library

Props are given as TypeScript for a React implementation. Class names are indicative; any styling approach is fine if it uses the tokens.

### 6.1 Button

```ts
type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'danger' | 'danger-outline';
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;      // default 'secondary'
  size?: 'md' | 'sm';           // md 36px, sm 28px
  icon?: IconName;              // leading 16px (14px for sm)
  busy?: boolean;               // shows spin icon + busy label, disables
}
```
- Height 36px (sm 28px), padding 0 16px (sm 0 10px), radius `r-md`, label 13/18 500.
- **primary:** `primary` fill, `on-primary` text. **One per view** (page header or dialog footer).
- **secondary:** `surface-1`, `border-strong` outline, `ink` text.
- **quiet:** transparent, `primary` text; hover `primary-subtle`. For "View all", inline links in card headers.
- **danger:** `danger` fill, `on-danger` text — only as the confirm button inside a confirmation dialog, and for Emergency stop.
- **danger-outline:** `surface-1`, `danger` text and border — row-level destructive entry points (Cancel, Revoke, Drain, Discard draft) that open a confirmation.
- **Disabled:** `surface-2`, `ink-disabled`, `border`. MUST sit next to text explaining why (hint, `title`, or inline error).
- Labels are verbs naming the outcome: "Validate target", "Submit scan", "Request retest", "Lower to 1".

### 6.2 StatusBadge

```ts
interface StatusBadgeProps { kind: 'job' | 'module' | 'finding' | 'validation' | 'assessment'; status: string; label?: string; live?: boolean }
```
- Height 22px, padding 0 8px 0 6px, radius `r-sm`, caption type, gap 4px, 12px icon + label, `white-space: nowrap`.
- Tone classes: `ok`, `warn`, `danger`, `neutral` → `{tone}` text on `{tone}-bg`; `info` → `primary` on `primary-subtle`.
- `live` sets `role="status"` so changes are announced.
- Any extra sub-status goes on a second line under the badge in 12px (`ink-muted` or `warn`).

### 6.3 SeverityBadge

```ts
interface SeverityBadgeProps { severity: 'critical'|'high'|'medium'|'low'|'info'; compact?: boolean }
```
Badge geometry as StatusBadge; `sev-{x}` text on `sev-{x}-bg`; bar glyph; `title="Severity: {Label}"`; `compact` shortens Informational to "Info" (tables only).

### 6.4 ConfidenceTag

```ts
interface ConfidenceTagProps { confidence: 'confirmed' | 'suspected' }
```
Outlined neutral tag, two-dot glyph, `title="Confidence"`. Always shown next to severity in finding lists.

### 6.5 Banner

```ts
interface BannerProps { tone: 'info'|'warn'|'danger'|'ok'; title?: string; children: React.ReactNode; action?: React.ReactNode }
```
- Padding 12px 16px, radius `r-lg`, tone background, 16px icon in tone colour, body text in `ink`, bold title on its own line, optional action on the right.
- `danger` uses `role="alert"`; others `role="note"`.
- One or two sentences. Error banners give the next safe action.

### 6.6 Disclaimer (fixed copy)

`Banner tone="warn"`, title **"Pre-assessment, not a security clearance"**, body: "These results help prepare for formal security testing. They are not a penetration test, statutory certificate or security clearance, and they are not exhaustive." MUST appear on: Dashboard, Assessment overview, Review & submit step, Help. Reports use the watermark box (§6.30).

### 6.7 Card

`surface-1`, 1px `border`, radius `r-lg`, `shadow-raised`. Header: 14px 20px, bottom border, `h2` 15/22 600, optional right-aligned quiet action. Body: 20px (or 0 when it holds a full-bleed table). Use cards to group a single topic — do not nest cards.

### 6.8 StatCard

Clickable card (button element): caption label (12/16 500 `ink-muted`), numeral (30/36 600 tabular), one context line (13/18 `ink-muted`). Optional `tone` colours the numeral (`danger` for counts needing attention). Rows of 4 on desktop, 2 under 1100px, 1 under 760px. Only real counts the viewer is allowed to see.

### 6.9 DataTable

- Wrapped in a card; container `overflow-x: auto; position: relative` (tables scroll, the page never does).
- Header: caption type, `ink-muted` on `surface-2`, padding 10px 12px, `white-space: nowrap`.
- Cells: 13/18, padding 12px, top border `border`. Mono cells (IDs, hosts) do not wrap; long URLs use 12px mono and may wrap.
- Clickable rows: whole row clickable **and** the title is a real link/button (keyboard reachable); hover `surface-2`.
- Selected rows: `primary-subtle`.
- Selection checkbox column 36px wide with a screen-reader-only header ("Select for retest"); each checkbox has an `aria-label` naming the row.
- Row actions are right-aligned; use `sm` buttons; at most two visible actions, otherwise an "Actions…" select/menu.
- Sorting default for findings: severity (critical→info), then confidence (confirmed first).
- Empty table → EmptyState (§6.26), never an empty grid.

### 6.10 Tabs

`role="tablist"` with `role="tab"` buttons, `aria-selected`. 13/18 500, `ink-muted`; selected = `primary` text + 2px `primary` bottom border. Optional count chip (`surface-2`). Tabs switch peer views of one object; they never navigate to another object. Tab state is reflected in the URL (`?tab=`).

### 6.11 TextField / Select / Textarea

```ts
interface FieldProps { id: string; label: string; required?: boolean; hint?: string; error?: string; mono?: boolean; disabled?: boolean }
```
- Label above (13/18 500), required marker `*` in `danger`. Input 36px, `border-strong`, radius `r-md`, `surface-1`, 14px (mono 13px).
- Hint below in 13/18 `ink-muted`. Error replaces the hint: `danger` 13/18 500 with `x` icon; input gets `aria-invalid="true"` and a 2px `danger` border; `aria-describedby` points at hint/error.
- Placeholders show **format only** ("e.g. https://staging.service.example/"), never replace labels.
- Use `mono` for targets, hostnames, IPs, ports, paths, exclusions, IDs.
- Validate on submit/blur; show all errors at once; do not clear user input on error.
- Two-column rows (`f2`) on desktop collapse to one column under 760px.

### 6.12 Checkbox, Radio, OptionCard

- Native inputs with `accent-color: var(--primary)`, 16px, label to the right.
- **OptionCard (`modopt`):** a bordered label (radius `r-md`, padding 10px 12px) wrapping a checkbox/radio + title + 12px description. Selected: `primary` border + `primary-subtle`. Disabled: `surface-2`, and the description states why ("Disabled by an administrator. It will show as Unavailable.").

### 6.13 ProfileCard (scan profile picker)

Radio card in a `radiogroup`, 3 columns (1 column under 1100px). Content: custom radio + name (16/24 600), description, meta row ("Duration **…** · Impact **…**"), module chips (mono 12px on `surface-2`). Selected: 2px `primary` border, `primary-subtle`. Modules disabled by an admin show struck-through chips plus a warn banner below the grid.

| Profile | Duration (estimate) | Impact |
|---|---|---|
| Quick Scan | Seconds to minutes for small targets | Low |
| Pre-Assessment | Minutes to tens of minutes | Moderate |
| Deep Scan | Tens of minutes to hours (not exhaustive) | Higher |

### 6.14 Stepper

Ordered list; each step = 22px circle number + label. Current: filled `primary`; done: `ok` outline with check; todo: `border-strong` outline. 32px connector line. `aria-current="step"` on the current step.

### 6.15 ValidationResult

Card with a tone-coloured header row (icon + heading from §5.4), a list of checks (grid: 16px icon · label · detail), and a footer: normalised target (mono) + "Decision recorded · policy {v} · {timestamp IST}". `aria-live="polite"`.

Check order (fixed): URL normalised → DNS resolution → Destination addresses → Redirects → Ports → Allow / deny rules → Environment policy. After the first `fail`, remaining checks are `skip`.

### 6.16 ModuleProgress

Card: header "{JOB-ID} · {run}" + "{n} of {total} modules finished" (`role="status"`). Ordered list rows: icon · module name + 12px detail · module StatusBadge. Running row background `primary-subtle`. **Never show a single unlabelled percentage.** Compact variant (dashboard): one 8px segment per module (ok = completed, primary = running, warn = interrupted/inconclusive/cancelled, `surface-2` = queued).

### 6.17 CapacityMeter

Line: caption "Global capacity" · pips · "**{active} / {limit} active**" · "{queued} queued · {n} healthy workers". Pips: 28×8px, `r-full`; filled `primary` = active slot; outlined = free; **dashed** = provisionable but not enabled (ceiling). If healthy workers < limit, show `danger` text: "Effective capacity reduced to {n}: not enough healthy workers. Administrators have been alerted." Owners see counts only — never other users' targets.

### 6.18 SeverityBar

12px stacked bar (2px gaps, `surface-2` track) with one segment per non-zero severity, flex proportional to count, `role="img"` with an `aria-label` listing every count. Legend below: glyph + bold count + label for all five severities (including zeros).

### 6.19 KeyValue list

`<dl>` grid `minmax(96px, 38%) 1fr`, 13/18, `dt` in `ink-muted`. Collapses to one column under 760px. Values that are identifiers use mono.

### 6.20 Modal

`role="dialog"` (`alertdialog` for confirmations), `aria-modal`, labelled by its title. Width 560px (wide 760px). Body padding 24px, gap 16px, title 20/28 600. Footer: `surface-2`, right-aligned buttons: secondary (cancel) then primary/danger (confirm). Esc and scrim click close. Focus moves to the first field/button on open.

### 6.21 ConfirmDialog

Title is a question naming the action ("Lower the global limit to 1?"). Body: one or two sentences stating the consequence. Cancel label names the safe outcome ("Keep at 2", "Keep scanning", "Keep access"). Confirm label repeats the verb. Footer line: `doc` icon + "This action is recorded in the audit log." Confirm uses `danger` for destructive actions, `primary` otherwise.

### 6.22 ReasonConfirm

ConfirmDialog + required **Reason** textarea ("Recorded in the audit log."). Confirm stays disabled until a reason is entered. Optional **typed confirmation** ("Type STOP to confirm") for Emergency stop. Used for every admin high-impact action (§7.24).

### 6.23 Drawer (side panel)

Right-side, `min(720px, 100%)` wide, `surface-1`, `shadow-overlay`, scrim behind. Header: badges row + title (20/28 600) + close button (`aria-label="Close"`). Scrollable body (padding 20px 24px, gap 20px). Sticky footer on `surface-2` with the allowed actions — or one line explaining why there are none. Used for finding detail and audit event detail.

### 6.24 Toast

Bottom-right, `ink` background, `surface-1` text, 13px, radius `r-md`, max 380px, icon + one sentence. Region `role="status" aria-live="polite"`. **Max 3 visible**; auto-dismiss after ~4s. Use for confirming a completed action ("JOB-001473 accepted — queued."). Never for errors that need action — use a Banner.

### 6.25 Notifications popover

Bell button in the top bar with unread count (danger dot, 16px). Popover 380px: title "Notifications" (+ "in-app only"), items with tone icon, one sentence, relative time; clicking navigates to the linked object. Notifications are addressed to a specific user (`to`); show only the viewer's.

### 6.26 EmptyState

Centered in the card, padding 40px 24px: bold title (15px) + one sentence of guidance + optional primary/secondary action. Explains how to start ("Create an assessment with your target and scope. The target is validated before any scan can run."). Distinguish "nothing yet" from "nothing matches filters" (offer **Clear filters**).

### 6.27 DeniedState

Card with `lock` icon (28px, `danger`), title "You don't have access to {thing}", one sentence of reason (not shared, revoked, expired, admin-only), and "Back to dashboard". Never reveal details of the object beyond its ID. Used for direct URL access, revoked/expired shares, owner-only and admin-only routes.

### 6.28 LocationList ("Where it is")

KeyValue list shown first in finding detail and in technical reports:

| Row | Content |
|---|---|
| Location | Full URL, `host:port`, or the component (cookie/header/certificate) — mono |
| Type | Web page · API endpoint · File · Network service · Cookie · Response header · TLS certificate |
| Host · port | mono |
| Path | mono (when applicable) |
| Parameter | mono (when applicable) |
| HTTP method | when applicable |
| Module · engine version | engine version is OD-13 |
| Found by | job ID + policy version |
| First / last seen | IST timestamps |
| Latest retest | "Fixed in JOB-…" / "Still present in JOB-…" |

### 6.29 EvidenceBlock

`<pre>` on `surface-2`, 1px `border`, radius `r-md`, mono 12/18, `white-space: pre-wrap`, horizontal scroll allowed. Every `[REDACTED]` token is highlighted (`warn` on `warn-bg`). Caption below: "Sanitized excerpt. Cookies, tokens and personal data are redacted." Never render unredacted secrets.

### 6.30 Report preview and PDF

Both are generated from **one report model** so they always match. Structure:
1. Header band: product name (left) · classification label (right, `TBD · OD-8`).
2. Title (assessment name, 26px) + type · report ID · version · generated time · by.
3. **Watermark box** (2px `warn` border, `warn` text): "PRE-ASSESSMENT RESULTS — not a penetration test, statutory certificate or security clearance. Results are not exhaustive and may include false positives."
4. Scope (target, in scope, exclusions, environment, scan, run time, policy · tools, hosts with findings).
5. Result categories table (all 7).
6. Modules table (module, outcome badge, note).
7. Management summary: Findings by severity (total, still open) + **Findings and where they are** (#, severity, finding, location, confidence, state).
   Technical report: **Findings overview** (same columns) + **Finding details** per finding (badges, title, LocationList, description, impact, evidence, how to reproduce, remediation + references, history).
8. Limitations paragraph.
PDF: A4 portrait, header and footer on every page (report ID, version, type, assessment name, "Page x of y", disclaimer line), coloured severity/state pills, findings rows never split across pages. Filename: `{ReportID}-v{n}-{management-summary|technical-report}-{Assessment-Name}.pdf`. The PDF is generated by the app (not the browser's print dialog).

### 6.31 Timeline

List of rows (grid 132px time · event), 13/18, top borders. Time in `ink-muted` IST. Used for finding history, activity, capacity/emergency history.

### 6.32 TBD marker

Inline chip: dashed 1px `note` border, `note-bg`, `note` text 11px 500, `flag` icon, text "{label} · OD-n", `title` with the decision name and source. Use wherever a value or behaviour depends on an open decision (§14). Never show a guessed value without it.

### 6.33 Sparkline (System Health)

220×48 SVG: area fill (`primary-subtle`, or `warn-bg` for queue depth), 1.75px line, endpoint dot, dashed 80% threshold line in `border`, label + current value header, caption "Last 24 h". `role="img"` with an `aria-label` giving the current value and range.

### 6.34 Global alert bar

Full-width `danger` banner directly under the top bar when scanning is paused or an emergency stop is active. Owners: "New scans are paused / Emergency stop in effect — An administrator has stopped new scanning. Your results and reports are still available." Admins: the reason plus an "Emergency controls" button.

### 6.35 ExportPdfButton

Primary (page) or secondary sm (table rows) button "Export PDF" with `doc` icon; shows "Preparing PDF…" with spin while generating. The save goes through the host's download/confirmation mechanism; handle "declined" (info toast "PDF export cancelled.") and other failures (danger toast). If exports are unavailable in the environment, show the text "PDF export unavailable here" instead of a dead button.

---

## 7. Interaction patterns

### 7.1 Sign-in

Password → one MFA challenge (6 single-digit inputs, auto-advance) → landing page (owner: Dashboard; admin: Admin overview). No sign-up link. "Forgot password?" explains that resets go through an administrator (`TBD · OD-11`). Errors are neutral: "The email or password is incorrect." · after repeated attempts "Too many attempts. Wait 5 minutes before trying again." · disabled account "This account cannot sign in. Contact your platform administrator." Never reveal whether an account exists.

### 7.2 New assessment wizard (3 steps)

**Step 1 — Target & scope** (two-column: form left, validation panel right, sticky):
Fields: Assessment name* · Target URL / API base URL* (mono) · Environment* (Development, Staging, UAT, Production) · In-scope hostnames / IPs* (mono, auto-filled from the target if empty) · In-scope paths (default `/*`) · Permitted ports (default `443`) · Exclusions (textarea, mono) · Notes (optional).
**No authorization reference and no validity period (PD-7).**
Target field errors (inline, before validation): empty; malformed; unsupported scheme ("Use http or https."); embedded credentials ("Remove credentials from the URL. Authenticated testing is set up in scan configuration."); ambiguous host representation.
Right panel: "Validate target" (secondary, shield icon, spin while validating) → ValidationResult → outcome actions:
- Allowed → primary "Continue to scan configuration" (disabled until required fields are valid).
- Approval required → "Save and request approval" (owner) — admins see that they can self-approve on the next screen.
- Blocked → "Target validation failed — no scan traffic was sent." + "Save as draft".
Any change to target, environment or ports clears the result.

**Step 2 — Scan configuration:** segmented control "Scan profile | Individual modules". Profile cards (§6.13) or module OptionCards (Reachability always on and disabled with "Always runs first."). Right column: Scope summary card + "Limits & impact" (expected impact, estimated duration, request cap/rate, crawl depth/timeouts as `TBD · OD-6`, Priority "Normal · set by an administrator"). Deep Scan adds an "Authenticated testing" card with a credential **reference** field — never a password field (`TBD · OD-12`).

**Step 3 — Review & submit:** KeyValue summary (assessment, target, scope, run, modules as chips, policy), duplicate-job warning banner if the assessment already has a queued/running job, queue limits line (`TBD · OD-10`), **authorization checkbox**: "I confirm I am authorized to test this target within the scope above." Submit is disabled until checked and while submissions are blocked (§7.21). Right column: Disclaimer + CapacityMeter.

**Submitted:** success card with job ID (mono), status badge, queue position + "approx. {lo}–{hi} min", plain message ("Scan queued — another scan is using the available capacity. It starts automatically; you can leave this page."), actions "Follow progress" (primary) and "View scan queue".

If the API returns no job ID: danger banner "Service unavailable — your scan was not submitted. No job ID was returned, so nothing is queued. Check Scan Queue before trying again." Never imply success.

### 7.3 Assessment detail

Header: name (h1) + assessment status badge if not active; sub-row: target (mono, `ink`), environment, owner, access badge for non-owners ("View only (shared)" / "Administrator view").
Owner actions: **New scan** (primary; disabled with reason when validation is not Allowed, awaiting approval, or submissions are blocked) or **Edit & revalidate** (draft/blocked), **Share**, **Generate report** (disabled until a scan finished). Admin on own awaiting target: **Approve my target**.
Context banners under the header: awaiting approval, blocked, view-only explanation, administrator view explanation, interrupted scan.
Tabs: Overview · Findings · Modules · Scan history · Reports · Sharing (owner only) · Activity (owner and admin).

**Overview:** two columns. Left: Findings summary card (SeverityBar, confidence counts, lifecycle counts, "{n} findings still need action") and Current/Latest scan card. Right: Scope & authorization KeyValue + Disclaimer.

### 7.4 Findings triage

Filter row: Severity · State · Module · Confidence selects + "Group by module" checkbox; right-aligned **Request retest ({n})** (primary, owner only, disabled until something is selected). Columns: [select] · Severity · Finding (title link + "{ID} · {module}") · Asset / endpoint (mono 12px) · Confidence · State · Retest. False-positive and accepted-risk rows cannot be selected for retest. Group headers are full-width rows on `surface-2`.

### 7.5 Finding detail (Drawer)

Header: severity, confidence, state badges + finding ID; title. Body order: **Where it is** (LocationList) → Description → Impact → Evidence (EvidenceBlock) → How to reproduce → Remediation (+ reference chips) → History (Timeline) → Comments (owner can post; others read). Footer (owner): allowed state actions + "Request retest". Non-owners: "Shared with you, view only. Only the owner, {name}, can change or retest this finding." / "Administrator view. …".

### 7.6 Finding state change (PD-4)

| Action | From states | Reason required |
|---|---|---|
| Acknowledge (Open) | new | No |
| Mark under review | new, open, reopened | No |
| Mark false positive | new, open, under-review, reopened | Yes |
| Accept risk | open, under-review, reopened | Yes (note: stays unresolved in reports) |
| Reopen | false-positive, accepted-risk, resolved | Yes |
| Resolved | — | Only via retest (not a manual action) |

Each change opens a small modal (reason field when required), writes a history line "{Label} — {reason} · {user}" and an audit event, and shows a toast.

### 7.7 Retest (PD-3)

Owner only. Modal "Request retest of {n} finding(s)": table of selected findings, modules to run (Reachability + the findings' modules, as chips), scope, priority line, note "Other findings from these modules that the retest does not observe will be marked 'Not retested'.", authorization checkbox ("I confirm I am still authorized to test this target within the scope above."), **Queue retest**. Creates a new linked job; results: not observed → Resolved ("Fixed in JOB-…"), still present → stays or becomes Reopened ("Still present in JOB-…"). Original evidence is kept.

### 7.8 Sharing (PD-2)

Sharing tab (owner): table Person · Permission ("View only") · Expires · Granted · Status · Revoke (danger-outline → ConfirmDialog "Revoke access for {name}?", "Keep access"). **Share** dialog: search existing **active** accounts (owners and admins; excludes self and people already shared), one fixed permission card "View only" with description, optional expiry date → confirmation dialog summarising person, permission, expiry and "Credentials, tokens, cookies and raw sensitive request data are never shared."

### 7.9 Shared reports (recipient)

Page "Shared reports": table Assessment · Owner (initiator) · Reports (link "{n} reports") · Open findings · Last scan · Shared · Expires · Status. Active rows open the assessment read-only; expired and revoked rows stay listed, greyed and not clickable. The read-only assessment hides Sharing and Activity tabs, all state actions, comments input and retest controls, and shows the view-only banner. Reports (management and technical) can be previewed and exported as PDF.

### 7.10 Reports

Generate dialog: two OptionCards (Management summary · Technical / developer report) + "Based on scan" select (finished jobs only) + note listing the 7 categories and classification `TBD · OD-8`. Reports table: Report (ID + version) · Type · Based on · Generated (time · by) · Status · actions (Preview, Export PDF; Retry when Failed). Failed generation shows the danger banner "Report generation failed — your assessment results are unchanged" — retry never reruns the scan.

### 7.11 Scan queue (owner)

CapacityMeter + ordering note ("Order: authorised and eligible jobs by priority (High, Normal, Low), then by submission sequence. Waiting jobs gain priority over time…"). Tables: **Your queued and running jobs** (job, assessment, run, priority, submitted, position · wait, status, Cancel), **Platform queue** (slot, job — others shown as "Another user's scan" with no details), **Your recent finished jobs**.

### 7.12 Scan progress and failure states

- Running: ModuleProgress with the running row highlighted.
- Queued: info banner "Waiting for capacity — Scan queued — another scan is using the available capacity. #{n} in queue, approx. …".
- Interrupted: warn banner "Scan interrupted — partial results have been preserved" + reason; completed modules and findings kept; unfinished modules marked Interrupted/Queued, reported as Not tested. After admin review, the banner states the outcome.
- Module disabled by admin: recorded as Unavailable ("Disabled by an administrator"), never passed.
- Rate limiting / WAF: module Inconclusive with a detail line.
- Cancel (owner, own job): ConfirmDialog → queued jobs become Cancelled immediately (modules Skipped); running jobs go Cancelling → Cancelled, partial results kept.

### 7.13 Admin overview

Four StatCards (Active · queued; Healthy workers; Needs a decision = approvals + unreviewed interrupted; Open alerts) → Services grid (8 service cards with health badge + one detail line) → two columns: "Scanning now" (CapacityMeter + table incl. owner and target) | Policy card + Alerts list → Recent administrative events table.

### 7.14 Users & roles (admin)

Tabs: Accounts · Roles & permissions · Sign-in & sessions. Accounts table: person (name, email · team), role, status, MFA, last sign-in, sessions, "Actions…" select (Change role, Deactivate/Reactivate, Reset two-step verification, Revoke all sessions) — each via ReasonConfirm; the admin's own row shows "You". **Create account** modal: full name*, work email* (validated, unique), role (Assessment Owner | Platform Administrator), team. Roles tab: the two-role matrix (§11). Sign-in tab: MFA (admins locked on; owners `TBD · OD-5`), SSO `TBD · OD-5`, session lifetime/idle timeout/throttling `TBD · OD-19`.

### 7.15 Approvals (admin)

Assessments / Jobs → **Approval requests** tab: table (assessment, target, environment, owner — with "Your own request" warn badge when it is the admin's own — requested, Refuse / Approve). Decision modal shows scope, the full ValidationResult and a required note ("Shown to the owner and recorded in the audit log."). Self-approval shows a warn banner "Self-approval — This is your own target. Self-approval is allowed with a reason, and it is flagged in the audit log." Approval never overrides safety invariants or scope. Owner is notified.

### 7.16 Interrupted-job review (admin)

**Interrupted** tab: job, assessment, owner, stopped, unfinished modules, review status, Review. Review modal: completed vs not finished module lists + three OptionCards — **Resume safe modules** (new linked job with only the unfinished modules, under the current policy), **Advise a full rerun**, **Close as interrupted** — + required reason.

### 7.17 Jobs and priority (admin)

Jobs tab with filter (Queued and running, All, Completed, …): job (with "resumes …"/"retest of …"), assessment · target, owner, run, priority (link on queued jobs only → Priority modal: segmented High/Normal/Low + reason), submitted, status, Cancel (ReasonConfirm, owner notified). Note: "Priority can be changed on queued jobs only, by administrators. It never bypasses authorization, scope or capacity." **All assessments** tab: every assessment, clickable into Administrator view.

### 7.18 Capacity & scheduling (admin)

Settings form: Global concurrency limit (1–3; ceiling `TBD · OD-9`) with live hint "Healthy workers: n · Active scans: n · Queued: n"; queue policy text; Priority aging checkbox + interval; Queue cap (wireframe value 50, `TBD · OD-10`); Per-user quota; Per-profile limits (`TBD · OD-6`); fixed "Safe FIFO fallback" note. **Save configuration** (disabled until changed) → if limit > healthy workers: inline error "Only {n} healthy worker is available. Enable or provision more workers before raising the limit to {x}." → else ReasonConfirm (lowering with active > new limit shows "They will finish normally; no new scan starts until fewer than {x} are active."). Right column: Now (CapacityMeter) + Worker pool table (Enable on standby; Drain on healthy when >1 enabled; both ReasonConfirm). Bottom: Recent changes timeline.

### 7.19 Profiles & modules (admin)

Three profile cards (description, module chips, duration, limits `TBD · OD-6`, Edit → modal with module OptionCards + reason; Reachability locked). Modules table: name + description, used by, selectable alone, engine version (`TBD · OD-13`), status (Available/Unavailable), Enable/Disable (ReasonConfirm). Disabled modules flow through to owners' configuration and are recorded as Unavailable.

### 7.20 Target policies and versions (admin, PD-5)

- No draft: info banner "Published policy {v} is in force…" + **Start new draft**.
- Draft: Stepper (Draft → Validated → Dry run → Published). Editor segmented "Visual rules | Structured config".
  - Visual: rules table (ID, outcome badge, match type, value mono, note, Edit/Remove), **Add rule** modal (outcome, match on: hostname suffix | exact domain | IP | CIDR | environment, value with format validation, note), Permitted ports, "When no rule matches" (`TBD · OD-18`), change note.
  - Structured config: JSON textarea; **Validate & apply to draft**; schema errors inline ("rules[2] (R-07): CIDR must look like 203.0.113.0/24"). Never executes code.
- Right column: **Safety invariants** card (locked list: loopback, unspecified, link-local, cloud metadata, private ranges unless an approved internal policy, scope-leaving redirects/DNS) + **Next step** card: Validate draft → checks list (schema, conflicts, invariant overrides, ports) → Run dry run (table: target, env, published outcome, draft outcome, changed rows highlighted) → **Publish {v}** (ConfirmDialog stating how many targets change). Discard draft via ConfirmDialog.
- **Policy versions:** table (version, status, published, published by, rules, note, used by, "Roll back to this" for superseded) + Compare (two selects → added/removed/changed rules, ports, no-match outcome). Rollback = ReasonConfirm; it publishes a **new** version with the old rules.

### 7.21 Submission blocking

`blockedReason` order: Emergency stop → Paused by admin → Queue service down. When blocked: Dashboard banner, Review step banner + disabled Submit, retest modal banner + disabled confirm, Scan Queue banner, New scan disabled with reason. Queued jobs keep their place.

### 7.22 Emergency controls (admin)

Current state row (Scanning normally / New scans paused / Emergency stop in effect + reason + counts). **Pause new scans** card (danger-outline → ReasonConfirm; "Resume scanning" primary when paused). **Emergency stop** card (red border; danger button → ReasonConfirm with typed "STOP" and a danger banner listing active job IDs). History timeline. Effects: global alert bar for all users, running jobs → Cancelling, owners notified, admin alert raised.

### 7.23 Audit logs, health, alerts (admin)

- **Audit logs:** filters (search, area, actor, outcome) → table (when, actor, area, action link, object mono, outcome badge) → Drawer with timestamp, actor, object, target, policy version, scanner version (`TBD · OD-13`), detail/reason, source. **Export CSV ({n})** (the export itself is audited). Footer: "Events cannot be edited or deleted here. Secrets, passwords and tokens are never logged."
- **System health:** services grid, four sparklines (worker CPU, memory, evidence storage, queue depth), worker heartbeats table, backups & recovery card (RPO/RTO `TBD · OD-7`) with recovery order note.
- **Notifications & alerts:** segmented Open | Resolved | All; each alert is a card: severity badge, title, ID, Acknowledge / Resolve; KeyValue: affected service, first seen, impact, active jobs, safe action taken, recovery owner. Delivery card (in-app on; other channels `TBD · OD-14`).

### 7.24 High-impact actions (MUST confirm + audit)

| Action | Who | Dialog |
|---|---|---|
| Cancel a queued/running job (own) | Owner | ConfirmDialog |
| Cancel any job | Admin | ReasonConfirm |
| Revoke a share | Owner | ConfirmDialog |
| Revoke a session / sign out others | Any user (own) | ConfirmDialog |
| Change role, deactivate/reactivate, reset MFA, revoke sessions | Admin | ReasonConfirm |
| Approve / refuse a target (incl. self-approval) | Admin | Modal with required note |
| Change priority | Admin | Modal with required reason |
| Review interrupted job | Admin | Modal with required reason |
| Save capacity/scheduling, enable/drain worker | Admin | ReasonConfirm |
| Enable/disable module, edit profile | Admin | ReasonConfirm / modal + reason |
| Publish policy, discard draft | Admin | ConfirmDialog |
| Roll back policy | Admin | ReasonConfirm |
| Save report templates/export permissions | Admin | ReasonConfirm |
| Pause / resume scanning | Admin | ReasonConfirm |
| Emergency stop | Admin | ReasonConfirm + typed STOP |
| Finding: false positive, accept risk, reopen | Owner | Modal with required reason |

### 7.25 Loading, empty, error, denied

- **Loading:** skeleton rows or a spin icon in the triggering button; never a blank page; keep previous data visible while refreshing.
- **Empty:** EmptyState with next action.
- **Error:** Banner with a safe next action; never a stack trace, internal host, worker name or secret.
- **Denied:** DeniedState (§6.27).

### 7.26 Live updates

Progress, queue position, capacity and notifications update live (SSE/WebSocket or polling). Announce job state changes via `role="status"`. Do not move focus or reorder rows under the user's cursor while they interact.

---

## 8. Content and copy rules

- **Voice:** plain, factual, second person ("Your job is #3 in the queue"). Prefer plain words over scanner jargon ("Session cookie missing SameSite", not "CWE-1275").
- **Sentence case** for everything (buttons, headings, badges, tabs, menu items). Product nouns keep capitals: Quick Scan, Pre-Assessment, Deep Scan.
- **Buttons are verbs** naming the outcome. The safe choice in a dialog names what stays ("Keep at 2").
- **Errors say what to do next**, without apologies.
- **Estimates are ranges** ("approx. 20–45 min", "Minutes to tens of minutes"). Never promise completion times.
- **Dates:** `DD Mon YYYY, HH:MM IST` (e.g. 02 Nov 2026, 14:20 IST). Relative time ("5 min ago") in lists, absolute time in detail views.
- **IDs:** `A-0112` (assessment), `JOB-001402` (job), `F-2204` (finding), `R-0311` (report), `S-091` (share), `R-04` (policy rule), `v14` (policy version), `AL-31` (alert) — always mono.
- No emoji, no exclamation marks, no celebratory copy.

**Standard messages (use verbatim):**

| Situation | Message |
|---|---|
| Waiting for capacity | Scan queued — another scan is using the available capacity. |
| Worker lost | Scan interrupted — partial results have been preserved. |
| Validation failed | Target validation failed — no scan traffic was sent. |
| Report failed | Report generation failed — your assessment results are unchanged. |
| Submit without job ID | Service unavailable — your scan was not submitted. |
| Queue down | The scan queue service is not responding, so new submissions are refused. |
| Paused | An administrator has paused new scans. Submissions are not accepted until scanning resumes. |
| Emergency stop | An administrator used Emergency stop. New scans are blocked until it is lifted. |
| Audit line | This action is recorded in the audit log. |
| Redaction | Sanitized excerpt. Cookies, tokens and personal data are redacted. |

---

## 9. Accessibility rules (MUST)

- WCAG 2.1 AA: text ≥ 4.5:1 (≥ 3:1 at 24px+ or bold 19px+); borders, focus rings, icons that carry meaning ≥ 3:1 — in **both** themes.
- **Focus:** 2px solid `focus` outline at 2px offset on every interactive element; never removed.
- Full keyboard operation: tabs, dialogs (Esc closes; focus moves in and returns), drawers, menus, table row links, option cards (focus-within outline).
- Semantic structure: one `h1` per page; landmarks (`nav`, `main`, `header`, `aside`); breadcrumbs `nav aria-label="Breadcrumb"`.
- Every input has a visible `<label>`; errors linked by `aria-describedby`; `aria-invalid` on invalid fields.
- Status changes announced (`role="status"` / `aria-live="polite"`); danger banners `role="alert"`.
- Icon-only buttons have `aria-label`. Charts have `role="img"` + text alternative. Tables use `<th scope>`.
- Respect `prefers-reduced-motion`.

---

## 10. Responsive rules

| Breakpoint | Behaviour |
|---|---|
| ≥ 1101px | Full layout: sidebar 232px + content; stats 4-up; two-column `grid2` (2:1); profiles 3-up |
| ≤ 1100px | Stats 2-up; `grid2` and profiles stack to one column |
| ≤ 760px | Sidebar becomes a wrapping top nav; top bar not sticky; stats 1-up; all two-column form rows and KeyValue lists stack; page gutter `max(16px, safe-area)`; drawer full width |

The page body MUST never scroll horizontally; only tables, code/evidence and charts scroll inside their own containers. Give flex/grid children that hold text `min-width: 0`.

---

## 11. Roles, permissions and UI enforcement

### 11.1 Access levels on an assessment

| Level | Who |
|---|---|
| `owner` | The user who created the assessment (initiator of its scans) |
| `admin` | Any Platform Administrator viewing someone else's assessment |
| `view` | A user with an active, unexpired, unrevoked share |
| none | Everyone else → DeniedState |

### 11.2 Capability matrix

| Capability | owner | view (shared) | admin (others') |
|---|---|---|---|
| See overview, findings, modules, history, reports | ✓ | ✓ | ✓ |
| See redacted evidence | ✓ | ✓ | ✓ |
| Preview and export reports (PDF) | ✓ | ✓ | ✓ |
| Generate reports | ✓ | — | ✓ |
| Change finding state | ✓ | — | — |
| Comment | ✓ | — | — |
| Request retest | ✓ | — | — |
| Start a new scan, cancel own job | ✓ | — | — (admin cancels via console) |
| Share / revoke | ✓ | — | — |
| Sharing tab | ✓ | hidden | hidden |
| Activity tab | ✓ | hidden | ✓ |

### 11.3 Role matrix

| Function | Assessment Owner | Platform Administrator |
|---|---|---|
| Manage users and roles | No | Yes |
| Create assessments and test websites | Yes | Yes |
| Submit scans and retests on own assessments | Yes | Yes |
| View any assessment | No (only shared, read-only) | Yes, read-only |
| Share an assessment (view only) | Own, with any active user | Own, with any active user |
| Retest findings | Only on scans they initiated | Only on scans they initiated |
| Change finding state | Own assessments, directly | Own assessments, directly |
| Generate reports | Own assessments | Any assessment |
| Approve targets that need approval | No | Yes (own: self-approval with reason) |
| Change policy, profiles, modules | No | Yes |
| Change concurrency and scheduling | No | Yes |
| Emergency controls | No | Yes |
| View audit logs | Activity on own assessments | All |

### 11.4 Enforcement rules

- Compute access with one function (`permFor(user, assessment)`) and one capability check (`can(level, action)`); never scatter role checks in components.
- Hidden actions are **also** rejected by the API; the UI must handle a 403 by showing DeniedState or a danger banner, never a broken screen.
- Admin console routes for non-admins → DeniedState ("The admin console is limited to Platform Administrators. This attempt would be refused by the server and recorded.").
- Changing a URL to another assessment ID must show DeniedState unless the user has access.

---

## 12. Data contracts the UI relies on

```ts
type Role = 'Assessment Owner' | 'Platform Administrator';
type Environment = 'Development' | 'Staging' | 'UAT' | 'Production';
type ProfileKey = 'quick' | 'pre' | 'deep';
type ModuleKey = 'reach' | 'ports' | 'tls' | 'headers' | 'exposed' | 'finger' | 'crawl' | 'cms' | 'config' | 'dast' | 'api' | 'auth' | 'access' | 'cval';
type JobState = 'queued'|'validating'|'scheduled'|'running'|'cancelling'|'completed'|'completed-warnings'|'failed'|'cancelled'|'blocked'|'interrupted';
type ModuleState = 'queued'|'running'|'completed'|'completed-warnings'|'skipped'|'blocked'|'failed'|'cancelled'|'unavailable'|'inconclusive'|'interrupted';
type FindingState = 'new'|'open'|'under-review'|'false-positive'|'resolved'|'reopened'|'not-retested'|'accepted-risk';
type Severity = 'critical'|'high'|'medium'|'low'|'info';
type Confidence = 'confirmed'|'suspected';           // names: OD-1
type ValidationOutcome = 'allowed'|'approval'|'blocked';
type Priority = 'High'|'Normal'|'Low';

interface Assessment { id: string; name: string; owner: string; target: string; env: Environment; hosts: string; paths: string; ports: string;
  exclusions: string; notes?: string; created: number; status: 'draft'|'active'|'awaiting-approval'; validation: ValidationOutcome; policy: string; }
interface Job { id: string; seq: number; assessmentId: string; owner: string; requestedBy: string; type: 'scan'|'retest'; profile: ProfileKey|null;
  priority: Priority; state: JobState; submittedAt: number; startedAt?: number; endedAt?: number; policy: string;
  retestOf?: string[]; parent?: string; resumeOf?: string; note?: string; reviewed?: 'resumed'|'rerun-advised'|'closed';
  modules: { key: ModuleKey; state: ModuleState; detail?: string }[]; }
interface Finding { id: string; assessmentId: string; jobId: string; severity: Severity; confidence: Confidence; state: FindingState; module: ModuleKey;
  title: string; asset: string; param?: string; retest?: string; history: { at: number; by: string; text: string }[];
  comments: { at: number; by: string; text: string }[]; }
interface FindingLocation { url: string; host: string; port: string; path: string|null; param: string|null; method: string|null;
  component: string|null; kind: 'Web page'|'API endpoint'|'File'|'Network service'|'Cookie'|'Response header'|'TLS certificate'; }
interface Share { id: string; assessmentId: string; user: string; perm: 'view'; expires?: string; by: string; at: number; revoked?: number; }
interface Report { id: string; assessmentId: string; type: 'management'|'technical'; jobId: string; state: 'generating'|'ready'|'failed'; at: number; by: string; version: number; }
interface Notification { id: string; to: string; at: number; tone: 'ok'|'warn'|'danger'|'info'; text: string; link?: Route; }
interface AuditEvent { at: number; actor: string; category: string; action: string; object: string; outcome: 'success'|'blocked'; detail: string; }
```

Timestamps are stored in UTC and displayed in IST (`Asia/Kolkata`).

---

## 13. Review checklist (run before every UI PR)

- [ ] Only tokens used; no literal colours; light **and** dark checked.
- [ ] Status words, tones and icons match §5 exactly; colour is never the only signal.
- [ ] Severity and confidence shown separately; confidence uses the neutral tag.
- [ ] Disclaimer present where required (§6.6, §6.30).
- [ ] No scan/retest path that skips validation, approval or the authorization checkbox.
- [ ] Permission rules from §11 applied through `permFor`/`can`; denied states handled.
- [ ] High-impact actions confirm and audit (§7.24); reasons required where listed.
- [ ] No false success: interrupted/failed/unavailable/inconclusive never shown as passed.
- [ ] Evidence redacted; no secrets, internal hosts, worker names or stack traces in user-facing UI.
- [ ] Empty, loading, error and denied states implemented.
- [ ] Keyboard, focus ring, labels, live regions, contrast verified.
- [ ] Works at 400px wide without horizontal page scroll.
- [ ] Copy follows §8 (sentence case, verbs, IST dates, ranges, no emoji).
- [ ] Undefined behaviour marked with a `TBD · OD-n` chip and listed in the PR.

---

## 14. Open decisions

Show these with the TBD marker (§6.32) wherever they apply. Do not invent values.

| ID | Decision needed | Where it shows |
|---|---|---|
| OD-1 | Confidence level names | Confidence tags, filters, reports |
| OD-5 | Authentication provider / SSO and MFA scope for owners | Sign-in, Users & Roles → Sign-in & sessions, Profile |
| OD-6 | Profile request caps, rates, crawl depth, timeouts | Scan configuration, Profiles & Modules, Capacity |
| OD-7 | Evidence, report and audit retention periods; RPO/RTO | Evidence caption, Reports & Retention, Audit logs, Health |
| OD-8 | Report branding, classification labels, distribution | Report preview, PDF, Reports & Retention |
| OD-9 | Concurrency ceiling beyond 1–3 | Capacity |
| OD-10 | Queue cap and per-user quota values | Review step, Capacity |
| OD-11 | Password reset procedure | Sign-in, Profile, Create account |
| OD-12 | Credential handling for authenticated testing | Deep Scan configuration |
| OD-13 | Final scanner tools and versions | Finding detail, Modules, Profiles & Modules, Audit, Reports |
| OD-14 | Notification channels (email vs in-app) | Notifications |
| OD-18 | Default outcome when no allow/deny rule matches | Target Policies |
| OD-19 | Session lifetime, idle timeout, sign-in throttling values | Users & Roles → Sign-in & sessions |
