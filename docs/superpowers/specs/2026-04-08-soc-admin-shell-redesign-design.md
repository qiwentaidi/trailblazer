# SOC Admin Shell Redesign

## Goal

Redesign the frontend admin shell so the platform feels like a professional SOC console instead of a default Element Plus backend. This phase only rebuilds the shared shell and global visual system, without reworking business logic.

## Scope

This phase covers:

- global theme tokens and base styles
- application shell layout
- top header
- sidebar navigation
- shared content canvas and page spacing rules
- global Element Plus visual overrides for cards, tables, forms, buttons, inputs, tags, dialogs, drawers, tabs, and pagination

This phase does not cover:

- full page-by-page information architecture redesign
- backend behavior changes
- new product features
- login page redesign unless required by the new global theme wiring

## Product Direction

The approved direction is:

- visual style: deep dark SOC console
- information density: hybrid
- accent color: cold cyan-blue
- shell direction: command-center style

Interpretation:

- navigation and shell should feel like a security operations platform
- content areas should stay readable for daily use, not become a large-screen dashboard
- the UI should feel stable, high-signal, and data-oriented

## Design Principles

The shell should optimize for:

- strong hierarchy
- restrained enterprise aesthetics
- clear panel boundaries
- fast scanning in list and detail pages
- low-noise dark surfaces
- consistent status signaling

The redesign must avoid:

- default Element Plus white-card look
- bright neon effects
- decorative gradients that reduce readability
- consumer SaaS styling
- oversized spacing that wastes screen real estate

## Visual System

### Color

Base palette:

- background: dark graphite and blue-black surfaces, not pure black
- primary accent: cold cyan-blue
- panel borders: low-contrast steel-blue lines
- secondary text: cool gray-blue
- success: restrained teal-green
- warning: muted amber
- danger: controlled red

Rules:

- cyan-blue is the only strong accent
- risk and state colors must remain distinct from the primary accent
- surface contrast should come from layered dark panels, borders, and subtle shadows rather than bright fills

### Typography

Typography should feel more technical and controlled than the current `Inter/system-ui` default stack while remaining stable for Chinese text rendering.

Rules:

- use a more console-oriented Latin-first stack for titles, labels, and numeric data
- keep Chinese fallback rendering stable and readable
- emphasize weight, letter spacing, and hierarchy rather than large font sizes

### Shape and Depth

- corners should be tighter than the current default Element feel
- cards and panels should use subtle depth and crisp outlines
- avoid soft, playful rounding
- depth should be created with layers and shadows, not heavy blur

## Shell Layout

### Header

The header becomes a compact control bar.

Requirements:

- thinner and sharper than the current generic white header
- brand block on the left with a more platform-like identity treatment
- user entry on the right
- reserve room for future system status indicators
- no crowded center content

### Sidebar

The sidebar becomes a strong structural navigation rail.

Requirements:

- dark equipment-rack feel
- active item uses cyan-blue edge lighting plus darker filled state
- collapsed mode preserves recognizability
- item rhythm should feel operational, not consumer-app-like

### Content Canvas

`el-main` should no longer feel like a raw container.

Requirements:

- outer app background remains dark and atmospheric
- inner content canvas provides a consistent reading surface
- page content should inherit unified spacing, max widths where helpful, and section rhythm

## Component System

### Cards

- deep-panel surfaces
- tighter corners
- stronger border definition
- consistent header/body spacing

### Tables

- more structured than default Element tables
- improved row separation and header hierarchy
- compact but readable density
- action columns and tags should look native to the shell

### Forms

- controls should feel denser and more professional
- focus state uses cyan-blue glow or edge emphasis
- labels and helper text should match the new hierarchy

### Status and Risk Tags

Approved state language:

- running: cyan-blue
- completed: teal-green
- failed: muted red
- stopped/pending: slate/gray family

Risk tags should remain semantically distinct and readable inside the new dark theme.

## File Strategy

Primary files for this phase:

- `/Users/qwtd/WorkManageCode/trailblazer/frontend/src/style.css`
- `/Users/qwtd/WorkManageCode/trailblazer/frontend/src/App.vue`
- `/Users/qwtd/WorkManageCode/trailblazer/frontend/src/components/Sidebar.vue`

Optional supporting files:

- a new theme stylesheet such as `frontend/src/styles/theme-soc.css`
- small shared shell wrappers if needed, but avoid broad refactors in this phase

## Implementation Boundaries

This phase should leave page internals mostly intact while making every page immediately inherit the new shell language.

Allowed:

- light page-level touch-ups required for the shell to fit cleanly
- shared page container classes
- token-driven cleanup of existing Element Plus surfaces

Not allowed:

- page-specific redesigns that belong to the next phase
- mixing shell redesign with unrelated feature work

## Verification

Success criteria for this phase:

- every authenticated page clearly inherits the new dark SOC shell
- the platform no longer reads as default Element Plus
- shell-level consistency exists across dashboard, task, search, and settings routes
- the frontend production build passes

## Next Phase

After the shell is complete, redesign these pages to fully exploit the new system:

- dashboard
- task list
- task detail
- search
- settings
