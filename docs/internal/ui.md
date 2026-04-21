# @oidfed/ui

Private shared UI component library built on [Coss UI](https://coss.com/ui/docs) (shadcn-style) + [Base UI](https://base-ui.com/) + Tailwind CSS v4.

## Role

Provides 53 reusable UI components consumed by all apps (`explorer`, `home`, `learn`). This package is **private** — it is not published to npm.

## Import convention

All components are re-exported from a single barrel entry point:

```ts
import { Button, Card, Tabs, TabsList, TabsTrigger } from "@oidfed/ui";
```

The `cn` utility and `useIsMobile` / `useMediaQuery` hooks are also available:

```ts
import { cn, useIsMobile } from "@oidfed/ui";
```

## No build step

Vite resolves TypeScript sources directly via the workspace symlink. There is no `build` script — the `typecheck` script validates types only.

## Adding new components

Run `npx coss add <component>` from `apps/explorer/` — `components.json` is configured to write into `internal/ui/src/components/`. After adding, export the new component from `internal/ui/src/index.ts`.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `@base-ui/react` | Headless UI primitives |
| `class-variance-authority` | Variant styling |
| `clsx` + `tailwind-merge` | Class name merging (`cn`) |
| `lucide-react` | Icons |
| `input-otp` | OTP input component |
| `react-day-picker` | Calendar / date picker |

Peer dependencies: `react`, `react-dom` (^19).

## Tailwind source scanning

Apps that consume `@oidfed/ui` must add a `@source` directive in their CSS so Tailwind v4 scans the component files:

```css
@source "../../../internal/ui/src";
```

The path is relative to the CSS file location.
