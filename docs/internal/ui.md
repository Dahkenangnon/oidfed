# @oidfed/ui

Shared UI components built on [Coss UI](https://coss.com/ui/docs) (shadcn-style) + [Base UI](https://base-ui.com/) + Tailwind CSS v4.

## Import convention

Import every component, utility, and hook from the barrel — subpath imports are not supported:

```ts
import { Button, Card, Tabs, cn, useIsMobile } from "@oidfed/ui";
```

## No build step

Vite resolves TypeScript sources directly via the workspace symlink. There is no `build` script — the `typecheck` script validates types only.

## Adding new components

Run `npx coss add <component>` from `apps/explorer/` — `components.json` is configured to write into `internal/ui/src/components/`. After adding, export the new component from `internal/ui/src/index.ts`.

## Tailwind source scanning

Apps that consume `@oidfed/ui` must add a `@source` directive in their CSS so Tailwind v4 scans the component files:

```css
@source "../../../internal/ui/src";
```

The path is relative to the CSS file location.
