# @oidfed/ui

Shared UI components built on [Coss UI](https://coss.com/ui/docs) and [Base UI](https://base-ui.com/), styled with Tailwind CSS v4.

## Import convention

Import every component, utility, and hook from the barrel; subpath imports are not supported:

```ts
import { Button, Card, Tabs, cn, useIsMobile } from "@oidfed/ui";
```

## No build step

Vite resolves TypeScript sources directly via the workspace symlink. There is no `build` script; the `typecheck` script validates types only.

## Adding new components

The explorer's `components.json` registers `@coss` and maps its UI alias to `internal/ui/src/components/`. From `apps/explorer/`, use the Coss registry installation command for the component you need, then export it from `internal/ui/src/index.ts`. Check the generated imports against the shared barrel convention.

## Tailwind source scanning

Apps that consume `@oidfed/ui` must add a `@source` directive in their CSS so Tailwind v4 scans the component files:

```css
@source "../../../internal/ui/src";
```

The path is relative to the CSS file location.
