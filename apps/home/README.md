# OidFed Home

The home site for the OidFed OpenID Federation SDK, including the documentation, ecosystem, and Trust Journal.

Run `pnpm --filter @oidfed/home dev` from the repository root. The Home build reads the repository’s `docs/` directory and prerenders its Markdown pages and TypeScript helpers, along with the sitemap. For example, `docs/api/leaf/README.md` is served at `/docs/api/leaf`. Edit the files under `docs/` to update the site. Links to other documentation pages stay on oidfed.com. Links to repository files outside `docs/` open GitHub.

Deploy `apps/home/build/client` as a static site. Serve the prerendered directory indexes and `.data` files alongside the assets and the SPA fallback.
