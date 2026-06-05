# Examples

The canonical, live example of integrating `@oidfed/*` end-to-end is the reference deployment at [`fed.oidfed.com`](https://fed.oidfed.com), whose source lives at:

**[`Dahkenangnon/fed-oidfed-com`](https://github.com/Dahkenangnon/fed-oidfed-com)**

It runs six OpenID Federation 1.0 topologies (single-anchor, hierarchical, multi-anchor, cross-federation, constrained, policy-operators) on the packages in this repo, and demonstrates a full OpenID Provider + Relying Party with automatic and explicit federation registration.

## Explore the demo federation

Use the demo deployment as input for either the browser Explorer or the CLI:

- **Visual:** open [`explore.oidfed.com`](https://explore.oidfed.com) and import the demo trust anchors from [`fed.oidfed.com`](https://fed.oidfed.com). One-click setup: [`Try the fed.oidfed.com reference deployment`](https://explore.oidfed.com/#/settings?import=https%3A%2F%2Fraw.githubusercontent.com%2FDahkenangnon%2Ffed-oidfed-com%2Fmain%2Fpages%2Fexplorer-settings.json).
- **Terminal:** install [`@oidfed/cli`](https://www.npmjs.com/package/@oidfed/cli), then inspect the same live entities:

```bash
npm install -g @oidfed/cli

oidfed entity https://ta.single.fed.oidfed.com
oidfed list https://ta.single.fed.oidfed.com
oidfed chain https://rp1.single.fed.oidfed.com \
  --trust-anchor https://ta.single.fed.oidfed.com
```

Start with [`fed.oidfed.com`](https://fed.oidfed.com) to pick a topology and entity ID, then use that entity ID in the Explorer or with `oidfed <command>`.
