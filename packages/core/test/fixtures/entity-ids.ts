import { entityId } from "../../src/types.js";

/** RP entity ID shared across leaf and oidc test suites. */
export const LEAF_ID = entityId("https://rp.example.com");
/** OP entity ID shared across leaf and oidc test suites. */
export const OP_ID = entityId("https://op.example.com");
/** Trust anchor entity ID shared across leaf and oidc test suites. */
export const TA_ID = entityId("https://ta.example.com");
