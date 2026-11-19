/** The Explorer explicitly opts into its browser's Web Crypto implementation. */
import { createWebCryptoEngine } from "@oidfed/crypto/web";

export const engine = createWebCryptoEngine();
