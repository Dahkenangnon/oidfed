/** HTTP handler contract for authority hosts. */

export type FederationHandler = (request: Request) => Promise<Response>;
