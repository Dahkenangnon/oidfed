/** HTTP handler and middleware contracts for authority hosts. */

export type FederationHandler = (request: Request) => Promise<Response>;

export type Middleware = (
	request: Request,
	next: (request: Request) => Promise<Response>,
) => Promise<Response>;
