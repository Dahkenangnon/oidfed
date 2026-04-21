/** Request routing: maps federation endpoint paths to their respective handlers. */
export type FederationHandler = (request: Request) => Promise<Response>;

export type Middleware = (
	request: Request,
	next: (request: Request) => Promise<Response>,
) => Promise<Response>;

/** Composes multiple middleware functions into a single middleware chain. */
export function compose(...middlewares: Middleware[]): Middleware {
	return (request, next) => {
		const dispatch = (i: number, req: Request): Promise<Response> => {
			const mw = middlewares[i];
			if (!mw) {
				return next(req);
			}
			return mw(req, (r) => dispatch(i + 1, r));
		};
		return dispatch(0, request);
	};
}
