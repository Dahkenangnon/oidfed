/** Positive and negative examples for the local security rules; never executed. */
// biome-ignore-all lint/security/noGlobalEval: Unexecuted fixtures verify that the scanner rejects dynamic execution.

declare const registry: Record<string, () => void>;
declare const parameters: URLSearchParams;
const name = parameters.get("method") ?? "";
declare const logger: { warn(...values: unknown[]): void };
declare const clientSecret: string;
declare const privateKey: string;
declare const publicKey: string;
declare function safeTransport(url: string): void;

// ruleid: no-dynamic-code
eval(name);
// ruleid: no-dynamic-code
new Function(name);
// ruleid: no-inherited-auth-dispatch
registry[name]();
if (Object.hasOwn(registry, name)) {
	// ok: no-inherited-auth-dispatch
	registry[name]();
}
// ruleid: no-prototype-assign-from-json
Object.assign({}, JSON.parse(name));
// ok: no-prototype-assign-from-json
Object.assign(Object.create(null), JSON.parse(name));
// ruleid: no-unbounded-fetch
fetch("https://entity.example");
// ok: no-unbounded-fetch
safeTransport("https://entity.example");
// ruleid: no-secret-logging
logger.warn(clientSecret);
// ruleid: no-secret-logging
logger.warn("Client details", privateKey);
// ruleid: no-secret-logging
logger.warn("Client details", clientSecret, "context");
// ruleid: no-secret-logging
logger.warn("Client details", "context", privateKey);
// ok: no-secret-logging
logger.warn("Public signing key", publicKey);
// ok: no-secret-logging
logger.warn("Client authentication failed");
