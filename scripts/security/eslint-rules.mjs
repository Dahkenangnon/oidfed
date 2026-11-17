/** Local AST checks for protocol boundaries; dispatch tracing stays within each function. */

const wrappers = new Set([
	"TSAsExpression",
	"TSTypeAssertion",
	"TSNonNullExpression",
	"TSSatisfiesExpression",
	"ChainExpression",
]);
function unwrap(node) {
	while (node && wrappers.has(node.type)) node = node.expression;
	return node;
}
function property(node) {
	node = unwrap(node);
	if (node?.type !== "MemberExpression") return undefined;
	const key = unwrap(node.property);
	if (!node.computed) return key.type === "Identifier" ? key.name : undefined;
	return key.type === "Literal" && ["string", "number"].includes(typeof key.value)
		? String(key.value)
		: undefined;
}
function member(node, object, name) {
	node = unwrap(node);
	const owner = unwrap(node?.object);
	return (
		node?.type === "MemberExpression" &&
		owner?.type === "Identifier" &&
		owner.name === object &&
		property(node) === name
	);
}
function rule(message, create) {
	return { meta: { type: "problem", schema: [], messages: { unsafe: message } }, create };
}

/** Resolve bindings, not identifier spelling, so a shadowed name cannot validate another key. */
function binding(source, node) {
	for (let scope = source.getScope(node); scope; scope = scope.upper) {
		const variable = scope.set.get(node.name);
		if (variable) return variable;
	}
	return undefined;
}
function sameReference(source, left, right) {
	left = unwrap(left);
	right = unwrap(right);
	if (!left || !right || left.type !== right.type) return false;
	if (left.type === "Identifier")
		return left.name === right.name && binding(source, left) === binding(source, right);
	if (left.type === "Literal") return left.value === right.value;
	if (left.type !== "MemberExpression" || !sameReference(source, left.object, right.object))
		return false;
	// Dot access and literal bracket access name the same property. A computed
	// identifier remains a variable reference, never a literal property name.
	const leftKey = property(left),
		rightKey = property(right);
	if (leftKey !== undefined || rightKey !== undefined)
		return leftKey !== undefined && leftKey === rightKey;
	return left.computed && right.computed && sameReference(source, left.property, right.property);
}
function children(source, node) {
	return (source.visitorKeys[node.type] ?? []).flatMap((key) => {
		const value = node[key];
		return Array.isArray(value) ? value.filter(Boolean) : value ? [value] : [];
	});
}
function functionNode(node) {
	return ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(
		node.type,
	);
}

function loopCarried(read, write) {
	for (let node = read.parent; node && !functionNode(node); node = node.parent) {
		if (
			[
				"ForStatement",
				"ForInStatement",
				"ForOfStatement",
				"WhileStatement",
				"DoWhileStatement",
			].includes(node.type) &&
			node.range[0] <= write.range[0] &&
			write.range[1] <= node.range[1]
		)
			return true;
	}
	return false;
}

function memberWrites(source, node) {
	const root = rootReference(node);
	if (root?.type !== "Identifier") return [];
	return (binding(source, root)?.references ?? []).flatMap((reference) => {
		let target = reference.identifier;
		while (target.parent?.type === "MemberExpression" && target.parent.object === target)
			target = target.parent;
		const assignment = target.parent;
		return assignment?.type === "AssignmentExpression" &&
			assignment.left === target &&
			sameReference(source, target, node) &&
			(assignment.range[0] < node.range[0] || loopCarried(node, assignment))
			? [assignment.right]
			: [];
	});
}

// Consider all earlier writes conservatively: a branch that may retain a tainted
// value must not become safe merely because a later assignment exists in the file.
function requestDerived(source, expression, seen = new Set()) {
	const node = unwrap(expression);
	if (!node || seen.has(node)) return false;
	seen.add(node);
	if (functionNode(node)) return false;
	if (
		node.type === "CallExpression" &&
		(property(node.callee) === "get" || member(node.callee, "JSON", "parse"))
	)
		return true;
	if (node.type === "Identifier") {
		return (binding(source, node)?.references ?? []).some(
			(reference) =>
				reference.isWrite() &&
				reference.writeExpr &&
				(reference.identifier.range[0] < node.range[0] ||
					loopCarried(node, reference.identifier)) &&
				requestDerived(source, reference.writeExpr, seen),
		);
	}
	if (
		node.type === "MemberExpression" &&
		memberWrites(source, node).some((value) => requestDerived(source, value, seen))
	)
		return true;
	return children(source, node).some((child) => requestDerived(source, child, seen));
}

function guards(node, truth) {
	node = unwrap(node);
	if (!node) return [];
	if (node.type === "UnaryExpression" && node.operator === "!")
		return guards(node.argument, !truth);
	if (
		node.type === "LogicalExpression" &&
		((node.operator === "&&" && truth) || (node.operator === "||" && !truth))
	)
		return [...guards(node.left, truth), ...guards(node.right, truth)];
	return truth &&
		node.type === "CallExpression" &&
		member(node.callee, "Object", "hasOwn") &&
		node.arguments.length === 2
		? [node]
		: [];
}
function exits(node) {
	if (!node) return false;
	if (["ReturnStatement", "ThrowStatement", "ContinueStatement"].includes(node.type)) return true;
	if (node.type === "BlockStatement") return exits(node.body.at(-1));
	return node.type === "IfStatement" && exits(node.consequent) && exits(node.alternate);
}
function rootReference(node) {
	node = unwrap(node);
	while (node?.type === "MemberExpression") node = unwrap(node.object);
	return node;
}
function referenceRoots(node) {
	node = unwrap(node);
	if (node?.type === "Identifier") return [node];
	if (node?.type !== "MemberExpression") return [];
	return [...referenceRoots(node.object), ...(node.computed ? referenceRoots(node.property) : [])];
}
function guarded(source, call, registry, key) {
	const candidates = [];
	let boundary = call;
	for (let node = call.parent; node && !functionNode(node); boundary = node, node = node.parent) {
		if (node.type === "IfStatement") {
			if (boundary === node.consequent) candidates.push(...guards(node.test, true));
			if (boundary === node.alternate) candidates.push(...guards(node.test, false));
		}
		if (node.type === "LogicalExpression" && boundary === node.right) {
			if (node.operator === "&&") candidates.push(...guards(node.left, true));
			if (node.operator === "||") candidates.push(...guards(node.left, false));
		}
		if (node.type === "BlockStatement" || node.type === "Program") {
			for (const previous of node.body.slice(0, node.body.indexOf(boundary))) {
				if (previous.type !== "IfStatement") continue;
				if (exits(previous.consequent)) candidates.push(...guards(previous.test, false));
				if (exits(previous.alternate)) candidates.push(...guards(previous.test, true));
			}
		}
	}
	return candidates.some((guard) => {
		if (
			!sameReference(source, guard.arguments[0], registry) ||
			!sameReference(source, guard.arguments[1], key)
		)
			return false;
		// A local Object replacement is not the built-in membership check.
		if (binding(source, unwrap(unwrap(guard.callee).object))?.defs.length) return false;
		const start = guard.range[1];
		let end = call.range[0];
		// A guard outside a loop cannot validate keys reassigned on its back edge.
		for (let node = call.parent; node && !functionNode(node); node = node.parent) {
			if (
				[
					"ForStatement",
					"ForInStatement",
					"ForOfStatement",
					"WhileStatement",
					"DoWhileStatement",
				].includes(node.type) &&
				start <= node.range[0]
			)
				end = Math.max(end, node.range[1]);
		}
		const roots = [...referenceRoots(registry), ...referenceRoots(key)];
		let valid = true;
		const visit = (node) => {
			if (!valid || node.range[1] <= start || node.range[0] >= end || functionNode(node)) return;
			if (node.type === "Identifier" && roots.some((root) => sameReference(source, root, node))) {
				const reference = binding(source, node)?.references.find((ref) => ref.identifier === node);
				if (reference?.isWrite()) valid = false;
			}
			if (
				["AssignmentExpression", "UpdateExpression"].includes(node.type) ||
				(node.type === "UnaryExpression" && node.operator === "delete")
			) {
				const target = node.left ?? node.argument;
				if (roots.some((root) => sameReference(source, root, rootReference(target)))) valid = false;
			}
			for (const child of children(source, node)) visit(child);
		};
		let container = call;
		while (container.parent && !functionNode(container.parent)) container = container.parent;
		for (const child of children(source, container)) visit(child);
		return valid;
	});
}

export default {
	rules: {
		"no-wrapped-function-constructor": rule(
			"TypeScript wrappers do not make the global Function constructor safe.",
			(context) => {
				// The core rule handles bare constructors. Cover only the wrappers it
				// cannot follow, and preserve its treatment of locally shadowed names.
				const inspect = (node) => {
					const callee = unwrap(node.callee);
					if (
						callee !== node.callee &&
						callee?.type === "Identifier" &&
						callee.name === "Function" &&
						!binding(context.sourceCode, callee)?.defs.length
					)
						context.report({ node, messageId: "unsafe" });
				};
				return { CallExpression: inspect, NewExpression: inspect };
			},
		),
		"no-inherited-auth-dispatch": rule(
			"Check registry membership with Object.hasOwn or use Map before dispatching a request-derived key.",
			(context) => ({
				CallExpression(node) {
					const callee = unwrap(node.callee);
					if (
						callee?.type === "MemberExpression" &&
						callee.computed &&
						requestDerived(context.sourceCode, callee.property) &&
						!guarded(context.sourceCode, node, callee.object, callee.property)
					)
						context.report({ node, messageId: "unsafe" });
				},
			}),
		),
		"no-prototype-assign-from-json": rule(
			"Copy decoded member names with setOwn or a null-prototype dictionary.",
			(context) => ({
				CallExpression(node) {
					const target = unwrap(node.arguments[0]);
					if (
						member(node.callee, "Object", "assign") &&
						target?.type === "ObjectExpression" &&
						!target.properties.length &&
						node.arguments.slice(1).some((arg) => {
							const value = unwrap(arg);
							return value?.type === "CallExpression" && member(value.callee, "JSON", "parse");
						})
					)
						context.report({ node, messageId: "unsafe" });
				},
			}),
		),
		"no-unbounded-fetch": rule(
			"Use the shared bounded transport so timeouts, response limits, and redirects are enforced.",
			(context) => ({
				CallExpression(node) {
					const callee = unwrap(node.callee);
					if (
						(callee?.type === "Identifier" && callee.name === "fetch") ||
						member(callee, "globalThis", "fetch")
					)
						context.report({ node, messageId: "unsafe" });
				},
			}),
		),
		"no-secret-logging": rule("Keep authentication material out of log messages.", (context) => ({
			CallExpression(node) {
				if (!["debug", "info", "warn", "error"].includes(property(unwrap(node.callee)))) return;
				if (
					node.arguments.some((argument) => {
						const value = unwrap(argument);
						return (
							value?.type === "Identifier" &&
							[
								"privateKey",
								"clientSecret",
								"clientAssertion",
								"client_secret",
								"client_assertion",
							].includes(value.name)
						);
					})
				)
					context.report({ node, messageId: "unsafe" });
			},
		})),
	},
};
