/** Exercise the actual tarball in consumers with their own dependency installations. */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
	copyFileSync,
	existsSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import ts from "typescript";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function assertPortableGraph(inputs) {
	for (const input of inputs) {
		assert(!/(?:^|\/)jose(?:\/|$)/.test(input), `Unexpected JOSE dependency: ${input}`);
		assert(!input.startsWith("node:"), `Unexpected Node dependency: ${input}`);
	}
}

function run(command, args, cwd) {
	return execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

const runtime = `
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {webcrypto} from 'node:crypto';
const require = createRequire(import.meta.url);
const names = ['crypto','structuredClone','TextEncoder','TextDecoder','Buffer','atob','btoa'];
const descriptors = new Map(names.map(name => [name,Object.getOwnPropertyDescriptor(globalThis,name)]));
function restore() {
  for (const [name,descriptor] of descriptors) {
    if (descriptor) Object.defineProperty(globalThis,name,descriptor);
    else Reflect.deleteProperty(globalThis,name);
  }
}
for (const load of [name => import(name), name => require(name)]) {
  const pair = await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const softwarePair = await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const rawPublic = await webcrypto.subtle.exportKey('jwk',pair.publicKey);
  const rawPrivate = await webcrypto.subtle.exportKey('jwk',softwarePair.privateKey);
  let core, input;
  try {
    for (const name of names) Reflect.deleteProperty(globalThis,name);
    core = await load('@oidfed/crypto');
    const web = await load('@oidfed/crypto/web');
    assert.throws(() => web.createWebCryptoEngine(),error => error instanceof core.CryptoError && error.code === 'UNSUPPORTED_RUNTIME');
    const publicJwk = {...core.toPublicJwk({...rawPublic,kty:'EC'}),kid:'opaque',alg:'ES256'};
    assert.equal(pair.privateKey.extractable,false);
    const signer = {publicJwk,sign:async bytes => new Uint8Array(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,new Uint8Array(bytes).buffer))};
    const hostEngine = {
      algorithms:['ES256'],
      async validatePublicKey(key) { await webcrypto.subtle.importKey('jwk',key,{name:'ECDSA',namedCurve:'P-256'},false,['verify']); },
      digest:async (algorithm,bytes) => new Uint8Array(await webcrypto.subtle.digest(algorithm,new Uint8Array(bytes).buffer)),
      random:async length => webcrypto.getRandomValues(new Uint8Array(length)),
      async verify({key,signingInput,signature}) {
        const imported = await webcrypto.subtle.importKey('jwk',key,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
        return webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},imported,new Uint8Array(signature).buffer,new Uint8Array(signingInput).buffer);
      }
    };
    const ring = new core.StaticKeyring({signers:{custom:signer}});
    const snapshot = await ring.entry('custom');
    const compact = await core.signCompactJws({jwks:snapshot.publishedJwks,message:'hello 😀'}, {alg:'ES256',kid:'opaque'},snapshot.signer);
    const parsed = core.parseCompactJws(compact);
    input = {algorithm:'ES256',key:publicJwk,signingInput:parsed.signingInput,signature:parsed.signature};
    assert.equal(await hostEngine.verify(input),true);
    assert.equal(await web.createWebCryptoEngine(webcrypto).verify(input),true);
    assert.equal((await core.jwkThumbprint(hostEngine,publicJwk)).length,32);
    assert.equal((await hostEngine.random(16)).length,16);
    const inspection = core.decodeCompactJws(core.encodeBase64url(core.utf8Encode(JSON.stringify({alg:'future'})))+'.e30.not a signature!');
    assert.equal(inspection.header.alg,'future');
    let imports = 0;
    const retryBackend = {
      getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
      subtle: {
        async importKey(...args) {
          if (++imports === 1) throw new Error('temporarily unavailable');
          return webcrypto.subtle.importKey(...args);
        },
        sign: webcrypto.subtle.sign.bind(webcrypto.subtle),
        verify: webcrypto.subtle.verify.bind(webcrypto.subtle),
        digest: webcrypto.subtle.digest.bind(webcrypto.subtle)
      }
    };
    const retrySigner = new web.SoftwareSigner({...rawPrivate,kty:'EC',kid:'retry',alg:'ES256'},retryBackend);
    const assertPrivate = () => {
      assert.deepEqual(Reflect.ownKeys(retrySigner), ['publicJwk']);
      assert.equal(JSON.stringify(retrySigner), JSON.stringify({publicJwk:retrySigner.publicJwk}));
      assert.equal(Object.hasOwn(retrySigner.publicJwk,'d'),false);
    };
    assertPrivate();
    const sign = () => retrySigner.sign(new Uint8Array([1,2,3]));
    assert((await Promise.allSettled([sign(),sign()])).every(r=>r.status==='rejected'));
    assert.equal(imports,1);
    await Promise.all([sign(),sign()]);
    assert.equal(imports,2);
    assertPrivate();
    const software = new web.SoftwareSigner({...rawPrivate,kty:'EC',kid:'software',alg:'ES256'},webcrypto);
    const softwareToken = await core.signCompactJws({}, {alg:'ES256',kid:'software'},software);
    const softwareParsed = core.parseCompactJws(softwareToken);
    assert.equal(await hostEngine.verify({...softwareParsed,key:software.publicJwk,algorithm:'ES256'}),true);
    const federation = await load('@oidfed/core');
    const {Leaf} = await load('@oidfed/leaf');
    const authorityExports = await load('@oidfed/authority');
    const oidcExports = await load('@oidfed/oidc');
    const walletExports = await load('@oidfed/wallet');
    const coreValues = new Set(Object.values(federation).filter(value =>
      typeof value === 'function' || (value !== null && typeof value === 'object')));
    for (const [packageName,exports] of Object.entries({authority:authorityExports,leaf:await load('@oidfed/leaf'),oidc:oidcExports,wallet:walletExports})) {
      for (const [name,value] of Object.entries(exports)) {
        assert(!coreValues.has(value), packageName + ' re-exports Core value ' + name);
        if (typeof value !== 'function') continue;
        for (let owner = value; owner && owner !== Function.prototype; owner = Object.getPrototypeOf(owner)) {
          for (const [member,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(owner))) {
            assert(!coreValues.has(descriptor.value), packageName + '.' + name + '.' + member + ' aliases Core');
          }
        }
      }
    }
    assert(!('discoverEntity' in Leaf));
    assert(!('OIDCRegistrationAdapter' in oidcExports));
    const {TrustAnchor,Intermediate} = authorityExports;
    assert(!('setTrustMarkIssuers' in Intermediate.prototype));
    assert(!('setTrustMarkOwners' in Intermediate.prototype));
    assert.equal('InvalidMetadata' in authorityExports, false);
    assert.equal('InvalidSubordinateRecord' in authorityExports, false);
    assert.equal(typeof federation.InvalidMetadata, 'function');
    assert.equal(typeof federation.InvalidSubordinateRecord, 'function');
    const {OidcRelyingPartyRole,OidcProviderRole} = oidcExports;
    const {WalletProviderRole} = walletExports;
    const keyring = new core.StaticKeyring({signers:{federation:signer,request_object:software,wallet_attestation:software},aliases:{client_assertion:'request_object'}});
    const crypto = {engine:hostEngine,keyring};
    const clock = {now:()=>1500};
    const rp = new OidcRelyingPartyRole({signing:{requestObject:'request_object',clientAssertion:'client_assertion'},metadata:{redirect_uris:['https://rp.example/cb'],response_types:['code'],client_registration_types:['automatic','explicit']}});
    const wallet = new WalletProviderRole({signing:{walletAttestation:'wallet_attestation'}});
    const leaf = await Leaf.create({entityId:'https://rp.example',authorityHints:['https://ta.example'],crypto,roles:[rp,wallet],metadata:{federation_entity:{}},options:{clock}});
    const ec = await leaf.getEntityConfiguration();
    const verified = await federation.verifyEntityStatement(ec,{keys:[publicJwk]},{engine:hostEngine,clock});
    assert.equal(verified.ok,true);
    assert.equal(verified.value.payload.metadata.openid_relying_party.jwks.keys[0].kid,'software');
    assert.equal(verified.value.payload.metadata.openid_wallet_provider.jwks.keys[0].kid,'software');
    const assertion = await rp.createClientAssertion('https://op.example');
    assert.equal((await federation.verifyClientAssertion(assertion,{keys:[software.publicJwk]},'https://op.example',{engine:hostEngine,clock})).ok,true);
    const attestation = await wallet.createWalletAttestation({subject:'wallet',confirmationKey:publicJwk,expiresAt:2000});
    assert.equal(attestation.ok,true);
    assert.equal((await new federation.JwsService({engine:hostEngine,clock}).verifyJwt(attestation.value,{keys:[software.publicJwk]},{typ:{expected:'oauth-client-attestation+jwt'},keyId:'allow-single-key'})).ok,true);
    const cache = new federation.MemoryFederationStorage({namespace:"test-cache",capabilities:["cache"],clock}).cache;
    await cache.set('sample',{nested:{value:1}},60);
    const cached = federation.cloneData(await cache.get('sample')); cached.nested.value=2;
    assert.equal((await cache.get('sample')).nested.value,1);
    assert.match(await federation.ecCacheKey('https://rp.example',hostEngine),/^ec:/);
    const replay = new federation.MemoryFederationStorage({namespace:"test-replay",capabilities:["replay"],clock}).replay;
    const claim = {issuer:'issuer',audience:'audience',jti:'id',expiresAt:2000};
    assert.equal(await replay.useJti(claim),true); assert.equal(await replay.useJti(claim),false);
    for (const Host of [TrustAnchor,Intermediate]) {
      const entityId=Host===TrustAnchor?'https://ta.example':'https://ia.example';
      const seen = [];
      const selected = {engine:hostEngine,keyring:{entry(purpose,context){
        assert.equal(context.issuer,entityId); seen.push(context); return keyring.entry(purpose,context);
      }}};
      class ManagedRole extends OidcRelyingPartyRole {
        validateMetadata(metadata) {
          super.validateMetadata(metadata);
          assert.equal(metadata.jwks.keys[0].kid,'software');
        }
      }
      const role=new ManagedRole({signing:{requestObject:'request_object'},metadata:{redirect_uris:[entityId+'/callback']}});
      let refreshedPolicy;
      const collection={trustAnchors:new Map([[entityId,{jwks:{keys:[publicJwk]}}]]),options:{engine:{...hostEngine},allowedAlgorithms:['ES256','RS256'],maxCompactBytes:9000,maxVerificationCandidates:10},collector:async({options})=>{refreshedPolicy=options;return federation.ok([]);}};
      const authority=await Host.create({entityId,crypto:selected,roles:[role],collection,storage:new federation.MemoryFederationStorage({namespace:entityId,clock}),...(Host===Intermediate?{authorityHints:['https://ta.example']}:{}),metadata:{federation_entity:{federation_fetch_endpoint:entityId+'/fetch',federation_list_endpoint:entityId+'/list'}},options:{clock,allowedAlgorithms:['ES256'],maxCompactBytes:5000,maxVerificationCandidates:2}});
      const subordinate='https://sub.example';
      await authority.registerSubordinate({entityId:subordinate,jwks:{keys:[publicJwk]}});
      await authority.getSubordinateStatement(subordinate);
      const markType='https://marks.example/type';
      await authority.issueTrustMarkDelegation(subordinate,markType);
      assert(seen.some(s=>s.subject===subordinate && s.trustMarkType===markType));
      await assert.rejects(authority.issueTrustMarkDelegation(subordinate,markType,{maxCompactBytes:9000,additionalClaims:{sample:'x'.repeat(5000)}}));
      await assert.rejects(authority.issueTrustMarkDelegation(subordinate,markType,{maxCompactBytes:30}));
      assert(seen.some(s=>s.subject===subordinate));
      assert((await authority.collection.refresh(entityId)).ok);
      assert.equal(refreshedPolicy.engine,hostEngine);
      assert.deepEqual(refreshedPolicy.allowedAlgorithms,['ES256']);
      assert.equal(refreshedPolicy.maxCompactBytes,5000);
      assert.equal(refreshedPolicy.maxVerificationCandidates,2);
      assert.equal((await federation.verifyEntityStatement(await authority.getEntityConfiguration(),{keys:[publicJwk]},{engine:hostEngine,clock})).ok,true);
    }
    const anchor = 'https://ta.example';
    const collection = new federation.EntityCollectionService({trustAnchors:new Map([[anchor,{jwks:{keys:[publicJwk]}}]]),options:{engine:hostEngine,clock,storage:new federation.MemoryFederationStorage({namespace:anchor,clock,capabilities:["entityCollection"]})},collector:async()=>federation.ok(['https://one.example','https://two.example'].map(entity_id=>({entity:{entity_id},expiresAt:2000})))});
    const refreshed=await collection.refresh(anchor); assert.equal(refreshed.ok,true,JSON.stringify(refreshed));
    const page=await collection.query({trustAnchor:anchor,limit:1});assert.equal(page.ok,true);assert.equal(page.value.entities.length,1);assert.equal(typeof page.value.next,'string');
    const following=await collection.query({trustAnchor:anchor,from:page.value.next});assert.equal(following.ok,true);assert.equal(following.value.entities[0].entity_id,'https://two.example');
    assert.equal(typeof OidcProviderRole,'function');
    assert.deepEqual(Reflect.ownKeys(keyring), []);
    assert.equal(Object.getOwnPropertyDescriptor(software, 'publicJwk').writable, false);
    const rotating = new core.MemoryRotatingKeyring({custom:signer},{nowSeconds:()=>100});
    await rotating.publish('custom',software);
    await rotating.activate('custom','software');
    await rotating.retire('custom','opaque');
    await rotating.revoke('custom','software','superseded');
    assert.deepEqual(Reflect.ownKeys(rotating), []);
    await assert.rejects(rotating.entry('custom'), error => error instanceof core.CryptoError && error.code === 'KEY_NOT_FOUND');
    const history = await rotating.history('custom');
    assert.equal(history.length,2);
    assert.equal(history[0].publishedAt,100);
    assert.equal(history[0].retiredAt,100);
    assert.equal(history[1].revokedAt,100);
    assert.equal(Object.isFrozen(history[0].publicJwk),true);
  } finally { restore(); }
  if (process.argv.includes('--jose')) {
    try {
      Object.defineProperty(globalThis,'crypto',{value:webcrypto,configurable:true,writable:true});
      const jose = await load('@oidfed/crypto/jose');
      assert.throws(() => jose.createJoseEngine(webcrypto,{algorithms:['invalid']}),error => error instanceof core.CryptoError);
      const engine = jose.createJoseEngine(webcrypto);
      assert.equal(await engine.verify(input),true);
      const signature = input.signature.slice(); signature[0] ^= 255;
      assert.equal(await engine.verify({...input,signature,compact:'stale serialization is ignored'}),false);
    } finally { restore(); }
  }
}
`;

function markedExamples() {
	return ["docs/api", "docs/features"].flatMap((directory) =>
		readdirSync(join(root, directory), { recursive: true })
			.filter((file) => file.endsWith(".md"))
			.sort()
			.flatMap((file) => {
				const source = `${directory}/${file}`;
				const markdown = readFileSync(join(root, source), "utf8");
				const examples = [
					...markdown.matchAll(/^<!-- oidfed-example -->\n```(?:ts|typescript)\n([\s\S]*?)^```$/gm),
				];
				assert.equal(
					examples.length,
					[...markdown.matchAll(/^<!-- oidfed-example -->$/gm)].length,
					`Each example marker in ${source} must precede a TypeScript block`,
				);
				return examples.map((match) => ({
					source,
					line: markdown.slice(0, match.index).split("\n").length + 2,
					code: match[1],
				}));
			}),
	);
}

/** Follow public declaration aliases through barrel files and renamed types. */
function assertCoreTypeOwnership(consumer, program, files) {
	const checker = program.getTypeChecker();
	const resolveAlias = (symbol) =>
		symbol && symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
	for (const file of files) {
		const source = program.getSourceFile(file);
		assert(source, `Missing ownership consumer in ${consumer}`);
		const [core, ...packages] = source.statements.map((statement) => {
			const module = checker.getSymbolAtLocation(statement.moduleSpecifier);
			assert(module, `Cannot resolve ${statement.moduleSpecifier.text} from ${file}`);
			return checker.getExportsOfModule(module);
		});
		const owned = new Set(core.map(resolveAlias));
		function refersToCore(symbol, visited = new Set()) {
			const target = resolveAlias(symbol);
			if (!target || visited.has(target)) return false;
			if (owned.has(target)) return true;
			visited.add(target);
			return target.declarations?.some(
				(declaration) => ts.isTypeAliasDeclaration(declaration) &&
					ts.isTypeReferenceNode(declaration.type) &&
					!declaration.type.typeArguments &&
					refersToCore(checker.getSymbolAtLocation(declaration.type.typeName), visited),
			);
		}
		for (const [index, exports] of packages.entries()) {
			const name = source.statements[index + 1].moduleSpecifier.text;
			for (const exported of exports)
				assert(!refersToCore(exported), `${name} re-exports Core declaration ${exported.name}`);
		}
	}
}

/** Compile the quick starts and marked standalone examples against packed declarations. */
function checkDocumentedExamples(consumer) {
	const sources = [
		"README.md",
		...["core", "crypto", "authority", "leaf", "oidc"].map((name) => `packages/${name}/README.md`),
	];
	const files = sources.flatMap((source, index) => {
		const markdown = readFileSync(join(root, source), "utf8");
		const examples = [...markdown.matchAll(/^`{3}ts\n([\s\S]*?)^`{3}$/gm)];
		assert(examples.length, "Missing TypeScript quick start in " + source);
		return examples.map(([, code], section) => {
			const file = join(consumer, `quick-start-${index}-${section}.mts`);
			writeFileSync(file, code);
			return file;
		});
	});
	for (const name of ["custom-crypto", "software-crypto"]) {
		const file = join(consumer, `${name}.mts`);
		copyFileSync(join(root, `docs/examples/${name}.ts`), file);
		files.push(file);
	}
	const examples = markedExamples();
	assert(examples.length, "Missing standalone documentation examples");
	const exampleSources = new Map();
	for (const [index, { source, line, code }] of examples.entries()) {
		const file = join(consumer, `documentation-example-${index}.mts`);
		writeFileSync(file, "\n".repeat(line - 1) + code + "\nexport {};\n");
		files.push(file);
		exampleSources.set(file, source);
	}
	// Use the application's own Zod import and the packed Core declarations.
	const collectionSource = `import { z } from "zod";
import { EntityIdSchema, entityId, type EntityCollectionStore, type EntityId } from "@oidfed/core";
const idSchema: z.ZodType<EntityId, string> = EntityIdSchema;
const composed = z.object({ entity_id: idSchema });
const parsed: EntityId = composed.parse({ entity_id: "https://leaf.example/" }).entity_id;
declare const collection: EntityCollectionStore;
void collection.publish({
  id: "snapshot",
  lastUpdated: 1000,
  trustAnchor: entityId("https://anchor.example/"),
  entries: [
    { entity: { entity_id: entityId("https://leaf.example/") }, expiresAt: 2000, verifiedMarks: [] },
    { entity: { entity_id: parsed }, expiresAt: 2000, verifiedMarks: [] },
  ],
});
`;
	const ownershipFiles = [];
	for (const extension of ["mts", "cts"]) {
		const file = join(consumer, `collection.${extension}`);
		writeFileSync(file, collectionSource);
		files.push(file);
		const ownership = join(consumer, `ownership.${extension}`);
		writeFileSync(ownership, ["core", "authority", "leaf", "oidc", "wallet"]
			.map((name) => `import "@oidfed/${name}";`).join("\n"));
		ownershipFiles.push(ownership);
		files.push(ownership);
	}
	const program = ts.createProgram(files, {
		strict: true,
		exactOptionalPropertyTypes: true,
		noEmit: true,
		module: ts.ModuleKind.NodeNext,
		target: ts.ScriptTarget.ES2022,
		lib: ["lib.es2022.d.ts", "lib.dom.d.ts", "lib.dom.iterable.d.ts"],
		types: [],
	});
	const diagnostics = ts.getPreEmitDiagnostics(program);
	const formatHost = {
		getCurrentDirectory: () => consumer,
		getCanonicalFileName: (file) => file,
		getNewLine: () => "\n",
	};
	assert.equal(
		diagnostics.length,
		0,
		diagnostics.map((diagnostic) => {
			const file = diagnostic.file?.fileName;
			const source = exampleSources.get(file);
			const message = ts.formatDiagnostic(diagnostic, formatHost);
			return source ? message.replace(relative(consumer, file), () => source) : message;
		}).join(""),
	);
	assertCoreTypeOwnership(consumer, program, ownershipFiles);
	const comparison = examples.find(
		({ source, code }) =>
			source === "docs/features/9.6.anchor-key-consistency.md" &&
			code.includes("export async function checkCampusKeys("),
	);
	assert(comparison, "Missing Trust Anchor key comparison example");
	const compiled = ts.transpileModule(comparison.code, {
		compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
	});
	writeFileSync(join(consumer, "anchor-key-comparison.mjs"), compiled.outputText);
	copyFileSync(
		join(root, "tests/scripts/fixtures/anchor-key-comparison.mjs"),
		join(consumer, "test-anchor-key-comparison.mjs"),
	);
	run(process.execPath, ["test-anchor-key-comparison.mjs"], consumer);
	process.stdout.write(
		`Packed documentation check OK: ${examples.length} standalone examples and Trust Anchor retry\n`,
	);
}

function types(consumer, includeJose) {
	const sample = `import {type CryptoEngine, type Keyring, type PublicJwk, StaticKeyring} from '@oidfed/crypto';
import {createWebCryptoEngine, type WebCryptoLike} from '@oidfed/crypto/web';
${includeJose ? "import {createJoseEngine} from '@oidfed/crypto/jose';" : ""}
declare const implementation: WebCryptoLike;
const engine: CryptoEngine = createWebCryptoEngine(implementation);
const ring: Keyring = new StaticKeyring({signers:{}});
const anonymous: PublicJwk = {kty:'EC'};
void [engine,ring,anonymous${includeJose ? ",createJoseEngine(implementation)" : ""}];
`;
	for (const [extension, module, moduleResolution] of [
		["mts", ts.ModuleKind.NodeNext, ts.ModuleResolutionKind.NodeNext],
		["cts", ts.ModuleKind.NodeNext, ts.ModuleResolutionKind.NodeNext],
		["ts", ts.ModuleKind.ESNext, ts.ModuleResolutionKind.Bundler],
	]) {
		const file = join(consumer, `consumer.${extension}`);
		writeFileSync(file, sample);
		const program = ts.createProgram([file], {
			strict: true,
			exactOptionalPropertyTypes: true,
			noEmit: true,
			skipLibCheck: false,
			target: ts.ScriptTarget.ES2022,
			lib: ["lib.es2022.d.ts"],
			types: [],
			module,
			moduleResolution,
		});
		const diagnostics = ts.getPreEmitDiagnostics(program);
		assert.equal(
			diagnostics.length,
			0,
			ts.formatDiagnostics(diagnostics, {
				getCanonicalFileName: (file) => file,
				getCurrentDirectory: () => consumer,
				getNewLine: () => "\n",
			}),
		);
	}
}

// Run before installing the full consumer so Node cannot resolve from a parent node_modules.
function checkHostInstall(consumer, names, archives, packageManager) {
	const host = mkdtempSync(join(consumer, "host-"));
	const overrides = Object.fromEntries(
		Object.entries(archives).map(([name, file]) => [name, file.replace("file:./", "file:../")]),
	);
	const dependencies = Object.fromEntries(names.map((name) => [name, overrides[name]]));
	writeFileSync(
		join(host, "package.json"),
		JSON.stringify({ private: true, packageManager, dependencies, pnpm: { overrides } }),
	);
	writeFileSync(
		join(host, ".npmrc"),
		"auto-install-peers=false\nstrict-peer-dependencies=true\nhoist=false\nnode-linker=isolated\n",
	);
	run("pnpm", ["install", "--prod", "--offline", "--ignore-scripts"], host);

	writeFileSync(
		join(host, "entrypoints.mjs"),
		`import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const [host, role] = process.argv.slice(2);
for (const name of ["@oidfed/core", "zod", "jose"]) {
	assert.throws(() => require.resolve(name), { code: "MODULE_NOT_FOUND" });
}
for (const name of [host, role]) {
	require(name);
	await import(name);
}
const hostRequire = createRequire(require.resolve(host));
const roleRequire = createRequire(require.resolve(role));
const core = hostRequire.resolve("@oidfed/core");
assert.equal(roleRequire.resolve("@oidfed/core"), core);
const coreRequire = createRequire(core);
coreRequire("@oidfed/crypto");
assert.equal(roleRequire.resolve("zod/package.json"), coreRequire.resolve("zod/package.json"));
`,
	);
	run(process.execPath, ["entrypoints.mjs", ...names], host);
	assert(!readFileSync(join(host, "pnpm-lock.yaml"), "utf8").includes("jose@"));
}

/** Stage the six consumer dependencies, retaining the exact saved bytes in release mode. */
export function stageLibraryArchives(consumer, savedArchives) {
	const dependencies = {};
	for (const name of ["crypto", "core", "authority", "leaf", "oidc", "wallet"]) {
		let archive;
		if (savedArchives !== undefined) {
			assert(savedArchives[name], "Missing saved " + name + " tarball");
			archive = name + ".tgz";
			copyFileSync(savedArchives[name], join(consumer, archive));
		} else {
			run(
				"pnpm",
				["--dir", join(root, "packages", name), "pack", "--pack-destination", consumer],
				root,
			);
			archive = readdirSync(consumer).find(
				(file) => file.startsWith("oidfed-" + name + "-") && file.endsWith(".tgz"),
			);
			assert(archive, "Missing " + name + " tarball");
		}
		dependencies["@oidfed/" + name] = "file:./" + archive;
	}
	return dependencies;
}

export async function checkCryptoIsolation(savedArchives) {
	const consumer = mkdtempSync(join(tmpdir(), "oidfed-crypto-consumer-"));
	try {
		const dependencies = stageLibraryArchives(consumer, savedArchives);
		run(
			"pnpm",
			[
				"--dir",
				join(root, "packages/core/node_modules/zod"),
				"pack",
				"--config.ignore-scripts=true",
				"--pack-destination",
				consumer,
			],
			root,
		);
		const zodArchive = readdirSync(consumer).find(
			(file) => file.startsWith("zod-") && file.endsWith(".tgz"),
		);
		assert(zodArchive, "Missing installed Zod tarball");
		const overrides = { ...dependencies };
		const packageManager = JSON.parse(
			readFileSync(join(root, "package.json"), "utf8"),
		).packageManager;
		for (const names of [["@oidfed/leaf", "@oidfed/wallet"], ["@oidfed/authority", "@oidfed/oidc"]]) {
			checkHostInstall(consumer, names, overrides, packageManager);
		}
		// The app and libraries use the same Zod archive in the schema-composition fixture.
		const zodSpec = `file:./${zodArchive}`;
		writeFileSync(
			join(consumer, "package.json"),
			JSON.stringify({
				private: true,
				type: "module",
				packageManager,
				dependencies: { ...dependencies, zod: zodSpec },
				pnpm: { overrides: { ...overrides, zod: zodSpec } },
			}),
		);
		run("pnpm", ["install", "--offline", "--ignore-scripts"], consumer);
		assert(
			!existsSync(join(consumer, "node_modules/jose")),
			"JOSE must not be installed by the optional peer",
		);
		assert(
			!readFileSync(join(consumer, "pnpm-lock.yaml"), "utf8").includes("jose@"),
			"Consumer lockfile unexpectedly resolves JOSE",
		);
		const require = createRequire(join(consumer, "package.json"));
		const zod = require.resolve("zod/package.json");
		for (const name of ["core", "oidc", "wallet"]) {
			assert.equal(createRequire(require.resolve(`@oidfed/${name}`)).resolve("zod/package.json"), zod);
		}
		const { z: appZod } = require("zod");
		const composed = appZod.object({ entity_id: require("@oidfed/core").EntityIdSchema });
		const entity = { entity_id: "https://leaf.example/" };
		assert.deepEqual(composed.parse(entity), entity);
		assert.equal(appZod.toJSONSchema(composed).properties.entity_id.format, "uri");
		writeFileSync(join(consumer, "runtime.mjs"), runtime);
		run(process.execPath, ["runtime.mjs"], consumer);
		types(consumer, false);
		const bundle = await build({
			stdin: {
				contents: ["crypto", "core", "authority", "leaf", "oidc", "wallet"]
					.map((name) => "export * as " + name + " from '@oidfed/" + name + "';")
					.join("\n"),
				resolveDir: consumer,
				sourcefile: "portable.ts",
			},
			bundle: true,
			platform: "browser",
			format: "esm",
			write: false,
			metafile: true,
		});
		assertPortableGraph(Object.keys(bundle.metafile.inputs));
		run(
			"pnpm",
			[
				"--dir",
				join(root, "node_modules/jose"),
				"pack",
				"--config.ignore-scripts=true",
				"--pack-destination",
				consumer,
			],
			root,
		);
		const joseArchive = readdirSync(consumer).find(
			(file) => file.startsWith("jose-") && file.endsWith(".tgz"),
		);
		assert(joseArchive, "Missing installed JOSE tarball");
		run("pnpm", ["add", "file:./" + joseArchive, "--offline", "--ignore-scripts"], consumer);
		run(process.execPath, ["runtime.mjs", "--jose"], consumer);
		types(consumer, true);
		checkDocumentedExamples(consumer);
		process.stdout.write(
			"Six-library crypto isolation OK: packed ESM/CJS, NodeNext/bundler declarations, browser graph, host contracts without Web globals, opaque custody, optional JOSE and error identity\n",
		);
	} finally {
		rmSync(consumer, { recursive: true, force: true });
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await checkCryptoIsolation();
