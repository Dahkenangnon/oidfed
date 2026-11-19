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
import { dirname, join, resolve } from "node:path";
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
    const {TrustAnchor,Intermediate,MemoryStorageAdapter} = await load('@oidfed/authority');
    const {OidcRelyingPartyRole,OidcProviderRole} = await load('@oidfed/oidc');
    const {WalletProviderRole} = await load('@oidfed/wallet');
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
    const cache = new federation.MemoryCache({clock});
    await cache.set('sample',{map:new Map([['nested',{value:1}]])},60);
    const cached = federation.cloneData(await cache.get('sample')); cached.map.get('nested').value=2;
    assert.equal((await cache.get('sample')).map.get('nested').value,1);
    assert.match(await federation.ecCacheKey('https://rp.example',hostEngine),/^ec:/);
    const replay = new federation.MemoryReplayStore({engine:hostEngine,clock});
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
      const authority=await Host.create({entityId,crypto:selected,roles:[role],collection,storage:new MemoryStorageAdapter({engine:hostEngine}),...(Host===Intermediate?{authorityHints:['https://ta.example']}:{}),metadata:{federation_entity:{federation_fetch_endpoint:entityId+'/fetch',federation_list_endpoint:entityId+'/list'}},options:{clock,allowedAlgorithms:['ES256'],maxCompactBytes:5000,maxVerificationCandidates:2}});
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
    const collection = new federation.EntityCollectionService({trustAnchors:new Map([[anchor,{jwks:{keys:[publicJwk]}}]]),options:{engine:hostEngine,clock},collector:async()=>federation.ok(['https://one.example','https://two.example'].map(entity_id=>({entity:{entity_id},expiresAt:2000})))});
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

/** Compile the actual quick starts against the declarations installed from tarballs. */
function checkDocumentedExamples(consumer) {
	const sources = ["README.md", ...["core","crypto","authority","leaf","oidc"].map(name => "packages/" + name + "/README.md")];
	const files = sources.flatMap((source,index) => {
		const markdown = readFileSync(join(root,source),"utf8");
		const examples = [...markdown.matchAll(/^`{3}ts\n([\s\S]*?)^`{3}$/gm)];
		assert(examples.length, "Missing TypeScript quick start in " + source);
		return examples.map(([,code],section) => {
			const file = join(consumer, "quick-start-" + index + "-" + section + ".mts");
			writeFileSync(file, code);
			return file;
		});
	});
	const adapterExample = join(consumer, "custom-crypto.mts");
	copyFileSync(join(root, "docs/examples/custom-crypto.ts"), adapterExample);
	const program = ts.createProgram([...files, adapterExample], {
		strict: true,
		exactOptionalPropertyTypes: true,
		noEmit: true,
		module: ts.ModuleKind.NodeNext,
		target: ts.ScriptTarget.ES2022,
		lib: ["lib.es2022.d.ts", "lib.dom.d.ts", "lib.dom.iterable.d.ts"],
		types: [],
	});
	const diagnostics = ts.getPreEmitDiagnostics(program);
	assert.equal(diagnostics.length, 0, ts.formatDiagnostics(diagnostics, {
		getCurrentDirectory: () => consumer,
		getCanonicalFileName: file => file,
		getNewLine: () => "\n",
	}));
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
	writeFileSync(join(host, ".npmrc"), "auto-install-peers=false\nhoist=false\nnode-linker=isolated\n");
	run("pnpm", ["install", "--prod", "--offline", "--ignore-scripts"], host);

	const require = createRequire(join(host, "package.json"));
	assert.throws(() => require.resolve("@oidfed/core"), { code: "MODULE_NOT_FOUND" });
	const corePaths = names.map((name) => {
		require(name);
		return createRequire(require.resolve(name)).resolve("@oidfed/core");
	});
	assert.equal(new Set(corePaths).size, 1, `${names.join(" and ")} must resolve the same core`);
}

export async function checkCryptoIsolation(archivePath) {
	const consumer = mkdtempSync(join(tmpdir(), "oidfed-crypto-consumer-"));
	try {
		if (archivePath) copyFileSync(archivePath, join(consumer, "crypto.tgz"));
		else
			run(
				"pnpm",
				["--dir", join(root, "packages/crypto"), "pack", "--pack-destination", consumer],
				root,
			);
		const dependencies = {};
		for (const name of ["crypto", "core", "authority", "leaf", "oidc", "wallet"]) {
			if (name !== "crypto")
				run(
					"pnpm",
					["--dir", join(root, "packages", name), "pack", "--pack-destination", consumer],
					root,
				);
			const archive =
				readdirSync(consumer).find(
					(file) => file.startsWith("oidfed-" + name + "-") && file.endsWith(".tgz"),
				) ?? (name === "crypto" && archivePath ? "crypto.tgz" : undefined);
			assert(archive, "Missing " + name + " tarball");
			dependencies["@oidfed/" + name] = "file:./" + archive;
		}
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
		const overrides = { ...dependencies, zod: "file:./" + zodArchive };
		const packageManager = JSON.parse(
			readFileSync(join(root, "package.json"), "utf8"),
		).packageManager;
		checkHostInstall(consumer, ["@oidfed/leaf", "@oidfed/wallet"], overrides, packageManager);
		checkHostInstall(consumer, ["@oidfed/authority", "@oidfed/oidc"], overrides, packageManager);
		writeFileSync(
			join(consumer, "package.json"),
			JSON.stringify({
				private: true,
				type: "module",
				packageManager,
				dependencies,
				pnpm: { overrides },
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
