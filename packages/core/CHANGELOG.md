# Changelog

All notable changes to `@oidfed/core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-26

### Breaking Changes

* authorize federation requests and scope resolve reuse ([8a93565](https://github.com/Dahkenangnon/oidfed/commit/8a935655f5ca15c5f4fdc00b5b8c31be297f1978))
* enforce federation artifact signing policy ([888e2a8](https://github.com/Dahkenangnon/oidfed/commit/888e2a86308baad021346123c109549c3740a704))
* require federation POST selectors in the form ([7997498](https://github.com/Dahkenangnon/oidfed/commit/7997498008d5e674a8488827bca84e268c9bfb64))
* unify storage and federation host contracts ([2882619](https://github.com/Dahkenangnon/oidfed/commit/28826192c47f6eb898a0d1f590c87aa12b3a3d5d))
* require host-provided crypto ([d748f11](https://github.com/Dahkenangnon/oidfed/commit/d748f1168d8819ea5943433400b858e26f7030fb))
* bind verification to caller context ([c138e09](https://github.com/Dahkenangnon/oidfed/commit/c138e09808827d95c83e0b4ea3cc90c5fce47ee4))
* separate Trust Mark results from chain validity ([921bd96](https://github.com/Dahkenangnon/oidfed/commit/921bd96a0b0391590b9c54ead9d0473f6065c6df))

### Features

* verify standalone Trust Mark delegations ([c5777fe](https://github.com/Dahkenangnon/oidfed/commit/c5777fecbcb448e9853351408915860e4cb39fa3))
* share bounded byte and protocol key preparation ([5c120db](https://github.com/Dahkenangnon/oidfed/commit/5c120db993b95b6365df74dc384e20f7c40b970f))
* expose verified Resolve policy and cache outcomes ([fe8a808](https://github.com/Dahkenangnon/oidfed/commit/fe8a808fadb463beaddf8a9e438ac90853178d6f))
* add signed protocol jwks issuance ([4e06cae](https://github.com/Dahkenangnon/oidfed/commit/4e06cae4212a8cac07567358c46e9576385a1fb7))
* serve historical keys and validate endpoint metadata ([6497391](https://github.com/Dahkenangnon/oidfed/commit/64973910bc04840efb690972b1cd14846e780808))
* configure request object typing policies ([a7e7de2](https://github.com/Dahkenangnon/oidfed/commit/a7e7de2a8f46084db3285d8055c5683049f53ac2))
* support custom extended listing filters ([e1c30be](https://github.com/Dahkenangnon/oidfed/commit/e1c30be3f99b375c952c7be2f997cd13de878c45))
* project stored extended listing claims ([a888350](https://github.com/Dahkenangnon/oidfed/commit/a88835017bce503b12abb509d07841ff2dde6b8d))
* add configurable collection query matching ([14a9150](https://github.com/Dahkenangnon/oidfed/commit/14a915072f6790717d31b5a8b8d75675ee4af545))
* add shared client attestation and authentication helpers ([c905345](https://github.com/Dahkenangnon/oidfed/commit/c9053456130eb849a4cab5a574971be6efb80892))
* add standalone federation resolver hosting ([86ea2bc](https://github.com/Dahkenangnon/oidfed/commit/86ea2bc5c3fe850a1bb1ace9cc2aba9f51e7cedb))
* add trusted assessments and supplied-chain discovery ([0488657](https://github.com/Dahkenangnon/oidfed/commit/0488657a7cecea4fac9c2d46de81a80726a20dd7))
* add configurable trust chain selection ([e13093d](https://github.com/Dahkenangnon/oidfed/commit/e13093d90819c553ee96bc98b2927f45b3141de2))
* support critical extensions in Entity Statement publication ([a558bea](https://github.com/Dahkenangnon/oidfed/commit/a558bea6f091c8e0bdcf31b0d4853dabde5df28e))
* select endpoint authentication per responder ([0664997](https://github.com/Dahkenangnon/oidfed/commit/0664997f5b99888527b63715378645d812791bab))
* add managed trust mark issuance and holder lifecycle ([8ecd4ef](https://github.com/Dahkenangnon/oidfed/commit/8ecd4ef6bb49340463c8a3970d3dba3afab656f3))
* add trusted issuer evidence and trust mark verification ([caac696](https://github.com/Dahkenangnon/oidfed/commit/caac696d05ddc9f9f35bedfa526b404f7d2e38c5))
* support extensible federation endpoint authentication ([f3cc261](https://github.com/Dahkenangnon/oidfed/commit/f3cc261115f9d82fdfd46bfc1a4ba8d3d22b70e3))
* support custom trust chain constraints ([254ce9b](https://github.com/Dahkenangnon/oidfed/commit/254ce9bf668b76d85fa44797f576c8bae5ec1dc6))
* add shared OAuth authorization server metadata validators ([c0f06ff](https://github.com/Dahkenangnon/oidfed/commit/c0f06ffe8186e97d8dabeb8179cb06664fde3da2))
* configure default collection claim selectors ([ed051ee](https://github.com/Dahkenangnon/oidfed/commit/ed051ee752cb47fc67b8022b3ea15c0db06a5f92))
* support object-valued metadata policies ([89d9ccf](https://github.com/Dahkenangnon/oidfed/commit/89d9ccf922afdac83e2d5ff312754bdadca4b1e2))
* bound supplied trust chains ([a8ed789](https://github.com/Dahkenangnon/oidfed/commit/a8ed7892a929b53b968dceca9ffdaf5434a22064))

### Bug Fixes

* bound explicit registration HTTP transport ([cde0a66](https://github.com/Dahkenangnon/oidfed/commit/cde0a66c3c42f3062873922d5850365f70943115))
* harden Resolve caching and federation signing ([d2c42f6](https://github.com/Dahkenangnon/oidfed/commit/d2c42f646cab7d6f1ef6083495db32dc6829fccc))
* preserve legacy text reader limits ([4279d62](https://github.com/Dahkenangnon/oidfed/commit/4279d626b964e048729d1d12fca5ec4fbcdd7f71))
* keep Resolve eligible after optional fetch exhaustion ([4575f58](https://github.com/Dahkenangnon/oidfed/commit/4575f582644b8ffcdad2075da14f83f823634bee))
* reject invalid signed protocol jwks ([baf1512](https://github.com/Dahkenangnon/oidfed/commit/baf15125aa4991cb6f73bfd508f5cc11424187a2))
* correct metadata, theming, links and docs scrolling ([c6053e4](https://github.com/Dahkenangnon/oidfed/commit/c6053e47549cfa8bce16d99105de940c7c810dd3))
* correct ESM and CommonJS declaration exports ([3475f0b](https://github.com/Dahkenangnon/oidfed/commit/3475f0bbc7cc7eea7c8501e02acb83edd0970375))
* harden metadata writes and HTTP body handling ([a91de89](https://github.com/Dahkenangnon/oidfed/commit/a91de89f9c68b07cd3d7138f463c3e515aea4026))
* validate configured TTLs before publication ([633fad1](https://github.com/Dahkenangnon/oidfed/commit/633fad1efaf507166dc8d44266f3cd60e7745fda))
* isolate and safely compose host metadata ([9ec838a](https://github.com/Dahkenangnon/oidfed/commit/9ec838a3bbb49dcf0973f0a7051a30feada1b7c6))
* snapshot storage inputs before queued writes ([5ea042e](https://github.com/Dahkenangnon/oidfed/commit/5ea042e7283c5a1dece50efc02a246fa95e91769))
* enforce wallet federation metadata requirements ([b0c0f2a](https://github.com/Dahkenangnon/oidfed/commit/b0c0f2a2bb73f964f3b0cfccb08fabd7aadbd9d0))
* contain extended listing storage errors and cancellation ([56ddfb5](https://github.com/Dahkenangnon/oidfed/commit/56ddfb5e8ca34546b4285d9b33238e4771e5de21))
* reject collection credentials in URL queries ([012f501](https://github.com/Dahkenangnon/oidfed/commit/012f501bd24fd246c0e073f7de6e06367898d51d))
* cancel queued collection refreshes safely ([6c355e6](https://github.com/Dahkenangnon/oidfed/commit/6c355e6f3616b683fa7f7faa8c86cd70a4427508))
* honor collection trust mark verification options ([6f3289a](https://github.com/Dahkenangnon/oidfed/commit/6f3289a5125f1e36f298367d44b703f9da633250))
* reconcile custom collection entity types ([47984dd](https://github.com/Dahkenangnon/oidfed/commit/47984dd106b38a5a813cbc57625d7e340f09552b))
* accept valid protocol JWK sets and NumericDates ([347a3ad](https://github.com/Dahkenangnon/oidfed/commit/347a3ad450833ef1c3fe0595fda77cdac5d6d708))
* reject empty trust mark delegations ([ba17ac8](https://github.com/Dahkenangnon/oidfed/commit/ba17ac851e885ac1d0453711c8ace28dcfb29723))
* reject empty metadata policy declarations ([5959dba](https://github.com/Dahkenangnon/oidfed/commit/5959dba7973fe930d97fd0ea21d3583896eced56))
* make policy and trust chain validation stack-safe ([0743251](https://github.com/Dahkenangnon/oidfed/commit/074325172b2103223bc50d7a4d3bf9cd87e2857c))
* isolate trust mark issuer checks from registration context ([9ef0308](https://github.com/Dahkenangnon/oidfed/commit/9ef0308ae318c61a3633899fcd27f52166e8336b))
* reject endpoint redirects portably across runtimes ([8a569ef](https://github.com/Dahkenangnon/oidfed/commit/8a569efea9e4bee37de29694f46b68cf1cf26846))
* honor refresh clocks and bypass stale statement caches ([233c660](https://github.com/Dahkenangnon/oidfed/commit/233c6605e02cc529dce4b8069f7d867291934bd6))
* discover chains beyond configured trust anchors ([29b0921](https://github.com/Dahkenangnon/oidfed/commit/29b09210fe8105a043dce9fb8602b26961aff89d))
* validate Resolve candidates and evidence lifetimes ([790d186](https://github.com/Dahkenangnon/oidfed/commit/790d18644f9f0fd72169398ed80cb258a4ad8646))
* unify fixed endpoint selector matching ([d23a183](https://github.com/Dahkenangnon/oidfed/commit/d23a183e6f85950d27e2812f6830114fca517b8c))
* authenticate federation requests and require HTTP 200 ([46ef55b](https://github.com/Dahkenangnon/oidfed/commit/46ef55b01ddfaafe82699ee9d7152c4ec367a938))
* use own properties for deferred metadata ([87d047e](https://github.com/Dahkenangnon/oidfed/commit/87d047e83198fab05a39d1e71f899ebc80d07496))
* validate subordinate claims before publication ([d0c100c](https://github.com/Dahkenangnon/oidfed/commit/d0c100c25fcff716ae0dfda029603c00c06a2885))
* enforce DNS naming constraint rules ([7dace14](https://github.com/Dahkenangnon/oidfed/commit/7dace14b9c06a1565d4261ee13d9437de9449cf3))
* harden policy dictionaries and callbacks ([34ed35d](https://github.com/Dahkenangnon/oidfed/commit/34ed35d07366f30f4ef7894dadca9f48e8e5ab89))
* harden signed key retrieval and fallback ([e2e0327](https://github.com/Dahkenangnon/oidfed/commit/e2e0327de387d9a685fc9dbabc00f5c6ed74a151))
* require authority fetch and list endpoints ([485c343](https://github.com/Dahkenangnon/oidfed/commit/485c34381b5ef5e646407cbf392012c3d8c92bd3))
* make host logging safe for sync and async sinks ([413b04f](https://github.com/Dahkenangnon/oidfed/commit/413b04faa88e90559fb62a5fbf289459cf259f6d))
* validate resolved metadata and published key usage ([5825b2e](https://github.com/Dahkenangnon/oidfed/commit/5825b2e4fe3f613b66c6dec7dbf424951b7def21))
* scope metadata null checks and authenticate resolver ECs ([483fba1](https://github.com/Dahkenangnon/oidfed/commit/483fba10914c2d3b634ccd90e18bbfffca3541e3))
* enforce trust-chain authority hints and offline wallet guards ([b5b3f07](https://github.com/Dahkenangnon/oidfed/commit/b5b3f074873132a460c45cf3e3b777a92cb2bbc0))
* bound replay keys and enforce expiry after awaits ([efc0fa0](https://github.com/Dahkenangnon/oidfed/commit/efc0fa08ee8d0f26e33faafc9c9e793f77647898))
* honor declared collection information claims ([978efb7](https://github.com/Dahkenangnon/oidfed/commit/978efb766abd4eccc8bce3f11494c6e226db7149))
* retain remote OAuth error details ([eec40b1](https://github.com/Dahkenangnon/oidfed/commit/eec40b1546174e19f4fb4d75af3f75fae30e6e52))
* accept extensible JWK use and operations ([85fee77](https://github.com/Dahkenangnon/oidfed/commit/85fee7786140859a5ebbf2efb5a08187fb58e583))
* retain custom entity type identifiers ([93fee97](https://github.com/Dahkenangnon/oidfed/commit/93fee97f81fea06b107dd7c8205240b7ae053a02))
* validate historical public keys ([00b0965](https://github.com/Dahkenangnon/oidfed/commit/00b09654df9ee341d50a17d48b127251d175ff99))
* isolate policy outputs and guard names ([4d9a303](https://github.com/Dahkenangnon/oidfed/commit/4d9a303cfb82e26a312d10478fbb3ede9a5419e4))
* align extended listing claims ([f6c5bc4](https://github.com/Dahkenangnon/oidfed/commit/f6c5bc465716b80959ebf65d004f8956b09d3378))
* require Entity Statement key sets ([1b2c601](https://github.com/Dahkenangnon/oidfed/commit/1b2c601605c4a99394e5b7c1443b0e1a89bf9853))
* reserve JWT signing headers ([41e9238](https://github.com/Dahkenangnon/oidfed/commit/41e9238abbbdd9f53b01c64e1bf5d2b43ef3ef9d))
* tighten publication and trust checks ([66e88e2](https://github.com/Dahkenangnon/oidfed/commit/66e88e2d6e53880da0d757e4a4a8932b0dfcf27f))
* validate federation boundaries ([5207ec5](https://github.com/Dahkenangnon/oidfed/commit/5207ec5a797d3b58df14b2f147b59bef69f478c2))
* tighten key and registration handling ([40e8526](https://github.com/Dahkenangnon/oidfed/commit/40e8526d427336f3060ec2a5804230e34772bde8))
* validate collection language variants ([b417a20](https://github.com/Dahkenangnon/oidfed/commit/b417a20472c91911bfd312bbdd347928e2005c85))
* validate extended listing public keys ([b1627e9](https://github.com/Dahkenangnon/oidfed/commit/b1627e9e1da9158a929424faa9f00c44870565bf))
* validate resolve response audiences ([afe41f6](https://github.com/Dahkenangnon/oidfed/commit/afe41f636c3c73347bb57ca6085181328c4bb6af))
* serialize policy-generated client scopes ([ae069b4](https://github.com/Dahkenangnon/oidfed/commit/ae069b4e950effcd7834ae3104ff2d4bc588a758))
* allow unequal value and default policies ([d0a6230](https://github.com/Dahkenangnon/oidfed/commit/d0a623041c915b590ff20048756209716f297336))
* apply policies only to declared entity types ([82d852e](https://github.com/Dahkenangnon/oidfed/commit/82d852e810e66228a4d65235e613e11a197cffe0))
* check naming constraints on immediate subordinates ([b416cad](https://github.com/Dahkenangnon/oidfed/commit/b416cadcffa5282058d2c7378ba3f4b260fcb78d))
* validate supplied and resolved federation metadata ([1d01808](https://github.com/Dahkenangnon/oidfed/commit/1d0180871fc3bd5b047d91e42adf9684304fa685))
* separate protocol key identifier requirements ([34ba00e](https://github.com/Dahkenangnon/oidfed/commit/34ba00ec50007360ff7c599916909dcfb433e817))
* validate federation keys before publication ([8267a10](https://github.com/Dahkenangnon/oidfed/commit/8267a10af39e724f92cbead9c69add4e53ee608a))
* reject empty authority hints in public schemas ([67946e9](https://github.com/Dahkenangnon/oidfed/commit/67946e9774f371c2380a26178837b669e95d1b67))
* reuse statements during trust chain resolution ([46683d8](https://github.com/Dahkenangnon/oidfed/commit/46683d8c1573060088101a4f4a5b374809101787))
* verify anchor configuration self-signatures ([5fbe8c1](https://github.com/Dahkenangnon/oidfed/commit/5fbe8c146b87f6cedd1a68eca24946c26188874d))
* reject cyclic trust chains ([7d54352](https://github.com/Dahkenangnon/oidfed/commit/7d543523d0cc92249022aa69e43127443f9fe210))
* preserve historical key lifetimes ([84c5dc5](https://github.com/Dahkenangnon/oidfed/commit/84c5dc5594112616cd0ed2c04ec4ecf2dc5cdc92))
* guard Trust Mark registry lookups ([a4f69b4](https://github.com/Dahkenangnon/oidfed/commit/a4f69b4f66353261a2fcf977147d816157ffb504))
* bind registration to federation trust ([a3bcbf7](https://github.com/Dahkenangnon/oidfed/commit/a3bcbf76b9088f091f39027e6460d518f42a39a1))
* accept trust anchors with superiors ([fde6cb6](https://github.com/Dahkenangnon/oidfed/commit/fde6cb63aa0b64c6cb90cb02da0042c85b6d8526))
* remove the path length constraint cap ([0665cba](https://github.com/Dahkenangnon/oidfed/commit/0665cba589a3000e69d1e33e4478c41a8751f9d0))
* allow custom entity type constraints ([1f75e2e](https://github.com/Dahkenangnon/oidfed/commit/1f75e2e8d7cc7c9f15e9630779e2d85b78d79a04))
* accept custom entity_type values in list filters ([32664f8](https://github.com/Dahkenangnon/oidfed/commit/32664f8b04cbd7bac4b32f49fbc350dad00fbfd3))

### Refactor

* share protocol helpers and remove dead code ([f299374](https://github.com/Dahkenangnon/oidfed/commit/f299374faab2822cd06c543832e0d959e5210c39))
* remove unused resolution concurrency option ([50bc2f2](https://github.com/Dahkenangnon/oidfed/commit/50bc2f2f61675e629805b385124caca2f4a69106))
* centralize stored trust mark eligibility ([a3309f3](https://github.com/Dahkenangnon/oidfed/commit/a3309f37519109c35ac4bbdc76a97c02661f37d7))
* share extended listing request handling ([8b99cea](https://github.com/Dahkenangnon/oidfed/commit/8b99cea35a87c9bd59d8b38ff47920c5e7c0a3fd))


## [2.0.0] - 2026-10-26

### Breaking changes

- Extended Listing replaces `fromEntityId` / `from_entity_id` and `next_entity_id` with opaque `from` and `next` cursors. Legacy cursor names are unsupported. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Client assertions require `exp` and `jti`; `iat` is optional. `VerifiedClientAssertion.jti` is required and `issuedAt` is optional. Authentication integrations must supply replay storage for one-time use. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))

### Added

- Entity Collection Draft 01 service, schemas, storage contracts, and HTTP client. Support custom collectors, refresh-time filters, verified Trust Mark filtering, claim selection, language matching, and opaque pagination. Failed mandatory refresh work preserves the previous snapshot. ([3d69d77](https://github.com/Dahkenangnon/oidfed/commit/3d69d778bd4ea074826e89872467f65e6b2073ab))
- Subordinate Events Draft 01 schemas, media types, and a client that verifies signed histories against caller-supplied trusted authority keys. Requests reject redirects and enforce response byte and time limits. ([4c6398c](https://github.com/Dahkenangnon/oidfed/commit/4c6398cc568149ebeb01377e1df9cdee022ba44c))
- Staged trust-chain validation for request-dependent wallet policies, a composed-role metadata validation hook, and support for wallet claim-path wildcards without accepting null metadata fields elsewhere. ([5863459](https://github.com/Dahkenangnon/oidfed/commit/58634591566fc500f3872b46b480d34d01a29a7b))

### Fixed

- Make federation key transitions atomic and order activations independently of the clock. Copy key inputs and outputs, derive verification-capable public JWKs from WebCrypto signing keys, and preserve revocation timestamps at epoch zero. ([f51d9c6](https://github.com/Dahkenangnon/oidfed/commit/f51d9c64859a099d1720ee66675cd442554aedde))
- Support repeated Extended Listing Trust Mark types and explicit empty claim selections. Accept finite NumericDates and enforce response limits, cancelling unread rejected response bodies. ([6c1c8a6](https://github.com/Dahkenangnon/oidfed/commit/6c1c8a60c234574109aedc062ead11094e99f82a))
- Keep bundled TypeScript declaration generation working with TypeScript 6. ([a473ebb](https://github.com/Dahkenangnon/oidfed/commit/a473ebbb93d166ebcd69f9c8c52d376e48ff29fc))
- Update JOSE and schema-validation dependencies. ([d83b296](https://github.com/Dahkenangnon/oidfed/commit/d83b296634b86ae059cd71aa79b2a77d6fd05b89)) ([692ef7d](https://github.com/Dahkenangnon/oidfed/commit/692ef7de7218c2085983fd05a620051f35c5971e))

## [1.0.0] - 2026-07-13

### Features

* expose typed entity statement decoders ([c81bdf5](https://github.com/Dahkenangnon/oidfed/commit/c81bdf5005906e69fe5a977a4a18cb20ac0d3637))
* add stable statement builders ([e726a5c](https://github.com/Dahkenangnon/oidfed/commit/e726a5ccbb24a816dba3356ba3b1607a3fbc3d6a))

### Bug Fixes

* return public generated signing keys ([8c2a966](https://github.com/Dahkenangnon/oidfed/commit/8c2a966f1440de321db09a273052603977b2d475))
* enforce provider-owned federation key rollover ([776d123](https://github.com/Dahkenangnon/oidfed/commit/776d1236092366b007ed8a7d9882bd570a35f004))
* enforce federation endpoint validation ([ceae64b](https://github.com/Dahkenangnon/oidfed/commit/ceae64baf66980758db445ebc4bdb5343dff7f1d))
* enforce trust mark payload validation ([cd3af0c](https://github.com/Dahkenangnon/oidfed/commit/cd3af0cb31c99eabbcd9ebd4f4d2e783731a62ae))
* enforce federation policy validation ([54de0f0](https://github.com/Dahkenangnon/oidfed/commit/54de0f06b733258dfd4f0b94d627b469dff94fc5))
* tighten federation metadata validation ([a102e38](https://github.com/Dahkenangnon/oidfed/commit/a102e386736a8be57e191352dab7a4d6a165ef53))
* cover section 3 entity statement validation ([d098c56](https://github.com/Dahkenangnon/oidfed/commit/d098c56f2a3278ae5dcb520026bd25d2b529ff1d))
* enforce exact federation media types ([6c00afe](https://github.com/Dahkenangnon/oidfed/commit/6c00afeb3549ed06fde3fc077c039a561826db28))
* align config docs and package claims ([ea093ac](https://github.com/Dahkenangnon/oidfed/commit/ea093acb7d3df03bbd43e90b30525681aedb7824))
* remove avoidable public any ([d0e754d](https://github.com/Dahkenangnon/oidfed/commit/d0e754d9a2f72fdf57b1bf584a131491a5ef4006))
* harden raw trust-chain validation ([3d5f2c4](https://github.com/Dahkenangnon/oidfed/commit/3d5f2c4a185d9791fb551cf087415f601962bf13))
* validate supplied registration trust chains ([5c21f4f](https://github.com/Dahkenangnon/oidfed/commit/5c21f4f9d62b1d35a2802414e9391047b54f487f))
* require trust anchors for op registration ([36bd338](https://github.com/Dahkenangnon/oidfed/commit/36bd33813fdfced76f0930fa6da0b95e30297133))
* align root docs with class api ([f8ae317](https://github.com/Dahkenangnon/oidfed/commit/f8ae317783708d5a89d107c93a1d6665f4ba0ca2))
* align public docs with class-only APIs ([eb6c359](https://github.com/Dahkenangnon/oidfed/commit/eb6c35953963b8dae0b9f700bfbe69ba92f223f4))

### Refactor

* clarify public role and key provider names ([1211280](https://github.com/Dahkenangnon/oidfed/commit/1211280b7cea233b6522830c149e8ac0abc7a352))


### Added

- Stable Entity Configuration and Subordinate Statement payload builders, signing helpers, and claim-placement validation helpers for normal Entity Statements.
- Schema-backed `decodeEntityConfiguration()` and `decodeSubordinateStatement()` helpers for kind-safe unsigned Entity Statement inspection.

### Changed

- Federation HTTP fetch helpers now require exact parameter-free Content-Type values for spec-defined media types, including Entity Statements, Resolve Responses, Trust Marks, signed JWK Sets, and federation JSON list responses.
- `validateTrustChain()` now rejects malformed raw Entity Statements, invalid metadata policy critical operators, and invalid published Trust Marks during Trust Chain validation.
- `MemoryFederationKeyProvider` now requires an initial federation signing key or non-empty key array and rejects empty arrays during construction.
- **BREAKING.** `FederationKeyLifecycleProvider` is the public contract for provider-owned federation rollover through `publishKey()` and `switchActiveKey()` instead of the previous `addKey()` / `activateKey()` / `retireKey()` sequence. Published keys appear in the active Federation JWKS before signer switch, and expired retiring keys are excluded from the active Federation JWKS while remaining available through historical keys.
- Public federation signing-key construction and Trust Anchor key comparison result types now use explicit behavior-oriented names.
- `compareTrustAnchorKeys()` now compares public key material for matching `kid` values and reports missing or mismatched keys with behavior-focused field names.

## [0.8.0] - 2026-06-25

### Refactor

* context propagation, type exports and request overrides ([d6e9174](https://github.com/Dahkenangnon/oidfed/commit/d6e91742f9e32818caf96d05673f86a01fc15364))
* migrate E2E scenarios and OP participant to new class-based facades ([1e6f5e5](https://github.com/Dahkenangnon/oidfed/commit/1e6f5e56cadb107f4a5d860a4ce39adf2455229c))


## [0.7.0] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.1] - 2026-06-24

_No user-visible changes — released as part of the coordinated wave._


## [0.6.0] - 2026-06-24

### Features

* relax entityId and authorityHints parameter type constraints ([07a3da5](https://github.com/Dahkenangnon/oidfed/commit/07a3da5618a740f6b7ed5547fb45c0b2bdf8ec08))
* unify runtime errors to monadic Result ([ba58a65](https://github.com/Dahkenangnon/oidfed/commit/ba58a656eec56ff34ef0ce1254b5747210219e17))
* export standard policy operators enum and re-export common core primitives ([92aeda6](https://github.com/Dahkenangnon/oidfed/commit/92aeda67ff5c8279b8211e089fc10374d7803433))
* unify persistence behind storage adapter ([f622fca](https://github.com/Dahkenangnon/oidfed/commit/f622fca5955bfee03c90192308bd86bd3e1ec9ed))
* separate federation and OIDC signing keys ([0664c90](https://github.com/Dahkenangnon/oidfed/commit/0664c90641288f41b561588d954badd7f6ae5a4e))
* enhance the npm published keyworks ([a0e38c4](https://github.com/Dahkenangnon/oidfed/commit/a0e38c46c7fcafd75341a3aa306350e8f0f1df8d))

### Bug Fixes

* harden public API types and add trust anchor helper ([3283001](https://github.com/Dahkenangnon/oidfed/commit/3283001bbd291a42843c5e768d34405c0b064eac))
* review the public api of every pkg ([a95c473](https://github.com/Dahkenangnon/oidfed/commit/a95c473f1a92bdd55a248fcc1a8b319da2208295))


### Added

- `ReplayStore`, structured `JtiReplayClaim`, and the runtime-neutral development `MemoryReplayStore`. Replay identity is scoped by issuer, audience, and JTI; capacity failures fail closed.
- Public `MemoryCacheOptions` and `MemoryFederationKeyProviderOptions`; key lifecycle time is explicitly exposed as `nowMs`.

### Changed

- **BREAKING.** `Clock.now()` is consistently Unix NumericDate seconds. Cache TTLs, JOSE verification, trust-chain validation, trust marks, and protocol assertions honor injected clocks.
- `validateTrustChain()` accepts readonly statement arrays.

### Removed

- **BREAKING.** Removed `JtiStore`, `InMemoryJtiStore`, and `hasSeenAndRecord()` in favor of atomic `ReplayStore.useJti()`.
- Internal federation key state and managed-entry types are no longer exported.

## [0.5.2] - 2026-05-28

_No user-visible changes — released as part of the coordinated wave._


## [0.5.1] - 2026-05-28

### Changed

- Refreshed runtime dependency ranges to pull in patch and minor updates: `jose` (^6.0.0 resolving to 6.2.3) and `zod` (^4.0.0 resolving to 4.4.3). No API change.

## [0.5.0] - 2026-05-23

### Removed

- **BREAKING.** OIDC explicit-registration payload schemas are no longer exported from `@oidfed/core`; use the type-only payload exports and role APIs from `@oidfed/oidc` instead.
- **BREAKING.** Typed OIDC metadata schemas (`OpenIDProviderMetadataSchema`, `OpenIDRelyingPartyMetadataSchema`) are no longer re-exported from `@oidfed/core`. The federation layer treats them as loose `z.record()`; OIDC-strict validation happens inside `@oidfed/oidc` role APIs.
- **BREAKING.** `RegistrationProtocolAdapter` and `RegistrationProtocolAdapterContext` interfaces moved to `@oidfed/oidc`.
- **BREAKING.** Client registration type definitions moved to `@oidfed/oidc`; runtime constants are implementation details.
- **BREAKING.** `JwtTyp.ExplicitRegistrationResponse` and `MediaType.ExplicitRegistrationResponse` removed. OIDC-specific response type and media-type constants are internal to `@oidfed/oidc`.
- **BREAKING.** `normalizeScope` and `denormalizeScope` are no longer part of the public API; they are internal implementation details of `applyMetadataPolicy` and remain in `packages/core/src/metadata-policy/apply.ts`.

### Changed

- `packages/core/src/schemas/metadata.ts` continues to define loose `OpenIDProviderMetadataSchema` / `OpenIDRelyingPartyMetadataSchema` (each `z.record()`) for internal use by `FederationMetadataSchema`. They are no longer publicly exported.

## [0.4.1] - 2026-05-23

### Added

- Public export `STANDARD_ENTITY_STATEMENT_CLAIMS` — the canonical set of claim names defined for Entity Statements. Used by callers that need to validate `crit` lists against the spec-defined claim set.

## [0.4.0] - 2026-05-18

### Added

- New `federation_extended_list_endpoint` claim and `federation_extended_list_endpoint_auth_methods` on `FederationEntityMetadataSchema`.
- New `FederationEndpoint.ExtendedList = "/federation_extended_list"`.
- New `FederationErrorCode.EntityIdNotFound = "entity_id_not_found"`.
- New Zod schemas for the Extended Subordinate Listing endpoint: `ExtendedListClaim`, `EXTENDED_LIST_SUPPORTED_CLAIMS` (13 claim names), `ExtendedListQuerySchema`, `ExtendedListEntitySchema`, `ExtendedListResponseSchema`, plus `ExtendedListQuery` / `ExtendedListEntity` / `ExtendedListResponse` / `ExtendedListRequestParams` types.
- `ExtendedListClaim` covers all top-level Subordinate Statement claims: `subordinate_statement`, `iss`, `sub`, `iat`, `exp`, `jwks`, `metadata`, `metadata_policy`, `constraints`, `crit`, `metadata_policy_crit`, `source_endpoint`, `trust_marks`.
- New `fetchExtendedSubordinatesList(endpoint, params?, options?)` client. HTTPS-only, content-type checked, surfaces spec-defined error codes (`entity_id_not_found`, `unsupported_parameter`) from `400 application/json` responses. Sends `claims` as a single comma-separated value on the wire.

## [0.3.0] - 2026-05-12

### Changed

- Align with OpenID Federation 1.1 Final and OpenID Connect for OpenID Federation 1.1 Final (published 2026-05-11).

## [0.2.0] - 2026-04-28

### Changed

- Relicensed from MIT to Apache License 2.0. Includes `NOTICE` file.

## [0.1.0] - 2026-04-21

Initial release.
