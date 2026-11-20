# React Native

For issuer discovery and verifier request validation, supply your app's `CryptoEngine` and trust anchors. If your app signs, provide a `Signer` backed by its own key store. See the [crypto adapter guide](crypto/adapters.md).

Core and Wallet bundle with Metro and compile to Hermes bytecode on React Native 0.88.1 with the Babel setting below. Device execution still needs verification.

## Metro build

If Metro reports `Export namespace should be first transformed` in Zod, install `@babel/plugin-transform-export-namespace-from` as a development dependency and add it to your app's Babel `plugins` list. Keep your existing preset.

## URLs

Core uses `URL.canParse` to validate entity IDs and copies `URLSearchParams` when building endpoint requests. The stock React Native 0.88.1 shims lack `canParse` and can drop query parameters during the copy.

`react-native-url-polyfill` 4.0.0 passed both checks. Import `react-native-url-polyfill/auto` at app startup, before calling Core or Wallet. Use ASCII hostnames with that polyfill. [URL polyfill setup](https://github.com/charpeni/react-native-url-polyfill#installation)

## Live requests

Pass a streaming `httpClient` in the options for network calls. Core reads `Response.body` in chunks so it can stop oversized downloads early. React Native's built-in Fetch can return a successful response without that stream and does not honor `redirect: "manual"`, which Core uses for authenticated endpoint requests. [React Native networking](https://reactnative.dev/docs/network)

`expo/fetch` supports streaming and is a candidate for `httpClient`. On your target device, try a real federation request and check that the transport stops on the response-size limit, cancellation, and authenticated redirects. If `DOMException` is missing, provide it at startup so Core can handle network failures. [Expo Fetch](https://docs.expo.dev/versions/latest/sdk/expo/#expofetch-api)
