# web-bot-auth

![License](https://img.shields.io/npm/l/web-bot-auth.svg)
[![crates.io](https://img.shields.io/npm/v/web-bot-auth.svg)][npm]

[npm]: https://www.npmjs.com/package/web-bot-auth

TypeScript helpers for Web Bot Auth, as described in [draft-meunier-webbotauth-httpsig-protocol-01](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/01/).

## Table of Contents

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- Web Bot Auth request signing and verification policy
- Request method and body integrity through `@method` and `Content-Digest`
- Ed25519 and RSA-PSS/SHA-512 JWK signers and verifiers
- `Signature-Agent`, registry, and Signature Agent Card parsers
- TypeScript types

## Usage

This section shows basic signing and verification. To select one of several signatures, pass its `label` to `verify`; verify each label separately when all signatures matter.
More concrete examples are provided on [cloudflareresearch/web-bot-auth/examples](https://github.com/cloudflareresearch/web-bot-auth#examples).

### Research server for debug purposes

To help debug `web-both-auth` HTTPS requests, Cloudflare Research provides a test endpoint on `https://http-message-signatures-example.research.cloudflare.com/debug`. You may also run this [research server's code on GitHub](https://github.com/cloudflare/web-bot-auth/tree/main/examples/verification-workers) on a local endpoint.

### Signing

```typescript
import { generateNonce, sign } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";

const signatureAgent = 'sig1="https://signature-agent.test"';
const request = new Request("https://example.com", {
  headers: { "Signature-Agent": signatureAgent },
});

// Published RFC 9421 test key. Never use it in production; see Security Considerations below.
// Fixture: https://github.com/cloudflareresearch/web-bot-auth/blob/main/examples/rfc9421-keys/ed25519.json
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  alg: "EdDSA",
  kid: "test-key-ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

const now = new Date();
const fields = await sign(request, {
  signer: await signerFromJWK(RFC_9421_ED25519_TEST_KEY),
  created: now,
  expires: new Date(now.getTime() + 300_000),
  nonce: generateNonce(),
});

// Et voila! Here is our signed request.
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: fields.signature,
    "Signature-Agent": signatureAgent,
    "Signature-Input": fields.signatureInput,
  },
});
```

### Signing a request body

Requests that carry a body must bind it to the signature. Pass the exact
bytes sent on the wire as `body`; `sign` computes an RFC 9530
`Content-Digest` with SHA-256, adds the header to the signed message, and
covers both `@method` and `content-digest`. The header value is returned as
`contentDigest` so it can be attached to the outgoing request.

```typescript
import { sign } from "web-bot-auth";

const body = JSON.stringify({ hello: "world" });
const request = new Request("https://example.com/resource", {
  method: "POST",
});
const fields = await sign(request, {
  signer,
  created: now,
  expires: new Date(now.getTime() + 300_000),
  body,
});
// Signature-Input covers ("@authority" "@method" "content-digest" ...)
const signedRequest = new Request(request, {
  method: "POST",
  headers: {
    "Content-Digest": fields.contentDigest,
    Signature: fields.signature,
    "Signature-Input": fields.signatureInput,
  },
  body,
});
```

`signSync` cannot compute a digest, so passing `body` to it fails; use the
asynchronous `sign`. `createContentDigest` and `verifyContentDigest` are also
exported when the digest must be handled separately. Only `sha-256` and
`sha-512` are accepted: missing digests, weak or unknown algorithms such as
`md5` or `sha-1`, malformed fields, and digests that do not match the body
all fail verification.

### Verifying

```typescript
import { verify } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";

// available at https://github.com/cloudflareresearch/web-bot-auth/blob/main/examples/rfc9421-keys/ed25519.json
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  alg: "EdDSA",
  kid: "test-key-ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

// Reusing the incoming request signed in the above section
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: fields.signature,
    "Signature-Agent": signatureAgent,
    "Signature-Input": fields.signatureInput,
  },
});

const verifier = await verifierFromJWK(RFC_9421_ED25519_TEST_KEY);
const authenticated = await verify(signedRequest, {
  // Resolve only from trusted local configuration. The candidate is untrusted.
  resolver: (candidate) => {
    if (candidate.keyid !== verifier.keyid) throw new Error("unknown key");
    return verifier;
  },
  validate: ({ nonce }) => {
    // Atomically reject a nonce already present in your replay cache.
  },
});
```

For `POST`, `PUT`, and `PATCH` requests, pass the received bytes as `body`.
Verification then requires the signature to cover bare `@method` and
`content-digest`, requires a `Content-Digest` header, and recomputes the
digest before the signature is checked. A rewritten body, a deleted digest,
a weak digest algorithm, or a changed method therefore fails before key
resolution completes. Bodyless requests keep the legacy behaviour and do not
require a digest.

```typescript
const body = await request.text();
await verify(request, {
  resolver: () => verifier,
  body,
});
```

## Security Considerations

This software has not been audited. Use it at your sole discretion. RFC test keys [must not be used in production](https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-httpsig-protocol-02#section-6.8). For production, [generate a unique asymmetric key](https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-httpsig-protocol-02#section-6.4) with [Web Crypto](https://github.com/cloudflare/web-bot-auth/tree/main/packages/jsonwebkey-thumbprint#usage) or [OpenSSL](https://developers.cloudflare.com/bots/concepts/bot/verified-bots/web-bot-auth/#1-generate-a-valid-signing-key). Publish only its public JWK values. [Overlap old and new public keys during rotation](https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-httpsig-protocol-02#section-5.5.2).

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
