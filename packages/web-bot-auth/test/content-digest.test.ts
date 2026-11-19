import { createSignature } from "http-message-sig";
import { parseDictionary } from "structured-headers";
import { describe, expect, it, vi } from "vitest";
import {
  BODY_METHODS,
  CONTENT_DIGEST_ALGORITHMS,
  createContentDigest,
  sign,
  signSync,
  verify,
  verifyContentDigest,
  type SignatureFields,
  type WebBotSigner,
  type WebBotVerifier,
} from "../src/index";
import { signerFromJWK, verifierFromJWK } from "../src/crypto";
import vectors1 from "./test_data/web_bot_auth_architecture_v1.json";
import vectors2 from "./test_data/web_bot_auth_architecture_v2.json";

const vectors = [...vectors1, ...vectors2];
const ed25519Vector = vectors.find((vector) => vector.key.kty === "OKP");
if (ed25519Vector === undefined) throw new Error("missing Ed25519 vector");
const ed25519Jwk: JsonWebKey = ed25519Vector.key;

const created = new Date("2025-01-01T00:00:00Z");
const expires = new Date("2025-01-01T01:00:00Z");
const now = new Date("2025-01-01T00:30:00Z");
const payload = JSON.stringify({ hello: "world" });

function withSignature(request: Request, fields: SignatureFields): Request {
  const headers = new Headers(request.headers);
  headers.set("signature", fields.signature);
  headers.set("signature-input", fields.signatureInput);
  return new Request(request, { headers });
}

async function signedBodyRequest(
  body: string | Uint8Array = payload,
  method = "POST"
): Promise<{ request: Request; verifier: WebBotVerifier }> {
  const signer = await signerFromJWK(ed25519Jwk);
  const verifier = await verifierFromJWK(ed25519Jwk);
  const request = new Request("https://example.com/resource", { method });
  const fields = await sign(request, {
    signer,
    created,
    expires,
    body,
  });
  expect(fields.contentDigest).toBeDefined();
  const headers = new Headers(request.headers);
  headers.set("content-digest", fields.contentDigest ?? "");
  headers.set("signature", fields.signature);
  headers.set("signature-input", fields.signatureInput);
  return {
    request: new Request(request.url, { method, headers, body }),
    verifier,
  };
}

describe("Content-Digest helpers", () => {
  it("creates an RFC 9530 sha-256 structured field", async () => {
    const digest = await createContentDigest(payload);
    expect(digest.algorithm).toBe("sha-256");
    expect(digest.value).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
    const parsed = parseDictionary(digest.value);
    const member = parsed.get("sha-256");
    expect(member?.[0]).toBeInstanceOf(ArrayBuffer);
  });

  it("supports sha-512", async () => {
    const digest = await createContentDigest(payload, "sha-512");
    expect(digest.value.startsWith("sha-512=:")).toBe(true);
    const verified = await verifyContentDigest(payload, digest.value);
    expect(verified.algorithm).toBe("sha-512");
  });

  it.each(["md5", "sha-1", "sha-123", "unknown"])(
    "rejects weak or unknown algorithm %s",
    async (algorithm) => {
      const value = `${algorithm}=:AAAA:`;
      await expect(verifyContentDigest(payload, value)).rejects.toThrow(
        "weak or not allowed"
      );
    }
  );

  it("rejects malformed fields", async () => {
    await expect(
      verifyContentDigest(payload, "not a dictionary")
    ).rejects.toThrow();
  });

  it("rejects empty, multi-member, or parameterized digests", async () => {
    const digest = await createContentDigest(payload);
    await expect(verifyContentDigest(payload, "")).rejects.toThrow(
      "must not be empty"
    );
    await expect(
      verifyContentDigest(payload, `${digest.value}, sha-512=:AAAA:`)
    ).rejects.toThrow("exactly one digest");
    await expect(
      verifyContentDigest(payload, "sha-256=:YWJjZA==:;foo=1")
    ).rejects.toThrow("unparameterized bytes");
  });

  it("rejects a digest that does not match the body", async () => {
    const digest = await createContentDigest(payload);
    await expect(
      verifyContentDigest(`${payload} tampered`, digest.value)
    ).rejects.toThrow("does not match");
  });

  it("exposes only strong algorithms", () => {
    expect(Object.keys(CONTENT_DIGEST_ALGORITHMS).sort()).toEqual([
      "sha-256",
      "sha-512",
    ]);
  });
});

describe("body-bound signing", () => {
  it("covers @method and content-digest and returns the digest", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com/resource", {
      method: "POST",
    });
    const fields = await sign(request, {
      signer,
      created,
      expires,
      body: payload,
    });
    expect(fields.signatureInput).toContain('"@method"');
    expect(fields.signatureInput).toContain('"content-digest"');
    expect(fields.contentDigest).toMatch(/^sha-256=:/);
  });

  it("does not duplicate explicitly provided bound components", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com/resource", {
      method: "PUT",
    });
    const fields = await sign(request, {
      signer,
      created,
      expires,
      body: payload,
      additionalComponents: ["@method"],
    });
    expect(fields.signatureInput.match(/"@method"/g)?.length).toBe(1);
  });

  it("rejects body signing through signSync", () => {
    const signer: WebBotSigner = {
      algorithm: "ed25519",
      keyid: "test-key",
      sign: () => new Uint8Array(64),
    };
    const request = new Request("https://example.com", { method: "POST" });
    expect(() =>
      signSync(request, { signer, created, expires, body: payload })
    ).toThrow("use sign");
  });
});

describe("body-bound verification", () => {
  it("signs and verifies a POST body end to end", async () => {
    const { request, verifier } = await signedBodyRequest();
    await expect(
      verify(request, { resolver: () => verifier, now, body: payload })
    ).resolves.toMatchObject({
      keyid: (await verifierFromJWK(ed25519Jwk)).keyid,
    });
  });

  it.each(BODY_METHODS)(
    "enforces integrity for %s requests",
    async (method) => {
      const { request, verifier } = await signedBodyRequest(payload, method);
      await expect(
        verify(request, { resolver: () => verifier, now, body: payload })
      ).resolves.toBeDefined();
      await expect(
        verify(request, { resolver: () => verifier, now })
      ).rejects.toThrow("require a body");
    }
  );

  it("rejects a same-origin rewritten POST body", async () => {
    const { request, verifier } = await signedBodyRequest();
    const attackerBody = JSON.stringify({ hello: "attacker" });
    const rewritten = new Request(request.url, {
      method: request.method,
      headers: request.headers,
      body: attackerBody,
    });
    await expect(
      verify(rewritten, {
        resolver: () => verifier,
        now,
        body: attackerBody,
      })
    ).rejects.toThrow("does not match");
  });

  it("rejects a deleted Content-Digest header before key resolution", async () => {
    const { request, verifier } = await signedBodyRequest();
    const headers = new Headers(request.headers);
    headers.delete("content-digest");
    const stripped = new Request(request.url, {
      method: request.method,
      headers,
      body: payload,
    });
    const resolver = vi.fn(() => verifier);
    await expect(
      verify(stripped, { resolver, now, body: payload })
    ).rejects.toThrow("content-digest");
    expect(resolver).not.toHaveBeenCalled();
  });

  it("rejects a signature without content-digest coverage", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const request = new Request("https://example.com/resource", {
      method: "POST",
    });
    const digest = await createContentDigest(payload);
    const headers = new Headers(request.headers);
    headers.set("content-digest", digest.value);
    const requestWithDigest = new Request(request.url, {
      method: "POST",
      headers,
      body: payload,
    });
    const fields = await createSignature(requestWithDigest, {
      signer,
      components: ["@authority", "@method"],
      parameters: {
        created: Math.floor(created.getTime() / 1000),
        expires: Math.floor(expires.getTime() / 1000),
        keyid: signer.keyid,
        alg: signer.algorithm,
        tag: "web-bot-auth",
      },
    });
    headers.set("content-digest", digest.value);
    headers.set("signature", fields.signature);
    headers.set("signature-input", fields.signatureInput);
    const signed = new Request(requestWithDigest, { headers });
    const resolver = vi.fn(() => verifier);
    await expect(
      verify(signed, { resolver, now, body: payload })
    ).rejects.toMatchObject({
      message: "Verifier resolution failed",
      cause: { message: expect.stringContaining("content-digest") },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it("rejects a signature without @method coverage", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const request = new Request("https://example.com/resource", {
      method: "POST",
    });
    const digest = await createContentDigest(payload);
    const headers = new Headers(request.headers);
    headers.set("content-digest", digest.value);
    const requestWithDigest = new Request(request.url, {
      method: "POST",
      headers,
      body: payload,
    });
    const fields = await createSignature(requestWithDigest, {
      signer,
      components: ["@authority", "content-digest"],
      parameters: {
        created: Math.floor(created.getTime() / 1000),
        expires: Math.floor(expires.getTime() / 1000),
        keyid: signer.keyid,
        alg: signer.algorithm,
        tag: "web-bot-auth",
      },
    });
    headers.set("signature", fields.signature);
    headers.set("signature-input", fields.signatureInput);
    const signed = new Request(requestWithDigest, { headers });
    const resolver = vi.fn(() => verifier);
    await expect(
      verify(signed, { resolver, now, body: payload })
    ).rejects.toMatchObject({
      message: "Verifier resolution failed",
      cause: { message: expect.stringContaining("@method") },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it("rejects a tampered method even when the body digest matches", async () => {
    const { request, verifier } = await signedBodyRequest(payload, "POST");
    const headers = new Headers(request.headers);
    const tampered = new Request("https://example.com/resource", {
      method: "PUT",
      headers,
      body: payload,
    });
    await expect(
      verify(tampered, { resolver: () => verifier, now, body: payload })
    ).rejects.toThrow();
  });

  it("rejects a weak algorithm in the presented Content-Digest", async () => {
    const { request, verifier } = await signedBodyRequest();
    const headers = new Headers(request.headers);
    headers.set("content-digest", "sha-1=:AAAA:");
    const weak = new Request(request.url, {
      method: request.method,
      headers,
      body: payload,
    });
    await expect(
      verify(weak, { resolver: () => verifier, now, body: payload })
    ).rejects.toThrow("weak or not allowed");
  });

  it("verifies descriptor requests with a body", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const digest = await createContentDigest(payload);
    const descriptor = {
      kind: "request" as const,
      method: "POST",
      targetUri: "https://example.com/resource",
      fields: [{ name: "content-digest", value: digest.value }],
    };
    const fields = await sign(descriptor, {
      signer,
      created,
      expires,
      body: payload,
    });
    const signed = {
      ...descriptor,
      fields: [
        ...descriptor.fields,
        { name: "signature", value: fields.signature },
        { name: "signature-input", value: fields.signatureInput },
      ],
    };
    await expect(
      verify(signed, { resolver: () => verifier, now, body: payload })
    ).resolves.toBeDefined();
  });
});

describe("legacy behaviour", () => {
  it("still verifies bodyless GET requests without a digest", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const request = new Request("https://example.com");
    const fields = await sign(request, { signer, created, expires });
    expect(fields.signatureInput).not.toContain("content-digest");
    expect(fields.contentDigest).toBeUndefined();
    await expect(
      verify(withSignature(request, fields), {
        resolver: () => verifier,
        now,
      })
    ).resolves.toBeDefined();
  });

  it("still accepts bodyless requests that merely carry a content-digest header", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: { "content-digest": "sha-256=:AAAA:" },
    });
    const fields = await sign(request, { signer, created, expires });
    await expect(
      verify(withSignature(request, fields), {
        resolver: () => verifier,
        now,
      })
    ).resolves.toBeDefined();
  });
});
