import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  createSignature,
  SignatureError,
  SignatureErrorCode,
  verifySignature,
  type RequestDescriptor,
} from "../src";

// Shared with the Rust `web-bot-auth` crate, which includes this same file in
// its own test suite. Any divergence between the two implementations is caught
// here instead of being discovered against a live signed request.
const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../../web-bot-auth/test/test_data/canonicalization_vectors_v1.json",
      import.meta.url
    ),
    "utf8"
  )
) as {
  fields: {
    name: string;
    occurrences: { name: string; value: string }[];
    components: string[];
    base?: string;
    error?: string;
  }[];
  dictionaries: {
    name: string;
    field: string;
    values: string[];
    error?: string;
  }[];
  components: {
    name: string;
    signature_input: string;
    error?: string;
  }[];
};

async function baseOf(message: RequestDescriptor, components: string[]) {
  let base = "";
  await createSignature(message, {
    components,
    parameters: {},
    signer: {
      algorithm: "test-alg",
      sign(data) {
        base = new TextDecoder().decode(data);
        return new Uint8Array();
      },
    },
  });
  return base;
}

async function verifyError(fields: { name: string; value: string }[]) {
  const message: RequestDescriptor = {
    kind: "request",
    method: "GET",
    targetUri: "https://example.com/",
    fields,
  };
  try {
    await verifySignature(message, {
      label: "sig1",
      policy: {
        algorithms: ["test-alg"],
        requiredComponents: [],
        requiredParameters: [],
        now: 0,
      },
      resolveVerifier: () => {
        throw new Error("resolver must not be reached");
      },
    });
  } catch (caught) {
    return caught as SignatureError;
  }
  return undefined;
}

describe("canonicalization fixed vectors", () => {
  for (const vector of vectors.fields) {
    it(vector.name, async () => {
      const message: RequestDescriptor = {
        kind: "request",
        method: "GET",
        targetUri: "https://example.com/",
        fields: vector.occurrences.map(({ name, value }) => ({ name, value })),
      };
      if (vector.error !== undefined) {
        await expect(baseOf(message, vector.components)).rejects.toBeInstanceOf(
          SignatureError
        );
      } else {
        expect(await baseOf(message, vector.components)).toBe(vector.base);
      }
    });
  }
});

describe("signature dictionary fixed vectors", () => {
  for (const vector of vectors.dictionaries) {
    it(vector.name, async () => {
      const fields = [
        ...vector.values.map((value) => ({ name: vector.field, value })),
        ...(vector.field === "signature"
          ? [{ name: "signature-input", value: 'sig1=("@authority")' }]
          : [{ name: "signature", value: "sig1=:AAEC:" }]),
      ];
      const error = await verifyError(fields);
      expect(error).toBeInstanceOf(SignatureError);
      switch (vector.error) {
        case "duplicate-label":
          expect(error?.code).toBe(SignatureErrorCode.DuplicateLabel);
          break;
        case "duplicate-parameter":
          expect(error?.code).toBe(SignatureErrorCode.MalformedField);
          break;
        default:
          expect([
            SignatureErrorCode.MalformedField,
            SignatureErrorCode.DuplicateLabel,
          ]).toContain(error?.code);
      }
    });
  }
});

describe("covered component fixed vectors", () => {
  for (const vector of vectors.components) {
    it(vector.name, async () => {
      const error = await verifyError([
        { name: "signature-input", value: vector.signature_input },
        { name: "signature", value: "sig1=:AAEC:" },
      ]);
      expect(error).toBeInstanceOf(SignatureError);
      expect([
        SignatureErrorCode.DuplicateComponent,
        SignatureErrorCode.MalformedField,
        SignatureErrorCode.InvalidComponent,
      ]).toContain(error?.code);
    });
  }
});
