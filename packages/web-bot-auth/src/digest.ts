import {
  isInnerList,
  parseDictionary,
  serializeDictionary,
  type Item,
} from "structured-headers";
import { SignatureError, SignatureErrorCode } from "http-message-sig";

export const CONTENT_DIGEST_HEADER = "content-digest";

export const CONTENT_DIGEST_ALGORITHMS = Object.freeze({
  "sha-256": "SHA-256",
  "sha-512": "SHA-512",
} as const);

export type ContentDigestAlgorithm = keyof typeof CONTENT_DIGEST_ALGORITHMS;

export type RequestBody = Uint8Array | ArrayBuffer | string;

export interface ContentDigest {
  readonly algorithm: ContentDigestAlgorithm;
  readonly digest: Uint8Array<ArrayBuffer>;
  readonly value: string;
}

const encoder = new TextEncoder();

function digestError(message: string): never {
  throw new SignatureError(SignatureErrorCode.PolicyViolation, message);
}

export function normalizeBody(body: RequestBody): Uint8Array<ArrayBuffer> {
  const bytes =
    typeof body === "string"
      ? encoder.encode(body)
      : body instanceof ArrayBuffer
        ? new Uint8Array(body)
        : body;
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export async function createContentDigest(
  body: RequestBody,
  algorithm: ContentDigestAlgorithm = "sha-256"
): Promise<ContentDigest> {
  const webCryptoName = CONTENT_DIGEST_ALGORITHMS[algorithm];
  if (webCryptoName === undefined) {
    return digestError(`Content-Digest algorithm ${algorithm} is not allowed`);
  }
  const bytes = normalizeBody(body);
  const digest: Uint8Array<ArrayBuffer> = new Uint8Array(
    await crypto.subtle.digest(webCryptoName, bytes)
  );
  const parameters = new Map();
  const member: Item = [digest.buffer as ArrayBuffer, parameters];
  const value = serializeDictionary(new Map([[algorithm, member]]));
  return Object.freeze({ algorithm, digest, value });
}

export async function verifyContentDigest(
  body: RequestBody,
  headerValue: string
): Promise<ContentDigest> {
  let dictionary: ReturnType<typeof parseDictionary>;
  try {
    dictionary = parseDictionary(headerValue);
  } catch (error) {
    throw new SignatureError(
      SignatureErrorCode.MalformedField,
      "Content-Digest is not a valid structured dictionary",
      error
    );
  }
  if (dictionary.size === 0) {
    return digestError("Content-Digest must not be empty");
  }
  const entries = [...dictionary];
  if (entries.length !== 1) {
    return digestError("Content-Digest must contain exactly one digest");
  }
  const [algorithm, member] = entries[0];
  if (isInnerList(member)) {
    return digestError("Content-Digest members must be byte sequences");
  }
  const [digest, parameters] = member;
  if (!(digest instanceof ArrayBuffer) || parameters.size !== 0) {
    return digestError("Content-Digest members must be unparameterized bytes");
  }
  const webCryptoName =
    CONTENT_DIGEST_ALGORITHMS[algorithm as ContentDigestAlgorithm];
  if (webCryptoName === undefined) {
    return digestError(
      `Content-Digest algorithm ${algorithm} is weak or not allowed`
    );
  }
  const bytes = normalizeBody(body);
  const actual = new Uint8Array(
    await crypto.subtle.digest(webCryptoName, bytes)
  );
  if (!timingSafeEqual(new Uint8Array(digest), actual)) {
    return digestError("Content-Digest does not match the request body");
  }
  return Object.freeze({
    algorithm: algorithm as ContentDigestAlgorithm,
    digest: new Uint8Array(digest.slice(0)),
    value: headerValue,
  });
}
