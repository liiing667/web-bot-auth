import { describe, expect, it } from "vitest";
import {
  parseRegistry,
  parseSignatureAgentCard,
  parseSignatureAgentHeader,
  parseSignatureAgentHeaderLines,
} from "../src/index";

import cardVectors from "./test_data/web_bot_auth_signature_agent_card_v1.json";
import registryVectors from "./test_data/web_bot_auth_registry_v1.json";
import signatureAgentVectors from "./test_data/web_bot_auth_signature_agent_v2.json";

describe.each(signatureAgentVectors)("Signature-Agent $name", (vector) => {
  it("parses the header", () => {
    const result = parseSignatureAgentHeader(vector.header);

    expect(result.kind).toBe("current");
    expect(result.entries).toEqual(vector.entries);
  });
});

describe("Signature-Agent invalid syntax", () => {
  it("ignores removed discovery types", () => {
    expect(
      parseSignatureAgentHeader(
        'a="https://example.com";type=directory, b="https://example.com";type=jwks_uri'
      ).entries
    ).toEqual([]);
  });

  it("rejects an empty header", () => {
    expect(() => parseSignatureAgentHeader("")).toThrow("must not be empty");
  });

  it("accepts legacy string syntax with a warning", () => {
    expect(parseSignatureAgentHeader('"https://signature-agent.test"')).toEqual(
      {
        kind: "legacy",
        entries: [
          {
            label: "",
            uri: "https://signature-agent.test",
          },
        ],
      }
    );
  });
});

describe("Signature-Agent field lines", () => {
  it("parses separate legacy field lines", () => {
    expect(
      parseSignatureAgentHeaderLines([
        '"https://one.example"',
        '"https://two.example"',
      ])
    ).toEqual({
      kind: "legacy",
      entries: [
        { label: "", uri: "https://one.example" },
        { label: "", uri: "https://two.example" },
      ],
    });
  });

  it("replaces earlier members before validation", () => {
    // An ignored unsupported replacement must not revive an earlier URI that
    // the selected dictionary member no longer covers.
    expect(
      parseSignatureAgentHeaderLines([
        'a="https://old.example", b="http://replaced.example"',
        'a="https://ignored.example";unknown, b="https://new.example"',
      ])
    ).toEqual({
      kind: "current",
      entries: [{ label: "b", uri: "https://new.example" }],
    });
  });

  it("rejects mixed legacy and dictionary field lines", () => {
    for (const lines of [
      ['"https://legacy.example"', 'a="https://current.example"'],
      ['a="https://current.example"', '"https://legacy.example"'],
    ]) {
      expect(() => parseSignatureAgentHeaderLines(lines)).toThrow();
    }
  });

  it("rejects empty field lines", () => {
    expect(() => parseSignatureAgentHeaderLines([])).toThrow(
      "must not be empty"
    );
  });
});

describe.each(registryVectors)("registry $name", (vector) => {
  it("parses the registry", () => {
    expect(
      parseRegistry(vector.registry_txt).map((entry) => entry.href)
    ).toEqual(vector.signature_agent_cards);
  });
});

describe("invalid registry", () => {
  it.each([
    ["http://example.com/bot\n", "registry entries must use https"],
    [
      'data:application/json,{"client_name":"Inline Bot"}\n',
      "inline signature agent cards are not supported",
    ],
  ])("rejects %s", (registry, error) => {
    expect(() => parseRegistry(registry)).toThrow(error);
  });
});

describe.each(cardVectors)("signature agent card $name", (vector) => {
  it("validates the card", () => {
    if (vector.valid) {
      expect(parseSignatureAgentCard(vector.card, vector.url)).toMatchObject(
        vector.card
      );
    } else {
      expect(() => parseSignatureAgentCard(vector.card, vector.url)).toThrow(
        vector.error
      );
    }
  });
});

describe("signature agent card key material", () => {
  it("requires key material", () => {
    expect(() =>
      parseSignatureAgentCard(
        { client_id: "https://example.com/bot" },
        "https://example.com/bot"
      )
    ).toThrow("either jwks or jwks_uri");
  });

  it("requires client_id when card URL is known", () => {
    expect(() =>
      parseSignatureAgentCard(
        { jwks_uri: "https://example.com/jwks.json" },
        "https://example.com/bot"
      )
    ).toThrow("client_id is required");
  });
});
