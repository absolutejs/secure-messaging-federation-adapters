import { describe, expect, test } from "bun:test";
import {
  MIMI_DRAFT_OPT_IN,
  MIMI_DRAFT_PROFILE_ID,
  MIMI_DRAFT_REVISIONS,
  assertMimiDraftAdvertisement,
  createMimiDraftProfile,
} from "../src";

describe("experimental MIMI draft profile", () => {
  test("requires explicit opt-in and exposes exact draft revisions", () => {
    expect(
      createMimiDraftProfile({
        contentTypes: ["application/example-message"],
        experimentalOptIn: MIMI_DRAFT_OPT_IN,
        maximumFrameBytes: 1_048_576,
      }),
    ).toEqual({
      contentTypes: ["application/example-message"],
      e2eeProtocol: "MLS-1.0",
      features: [],
      federationProtocol: "MIMI+MLS-over-mutual-TLS",
      id: MIMI_DRAFT_PROFILE_ID,
      maximumFrameBytes: 1_048_576,
      revision: "draft-ietf-mimi-protocol-06",
      security: { mode: "strict-e2ee" },
    });
  });

  test("fails closed when any advertised revision or draft caveat differs", () => {
    const advertisement = {
      ...MIMI_DRAFT_REVISIONS,
      encodingStatus: "draft-placeholder",
      identifierStatus: "notional",
      mutualTlsRequired: true,
    } as const;
    expect(() => assertMimiDraftAdvertisement(advertisement)).not.toThrow();
    expect(() =>
      assertMimiDraftAdvertisement({
        ...advertisement,
        protocol: "draft-ietf-mimi-protocol-05" as never,
      }),
    ).toThrow("does not match");
  });
});
