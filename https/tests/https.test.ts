import { describe, expect, test } from "bun:test";
import {
  decodeFederationHttpsAdvertisement,
  acceptFederationHttpsRequest,
  createHttpsFederationTransportAdapter,
  encodeFederationHttpsAdvertisement,
  encodeFederationHttpsBatch,
  isPublicFederationAddress,
  HTTPS_FEDERATION_MESSAGES_PATH,
  HTTPS_FEDERATION_PROTOCOL,
  type FederationHttpsAdvertisement,
  type FederationHttpsLimits,
  type FederationHttpsPeer,
} from "../src";
import {
  FEDERATION_CONTRACT,
  type SignedFederationEnvelope,
} from "@absolutejs/secure-messaging-federation";

const fingerprint = Array.from({ length: 32 }, () => "AA").join(":");
const limits: FederationHttpsLimits = {
  maximumBatchBytes: 8_192,
  maximumBatchMessages: 10,
  maximumEnvelopeBytes: 4_096,
  maximumPayloadBytes: 2_048,
  maximumResponseBytes: 4_096,
  maximumSignatureBytes: 256,
  requestTimeoutMs: 1_000,
};
const advertisement: FederationHttpsAdvertisement = {
  certificateFingerprintsSha256: [fingerprint],
  contract: 1,
  createdAt: 1_000,
  domain: "bob.example",
  expiresAt: 1_500,
  maximumBatchBytes: 8_192,
  maximumBatchMessages: 10,
  messagesPath: HTTPS_FEDERATION_MESSAGES_PATH,
  protocol: HTTPS_FEDERATION_PROTOCOL,
  requiresMutualTls: true,
};
const peer: FederationHttpsPeer = {
  ...advertisement,
  addresses: ["203.0.113.10"],
  port: 443,
};
const signed: SignedFederationEnvelope = {
  envelope: {
    contract: FEDERATION_CONTRACT,
    createdAt: 1_000,
    destinationDomain: "bob.example",
    expiresAt: 1_500,
    id: "message-1",
    kind: "application",
    originDomain: "alice.example",
    payload: Uint8Array.of(1, 2, 3),
    routeId: "opaque-route-1",
    sessionId: "session-1",
    transcriptHash: "transcript-1",
  },
  signature: {
    algorithm: "TEST",
    keyId: "key-1",
    signature: Uint8Array.of(4, 5, 6),
  },
};

describe("federation HTTPS adapter", () => {
  test("strictly decodes an exact, expiring mTLS advertisement", () => {
    const bytes = encodeFederationHttpsAdvertisement(advertisement);
    expect(
      decodeFederationHttpsAdvertisement(bytes, {
        expectedDomain: "bob.example",
        maximumBytes: 4_096,
        maximumClockSkewMs: 100,
        maximumTtlMs: 1_000,
        now: 1_001,
      }),
    ).toEqual(advertisement);
    const extended = new TextEncoder().encode(
      JSON.stringify({ ...advertisement, fallback: "http" }),
    );
    expect(() =>
      decodeFederationHttpsAdvertisement(extended, {
        expectedDomain: "bob.example",
        maximumBytes: 4_096,
        maximumClockSkewMs: 100,
        maximumTtlMs: 1_000,
        now: 1_001,
      }),
    ).toThrow("unknown fields");
  });

  test("rejects private and special-use addresses by default", () => {
    expect(isPublicFederationAddress("8.8.8.8")).toBe(true);
    expect(isPublicFederationAddress("10.0.0.1")).toBe(false);
    expect(isPublicFederationAddress("127.0.0.1")).toBe(false);
    expect(isPublicFederationAddress("169.254.169.254")).toBe(false);
    expect(isPublicFederationAddress("203.0.113.10")).toBe(false);
    expect(isPublicFederationAddress("::1")).toBe(false);
    expect(isPublicFederationAddress("fd00::1")).toBe(false);
  });

  test("sends one strict batch and delegates acknowledgement to the local inbox", async () => {
    const requests: Array<{ body?: Uint8Array; path: string }> = [];
    const acknowledgements: string[] = [];
    const transport = createHttpsFederationTransportAdapter({
      client: {
        request: async (request) => {
          requests.push({ body: request.body, path: request.path });
          return {
            body: new Uint8Array(),
            certificateFingerprintSha256: fingerprint,
            headers: {},
            status: 202,
          };
        },
      },
      inbox: {
        acknowledge: async ({ cursor }) => {
          acknowledgements.push(cursor);
        },
        receive: async () => ({ cursor: "cursor-1", messages: [signed] }),
      },
      limits,
      localDomain: "alice.example",
      peers: { resolve: async () => peer },
    });
    await transport.send([signed]);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.path).toBe(HTTPS_FEDERATION_MESSAGES_PATH);
    expect(requests[0]?.body?.length).toBeGreaterThan(0);
    expect(
      await transport.receive({
        localDomain: "alice.example",
        maximumMessages: 10,
      }),
    ).toEqual({ cursor: "cursor-1", messages: [signed] });
    await transport.acknowledge({
      cursor: "cursor-1",
      localDomain: "alice.example",
    });
    expect(acknowledgements).toEqual(["cursor-1"]);
  });

  test("accepts only a certificate-bound origin and local destination", async () => {
    let enqueued = 0;
    const body = encodeFederationHttpsBatch([signed], limits);
    expect(
      await acceptFederationHttpsRequest({
        inbox: {
          enqueue: async () => {
            enqueued += 1;
            return "accepted";
          },
        },
        limits,
        localDomain: "bob.example",
        request: {
          authenticatedPeerDomain: "alice.example",
          body,
          headers: {
            "content-type": "application/absolutejs-federation-batch+json",
            "x-absolutejs-federation-origin": "alice.example",
          },
          method: "POST",
          path: HTTPS_FEDERATION_MESSAGES_PATH,
        },
      }),
    ).toEqual({ body: new Uint8Array(), status: 202 });
    expect(enqueued).toBe(1);
    await expect(
      acceptFederationHttpsRequest({
        inbox: { enqueue: async () => "accepted" },
        limits,
        localDomain: "bob.example",
        request: {
          authenticatedPeerDomain: "mallory.example",
          body,
          headers: {
            "content-type": "application/absolutejs-federation-batch+json",
            "x-absolutejs-federation-origin": "alice.example",
          },
          method: "POST",
          path: HTTPS_FEDERATION_MESSAGES_PATH,
        },
      }),
    ).rejects.toThrow("metadata");
  });
});
