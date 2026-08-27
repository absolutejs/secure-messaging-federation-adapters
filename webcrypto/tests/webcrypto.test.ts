import { describe, expect, test } from "bun:test";
import {
  createWebCryptoFederationAbuseEvidenceProvider,
  createWebCryptoFederationSignatureProvider,
  openWebCryptoFederationAbuseEvidence,
} from "../src";

const text = new TextEncoder();

describe("federation Web Crypto providers", () => {
  test("signs for one domain and rejects substitution", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    const provider = createWebCryptoFederationSignatureProvider({
      keyId: "key-1",
      localDomain: "alice.example",
      privateKey: pair.privateKey,
      resolvePublicKey: async ({ domain, keyId }) =>
        domain === "alice.example" && keyId === "key-1"
          ? pair.publicKey
          : undefined,
    });
    const payload = text.encode("transcript");
    const signature = await provider.sign({
      destinationDomain: "bob.example",
      payload,
      purpose: "federation-transcript",
    });
    expect(
      await provider.verify({
        destinationDomain: "bob.example",
        expectedDomain: "alice.example",
        payload,
        purpose: "federation-transcript",
        signature,
      }),
    ).toBe(true);
    expect(
      await provider.verify({
        destinationDomain: "bob.example",
        expectedDomain: "mallory.example",
        payload,
        purpose: "federation-transcript",
        signature,
      }),
    ).toBe(false);
    expect(
      await provider.verify({
        destinationDomain: "mallory.example",
        expectedDomain: "alice.example",
        payload,
        purpose: "federation-transcript",
        signature,
      }),
    ).toBe(false);
    expect(
      await provider.verify({
        destinationDomain: "bob.example",
        expectedDomain: "alice.example",
        payload,
        purpose: "federation-envelope",
        signature,
      }),
    ).toBe(false);
  });

  test("seals evidence and authenticates the complete disclosure context", async () => {
    const pair = await crypto.subtle.generateKey(
      {
        hash: "SHA-256",
        modulusLength: 2048,
        name: "RSA-OAEP",
        publicExponent: Uint8Array.of(1, 0, 1),
      },
      false,
      ["encrypt", "decrypt"],
    );
    const authorization = {
      approvalId: "approval-1",
      method: "user-approved",
    } as const;
    const provider = createWebCryptoFederationAbuseEvidenceProvider({
      createEvidenceId: () => "evidence-1",
      resolveRecipientPublicKey: async (keyId) =>
        keyId === "moderation-key-1" ? pair.publicKey : undefined,
    });
    const sealed = await provider.seal({
      allegedSender: "sender-1",
      authorization,
      evidence: text.encode("private evidence"),
      messageIds: ["message-1"],
      recipientKeyId: "moderation-key-1",
      reportId: "report-1",
    });
    const context = {
      allegedSender: "sender-1",
      authorization,
      messageIds: ["message-1"],
      recipientKeyId: "moderation-key-1",
      reportId: "report-1",
    };
    expect(
      new TextDecoder().decode(
        await openWebCryptoFederationAbuseEvidence({
          context,
          maximumSealedBytes: 4_096,
          privateKey: pair.privateKey,
          sealed: sealed.bytes,
        }),
      ),
    ).toBe("private evidence");
    await expect(
      openWebCryptoFederationAbuseEvidence({
        context: { ...context, messageIds: ["substituted-message"] },
        maximumSealedBytes: 4_096,
        privateKey: pair.privateKey,
        sealed: sealed.bytes,
      }),
    ).rejects.toThrow();
    expect(sealed.senderAuthenticity).toBe("receiver-asserted");
  });
});
