import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  evidenceRecipientKeyId?: string;
  signatureKeyId?: string;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "sign a federation transcript or envelope with Web Crypto",
      "verify a remote provider domain signature",
      "seal confidential abuse evidence to a moderation key",
      "open authorized abuse evidence in a moderation boundary",
    ],
    keywords: [
      "federation signature",
      "ECDSA",
      "RSA-OAEP",
      "AES-GCM",
      "abuse evidence",
    ],
    protocols: ["ECDSA P-256 SHA-256", "RSA-OAEP SHA-256", "AES-256-GCM"],
  },
  identity: {
    accent: "#0369a1",
    category: "security",
    description:
      "Web Crypto domain signatures and endpoint-sealed confidential abuse evidence.",
    docsUrl:
      "https://github.com/absolutejs/secure-messaging-federation-adapters/tree/main/webcrypto",
    name: "@absolutejs/secure-messaging-federation-webcrypto",
    tagline: "Authenticate domains and seal evidence with standard Web Crypto.",
  },
  settings: Type.Object(
    {
      evidenceRecipientKeyId: Type.Optional(
        Type.String({ minLength: 1, title: "Evidence recipient key ID" }),
      ),
      signatureKeyId: Type.Optional(
        Type.String({ minLength: 1, title: "Signature key ID" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
