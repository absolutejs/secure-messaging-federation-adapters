import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  addressPolicy?: "allow-private" | "public-only";
  maximumBatchBytes?: number;
  requestTimeoutMs?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "send signed federation envelopes over mutual TLS",
      "discover an authenticated provider federation endpoint",
      "pin provider certificate rotation",
      "reject redirects DNS rebinding and private-network SSRF",
      "accept a bounded provider-authenticated federation batch",
    ],
    keywords: [
      "secure messaging federation",
      "mutual TLS",
      "HTTPS",
      "certificate pinning",
      "SSRF",
      "DNS rebinding",
    ],
    protocols: ["ABS-FED-HTTPS-1"],
  },
  identity: {
    accent: "#1d4ed8",
    category: "security",
    description:
      "Mutual-TLS HTTPS federation with authenticated discovery, pinned addresses, strict batches, and no redirects.",
    docsUrl:
      "https://github.com/absolutejs/secure-messaging-federation-adapters/tree/main/https",
    name: "@absolutejs/secure-messaging-federation-https",
    tagline: "Carry signed federation envelopes across hardened HTTPS.",
  },
  settings: Type.Object(
    {
      addressPolicy: Type.Optional(
        Type.Union(
          [Type.Literal("public-only"), Type.Literal("allow-private")],
          {
            title: "Address policy",
          },
        ),
      ),
      maximumBatchBytes: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum batch bytes" }),
      ),
      requestTimeoutMs: Type.Optional(
        Type.Integer({ minimum: 1, title: "Request timeout milliseconds" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
