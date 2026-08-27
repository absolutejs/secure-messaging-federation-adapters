import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  maximumMessagesPerReceive?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "send MLS secure messaging frames across provider federation",
      "verify a remote domain before resolving application routing",
      "keep federation security modes explicit",
      "bridge secure messaging DeliveryService to interchangeable transports",
    ],
    keywords: [
      "secure messaging",
      "federation",
      "MLS",
      "DeliveryService",
      "strict E2EE",
    ],
    protocols: ["ABS-FED-1", "MLS-1.0"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "Authenticated federation DeliveryService bridge for AbsoluteJS secure messaging frames.",
    docsUrl:
      "https://github.com/absolutejs/secure-messaging-federation-adapters/tree/main/delivery",
    name: "@absolutejs/secure-messaging-federation-delivery",
    tagline: "Carry real secure messaging frames between domains.",
  },
  settings: Type.Object(
    {
      maximumMessagesPerReceive: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum receive batch" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
