import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  experimentalOptIn?: string;
  maximumFrameBytes?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams"],
    intents: [
      "pin an experimental MIMI draft profile",
      "reject mismatched MIMI draft revisions",
      "track MIMI without claiming stable interoperability",
    ],
    keywords: [
      "MIMI",
      "MLS",
      "federation",
      "Internet-Draft",
      "revision pinning",
    ],
    protocols: ["draft-ietf-mimi-protocol-06"],
  },
  identity: {
    accent: "#7c3aed",
    category: "security",
    description:
      "Explicit, revision-pinned profile adapter for active MIMI Internet-Drafts.",
    docsUrl:
      "https://github.com/absolutejs/secure-messaging-federation-adapters/tree/main/mimi",
    name: "@absolutejs/secure-messaging-federation-mimi",
    tagline:
      "Experiment with MIMI drafts without pretending they are finished.",
  },
  settings: Type.Object(
    {
      experimentalOptIn: Type.Optional(
        Type.String({ minLength: 1, title: "Experimental draft opt-in" }),
      ),
      maximumFrameBytes: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum frame bytes" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
