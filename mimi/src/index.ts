import type { FederationProfile } from "@absolutejs/secure-messaging-federation";

export const MIMI_DRAFT_OPT_IN =
  "I understand MIMI drafts are work in progress" as const;
export const MIMI_DRAFT_REVISIONS = Object.freeze({
  architecture: "draft-ietf-mimi-arch-03",
  content: "draft-ietf-mimi-content-09",
  protocol: "draft-ietf-mimi-protocol-06",
  roomPolicy: "draft-ietf-mimi-room-policy-04",
});
export const MIMI_DRAFT_PROFILE_ID =
  "mimi.protocol-06.content-09.policy-04.mls10.strict" as const;

export type MimiDraftAdvertisement = {
  readonly architecture: typeof MIMI_DRAFT_REVISIONS.architecture;
  readonly content: typeof MIMI_DRAFT_REVISIONS.content;
  /** Draft-06 still describes its binary encoding as a placeholder. */
  readonly encodingStatus: "draft-placeholder";
  /** Draft-06 describes some identifier syntax as notional. */
  readonly identifierStatus: "notional";
  readonly mutualTlsRequired: true;
  readonly protocol: typeof MIMI_DRAFT_REVISIONS.protocol;
  readonly roomPolicy: typeof MIMI_DRAFT_REVISIONS.roomPolicy;
};

export type MimiDraftProfileOptions = {
  readonly contentTypes: readonly string[];
  readonly experimentalOptIn: typeof MIMI_DRAFT_OPT_IN;
  readonly features?: readonly string[];
  readonly maximumFrameBytes: number;
};

export const assertMimiDraftAdvertisement = (
  advertisement: MimiDraftAdvertisement,
): void => {
  if (
    advertisement.architecture !== MIMI_DRAFT_REVISIONS.architecture ||
    advertisement.content !== MIMI_DRAFT_REVISIONS.content ||
    advertisement.protocol !== MIMI_DRAFT_REVISIONS.protocol ||
    advertisement.roomPolicy !== MIMI_DRAFT_REVISIONS.roomPolicy ||
    advertisement.encodingStatus !== "draft-placeholder" ||
    advertisement.identifierStatus !== "notional" ||
    advertisement.mutualTlsRequired !== true
  )
    throw new Error(
      "Peer does not match the pinned experimental MIMI draft set.",
    );
};

export const createMimiDraftProfile = (
  options: MimiDraftProfileOptions,
): FederationProfile => {
  if (options.experimentalOptIn !== MIMI_DRAFT_OPT_IN)
    throw new Error("Explicit MIMI draft opt-in is required.");
  if (
    !Number.isSafeInteger(options.maximumFrameBytes) ||
    options.maximumFrameBytes < 1 ||
    options.contentTypes.length === 0 ||
    new Set(options.contentTypes).size !== options.contentTypes.length ||
    new Set(options.features ?? []).size !== (options.features ?? []).length
  )
    throw new Error("MIMI draft profile configuration is invalid.");
  return Object.freeze({
    contentTypes: Object.freeze([...options.contentTypes]),
    e2eeProtocol: "MLS-1.0",
    features: Object.freeze([...(options.features ?? [])]),
    federationProtocol: "MIMI+MLS-over-mutual-TLS",
    id: MIMI_DRAFT_PROFILE_ID,
    maximumFrameBytes: options.maximumFrameBytes,
    revision: MIMI_DRAFT_REVISIONS.protocol,
    security: Object.freeze({ mode: "strict-e2ee" }),
  });
};
