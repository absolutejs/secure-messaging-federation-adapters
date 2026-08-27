import type {
  FederationTransportAdapter,
  SignedFederationEnvelope,
} from "@absolutejs/secure-messaging-federation";

export const HTTPS_FEDERATION_PROTOCOL = "ABS-FED-HTTPS-1" as const;
export const HTTPS_FEDERATION_WELL_KNOWN_PATH =
  "/.well-known/absolutejs-secure-messaging-federation" as const;
export const HTTPS_FEDERATION_MESSAGES_PATH =
  "/.well-known/absolutejs-secure-messaging-federation/v1/messages" as const;

export type FederationHttpsAdvertisement = {
  readonly certificateFingerprintsSha256: readonly string[];
  readonly contract: 1;
  readonly createdAt: number;
  readonly domain: string;
  readonly expiresAt: number;
  readonly maximumBatchBytes: number;
  readonly maximumBatchMessages: number;
  readonly messagesPath: typeof HTTPS_FEDERATION_MESSAGES_PATH;
  readonly protocol: typeof HTTPS_FEDERATION_PROTOCOL;
  readonly requiresMutualTls: true;
};

export type FederationHttpsPeer = FederationHttpsAdvertisement & {
  /** Addresses resolved once and pinned for this peer record. */
  readonly addresses: readonly string[];
  readonly port: number;
};

export type FederationHttpsPeerDirectory = {
  readonly resolve: (domain: string) => Promise<FederationHttpsPeer>;
};

export type FederationMutualTlsRequest = {
  readonly body?: Uint8Array;
  readonly headers: Readonly<Record<string, string>>;
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly peer: FederationHttpsPeer;
};

export type FederationMutualTlsResponse = {
  readonly body: Uint8Array;
  readonly certificateFingerprintSha256: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly status: number;
};

export type FederationMutualTlsClient = {
  readonly request: (
    input: FederationMutualTlsRequest,
  ) => Promise<FederationMutualTlsResponse>;
};

export type FederationHttpsInbox = Pick<
  FederationTransportAdapter,
  "acknowledge" | "receive"
> & {
  readonly enqueue: (input: {
    readonly authenticatedPeerDomain: string;
    readonly messages: readonly SignedFederationEnvelope[];
  }) => Promise<"accepted" | "duplicate">;
};

export type FederationHttpsLimits = {
  readonly maximumBatchBytes: number;
  readonly maximumBatchMessages: number;
  readonly maximumEnvelopeBytes: number;
  readonly maximumPayloadBytes: number;
  readonly maximumResponseBytes: number;
  readonly maximumSignatureBytes: number;
  readonly requestTimeoutMs: number;
};
