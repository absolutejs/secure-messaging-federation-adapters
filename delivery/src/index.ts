import type {
  DeliveryMessage,
  DeliveryService,
  SecurityMode,
} from "@absolutejs/e2ee";
import {
  FEDERATION_CONTRACT,
  signFederationEnvelope,
  verifyFederationEnvelope,
  type FederationEnvelope,
  type FederationLimits,
  type FederationReplayStore,
  type FederationSession,
  type FederationSignatureProvider,
  type FederationTransportAdapter,
} from "@absolutejs/secure-messaging-federation";

export const SECURE_MESSAGING_FEDERATION_CONTENT_TYPE =
  "application/absolute-secure-message" as const;

export type FederationDeliveryOutboundRoute = {
  readonly expiresAt: number;
  readonly routeId: string;
  readonly securityMode: SecurityMode;
  readonly session: FederationSession;
};

export type FederationDeliveryInboundSession = {
  readonly securityMode: SecurityMode;
  readonly session: FederationSession;
};

export type FederationDeliveryInboundRoute = {
  readonly conversationId: string;
  readonly recipientDeviceId?: string;
};

export type FederationDeliveryDirectory = {
  /** Resolve only preconfigured opaque IDs. This runs before signature verification. */
  readonly resolveInboundSession: (input: {
    readonly originDomain: string;
    readonly routeId: string;
    readonly sessionId: string;
  }) => Promise<FederationDeliveryInboundSession | undefined>;
  /** Resolve application routing only after the envelope signature verifies. */
  readonly resolveVerifiedInboundRoute: (
    envelope: FederationEnvelope,
  ) => Promise<FederationDeliveryInboundRoute | undefined>;
  readonly resolveOutboundRoute: (
    message: DeliveryMessage,
  ) => Promise<FederationDeliveryOutboundRoute | undefined>;
};

const requireSession = (
  session: FederationSession,
  securityMode: SecurityMode,
): void => {
  if (
    session.profile.security.mode !== securityMode ||
    !session.profile.contentTypes.includes(
      SECURE_MESSAGING_FEDERATION_CONTENT_TYPE,
    )
  )
    throw new Error(
      "Federation session does not match secure messaging mode or content type.",
    );
};

export const createFederatedDeliveryService = (input: {
  readonly directory: FederationDeliveryDirectory;
  readonly limits: FederationLimits;
  readonly localDomain: string;
  readonly maximumMessagesPerReceive: number;
  readonly now?: () => number;
  readonly replayStore: FederationReplayStore;
  readonly signatureProvider: FederationSignatureProvider;
  readonly transport: FederationTransportAdapter;
}): DeliveryService => ({
  acknowledge: async ({ cursor }) =>
    input.transport.acknowledge({
      cursor,
      localDomain: input.localDomain,
    }),
  receive: async ({ value: cursor }) => {
    const batch = await input.transport.receive({
      ...(cursor === undefined ? {} : { cursor }),
      localDomain: input.localDomain,
      maximumMessages: input.maximumMessagesPerReceive,
    });
    if (batch.messages.length > input.maximumMessagesPerReceive)
      throw new Error("Federation transport exceeded the receive batch limit.");
    const messages: DeliveryMessage[] = [];
    for (const signed of batch.messages) {
      const envelope = signed.envelope;
      const inboundSession = await input.directory.resolveInboundSession({
        originDomain: envelope.originDomain,
        routeId: envelope.routeId,
        sessionId: envelope.sessionId,
      });
      if (inboundSession === undefined)
        throw new Error("Federation session is not configured for this route.");
      requireSession(inboundSession.session, inboundSession.securityMode);
      const verified = await verifyFederationEnvelope({
        limits: input.limits,
        localDomain: input.localDomain,
        now: input.now?.() ?? Date.now(),
        replayStore: input.replayStore,
        session: inboundSession.session,
        signatureProvider: input.signatureProvider,
        signed,
      });
      const route = await input.directory.resolveVerifiedInboundRoute(verified);
      if (route === undefined)
        throw new Error("Verified federation route is not configured.");
      messages.push(
        Object.freeze({
          bytes: verified.payload,
          conversationId: route.conversationId,
          id: verified.id,
          kind: verified.kind,
          ...(route.recipientDeviceId === undefined
            ? {}
            : { recipientDeviceId: route.recipientDeviceId }),
        }),
      );
    }
    return Object.freeze({
      ...(batch.cursor === undefined ? {} : { cursor: batch.cursor }),
      messages: Object.freeze(messages),
    });
  },
  send: async (messages) => {
    if (messages.length === 0) return;
    const signed = await Promise.all(
      messages.map(async (message) => {
        const route = await input.directory.resolveOutboundRoute(message);
        if (route === undefined)
          throw new Error(
            "Federation route is not configured for the message.",
          );
        requireSession(route.session, route.securityMode);
        return signFederationEnvelope({
          envelope: {
            contract: FEDERATION_CONTRACT,
            createdAt: input.now?.() ?? Date.now(),
            destinationDomain:
              route.session.initiatorDomain === input.localDomain
                ? route.session.responderDomain
                : route.session.initiatorDomain,
            expiresAt: route.expiresAt,
            id: message.id,
            kind: message.kind,
            originDomain: input.localDomain,
            payload: message.bytes,
            routeId: route.routeId,
            sessionId: route.session.sessionId,
            transcriptHash: route.session.transcriptHash,
          },
          limits: input.limits,
          localDomain: input.localDomain,
          now: input.now?.() ?? Date.now(),
          session: route.session,
          signatureProvider: input.signatureProvider,
        });
      }),
    );
    await input.transport.send(signed);
  },
});

export { manifest } from "./manifest";
