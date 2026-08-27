import type {
  FederationTransportAdapter,
  SignedFederationEnvelope,
} from "@absolutejs/secure-messaging-federation";
import {
  decodeFederationHttpsBatch,
  encodeFederationHttpsBatch,
} from "./codec";
import {
  HTTPS_FEDERATION_MESSAGES_PATH,
  type FederationHttpsInbox,
  type FederationHttpsLimits,
  type FederationHttpsPeerDirectory,
  type FederationMutualTlsClient,
} from "./types";

export const createHttpsFederationTransportAdapter = (input: {
  readonly client: FederationMutualTlsClient;
  readonly inbox: Pick<FederationHttpsInbox, "acknowledge" | "receive">;
  readonly limits: FederationHttpsLimits;
  readonly localDomain: string;
  readonly peers: FederationHttpsPeerDirectory;
}): FederationTransportAdapter => ({
  acknowledge: async ({ cursor, localDomain }) => {
    if (localDomain !== input.localDomain)
      throw new Error("Federation acknowledgement belongs to another domain.");
    await input.inbox.acknowledge({ cursor, localDomain });
  },
  id: "absolutejs.federation-transport.https-mtls",
  receive: async ({ cursor, localDomain, maximumMessages }) => {
    if (localDomain !== input.localDomain)
      throw new Error("Federation receive belongs to another domain.");
    return input.inbox.receive({ cursor, localDomain, maximumMessages });
  },
  send: async (messages) => {
    const groups = new Map<string, SignedFederationEnvelope[]>();
    for (const message of messages) {
      if (message.envelope.originDomain !== input.localDomain)
        throw new Error("Federation send contains a foreign origin domain.");
      const group = groups.get(message.envelope.destinationDomain) ?? [];
      group.push(message);
      groups.set(message.envelope.destinationDomain, group);
    }
    for (const [domain, group] of groups) {
      const peer = await input.peers.resolve(domain);
      if (
        group.length > peer.maximumBatchMessages ||
        group.length > input.limits.maximumBatchMessages
      )
        throw new Error("Federation HTTPS peer batch count limit exceeded.");
      const body = encodeFederationHttpsBatch(group, {
        maximumBatchBytes: Math.min(
          peer.maximumBatchBytes,
          input.limits.maximumBatchBytes,
        ),
        maximumBatchMessages: Math.min(
          peer.maximumBatchMessages,
          input.limits.maximumBatchMessages,
        ),
      });
      const response = await input.client.request({
        body,
        headers: {
          accept: "application/json",
          "content-type": "application/absolutejs-federation-batch+json",
          "x-absolutejs-federation-origin": input.localDomain,
        },
        method: "POST",
        path: peer.messagesPath,
        peer,
      });
      if (response.status !== 202 || response.body.length !== 0)
        throw new Error("Federation HTTPS peer did not accept the batch.");
    }
  },
});

export type FederationHttpsServerRequest = {
  readonly authenticatedPeerDomain: string;
  readonly body: Uint8Array;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly method: string;
  readonly path: string;
};

export const acceptFederationHttpsRequest = async (input: {
  readonly inbox: Pick<FederationHttpsInbox, "enqueue">;
  readonly limits: FederationHttpsLimits;
  readonly localDomain: string;
  readonly request: FederationHttpsServerRequest;
}): Promise<{ readonly body: Uint8Array; readonly status: 202 }> => {
  const request = input.request;
  if (
    request.method !== "POST" ||
    request.path !== HTTPS_FEDERATION_MESSAGES_PATH ||
    request.headers["content-type"]?.split(";", 1)[0]?.trim() !==
      "application/absolutejs-federation-batch+json" ||
    request.headers["x-absolutejs-federation-origin"] !==
      request.authenticatedPeerDomain
  )
    throw new Error("Federation HTTPS request metadata is invalid.");
  const messages = decodeFederationHttpsBatch(request.body, input.limits);
  if (
    messages.some(
      ({ envelope }) =>
        envelope.originDomain !== request.authenticatedPeerDomain ||
        envelope.destinationDomain !== input.localDomain,
    )
  )
    throw new Error("Federation HTTPS batch domain binding is invalid.");
  await input.inbox.enqueue({
    authenticatedPeerDomain: request.authenticatedPeerDomain,
    messages,
  });
  return Object.freeze({ body: new Uint8Array(), status: 202 });
};
