import type {
  FederationLimits,
  FederationReplayStore,
  FederationSession,
  FederationSignatureProvider,
  FederationTransportAdapter,
  SignedFederationEnvelope,
} from "@absolutejs/secure-messaging-federation";
import { expect, test } from "bun:test";
import {
  createFederatedDeliveryService,
  SECURE_MESSAGING_FEDERATION_CONTENT_TYPE,
  type FederationDeliveryDirectory,
} from "../src";

const now = 1_800_000_000_000;
const limits: FederationLimits = {
  maximumClockSkewMs: 1_000,
  maximumFrameBytes: 1_000_000,
  maximumMessagesPerBatch: 10,
  maximumOfferTtlMs: 60_000,
  maximumTtlMs: 60_000,
};
const session: FederationSession = {
  expiresAt: now + 60_000,
  initiatorDomain: "alice.example",
  profile: {
    contentTypes: [SECURE_MESSAGING_FEDERATION_CONTENT_TYPE],
    e2eeProtocol: "MLS-1.0",
    features: [],
    federationProtocol: "ABS-FED-HTTPS-1",
    id: "absolute-mls",
    maximumFrameBytes: 1_000_000,
    revision: "1",
    security: { mode: "strict-e2ee" },
  },
  responderDomain: "bob.example",
  sessionId: "session-1",
  transcriptHash: "transcript-1",
};

const equal = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

const signatures: FederationSignatureProvider = {
  id: "test-signatures",
  sign: async ({ payload }) => ({
    algorithm: "TEST",
    keyId: "key-1",
    signature: payload.slice(),
  }),
  verify: async ({ payload, signature }) => equal(payload, signature.signature),
};

const replayStore = (): FederationReplayStore => {
  const claimed = new Set<string>();
  return {
    claim: async ({ id, originDomain, sessionId }) => {
      const key = `${originDomain}:${sessionId}:${id}`;
      if (claimed.has(key)) return "duplicate";
      claimed.add(key);
      return "claimed";
    },
  };
};

const network = () => {
  const queues = new Map<string, SignedFederationEnvelope[]>();
  const transport = (localDomain: string): FederationTransportAdapter => ({
    id: `memory:${localDomain}`,
    acknowledge: async ({ cursor }) => {
      if (cursor !== `cursor:${localDomain}`) throw new Error("Bad cursor.");
      queues.set(localDomain, []);
    },
    receive: async ({ maximumMessages }) => ({
      cursor: `cursor:${localDomain}`,
      messages: (queues.get(localDomain) ?? []).slice(0, maximumMessages),
    }),
    send: async (messages) => {
      for (const signed of messages) {
        const destination = signed.envelope.destinationDomain;
        queues.set(destination, [...(queues.get(destination) ?? []), signed]);
      }
    },
  });
  return { queues, transport };
};

const directory = (
  localDomain: string,
  remoteDeviceId: string,
  events: string[],
): FederationDeliveryDirectory => ({
  resolveInboundSession: async () => {
    events.push("session");
    return { securityMode: "strict-e2ee", session };
  },
  resolveVerifiedInboundRoute: async () => {
    events.push("route");
    return {
      conversationId: "c_7gsC1fWaQWqvPYxV",
      recipientDeviceId:
        localDomain === "alice.example" ? "alice-phone" : "bob-laptop",
    };
  },
  resolveOutboundRoute: async () => ({
    expiresAt: now + 30_000,
    routeId: remoteDeviceId,
    securityMode: "strict-e2ee",
    session,
  }),
});

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");

const authenticationService = (): AuthenticationService => {
  const bindings = new Map<string, string>();
  let sequence = 0;
  return {
    issueDeviceCredential: async ({ deviceId, identityId, publicKey }) => {
      const bytes = new TextEncoder().encode(`credential-${sequence++}`);
      bindings.set(hex(bytes), hex(publicKey));
      return {
        bytes,
        deviceId,
        expiresAt: Date.now() + 60_000,
        identityId,
        issuedAt: Date.now(),
      };
    },
    sameIdentity: async (left, right) => left.identityId === right.identityId,
    validateDeviceCredential: async ({ credential, publicKey }) => ({
      identityId: credential.identityId,
      status:
        bindings.get(hex(credential.bytes)) === hex(publicKey)
          ? "valid"
          : "invalid",
    }),
  };
};

const stateProtection = async (): Promise<MlsStateProtection> => {
  const key = await crypto.subtle.generateKey(
    { length: 256, name: "AES-GCM" },
    false,
    ["decrypt", "encrypt"],
  );
  return {
    open: async ({ sealedState }) =>
      new Uint8Array(
        await crypto.subtle.decrypt(
          { iv: sealedState.slice(0, 12), name: "AES-GCM" },
          key,
          sealedState.slice(12),
        ),
      ),
    seal: async ({ state }) => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { iv, name: "AES-GCM" },
          key,
          Uint8Array.from(state),
        ),
      );
      const sealed = new Uint8Array(iv.length + ciphertext.length);
      sealed.set(iv);
      sealed.set(ciphertext, iv.length);
      return sealed;
    },
  };
};

const messagingStore = (): SecureMessagingStore => {
  const conversations = new Map<string, SecureMessagingStoredConversation>();
  const receipts = new Map<string, string>();
  const outbox = new Map<string, SecureMessagingOutboxEntry>();
  return {
    commit: async ({
      conversation,
      expectedRevision,
      inbound,
      outbox: next,
    }) => {
      const prior = conversations.get(conversation.conversationId);
      if (
        (expectedRevision === undefined && prior !== undefined) ||
        (expectedRevision !== undefined && prior?.revision !== expectedRevision)
      )
        return "state-conflict";
      if (inbound !== undefined) {
        const key = `${inbound.conversationId}:${inbound.messageId}`;
        const digest = receipts.get(key);
        if (digest !== undefined && digest !== inbound.digest)
          return "replay-conflict";
        receipts.set(key, inbound.digest);
      }
      conversations.set(conversation.conversationId, {
        ...conversation,
        sealedState: conversation.sealedState.slice(),
      });
      for (const entry of next ?? []) outbox.set(entry.queueId, entry);
      return "committed";
    },
    inspectInbound: async ({ conversationId, digest, messageId }) => {
      const prior = receipts.get(`${conversationId}:${messageId}`);
      return prior === undefined
        ? "new"
        : prior === digest
          ? "duplicate"
          : "conflict";
    },
    listOutbox: async (limit) => [...outbox.values()].slice(0, limit),
    loadConversation: async (conversationId) =>
      conversations.get(conversationId),
    recordInbound: async (receipt) => {
      const key = `${receipt.conversationId}:${receipt.messageId}`;
      const prior = receipts.get(key);
      if (prior === receipt.digest) return "duplicate";
      if (prior !== undefined) return "conflict";
      receipts.set(key, receipt.digest);
      return "recorded";
    },
    removeConversation: async (conversationId, expectedRevision) => {
      if (conversations.get(conversationId)?.revision !== expectedRevision)
        return false;
      conversations.delete(conversationId);
      return true;
    },
    removeOutbox: async (queueIds) => {
      for (const queueId of queueIds) outbox.delete(queueId);
    },
  };
};

test("bridges an opaque protected frame and authenticates before app routing", async () => {
  const memory = network();
  const aliceEvents: string[] = [];
  const bobEvents: string[] = [];
  const alice = createFederatedDeliveryService({
    directory: directory("alice.example", "bob-laptop", aliceEvents),
    limits,
    localDomain: "alice.example",
    maximumMessagesPerReceive: 10,
    now: () => now,
    replayStore: replayStore(),
    signatureProvider: signatures,
    transport: memory.transport("alice.example"),
  });
  const bob = createFederatedDeliveryService({
    directory: directory("bob.example", "alice-phone", bobEvents),
    limits,
    localDomain: "bob.example",
    maximumMessagesPerReceive: 10,
    now: () => now,
    replayStore: replayStore(),
    signatureProvider: signatures,
    transport: memory.transport("bob.example"),
  });
  const protectedFrame = crypto.getRandomValues(new Uint8Array(128));
  await alice.send([
    {
      bytes: protectedFrame,
      conversationId: "c_7gsC1fWaQWqvPYxV",
      id: "message-1",
      kind: "application",
      recipientDeviceId: "bob-laptop",
    },
  ]);

  const outer = memory.queues.get("bob.example")?.[0]?.envelope;
  expect(outer?.routeId).toBe("bob-laptop");
  expect(outer?.routeId).not.toBe("c_7gsC1fWaQWqvPYxV");
  expect(bobEvents).toEqual([]);
  const received = await bob.receive({ deviceId: "bob-laptop" });
  expect(bobEvents).toEqual(["session", "route"]);
  expect(received.messages[0]?.conversationId).toBe("c_7gsC1fWaQWqvPYxV");
  expect(received.messages[0]?.bytes).toEqual(protectedFrame);
  if (received.cursor === undefined) throw new Error("Missing cursor.");
  await bob.acknowledge({ deviceId: "bob-laptop", cursor: received.cursor });
  expect((await bob.receive({ deviceId: "bob-laptop" })).messages).toEqual([]);
});

test("never resolves application routing for an invalid signature", async () => {
  const memory = network();
  const events: string[] = [];
  const alice = createFederatedDeliveryService({
    directory: directory("alice.example", "bob-laptop", []),
    limits,
    localDomain: "alice.example",
    maximumMessagesPerReceive: 10,
    now: () => now,
    replayStore: replayStore(),
    signatureProvider: signatures,
    transport: memory.transport("alice.example"),
  });
  await alice.send([
    {
      bytes: Uint8Array.of(1),
      conversationId: "c_7gsC1fWaQWqvPYxV",
      id: "message-2",
      kind: "application",
      recipientDeviceId: "bob-laptop",
    },
  ]);
  const queued = memory.queues.get("bob.example");
  if (queued === undefined || queued[0] === undefined)
    throw new Error("Missing fixture.");
  const signature = queued[0].signature.signature;
  signature[0] = (signature[0] ?? 0) ^ 1;
  const bob = createFederatedDeliveryService({
    directory: directory("bob.example", "alice-phone", events),
    limits,
    localDomain: "bob.example",
    maximumMessagesPerReceive: 10,
    now: () => now,
    replayStore: replayStore(),
    signatureProvider: signatures,
    transport: memory.transport("bob.example"),
  });
  await expect(bob.receive({ deviceId: "bob-laptop" })).rejects.toThrow(
    "signature",
  );
  expect(events).toEqual(["session"]);
});

test("carries a real strict-E2EE MLS welcome and bidirectional messages across domains", async () => {
  const authentication = authenticationService();
  const protection = await stateProtection();
  const providerOptions = {
    authenticationService: authentication,
    authorizeMembershipChange: () => true,
    stateProtection: protection,
  };
  const aliceProvider = await createMlsMessagingProvider(providerOptions);
  const bobProvider = await createMlsMessagingProvider(providerOptions);
  const aliceCredential = await aliceProvider.createDeviceCredential({
    deviceId: "alice-phone",
    identityId: "alice",
  });
  const bobCredential = await bobProvider.createDeviceCredential({
    deviceId: "bob-laptop",
    identityId: "bob",
  });
  const keyPackages = new Map<string, E2EEKeyPackage>();
  const keyPackageDirectory: KeyPackageDirectory = {
    claim: async (identityId) => {
      const keyPackage = keyPackages.get(identityId);
      keyPackages.delete(identityId);
      return keyPackage;
    },
    publish: async (keyPackage) => {
      keyPackages.set(keyPackage.credential.identityId, keyPackage);
    },
    remove: async () => undefined,
  };
  const memory = network();
  const aliceDelivery = createFederatedDeliveryService({
    directory: directory("alice.example", "bob-laptop", []),
    limits,
    localDomain: "alice.example",
    maximumMessagesPerReceive: 10,
    now: () => now,
    replayStore: replayStore(),
    signatureProvider: signatures,
    transport: memory.transport("alice.example"),
  });
  const bobDelivery = createFederatedDeliveryService({
    directory: directory("bob.example", "alice-phone", []),
    limits,
    localDomain: "bob.example",
    maximumMessagesPerReceive: 10,
    now: () => now,
    replayStore: replayStore(),
    signatureProvider: signatures,
    transport: memory.transport("bob.example"),
  });
  let id = 0;
  const common = {
    idFactory: () => `membership-${id++}`,
    keyPackageDirectory,
    membershipPolicy: {
      authorize: () => true,
      reviewInvitation: () => "accept" as const,
    },
    policy: {
      authorize: () => true,
      maximumFrameBytes: 1_000_000,
      maximumFutureSkewMs: 300_000,
      maximumMessageBytes: 1_024,
      maximumTtlMs: 60_000,
      securityMode: "strict-e2ee" as const,
    },
  };
  const alice = createSecureMessagingClient({
    ...common,
    delivery: aliceDelivery,
    deviceCredential: aliceCredential,
    provider: aliceProvider,
    store: messagingStore(),
  });
  const bob = createSecureMessagingClient({
    ...common,
    delivery: bobDelivery,
    deviceCredential: bobCredential,
    provider: bobProvider,
    store: messagingStore(),
  });

  await bob.publishKeyPackage(Date.now() + 30_000);
  await alice.createConversation("c_7gsC1fWaQWqvPYxV");
  expect(
    (
      await alice.invite({
        conversationId: "c_7gsC1fWaQWqvPYxV",
        identityId: "bob",
        ttlMs: 30_000,
      })
    ).delivery,
  ).toBe("delivered");
  expect((await bob.receive()).joined).toEqual(["c_7gsC1fWaQWqvPYxV"]);

  await alice.send({
    conversationId: "c_7gsC1fWaQWqvPYxV",
    id: "alice-message",
    plaintext: new TextEncoder().encode("hello Bob"),
    purpose: "chat.message",
    recipientDeviceId: "bob-laptop",
    ttlMs: 30_000,
  });
  const receivedByBob = await bob.receive();
  expect(receivedByBob.messages[0]?.kind).toBe("application");
  if (receivedByBob.messages[0]?.kind === "application")
    expect(
      new TextDecoder().decode(receivedByBob.messages[0].message.plaintext),
    ).toBe("hello Bob");

  await bob.send({
    conversationId: "c_7gsC1fWaQWqvPYxV",
    id: "bob-message",
    plaintext: new TextEncoder().encode("hello Alice"),
    purpose: "chat.message",
    recipientDeviceId: "alice-phone",
    ttlMs: 30_000,
  });
  const receivedByAlice = await alice.receive();
  expect(receivedByAlice.messages[0]?.kind).toBe("application");
  if (receivedByAlice.messages[0]?.kind === "application")
    expect(
      new TextDecoder().decode(receivedByAlice.messages[0].message.plaintext),
    ).toBe("hello Alice");

  const allOuter = [...memory.queues.values()].flat();
  expect(allOuter.length).toBe(0);
});
import type {
  AuthenticationService,
  E2EEKeyPackage,
  KeyPackageDirectory,
} from "@absolutejs/e2ee";
import {
  createMlsMessagingProvider,
  type MlsStateProtection,
} from "@absolutejs/e2ee-mls";
import {
  createSecureMessagingClient,
  type SecureMessagingOutboxEntry,
  type SecureMessagingStore,
  type SecureMessagingStoredConversation,
} from "@absolutejs/secure-messaging";
