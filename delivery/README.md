# `@absolutejs/secure-messaging-federation-delivery`

An adapter from AbsoluteJS secure messaging's `DeliveryService` to an
authenticated, interchangeable federation transport. It carries the actual
protected messaging frame as opaque bytes; it does not replace MLS or decrypt
application content.

## Security boundary

Outbound application routing is converted into a provider-local opaque
`routeId`. Inbound code resolves only a preconfigured session before checking
the remote-domain signature. The application conversation and recipient route
are resolved only after authentication and replay checks succeed.

The selected `strict-e2ee` or `managed-recovery` mode must exactly match the
negotiated federation session. Modes are never inferred or silently downgraded.

Use random, non-semantic conversation and route identifiers. MLS authenticated
data can be visible to a delivery provider even though application plaintext is
encrypted; do not place email addresses, usernames, or other personal data in
identifiers.

## Usage

```ts
import { createFederatedDeliveryService } from "@absolutejs/secure-messaging-federation-delivery";

const delivery = createFederatedDeliveryService({
  directory,
  limits,
  localDomain: "alice.example",
  maximumMessagesPerReceive: 100,
  replayStore,
  signatureProvider,
  transport,
});
```

Pass `delivery` to `createSecureMessagingClient`. The directory is the policy
boundary: it must return negotiated, unexpired sessions and opaque routes for
the current tenant.

## Protocol position

This package is an AbsoluteJS bridge, not a claim of independent MIMI
interoperability. Use the revision-pinned MIMI adapter for experiments with the
active Internet-Drafts and the HTTPS adapter for the hardened network hop.
