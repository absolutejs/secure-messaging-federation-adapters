# `@absolutejs/secure-messaging-federation-https`

Hardened HTTPS transport for `@absolutejs/secure-messaging-federation`.

- Provider discovery is fixed at
  `/.well-known/absolutejs-secure-messaging-federation`.
- Delivery is fixed at the advertised protocol path and never follows redirects.
- The Node/Bun client presents its certificate and key, validates the server CA
  and DNS identity, pins the resolved address for the request, and then enforces
  advertised SHA-256 certificate rotation pins.
- Private, loopback, link-local, metadata-service, and special-use addresses are
  rejected by default. `allow-private` is an explicit development/private-mesh
  mode and must never be enabled for public tenant-controlled domains.
- Strict bounded batches carry only already-signed federation envelopes.

The package does not terminate inbound TLS itself. A server or PaaS gateway must
require and validate client certificates, derive `authenticatedPeerDomain` from
the verified certificate, and pass that identity to
`acceptFederationHttpsRequest`. The function checks it against both the request
origin header and every envelope origin before enqueueing.

This is the stable AbsoluteJS `ABS-FED-HTTPS-1` transport, not a claim of MIMI
wire interoperability. MIMI tracking remains in the revision-pinned adapter.
