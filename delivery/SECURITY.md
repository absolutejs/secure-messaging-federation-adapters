# Security policy

Report vulnerabilities privately through GitHub's security-advisory workflow
for `absolutejs/secure-messaging-federation-adapters`.

Never put user identity data or authorization secrets in a `routeId`,
`sessionId`, envelope ID, or conversation ID. Treat transport authentication,
federation signatures, replay storage, and MLS as separate required controls.
Reject rather than downgrade when a configured security mode, session,
content type, destination domain, or transcript binding does not match.

The bridge authenticates messages; it does not establish TLS, operate a PKI,
retain durable queues, or decide whether a peer is authorized. Supply hardened
implementations for those boundaries.
