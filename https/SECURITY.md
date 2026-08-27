# Security policy

Experimental and unaudited. Use TLS 1.3 where available, an application-specific
CA or reviewed trust policy, non-exportable/HSM client keys, short certificate
lifetimes, overlap during rotation, and immediate peer revocation.

Never derive a reference identity from attacker-controlled discovery. The
configured domain remains the TLS server name and certificate identity. Resolve
addresses once per expiring record and connect to that exact address to prevent
DNS changes between policy evaluation and connection.

Do not follow redirects. Reject HTTP, proxy environment inheritance, unexpected
content types, unbounded responses, foreign origins, and empty or partial batch
success. Rate limiting, durable idempotent queues, certificate issuance, and
peer revocation remain gateway responsibilities.
