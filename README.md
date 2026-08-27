# AbsoluteJS secure messaging federation adapters

Interchangeable implementations for
`@absolutejs/secure-messaging-federation`:

- `@absolutejs/secure-messaging-federation-delivery` bridges real protected
  secure-messaging/MLS frames to a negotiated federation transport.
- `@absolutejs/secure-messaging-federation-https` provides a hardened HTTPS and
  mutual-TLS hop with authenticated discovery, certificate pins, bounded
  responses, and SSRF/DNS-rebinding defenses.
- `@absolutejs/secure-messaging-federation-webcrypto` provides domain signatures
  and endpoint-sealed abuse evidence with standard Web Crypto keys.
- `@absolutejs/secure-messaging-federation-mimi` pins and validates an explicit
  experimental profile for the current MIMI Internet-Drafts. It does not claim
  completed wire interoperability.

All releases remain `0.x` until the relevant APIs and standards stabilize.
