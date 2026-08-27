# `@absolutejs/secure-messaging-federation-webcrypto`

Standard Web Crypto providers for AbsoluteJS federation:

- ECDSA P-256/SHA-256 domain signatures; and
- RSA-OAEP/SHA-256 key wrapping plus AES-256-GCM confidential abuse evidence.

The application owns key generation, private-key custody, domain discovery,
rotation, revocation, and the public-key directory. Prefer non-exportable private
keys or an HSM/KMS-backed adapter in production.

Evidence is encrypted at the endpoint directly to the chosen moderation public
key. The report ID, alleged sender, selected message IDs, authorization, recipient
key ID, and format version are authenticated as AES-GCM AAD. This provider emits
`receiver-asserted`; it does not implement or claim cryptographic message franking.
