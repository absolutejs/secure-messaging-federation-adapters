# `@absolutejs/secure-messaging-federation-mimi`

An explicitly experimental profile adapter for active MIMI Internet-Drafts. It
pins:

- `draft-ietf-mimi-arch-03`
- `draft-ietf-mimi-protocol-06`
- `draft-ietf-mimi-content-09`
- `draft-ietf-mimi-room-policy-04`

This is not a wire transport and does not claim MIMI interoperability. Protocol
draft-06 says its example binary encoding is a placeholder, calls some identifier
syntax notional, and lists known gaps. The adapter makes those limitations
machine-visible and requires a literal experimental opt-in. A different revision
fails instead of silently falling back.

MIMI draft-06 requires HTTPS over mutually authenticated TLS between providers
and MLS for end-to-end message protection. Actual transport work should begin
when the working group settles the relevant wire encoding, identifiers,
authentication, discovery, and capability behavior.

Track the [official MIMI working-group documents](https://datatracker.ietf.org/wg/mimi/documents/)
and [protocol draft-06](https://datatracker.ietf.org/doc/html/draft-ietf-mimi-protocol-06).
