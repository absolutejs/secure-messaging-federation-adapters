# Changelog

## 0.0.3

- Race up to 16 resolved and pinned peer addresses with bounded 250 ms
  staggering, aborting the remaining attempts after the first authenticated
  HTTPS response.
- Validate the entire candidate set against the public-address policy before
  opening any connection.
- Add a real-socket mutual-TLS test covering address fallback, DNS SAN and
  certificate-pin validation, client authentication, and public-address policy.

## 0.0.2

- Preserve the certificate fingerprint from TLS identity verification so the
  Node mutual-TLS client also works on Bun, whose compatibility response socket
  does not expose `getPeerCertificate`.

## 0.0.1

- Add authenticated, expiring HTTPS discovery with certificate rotation pins.
- Add a Node/Bun mutual-TLS client with hostname verification, address pinning,
  response bounds, timeouts, and public-address SSRF policy.
- Add strict batch transport, server acceptance, origin-certificate binding, and
  local inbox acknowledgement without redirects or plaintext fallback.
