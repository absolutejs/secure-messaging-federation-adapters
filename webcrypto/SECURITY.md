# Security policy

Experimental and unaudited. Use fresh, non-extractable production private keys.
Pin public keys to an authenticated domain/key directory with rotation and
revocation. Reject unknown algorithms and key usages.

The evidence format protects confidentiality and metadata binding; it does not
prove the alleged sender authored the reported plaintext. A recipient can
fabricate `receiver-asserted` evidence. Decrypt only inside the authorized
moderation boundary and avoid logging plaintext.
