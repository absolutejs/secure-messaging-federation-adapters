import {
  canonicalBytes,
  type FederationAbuseAuthorization,
  type FederationAbuseEvidenceProvider,
  type FederationSignatureProvider,
} from "@absolutejs/secure-messaging-federation";

const SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256";
const EVIDENCE_PROTOCOL = "ABS-FED-EVIDENCE-RSA-OAEP-A256GCM-1";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const bytes = (value: Uint8Array): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(value);

const toBase64Url = (value: Uint8Array): string => {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const fromBase64Url = (value: string): Uint8Array<ArrayBuffer> => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("Invalid base64url.");
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(
    value.replaceAll("-", "+").replaceAll("_", "/") + padding,
  );
  const decoded = Uint8Array.from(binary, (character) =>
    character.charCodeAt(0),
  );
  if (toBase64Url(decoded) !== value)
    throw new Error("Non-canonical base64url.");
  return decoded;
};

const requireKey = (
  key: CryptoKey,
  algorithm: "ECDSA" | "RSA-OAEP",
  type: "private" | "public",
  usage: KeyUsage,
): void => {
  if (
    key.algorithm.name !== algorithm ||
    key.type !== type ||
    !key.usages.includes(usage) ||
    (algorithm === "ECDSA" &&
      (key.algorithm as EcKeyAlgorithm).namedCurve !== "P-256") ||
    (algorithm === "RSA-OAEP" &&
      (key.algorithm as RsaHashedKeyAlgorithm).hash.name !== "SHA-256")
  )
    throw new Error(`${algorithm} ${type} key does not permit ${usage}.`);
};

export type WebCryptoFederationSignatureOptions = {
  readonly keyId: string;
  readonly localDomain: string;
  readonly privateKey: CryptoKey;
  readonly resolvePublicKey: (input: {
    readonly algorithm: typeof SIGNATURE_ALGORITHM;
    readonly domain: string;
    readonly keyId: string;
  }) => Promise<CryptoKey | undefined>;
};

const signaturePayload = (input: {
  readonly destinationDomain: string;
  readonly payload: Uint8Array;
  readonly purpose: "federation-envelope" | "federation-transcript";
  readonly sourceDomain: string;
}): Uint8Array =>
  canonicalBytes({
    contract: 1,
    destinationDomain: input.destinationDomain,
    payload: input.payload,
    purpose: input.purpose,
    sourceDomain: input.sourceDomain,
  });

export const createWebCryptoFederationSignatureProvider = (
  options: WebCryptoFederationSignatureOptions,
): FederationSignatureProvider => {
  requireKey(options.privateKey, "ECDSA", "private", "sign");
  return Object.freeze({
    id: "absolutejs.federation-signature.webcrypto",
    sign: async ({ destinationDomain, payload, purpose }) => ({
      algorithm: SIGNATURE_ALGORITHM,
      keyId: options.keyId,
      signature: new Uint8Array(
        await crypto.subtle.sign(
          { hash: "SHA-256", name: "ECDSA" },
          options.privateKey,
          bytes(
            signaturePayload({
              destinationDomain,
              payload,
              purpose,
              sourceDomain: options.localDomain,
            }),
          ),
        ),
      ),
    }),
    verify: async ({
      destinationDomain,
      expectedDomain,
      payload,
      purpose,
      signature,
    }) => {
      if (signature.algorithm !== SIGNATURE_ALGORITHM) return false;
      const publicKey = await options.resolvePublicKey({
        algorithm: SIGNATURE_ALGORITHM,
        domain: expectedDomain,
        keyId: signature.keyId,
      });
      if (publicKey === undefined) return false;
      try {
        requireKey(publicKey, "ECDSA", "public", "verify");
        return await crypto.subtle.verify(
          { hash: "SHA-256", name: "ECDSA" },
          publicKey,
          bytes(signature.signature),
          bytes(
            signaturePayload({
              destinationDomain,
              payload,
              purpose,
              sourceDomain: expectedDomain,
            }),
          ),
        );
      } catch {
        return false;
      }
    },
  });
};

export type WebCryptoAbuseEvidenceContext = {
  readonly allegedSender: string;
  readonly authorization: FederationAbuseAuthorization;
  readonly messageIds: readonly string[];
  readonly recipientKeyId: string;
  readonly reportId: string;
};

export type WebCryptoFederationAbuseEvidenceOptions = {
  readonly createEvidenceId: () => string;
  readonly resolveRecipientPublicKey: (
    keyId: string,
  ) => Promise<CryptoKey | undefined>;
};

const evidenceAad = (context: WebCryptoAbuseEvidenceContext): Uint8Array =>
  canonicalBytes({
    allegedSender: context.allegedSender,
    authorization: context.authorization,
    messageIds: context.messageIds,
    protocol: EVIDENCE_PROTOCOL,
    recipientKeyId: context.recipientKeyId,
    reportId: context.reportId,
  });

export const createWebCryptoFederationAbuseEvidenceProvider = (
  options: WebCryptoFederationAbuseEvidenceOptions,
): FederationAbuseEvidenceProvider => ({
  id: "absolutejs.federation-abuse-evidence.webcrypto",
  seal: async (input) => {
    const recipientKey = await options.resolveRecipientPublicKey(
      input.recipientKeyId,
    );
    if (recipientKey === undefined)
      throw new Error("Abuse evidence recipient key is unavailable.");
    requireKey(recipientKey, "RSA-OAEP", "public", "encrypt");
    const contentKey = await crypto.subtle.generateKey(
      { length: 256, name: "AES-GCM" },
      true,
      ["encrypt"],
    );
    const rawContentKey = new Uint8Array(
      await crypto.subtle.exportKey("raw", contentKey),
    );
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const context: WebCryptoAbuseEvidenceContext = {
      allegedSender: input.allegedSender,
      authorization: input.authorization,
      messageIds: input.messageIds,
      recipientKeyId: input.recipientKeyId,
      reportId: input.reportId,
    };
    const [ciphertext, wrappedKey] = await Promise.all([
      crypto.subtle.encrypt(
        {
          additionalData: bytes(evidenceAad(context)),
          iv,
          name: "AES-GCM",
          tagLength: 128,
        },
        contentKey,
        bytes(input.evidence),
      ),
      crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientKey, rawContentKey),
    ]);
    rawContentKey.fill(0);
    const encoded = encoder.encode(
      JSON.stringify({
        ciphertext: toBase64Url(new Uint8Array(ciphertext)),
        contract: 1,
        iv: toBase64Url(iv),
        wrappedKey: toBase64Url(new Uint8Array(wrappedKey)),
      }),
    );
    const evidenceId = options.createEvidenceId();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}$/u.test(evidenceId))
      throw new Error("Evidence ID is invalid.");
    return Object.freeze({
      bytes: encoded,
      evidenceId,
      providerId: "absolutejs.federation-abuse-evidence.webcrypto",
      protocol: EVIDENCE_PROTOCOL,
      recipientKeyId: input.recipientKeyId,
      senderAuthenticity: "receiver-asserted",
    });
  },
});

const decodeEvidence = (encoded: Uint8Array) => {
  const value: unknown = JSON.parse(decoder.decode(encoded));
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "ciphertext,contract,iv,wrappedKey" ||
    !("contract" in value) ||
    value.contract !== 1 ||
    !("ciphertext" in value) ||
    typeof value.ciphertext !== "string" ||
    !("iv" in value) ||
    typeof value.iv !== "string" ||
    !("wrappedKey" in value) ||
    typeof value.wrappedKey !== "string"
  )
    throw new Error("Abuse evidence envelope is invalid.");
  const iv = fromBase64Url(value.iv);
  if (iv.length !== 12) throw new Error("Abuse evidence nonce is invalid.");
  return {
    ciphertext: fromBase64Url(value.ciphertext),
    iv,
    wrappedKey: fromBase64Url(value.wrappedKey),
  };
};

export const openWebCryptoFederationAbuseEvidence = async (input: {
  readonly context: WebCryptoAbuseEvidenceContext;
  readonly maximumSealedBytes: number;
  readonly privateKey: CryptoKey;
  readonly sealed: Uint8Array;
}): Promise<Uint8Array> => {
  requireKey(input.privateKey, "RSA-OAEP", "private", "decrypt");
  if (
    !Number.isSafeInteger(input.maximumSealedBytes) ||
    input.maximumSealedBytes < 1 ||
    input.sealed.length === 0 ||
    input.sealed.length > input.maximumSealedBytes
  )
    throw new Error("Sealed abuse evidence exceeds moderation policy.");
  const envelope = decodeEvidence(input.sealed);
  const rawContentKey = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      input.privateKey,
      envelope.wrappedKey,
    ),
  );
  try {
    const contentKey = await crypto.subtle.importKey(
      "raw",
      rawContentKey,
      { length: 256, name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          additionalData: bytes(evidenceAad(input.context)),
          iv: envelope.iv,
          name: "AES-GCM",
          tagLength: 128,
        },
        contentKey,
        envelope.ciphertext,
      ),
    );
  } finally {
    rawContentKey.fill(0);
  }
};

export {
  EVIDENCE_PROTOCOL as WEBCRYPTO_FEDERATION_EVIDENCE_PROTOCOL,
  SIGNATURE_ALGORITHM as WEBCRYPTO_FEDERATION_SIGNATURE_ALGORITHM,
};
