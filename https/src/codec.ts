import {
  decodeSignedFederationEnvelope,
  encodeSignedFederationEnvelope,
  type SignedFederationEnvelope,
} from "@absolutejs/secure-messaging-federation";
import {
  HTTPS_FEDERATION_MESSAGES_PATH,
  HTTPS_FEDERATION_PROTOCOL,
  type FederationHttpsAdvertisement,
  type FederationHttpsLimits,
} from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const FINGERPRINT = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/u;
const DOMAIN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const exactKeys = (
  value: Record<string, unknown>,
  expected: readonly string[],
) => Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");

const parseJson = (bytes: Uint8Array, label: string): unknown => {
  try {
    return JSON.parse(decoder.decode(bytes));
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
};

const toBase64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const fromBase64Url = (value: string, maximumBytes: number): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value))
    throw new Error("Batch item is not base64url.");
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let bytes: Uint8Array;
  try {
    const binary = atob(
      value.replaceAll("-", "+").replaceAll("_", "/") + padding,
    );
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error("Batch item is not base64url.");
  }
  if (
    bytes.length === 0 ||
    bytes.length > maximumBytes ||
    toBase64Url(bytes) !== value
  )
    throw new Error("Batch item is empty, oversized, or non-canonical.");
  return bytes;
};

export const encodeFederationHttpsAdvertisement = (
  advertisement: FederationHttpsAdvertisement,
): Uint8Array => encoder.encode(JSON.stringify(advertisement));

export const decodeFederationHttpsAdvertisement = (
  bytes: Uint8Array,
  input: {
    readonly expectedDomain: string;
    readonly maximumBytes: number;
    readonly maximumClockSkewMs: number;
    readonly maximumTtlMs: number;
    readonly now: number;
  },
): FederationHttpsAdvertisement => {
  if (bytes.length === 0 || bytes.length > input.maximumBytes)
    throw new Error("Federation HTTPS advertisement exceeds policy.");
  const value = parseJson(bytes, "Federation HTTPS advertisement");
  const keys = [
    "certificateFingerprintsSha256",
    "contract",
    "createdAt",
    "domain",
    "expiresAt",
    "maximumBatchBytes",
    "maximumBatchMessages",
    "messagesPath",
    "protocol",
    "requiresMutualTls",
  ];
  if (!isRecord(value) || !exactKeys(value, keys))
    throw new Error("Federation HTTPS advertisement has unknown fields.");
  if (
    value.contract !== 1 ||
    value.protocol !== HTTPS_FEDERATION_PROTOCOL ||
    value.messagesPath !== HTTPS_FEDERATION_MESSAGES_PATH ||
    value.requiresMutualTls !== true ||
    typeof value.domain !== "string" ||
    !DOMAIN.test(value.domain) ||
    value.domain !== input.expectedDomain ||
    !Array.isArray(value.certificateFingerprintsSha256) ||
    value.certificateFingerprintsSha256.length === 0 ||
    !value.certificateFingerprintsSha256.every(
      (entry) => typeof entry === "string" && FINGERPRINT.test(entry),
    ) ||
    new Set(value.certificateFingerprintsSha256).size !==
      value.certificateFingerprintsSha256.length ||
    typeof value.createdAt !== "number" ||
    !Number.isSafeInteger(value.createdAt) ||
    typeof value.expiresAt !== "number" ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.createdAt > input.now + input.maximumClockSkewMs ||
    value.expiresAt <= input.now ||
    value.expiresAt - value.createdAt > input.maximumTtlMs ||
    typeof value.maximumBatchBytes !== "number" ||
    !Number.isSafeInteger(value.maximumBatchBytes) ||
    value.maximumBatchBytes < 1 ||
    typeof value.maximumBatchMessages !== "number" ||
    !Number.isSafeInteger(value.maximumBatchMessages) ||
    value.maximumBatchMessages < 1
  )
    throw new Error("Federation HTTPS advertisement is invalid or expired.");
  return Object.freeze({
    certificateFingerprintsSha256: Object.freeze([
      ...value.certificateFingerprintsSha256,
    ]) as readonly string[],
    contract: 1,
    createdAt: value.createdAt,
    domain: value.domain,
    expiresAt: value.expiresAt,
    maximumBatchBytes: value.maximumBatchBytes,
    maximumBatchMessages: value.maximumBatchMessages,
    messagesPath: HTTPS_FEDERATION_MESSAGES_PATH,
    protocol: HTTPS_FEDERATION_PROTOCOL,
    requiresMutualTls: true,
  });
};

export const encodeFederationHttpsBatch = (
  messages: readonly SignedFederationEnvelope[],
  limits: Pick<
    FederationHttpsLimits,
    "maximumBatchBytes" | "maximumBatchMessages"
  >,
): Uint8Array => {
  if (messages.length === 0 || messages.length > limits.maximumBatchMessages)
    throw new Error("Federation HTTPS batch count exceeds policy.");
  const bytes = encoder.encode(
    JSON.stringify({
      contract: 1,
      messages: messages.map((message) =>
        toBase64Url(encodeSignedFederationEnvelope(message)),
      ),
    }),
  );
  if (bytes.length > limits.maximumBatchBytes)
    throw new Error("Federation HTTPS batch bytes exceed policy.");
  return bytes;
};

export const decodeFederationHttpsBatch = (
  bytes: Uint8Array,
  limits: Pick<
    FederationHttpsLimits,
    | "maximumBatchBytes"
    | "maximumBatchMessages"
    | "maximumEnvelopeBytes"
    | "maximumPayloadBytes"
    | "maximumSignatureBytes"
  >,
): readonly SignedFederationEnvelope[] => {
  if (bytes.length === 0 || bytes.length > limits.maximumBatchBytes)
    throw new Error("Federation HTTPS batch bytes exceed policy.");
  const value = parseJson(bytes, "Federation HTTPS batch");
  if (
    !isRecord(value) ||
    !exactKeys(value, ["contract", "messages"]) ||
    value.contract !== 1 ||
    !Array.isArray(value.messages) ||
    value.messages.length === 0 ||
    value.messages.length > limits.maximumBatchMessages ||
    !value.messages.every((entry) => typeof entry === "string")
  )
    throw new Error("Federation HTTPS batch is invalid.");
  return Object.freeze(
    value.messages.map((entry) =>
      decodeSignedFederationEnvelope(
        fromBase64Url(entry as string, limits.maximumEnvelopeBytes),
        limits,
      ),
    ),
  );
};
