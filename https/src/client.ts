import { Buffer } from "node:buffer";
import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";
import {
  checkServerIdentity,
  type PeerCertificate,
  type TLSSocket,
} from "node:tls";
import { decodeFederationHttpsAdvertisement } from "./codec";
import {
  HTTPS_FEDERATION_PROTOCOL,
  HTTPS_FEDERATION_WELL_KNOWN_PATH,
  type FederationHttpsPeer,
  type FederationHttpsPeerDirectory,
  type FederationMutualTlsClient,
} from "./types";

const normalizeFingerprint = (value: string): string => value.toUpperCase();
const pem = (value: string | Uint8Array): string | Buffer =>
  typeof value === "string" ? value : Buffer.from(value);

const isPrivateIpv4 = (address: string): boolean => {
  const octets = address.split(".").map(Number);
  const first = octets[0] ?? -1;
  const second = octets[1] ?? -1;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && (second === 0 || second === 168)) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51 && octets[2] === 100) ||
    (first === 203 && second === 0 && octets[2] === 113) ||
    first >= 224
  );
};

export const isPublicFederationAddress = (address: string): boolean => {
  const family = isIP(address);
  if (family === 4) return !isPrivateIpv4(address);
  if (family !== 6) return false;
  const normalized = address.toLowerCase();
  if (normalized.startsWith("::ffff:"))
    return isPublicFederationAddress(normalized.slice(7));
  return !(
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb") ||
    normalized.startsWith("2001:db8:") ||
    normalized.startsWith("ff")
  );
};

export type NodeMutualTlsFederationClientOptions = {
  readonly addressPolicy?: "allow-private" | "public-only";
  readonly ca: string | Uint8Array;
  readonly certificate: string | Uint8Array;
  readonly key: string | Uint8Array;
  readonly maximumResponseBytes: number;
  readonly requestTimeoutMs: number;
};

export const createNodeMutualTlsFederationClient = (
  options: NodeMutualTlsFederationClientOptions,
): FederationMutualTlsClient => ({
  request: (input) =>
    new Promise((resolve, reject) => {
      if (
        input.peer.addresses.length === 0 ||
        !Number.isSafeInteger(input.peer.port) ||
        input.peer.port < 1 ||
        input.peer.port > 65_535 ||
        !input.path.startsWith("/") ||
        input.path.includes("#")
      ) {
        reject(new Error("Federation HTTPS peer or request path is invalid."));
        return;
      }
      const address = input.peer.addresses[0] as string;
      if (
        isIP(address) === 0 ||
        ((options.addressPolicy ?? "public-only") === "public-only" &&
          !isPublicFederationAddress(address))
      ) {
        reject(new Error("Federation HTTPS address policy rejected the peer."));
        return;
      }
      const request = httpsRequest(
        {
          ca: pem(options.ca),
          cert: pem(options.certificate),
          checkServerIdentity: (hostname, certificate) => {
            const identityError = checkServerIdentity(hostname, certificate);
            if (identityError !== undefined) return identityError;
            const pins =
              input.peer.certificateFingerprintsSha256.map(
                normalizeFingerprint,
              );
            if (
              pins.length > 0 &&
              !pins.includes(normalizeFingerprint(certificate.fingerprint256))
            )
              return new Error("Federation HTTPS certificate pin mismatch.");
            return undefined;
          },
          headers: {
            ...input.headers,
            "content-length": String(input.body?.length ?? 0),
            host:
              input.peer.port === 443
                ? input.peer.domain
                : `${input.peer.domain}:${input.peer.port}`,
          },
          hostname: address,
          key: pem(options.key),
          method: input.method,
          path: input.path,
          port: String(input.peer.port),
          rejectUnauthorized: true,
          servername: input.peer.domain,
        },
        (response) => {
          const chunks: Uint8Array[] = [];
          let total = 0;
          response.on("data", (chunk: Uint8Array) => {
            total += chunk.length;
            if (total > options.maximumResponseBytes) {
              request.destroy(
                new Error("Federation HTTPS response exceeds policy."),
              );
              return;
            }
            chunks.push(Uint8Array.from(chunk));
          });
          response.on("end", () => {
            const certificate = (
              response.socket as TLSSocket
            ).getPeerCertificate(false) as PeerCertificate;
            if (
              typeof certificate.fingerprint256 !== "string" ||
              certificate.fingerprint256.length === 0
            ) {
              reject(new Error("Federation HTTPS peer certificate is absent."));
              return;
            }
            const headers: Record<string, string> = {};
            for (const [name, value] of Object.entries(response.headers))
              if (typeof value === "string") headers[name] = value;
              else if (Array.isArray(value)) headers[name] = value.join(", ");
            resolve({
              body: Uint8Array.from(chunks.flatMap((chunk) => [...chunk])),
              certificateFingerprintSha256: normalizeFingerprint(
                certificate.fingerprint256,
              ),
              headers: Object.freeze(headers),
              status: response.statusCode ?? 0,
            });
          });
        },
      );
      request.setTimeout(options.requestTimeoutMs, () =>
        request.destroy(new Error("Federation HTTPS request timed out.")),
      );
      request.on("error", reject);
      if (input.body !== undefined) request.write(input.body);
      request.end();
    }),
});

export const discoverFederationHttpsPeer = async (input: {
  readonly addresses: readonly string[];
  readonly client: FederationMutualTlsClient;
  readonly domain: string;
  readonly maximumAdvertisementBytes: number;
  readonly maximumAdvertisementTtlMs: number;
  readonly maximumClockSkewMs: number;
  readonly now: number;
  readonly port?: number;
}): Promise<FederationHttpsPeer> => {
  const port = input.port ?? 443;
  const bootstrap: FederationHttpsPeer = {
    addresses: input.addresses,
    certificateFingerprintsSha256: [],
    contract: 1,
    createdAt: input.now,
    domain: input.domain,
    expiresAt: input.now + input.maximumAdvertisementTtlMs,
    maximumBatchBytes: 1,
    maximumBatchMessages: 1,
    messagesPath:
      "/.well-known/absolutejs-secure-messaging-federation/v1/messages",
    port,
    protocol: HTTPS_FEDERATION_PROTOCOL,
    requiresMutualTls: true,
  };
  const response = await input.client.request({
    headers: { accept: "application/absolutejs-federation-advertisement+json" },
    method: "GET",
    path: HTTPS_FEDERATION_WELL_KNOWN_PATH,
    peer: bootstrap,
  });
  if (
    response.status !== 200 ||
    response.headers["content-type"]?.split(";", 1)[0]?.trim() !==
      "application/absolutejs-federation-advertisement+json"
  )
    throw new Error("Federation HTTPS discovery response is invalid.");
  const advertisement = decodeFederationHttpsAdvertisement(response.body, {
    expectedDomain: input.domain,
    maximumBytes: input.maximumAdvertisementBytes,
    maximumClockSkewMs: input.maximumClockSkewMs,
    maximumTtlMs: input.maximumAdvertisementTtlMs,
    now: input.now,
  });
  if (
    !advertisement.certificateFingerprintsSha256.includes(
      response.certificateFingerprintSha256,
    )
  )
    throw new Error("Discovery did not pin the authenticated TLS certificate.");
  return Object.freeze({
    ...advertisement,
    addresses: Object.freeze([...input.addresses]),
    port,
  });
};

export const createFederationHttpsPeerDirectory = (input: {
  readonly client: FederationMutualTlsClient;
  readonly maximumAdvertisementBytes: number;
  readonly maximumAdvertisementTtlMs: number;
  readonly maximumClockSkewMs: number;
  readonly now?: () => number;
  readonly resolveAddresses: (domain: string) => Promise<readonly string[]>;
  readonly resolvePort?: (domain: string) => number;
}): FederationHttpsPeerDirectory => {
  const cache = new Map<string, FederationHttpsPeer>();
  return {
    resolve: async (domain) => {
      const now = input.now?.() ?? Date.now();
      const cached = cache.get(domain);
      if (cached !== undefined && cached.expiresAt > now) return cached;
      const peer = await discoverFederationHttpsPeer({
        addresses: await input.resolveAddresses(domain),
        client: input.client,
        domain,
        maximumAdvertisementBytes: input.maximumAdvertisementBytes,
        maximumAdvertisementTtlMs: input.maximumAdvertisementTtlMs,
        maximumClockSkewMs: input.maximumClockSkewMs,
        now,
        port: input.resolvePort?.(domain),
      });
      cache.set(domain, peer);
      return peer;
    },
  };
};
