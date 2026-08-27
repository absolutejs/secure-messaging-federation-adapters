import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import {
  createNodeMutualTlsFederationClient,
  HTTPS_FEDERATION_MESSAGES_PATH,
  HTTPS_FEDERATION_PROTOCOL,
  type FederationHttpsPeer,
} from "../src";

const PEER_DOMAIN = "bob.example";
const MAXIMUM_RESPONSE_BYTES = 4_096;
const REQUEST_TIMEOUT_MS = 1_000;

const runOpenSsl = (arguments_: string[]) => {
  const result = Bun.spawnSync(["openssl", ...arguments_], {
    stderr: "pipe",
    stdout: "ignore",
  });
  if (result.exitCode !== 0)
    throw new Error(result.stderr.toString() || "OpenSSL failed");
};

const createCertificate = (input: {
  caCertificatePath: string;
  caKeyPath: string;
  directory: string;
  domain: string;
  extendedKeyUsage: "clientAuth" | "serverAuth";
  serial: string;
}) => {
  const prefix = path.join(input.directory, input.serial);
  const certificatePath = `${prefix}.pem`;
  const configPath = `${prefix}.cnf`;
  const keyPath = `${prefix}-key.pem`;
  const requestPath = `${prefix}.csr`;
  runOpenSsl([
    "genpkey",
    "-algorithm",
    "EC",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-out",
    keyPath,
  ]);
  runOpenSsl([
    "req",
    "-new",
    "-key",
    keyPath,
    "-out",
    requestPath,
    "-subj",
    `/CN=${input.domain}`,
  ]);
  writeFileSync(
    configPath,
    [
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature,keyAgreement",
      `extendedKeyUsage=critical,${input.extendedKeyUsage}`,
      `subjectAltName=DNS:${input.domain}`,
      "",
    ].join("\n"),
  );
  runOpenSsl([
    "x509",
    "-req",
    "-in",
    requestPath,
    "-CA",
    input.caCertificatePath,
    "-CAkey",
    input.caKeyPath,
    "-set_serial",
    input.serial,
    "-days",
    "2",
    "-sha256",
    "-extfile",
    configPath,
    "-out",
    certificatePath,
  ]);

  return { certificatePath, keyPath };
};

const fixture = () => {
  const directory = mkdtempSync(path.join(tmpdir(), "federation-client-"));
  const caCertificatePath = path.join(directory, "ca.pem");
  const caKeyPath = path.join(directory, "ca-key.pem");
  runOpenSsl([
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    caKeyPath,
    "-out",
    caCertificatePath,
    "-days",
    "2",
    "-sha256",
    "-subj",
    "/CN=AbsoluteJS federation test CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  const certificateInput = { caCertificatePath, caKeyPath, directory };
  const client = createCertificate({
    ...certificateInput,
    domain: "alice.example",
    extendedKeyUsage: "clientAuth",
    serial: "2",
  });
  const server = createCertificate({
    ...certificateInput,
    domain: PEER_DOMAIN,
    extendedKeyUsage: "serverAuth",
    serial: "3",
  });

  return {
    ca: readFileSync(caCertificatePath, "utf8"),
    caCertificatePath,
    cleanup: () => rmSync(directory, { force: true, recursive: true }),
    clientCertificate: readFileSync(client.certificatePath, "utf8"),
    clientPrivateKey: readFileSync(client.keyPath, "utf8"),
    serverCertificatePath: server.certificatePath,
    serverFingerprint: new X509Certificate(
      readFileSync(server.certificatePath),
    ).fingerprint256.toUpperCase(),
    serverPrivateKeyPath: server.keyPath,
  };
};

type ServerEvent =
  | { port: number; type: "ready" }
  | {
      authorized: boolean;
      host: string;
      method: string;
      type: "request";
      url: string;
    };

const isServerEvent = (value: unknown): value is ServerEvent =>
  typeof value === "object" &&
  value !== null &&
  "type" in value &&
  (value.type === "ready" || value.type === "request");

const serverEvents = async function* (stream: ReadableStream<Uint8Array>) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      buffered += decoder.decode(result.value, { stream: true });
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        const event: unknown = JSON.parse(line);
        if (isServerEvent(event)) yield event;
      }
    }
  } finally {
    reader.releaseLock();
  }
};

describe("Node mutual-TLS federation client", () => {
  test("falls through pinned addresses and authenticates the winning socket", async () => {
    const material = fixture();
    const child = Bun.spawn(
      ["node", new URL("./fixtures/mtls-server.mjs", import.meta.url).pathname],
      {
        env: {
          ...process.env,
          FEDERATION_TEST_CA: material.caCertificatePath,
          FEDERATION_TEST_CERTIFICATE: material.serverCertificatePath,
          FEDERATION_TEST_PRIVATE_KEY: material.serverPrivateKeyPath,
        },
        stderr: "pipe",
        stdout: "pipe",
      },
    );
    try {
      const events = serverEvents(child.stdout);
      const ready = await events.next();
      if (ready.done || ready.value.type !== "ready")
        throw new Error(
          `Federation test server did not become ready: ${await new Response(child.stderr).text()}`,
        );
      const peer: FederationHttpsPeer = {
        addresses: ["127.0.0.2", "127.0.0.1"],
        certificateFingerprintsSha256: [material.serverFingerprint],
        contract: 1,
        createdAt: Date.now(),
        domain: PEER_DOMAIN,
        expiresAt: Date.now() + 60_000,
        maximumBatchBytes: 8_192,
        maximumBatchMessages: 10,
        messagesPath: HTTPS_FEDERATION_MESSAGES_PATH,
        port: ready.value.port,
        protocol: HTTPS_FEDERATION_PROTOCOL,
        requiresMutualTls: true,
      };
      const client = createNodeMutualTlsFederationClient({
        addressPolicy: "allow-private",
        ca: material.ca,
        certificate: material.clientCertificate,
        key: material.clientPrivateKey,
        maximumResponseBytes: MAXIMUM_RESPONSE_BYTES,
        requestTimeoutMs: REQUEST_TIMEOUT_MS,
      });
      const response = await client.request({
        body: Uint8Array.of(1, 2, 3),
        headers: { "content-type": "application/octet-stream" },
        method: "POST",
        path: HTTPS_FEDERATION_MESSAGES_PATH,
        peer,
      });
      expect(response).toMatchObject({
        certificateFingerprintSha256: material.serverFingerprint,
        status: 202,
      });
      const requestObserved = await events.next();
      expect(requestObserved.done).toBe(false);
      expect(requestObserved.value).toEqual({
        authorized: true,
        host: `${PEER_DOMAIN}:${peer.port}`,
        method: "POST",
        type: "request",
        url: HTTPS_FEDERATION_MESSAGES_PATH,
      });
      await expect(
        client.request({
          headers: {},
          method: "GET",
          path: "/",
          peer: { ...peer, certificateFingerprintsSha256: ["AA"] },
        }),
      ).rejects.toThrow("Every federation HTTPS address failed");
      await expect(
        createNodeMutualTlsFederationClient({
          ca: material.ca,
          certificate: material.clientCertificate,
          key: material.clientPrivateKey,
          maximumResponseBytes: MAXIMUM_RESPONSE_BYTES,
          requestTimeoutMs: REQUEST_TIMEOUT_MS,
        }).request({ headers: {}, method: "GET", path: "/", peer }),
      ).rejects.toThrow("address policy rejected");
    } finally {
      child.kill();
      await child.exited;
      material.cleanup();
    }
  });
});
