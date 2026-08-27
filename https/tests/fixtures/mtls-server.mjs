import { readFileSync } from "node:fs";
import { createServer } from "node:https";

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};

const server = createServer(
  {
    ca: readFileSync(required("FEDERATION_TEST_CA")),
    cert: readFileSync(required("FEDERATION_TEST_CERTIFICATE")),
    key: readFileSync(required("FEDERATION_TEST_PRIVATE_KEY")),
    rejectUnauthorized: true,
    requestCert: true,
  },
  (request, response) => {
    console.log(
      JSON.stringify({
        authorized: request.socket.authorized,
        host: request.headers.host,
        method: request.method,
        type: "request",
        url: request.url,
      }),
    );
    response.writeHead(202, { "content-length": "0" });
    response.end();
  },
);

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Federation test server address is unavailable.");
  console.log(JSON.stringify({ port: address.port, type: "ready" }));
});
