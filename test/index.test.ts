import * as getPort from "get-port";
import * as assert from 'power-assert';
import * as jose from "node-jose";
import * as nock from 'nock';
import * as jwksRsa from "jwks-rsa";
import * as jsonwebtoken from "jsonwebtoken";
import * as http from "http";
import {generateHandler} from "../src/handler";
import * as piping from "piping-server";
import thenRequest from "then-request";

type JwksClientConstructor = new (options: jwksRsa.ClientOptions) => jwksRsa.JwksClient;

describe('custom piping-server handler', () => {
  const jswksBasePath = 'https://my-jwk-server';
  const jwksClient = new (jwksRsa as any as JwksClientConstructor)({
    cache: false,
    jwksUri: `${jswksBasePath}/jwks.json`,
  });
  let pipingServer: http.Server;
  let pipingPort: number;
  let pipingUrl: string;

  beforeEach(async () => {
    // Get available port
    pipingPort = await getPort();
    // Define Piping URL
    pipingUrl = `http://localhost:${pipingPort}`;
    // Create a Piping server
    pipingServer = http.createServer(generateHandler({
      pipingServer: new piping.Server(),
      jwtVerifyOptions: {
        algorithms: ['RS256'],
      },
      jwksClient,
    }));
    // Listen on the port
    await new Promise<void>((resolve) => {
      pipingServer.listen(pipingPort, resolve);
    });
  });

  afterEach(async () => {
    nock.cleanAll();
    // Close the piping server
    return new Promise<void>((resolve) => {
      pipingServer.close(() => resolve());
    });
  });

  it("should reject without token", async () => {
    const res = await thenRequest("POST", `${pipingUrl}/mypath`, {
      body: "my content",
    });
    assert.strictEqual(res.statusCode, 401);
  });

  it("should reject to get /version without token", async () => {
    const res = await thenRequest("GET", `${pipingUrl}/version`);
    assert.strictEqual(res.statusCode, 401);
  });

  it("should reject to transfer data with expired token", async () => {
    const key = await jose.JWK.createKeyStore().generate("RSA", 2048);
    const privateKeyPem = key.toPEM(true);
    const nowSeconds = Math.round(new Date().getTime() / 1000);
    // NOTE: expired
    const claims = {
      "sub": "mysubject",
      "iat": nowSeconds - (2 * 2600),
      "exp": nowSeconds - 3600,
    };
    const expiredJwt = jsonwebtoken.sign(claims, privateKeyPem, {
      algorithm: "RS256",
    });
    nock(jswksBasePath)
      .get('/jwks.json')
      .times(2)
      .reply(200, {
        keys: [
          key.toJSON(),
        ],
      });
    const postRes = await thenRequest("POST", `${pipingUrl}/mypath`, {
      headers: {
        Authorization: `Bearer ${expiredJwt}`,
      },
      body: "my content",
    });
    assert.strictEqual(postRes.statusCode, 401);
    const getRes = await thenRequest("GET", `${pipingUrl}/mypath`, {
      headers: {
        Authorization: `Bearer ${expiredJwt}`,
      },
    });
    assert.strictEqual(getRes.statusCode, 401);
  });

  it("should allow to transfer data with valid token", async () => {
    const key = await jose.JWK.createKeyStore().generate("RSA", 2048);
    const privateKeyPem = key.toPEM(true);
    const nowSeconds = Math.round(new Date().getTime() / 1000);
    const claims = {
      "sub": "mysubject",
      "iat": nowSeconds,
      "exp": nowSeconds + 3600,
    };
    const jwt = jsonwebtoken.sign(claims, privateKeyPem, {
      algorithm: "RS256",
    });
    nock(jswksBasePath)
      .get('/jwks.json')
      .times(2)
      .reply(200, {
        keys: [
          key.toJSON(),
        ],
      });
    const postResPromise = thenRequest("POST", `${pipingUrl}/mypath`, {
      headers: {
        Authorization: `Bearer ${jwt}`,
      },
      body: "my content",
    });
    await new Promise(resolve => setTimeout(resolve, 100));
    const getRes = await thenRequest("GET", `${pipingUrl}/mypath`, {
      headers: {
        Authorization: `Bearer ${jwt}`,
      },
    });
    assert.strictEqual(getRes.statusCode, 200);
    assert.strictEqual(getRes.getBody("UTF-8"), "my content");
    assert.strictEqual((await postResPromise).statusCode, 200);
  });
});
