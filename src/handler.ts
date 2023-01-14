import * as jsonwebtoken from "jsonwebtoken";
import * as jwksRsa from "jwks-rsa";
import * as http from "http";
import * as piping from "piping-server";

export function generateHandler({pipingServer, useHttps, jwtVerifyOptions, jwksClient}: {
  pipingServer: piping.Server,
  useHttps: boolean,
  jwtVerifyOptions: jsonwebtoken.VerifyOptions,
  jwksClient: jwksRsa.JwksClient,
}): (req: http.IncomingMessage, res: http.ServerResponse) => void {
  const httpHandler = pipingServer.generateHandler(useHttps);
  return async (req, res) => {
    // Support preflight request
    if (req.method === 'OPTIONS') {
      res.writeHead(200, {
        "Access-Control-Allow-Origin": req.headers.origin ?? '*',
        "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Content-Disposition, Authorization, X-Piping",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": 86400,
        "Content-Length": 0
      });
      res.end();
      return;
    }

    if (req.headers.authorization === undefined) {
      respondError(req, res, `"Authorization" header is not found\n`);
      return;
    }

    const matched = req.headers.authorization.match(/^Bearer (.*)$/i);
    if (matched === null) {
      respondError(req, res, `Invalid "Authorization" scheme\n`);
      return;
    }
    const jwt: string = matched[1];

    let decodedToken: { header: any, payload: any, signature: string };
    try {
      decodedToken = jsonwebtoken.decode(jwt, {complete: true}) as any;
    } catch (err) {
      respondError(req, res, "Invalid token\n");
      return;
    }

    let signingKey: jwksRsa.SigningKey;
    try {
      // NOTE: Only RS256 is supported.
      // (from: https://github.com/auth0/node-jwks-rsa/blob/bf5f7cc9203e20b8e1471c90d4b103cbd8e56660/src/integrations/express.js#L25)
      signingKey = await jwksClient.getSigningKey(decodedToken.header.kid);
    } catch (err) {
      respondError(req, res, "Failed to sign key\n");
      return;
    }
    const publicKey = "publicKey" in signingKey ? signingKey.publicKey : signingKey.rsaPublicKey;

    let verified: object | string;
    try {
      verified = jsonwebtoken.verify(jwt, publicKey, jwtVerifyOptions);
    } catch (err) {
      respondError(req, res, "Failed to verify token\n");
      return;
    }

    const originalWriteHead = res.writeHead.bind(res);
    // FIXME: Use better way
    (res as any).writeHead = (statusCode: number, headers?: http.OutgoingHttpHeaders): http.ServerResponse => {
      const newHeaders = {
        ...headers,
        "Access-Control-Allow-Origin": req.headers.origin ?? "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "Content-Type, Content-Disposition, X-Piping",
      };
      return originalWriteHead(statusCode, newHeaders);
    };
    httpHandler(req, res);
  };
}

function respondError(req: http.IncomingMessage, res: http.ServerResponse, message: string) {
  res.writeHead(401, {
    "Access-Control-Allow-Origin": req.headers.origin ?? '*',
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "text/plain",
  });
  res.end(message);
}
