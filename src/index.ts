import * as jwksRsa from 'jwks-rsa';
import * as jsonwebtoken from 'jsonwebtoken';
import * as http from 'http';
import * as yargs from "yargs";
import * as log4js from "log4js";
import * as piping from "piping-server";
import { config as environmentConfig } from "dotenv";

// Create option parser
const parser = yargs
  .option("http-port", {
    describe: "Port of HTTP server",
    default: 8080
  })
  // NOTE: This option name might be renamed
  .option("jwks-uri", {
    describe: "JWKs URI (e.g. https://example.us.auth0.com/.well-known/jwks.json)",
    type: "string",
  })
  // NOTE: This option name might be renamed
  .option("jwt-issuer", {
    describe: "JWT issuer (e.g. https://example.us.auth0.com/)",
    type: "string"
  })
  // NOTE: This option name might be renamed
  .option("jwt-audience", {
    describe: "JWT audience",
    type: "string"
  });

  
// Parse arguments
const args = parser.parse(process.argv);
environmentConfig();
const httpPort: number = process.env.HTTP_PORT ? parseInt(process.env.HTTP_PORT, 10) : args["http-port"];
if (!args['jwks-uri'] && !process.env.JWKS_URI) {
  console.error("Missing option 'jwks-uri'. Please either set the option in the commandline or as environment variable.");
  process.exit(-1);
}
const jwksUri: string = args['jwks-uri'] ?? process.env.JWKS_URI ?? '';

// Create a logger
const logger = log4js.getLogger();
logger.level = "info";

// Create a piping server
const pipingServer = new piping.Server({ logger });

type JwksClientConstructor = new (options: jwksRsa.ClientOptions) => jwksRsa.JwksClient;
const jwksClient = new (jwksRsa as any as JwksClientConstructor)({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri
});

const verifyOptions: jsonwebtoken.VerifyOptions = {
  audience: args['jwt-audience'] ?? process.env.JWT_AUDIENCE,
  issuer: args['jwt-issuer'] ?? process.env.JWKS_ISSUER,
  algorithms: ['RS256']
};

function respondError(req: http.IncomingMessage, res: http.ServerResponse, message: string) {
  res.writeHead(401, {
    "Access-Control-Allow-Origin": req.headers.origin ?? '*',
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "text/plain",
  });
  res.end(message);
}

const httpHandler = pipingServer.generateHandler(false);
const server = http.createServer(async (req, res) => {
  // Support preflight request
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      "Access-Control-Allow-Origin": req.headers.origin ?? '*',
      "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Content-Disposition, Authorization",
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
    signingKey = await jwksClient.getSigningKeyAsync(decodedToken.header.kid);
  } catch (err) {
    respondError(req, res, "Failed to sign key\n");
    return;
  }
  const publicKey = "publicKey" in signingKey ? signingKey.publicKey : signingKey.rsaPublicKey;

  let verified: object | string;
  try {
    verified = jsonwebtoken.verify(jwt, publicKey, verifyOptions);
  } catch (err) {
    respondError(req, res, "Failed to verify token\n");
    return;
  }

  const originalWriteHead = res.writeHead.bind(res);
  // FIXME: Use better way
  (res as any).writeHead = (statusCode: number, headers?: http.OutgoingHttpHeaders): http.ServerResponse => {
    const newHeaders = {
      ...headers,
      "Access-Control-Allow-Origin": req.headers.origin,
      "Access-Control-Allow-Credentials": "true",
    };
    return originalWriteHead(statusCode, newHeaders);
  };
  httpHandler(req, res);
});

server.listen(httpPort, () => {
  logger.info(`Listen HTTP on ${httpPort}...`);
});

// Catch and ignore error
process.on("uncaughtException", (err) => {
  logger.error("on uncaughtException", err);
});
