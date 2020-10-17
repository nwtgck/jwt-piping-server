import * as jwt from 'express-jwt';
import * as jwksRsa from 'jwks-rsa';
import * as http from 'http';
import * as yargs from "yargs";
import * as log4js from "log4js";
import * as piping from "piping-server";

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
    demandOption: true,
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
const httpPort: number = args["http-port"];

// Create a logger
const logger = log4js.getLogger();
logger.level = "info";

// Create a piping server
const pipingServer = new piping.Server({ logger });

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: args['jwks-uri'],
  }),
  audience: args['jwt-audience'],
  issuer: args['jwt-issuer'],
  algorithms: ['RS256']
});

const httpHandler = pipingServer.generateHandler(false);
const server = http.createServer((req, res) => {
  checkJwt(req as any, res as any, function (err?: any) {
    if(err) {
      if (err instanceof jwt.UnauthorizedError) {
        logger.info("UnauthorizedError: ", err.message);
        res.writeHead(err.status, {
          "Access-Control-Allow-Origin": req.headers.origin ?? '*',
          "Access-Control-Allow-Credentials": "true",
        });
        res.end(`${err.message}\n`);
        return;
      }
      logger.error("Unexpected authorization error", err);
      res.writeHead(500);
      res.end("Unexpected authorization error\n");
      return;
    }
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
  } as any);
});

server.listen(httpPort, () => {
  logger.info(`Listen HTTP on ${httpPort}...`);
});

// Catch and ignore error
process.on("uncaughtException", (err) => {
  logger.error("on uncaughtException", err);
});
