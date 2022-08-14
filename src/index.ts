import * as jwksRsa from 'jwks-rsa';
import * as jsonwebtoken from 'jsonwebtoken';
import * as http from 'http';
import * as yargs from "yargs";
import * as log4js from "log4js";
import * as piping from "piping-server";
import {generateHandler} from "./handler";

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

type JwksClientConstructor = new (options: jwksRsa.ClientOptions) => jwksRsa.JwksClient;
const jwksClient = new (jwksRsa as any as JwksClientConstructor)({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: args['jwks-uri'],
});

const jwtVerifyOptions: jsonwebtoken.VerifyOptions = {
  audience: args['jwt-audience'],
  issuer: args['jwt-issuer'],
  algorithms: ['RS256']
};

const server = http.createServer(generateHandler({
  pipingServer,
  jwtVerifyOptions,
  jwksClient,
}));

server.listen(httpPort, () => {
  logger.info(`Listen HTTP on ${httpPort}...`);
});

// Catch and ignore error
process.on("uncaughtException", (err) => {
  logger.error("on uncaughtException", err);
});
