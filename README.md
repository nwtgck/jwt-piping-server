# jwt-piping-server
[Piping Server](https://github.com/nwtgck/piping-server) with JWT authentication such as [Auth0](auth0.com/)  

The demo below uses Auth0.  
![Piping Server with Auth0](demo_assets/auth0-simple-client.gif)  

## Usage

Here are examples to run server.

```bash
cd <this repo>
npm ci
npm start -- --jwks-uri https://nwtgck.us.auth0.com/.well-known/jwks.json --jwt-issuer=https://nwtgck.us.auth0.com/ --http-port=8080
```

OR

```bash
docker run -p 8080:8080 nwtgck/jwt-piping-server --jwks-uri https://nwtgck.us.auth0.com/.well-known/jwks.json --jwt-issuer=https://nwtgck.us.auth0.com/ --http-port=8080
```

Here is how to run simple web client.

```bash
cd simple-frontend/
# Static hosting
python3 -m http.server 3000
```

Open http://localhost:3000/ on your Web browser.

### Change to your Auth0 setting

You can set your Auth0 `domain` and `client_id` in [simple-frontend/index.html](simple-frontend/index.html).

```js
auth0Promise = createAuth0Client({
  domain: "ooo.auth0.com",
  client_id: "............",
  cacheLocation: 'localstorage',
});
```

## Server help

```
Options:
  --help          Show help                                            [boolean]
  --version       Show version number                                  [boolean]
  --http-port     Port of HTTP server                            [default: 8080]
  --jwks-uri      JWKs URI (e.g.
                  https://example.us.auth0.com/.well-known/jwks.json)
                                                             [string] [required]
  --jwt-issuer    JWT issuer (e.g. https://example.us.auth0.com/)       [string]
  --jwt-audience  JWT audience                                          [string]
```

## Environment Variables
These environment variables can also be specified in a `.env` file.

- `JWKS_URI`      : JWKs URI
- `JWKS_ISSUER`   : JWT issuer
- `JWT_AUDIENCE`  : JWT audience