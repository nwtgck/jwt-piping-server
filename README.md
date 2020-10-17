# auth0-piping-server
[Piping Server](https://github.com/nwtgck/piping-server) with [Auth0](auth0.com/)  
(I will rename this repository when I find this repository can be used for more general authentication than Auth0)

![Piping Server with Auth0](demo_assets/auth0-simple-client.gif)  

## Usage

Here is an example to run server.

```bash
npm start -- --jwks-uri https://nwtgck.us.auth0.com/.well-known/jwks.json --jwt-issuer=https://nwtgck.us.auth0.com/ --http-port=8080
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
