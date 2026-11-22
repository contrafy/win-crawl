# bot-auth-directory

A Cloudflare Worker that serves wincrawl's Web Bot Auth key directory at
`/.well-known/http-message-signatures-directory`: the public JWK Set of the
crawler's signing keys, as `application/http-message-signatures-directory+json`,
with one possession-proof signature per key over `("@authority";req
"content-digest")` tagged `http-message-signatures-directory`
(draft-ietf-webbotauth-httpsig-protocol-01 §5.5 and Appendix B.1; Cloudflare's
directory requirements). The URL of this Worker is what wincrawl sends as
`Signature-Agent`. Background and verification results:
[`docs/web-bot-auth.md`](../../docs/web-bot-auth.md).

- `src/directory.js`: body and signatures, Web Crypto only (Ed25519, SHA-256).
- `src/index.js`: the Worker. GET/HEAD on the well-known path only; 404
  elsewhere, 405 for other methods, 503 without the key secret.
  `Cache-Control: max-age=<SIGNATURE_TTL>, no-transform` (no edge compression,
  since `Content-Digest` covers the exact bytes) and
  `Access-Control-Allow-Origin: *`.
- Secret `BOT_AUTH_PRIVATE_JWK`: the private JWK from `wincrawl-botauth
  keygen`, or `{"keys":[...]}` holding several while rotating (each gets its
  own signature, labels `binding0`, `binding1`, ...).
- Var `SIGNATURE_TTL` (default 300): lifetime of each response signature.

## Test locally

```powershell
cd tools\bot-auth-directory
npm install          # wrangler, pinned in package.json
npm test             # node --test: vectors + the handler, no network
```

The tests reproduce the `web_bot_auth_directory_response_v1.json` signature
from cloudflare/web-bot-auth byte for byte and verify the handler's output.
To run the real Workers runtime (workerd) locally and check its output with
the C++ verifier:

```powershell
build\release\wincrawl-botauth.exe keygen --out $env:TEMP\dev.jwk
"BOT_AUTH_PRIVATE_JWK='$((Get-Content $env:TEMP\dev.jwk -Raw).Trim())'" | Set-Content tools\bot-auth-directory\.dev.vars   # gitignored
cd tools\bot-auth-directory
npx wrangler dev --ip 127.0.0.1 --port 58787
# another shell:
curl.exe -si http://127.0.0.1:58787/.well-known/http-message-signatures-directory -o dir.http
build\release\wincrawl-botauth.exe verify-directory --authority 127.0.0.1:58787 --response dir.http
```

Delete `.dev.vars` and the dev key afterwards; never use them in production.

## Deploy (owner, once)

Needs a Cloudflare account. Nothing here is deployed by the build or CI.

1. Generate the production key, outside the repository (`secrets/` and
   `*.jwk` are gitignored anyway). The file gets an owner-only ACL:

   ```powershell
   mkdir secrets
   build\release\wincrawl-botauth.exe keygen --out secrets\bot-auth.jwk
   ```

2. Log in and choose the hostname. By default the Worker is published at
   `https://bot-auth-directory.<your-subdomain>.workers.dev`; to use your own
   domain instead, uncomment the `routes` block in `wrangler.toml` and put in
   a hostname of a zone in your account (for example `bot.example.com`, which
   then serves only this directory):

   ```powershell
   cd tools\bot-auth-directory
   npm install
   npx wrangler login
   ```

3. Store the private key as a Worker secret (read from stdin; it is never
   printed or written to `wrangler.toml`):

   ```powershell
   Get-Content ..\..\secrets\bot-auth.jwk -Raw | npx wrangler secret put BOT_AUTH_PRIVATE_JWK
   ```

   (bash: `npx wrangler secret put BOT_AUTH_PRIVATE_JWK < ../../secrets/bot-auth.jwk`)

4. Deploy and check it with the C++ verifier:

   ```powershell
   npx wrangler deploy
   curl.exe -si https://bot-auth-directory.<your-subdomain>.workers.dev/.well-known/http-message-signatures-directory -o dir.http
   ..\..\build\release\wincrawl-botauth.exe verify-directory --authority bot-auth-directory.<your-subdomain>.workers.dev --response dir.http
   ```

   Cloudflare's own validator gives a second opinion:
   `cargo install http-signature-directory` then
   `http-signature-directory https://bot-auth-directory.<your-subdomain>.workers.dev`.

5. Sign with wincrawl's `--signature-agent https://bot-auth-directory.<your-subdomain>.workers.dev`
   (the origin; verifiers append the well-known path) and check a signed
   request against Cloudflare's verifier, which answers 401 for a well-formed
   signature with an unknown key and 200 once the key is registered (Windows
   PowerShell 5.1's `>` writes UTF-16, which curl cannot read, hence
   `Out-File -Encoding ascii`):

   ```powershell
   ..\..\build\release\wincrawl-botauth.exe sign --key ..\..\secrets\bot-auth.jwk --authority crawltest.com --agent https://bot-auth-directory.<your-subdomain>.workers.dev | Out-File -Encoding ascii h.txt
   curl.exe -s -w " %{http_code}\n" -H "@h.txt" https://crawltest.com/cdn-cgi/web-bot-auth
   ```

6. Optional, for Cloudflare to treat the crawler as a verified bot: dashboard,
   Manage Account > Configurations > Bot Submission Form, Verification Method
   "Request Signature", and the directory URL under Validation Instructions.

## Rotating keys

Generate the new key, set the secret to `{"keys":[<old private JWK>,<new
private JWK>]}`, deploy, switch wincrawl to the new key once verifiers have
refetched (after `SIGNATURE_TTL`), then set the secret to the new key alone and
deploy again.
