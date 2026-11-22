// node --test: the directory signer against published vectors, and the Worker
// handler end to end (no network, no wrangler).

import assert from "node:assert/strict";
import { test } from "node:test";

import { DIRECTORY_PATH, MEDIA_TYPE, directoryBody, loadKeys, signDirectory, thumbprint } from "../src/directory.js";
import worker from "../src/index.js";

// RFC 9421 Appendix B.1.4 test-key-ed25519. A published test key: never deploy it.
const TEST_JWK = {
	kty: "OKP",
	crv: "Ed25519",
	kid: "test-key-ed25519",
	d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
	x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};
const TEST_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

// draft-ietf-webbotauth-httpsig-protocol-01 Appendix E.2.3 body.
const VECTOR_BODY =
	'{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",' +
	'"x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}';

async function generateJwk() {
	const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
	const { kty, crv, x, d } = await crypto.subtle.exportKey("jwk", pair.privateKey);
	return { kty, crv, x, d };
}

test("thumbprints match RFC 8037 A.3 and the RFC 9421 test key", async () => {
	assert.equal(await thumbprint("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
	assert.equal(await thumbprint(TEST_JWK.x), TEST_KEYID);
});

test("body and signature reproduce cloudflare/web-bot-auth web_bot_auth_directory_response_v1", async () => {
	const keys = await loadKeys(JSON.stringify(TEST_JWK));
	const body = directoryBody(keys);
	assert.equal(body, VECTOR_BODY);
	const headers = await signDirectory({
		authority: "signature-agent.test",
		body,
		keys,
		created: 1735689600,
		ttl: 4889289600 - 1735689600,
	});
	assert.equal(headers["Content-Digest"], "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:");
	assert.equal(
		headers["Signature-Input"],
		'binding0=("@authority";req "content-digest");created=1735689600;' +
			'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;' +
			'tag="http-message-signatures-directory"'
	);
	assert.equal(
		headers.Signature,
		"binding0=:yiHq0TXrbpzbmlttAQMpYoAufitFJUWuNsakB7QQMoN0EHbo5o51bZRVR8az/ptTWCwllix9clrKXfGKwdPzBg==:"
	);
});

test("rotation: one signature per key", async () => {
	const a = await generateJwk();
	const b = await generateJwk();
	const keys = await loadKeys(JSON.stringify({ keys: [a, b] }));
	assert.equal(keys.length, 2);
	const body = directoryBody(keys);
	assert.equal(JSON.parse(body).keys.length, 2);
	assert.ok(!body.includes('"d"'));
	const headers = await signDirectory({ authority: "bot.example", body, keys, created: 1000, ttl: 300 });
	assert.match(headers["Signature-Input"], /^binding0=\(.*, binding1=\(/);
	assert.match(headers.Signature, /^binding0=:[A-Za-z0-9+/]{86}==:, binding1=:[A-Za-z0-9+/]{86}==:$/);
});

test("bad secrets are rejected without echoing key material", async () => {
	await assert.rejects(loadKeys("not json"), /not JSON/);
	await assert.rejects(loadKeys(JSON.stringify({ keys: [] })), /no keys/);
	await assert.rejects(loadKeys(JSON.stringify({ kty: "OKP", crv: "Ed25519", x: TEST_JWK.x })), /private OKP/);
	await assert.rejects(loadKeys(JSON.stringify({ kty: "RSA", n: "AQAB", e: "AQAB" })), /private OKP/);
	const other = await generateJwk();
	await assert.rejects(loadKeys(JSON.stringify({ ...TEST_JWK, x: other.x })), (e) => {
		assert.match(e.message, /does not match/);
		assert.ok(!e.message.includes(TEST_JWK.d));
		return true;
	});
});

test("Worker serves the signed directory", async () => {
	const jwk = await generateJwk();
	const env = { BOT_AUTH_PRIVATE_JWK: JSON.stringify(jwk), SIGNATURE_TTL: "120" };
	const before = Math.floor(Date.now() / 1000);
	const res = await worker.fetch(new Request(`https://Bot.Example.com${DIRECTORY_PATH}`), env);
	assert.equal(res.status, 200);
	assert.equal(res.headers.get("content-type"), MEDIA_TYPE);
	assert.equal(res.headers.get("cache-control"), "max-age=120, no-transform");
	assert.equal(res.headers.get("access-control-allow-origin"), "*");
	const body = await res.text();
	const keyid = await thumbprint(jwk.x);
	assert.deepEqual(JSON.parse(body), { keys: [{ kty: "OKP", crv: "Ed25519", kid: keyid, x: jwk.x, use: "sig" }] });

	// Recompute the signature base and verify it with the public key.
	const input = res.headers.get("signature-input");
	const m = /^binding0=(\("@authority";req "content-digest"\);created=(\d+);keyid="([^"]+)";alg="ed25519";expires=(\d+);tag="http-message-signatures-directory")$/.exec(input);
	assert.ok(m, input);
	const created = Number(m[2]);
	assert.ok(created >= before && created <= before + 5);
	assert.equal(m[3], keyid);
	assert.equal(Number(m[4]), created + 120);
	const digest = res.headers.get("content-digest");
	const base = `"@authority";req: bot.example.com\n"content-digest": ${digest}\n"@signature-params": ${m[1]}`;
	const sig = Uint8Array.from(atob(/^binding0=:(.*):$/.exec(res.headers.get("signature"))[1]), (c) => c.charCodeAt(0));
	const pub = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
	assert.ok(await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, new TextEncoder().encode(base)));
	const bodyDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)));
	assert.equal(digest, `sha-256=:${btoa(String.fromCharCode(...bodyDigest))}:`);

	const head = await worker.fetch(new Request(`https://bot.example.com${DIRECTORY_PATH}`, { method: "HEAD" }), env);
	assert.equal(head.status, 200);
	assert.equal(await head.text(), "");
	assert.ok(head.headers.get("signature"));
});

test("Worker errors: wrong path, method, missing or bad secret", async () => {
	const env = { BOT_AUTH_PRIVATE_JWK: JSON.stringify(TEST_JWK) };
	assert.equal((await worker.fetch(new Request("https://bot.example.com/"), env)).status, 404);
	assert.equal((await worker.fetch(new Request(`https://bot.example.com${DIRECTORY_PATH}/x`), env)).status, 404);
	const post = await worker.fetch(new Request(`https://bot.example.com${DIRECTORY_PATH}`, { method: "POST" }), env);
	assert.equal(post.status, 405);
	assert.equal(post.headers.get("allow"), "GET, HEAD");
	assert.equal((await worker.fetch(new Request(`https://bot.example.com${DIRECTORY_PATH}`), {})).status, 503);
	const bad = await worker.fetch(new Request(`https://bot.example.com${DIRECTORY_PATH}`), { BOT_AUTH_PRIVATE_JWK: "{" });
	assert.equal(bad.status, 500);
	// A later good secret recovers (the failed import is not cached).
	assert.equal((await worker.fetch(new Request(`https://bot.example.com${DIRECTORY_PATH}`), env)).status, 200);
});
