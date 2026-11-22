// Cloudflare Worker serving the wincrawl Web Bot Auth key directory at
// /.well-known/http-message-signatures-directory (docs/web-bot-auth.md).
//
// Secret BOT_AUTH_PRIVATE_JWK: the private JWK (or {"keys":[...]}) whose
// public half the directory publishes; every response is signed with it.
// Var SIGNATURE_TTL: seconds each response signature stays valid (default 300),
// also the response's max-age.

import { DIRECTORY_PATH, MEDIA_TYPE, directoryBody, loadKeys, signDirectory } from "./directory.js";

let cache = null; // { secret, keys: Promise } per isolate

function keysFor(env) {
	if (cache === null || cache.secret !== env.BOT_AUTH_PRIVATE_JWK) {
		const keys = loadKeys(env.BOT_AUTH_PRIVATE_JWK);
		cache = { secret: env.BOT_AUTH_PRIVATE_JWK, keys };
		keys.catch(() => {
			cache = null;
		});
	}
	return cache.keys;
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (url.pathname !== DIRECTORY_PATH) {
			return new Response("Not found\n", { status: 404 });
		}
		if (request.method !== "GET" && request.method !== "HEAD") {
			return new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });
		}
		if (!env.BOT_AUTH_PRIVATE_JWK) {
			return new Response("directory key not configured\n", { status: 503 });
		}
		let keys;
		try {
			keys = await keysFor(env);
		} catch (e) {
			// The message names the problem, never key material.
			return new Response(`bad BOT_AUTH_PRIVATE_JWK: ${e.message}\n`, { status: 500 });
		}
		const ttl = Number.parseInt(env.SIGNATURE_TTL ?? "300", 10) || 300;
		const body = directoryBody(keys);
		const signature = await signDirectory({
			authority: url.host, // lowercase host[:port], default port omitted: RFC 9421 @authority
			body,
			keys,
			created: Math.floor(Date.now() / 1000),
			ttl,
		});
		return new Response(request.method === "HEAD" ? null : body, {
			status: 200,
			headers: {
				"Content-Type": MEDIA_TYPE,
				// no-transform: Content-Digest covers these exact bytes, so the
				// edge must not compress them.
				"Cache-Control": `max-age=${ttl}, no-transform`,
				"Access-Control-Allow-Origin": "*",
				...signature,
			},
		});
	},
};
