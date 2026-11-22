// Web Bot Auth key directory: the JWK Set served at
// /.well-known/http-message-signatures-directory and its possession proof
// (draft-ietf-webbotauth-httpsig-protocol-01 §5.5 and Appendix B.1): one RFC
// 9421 signature per key over ("@authority";req "content-digest"), tagged
// "http-message-signatures-directory".
//
// Only Web Crypto, so the same code runs in Workers and in Node (tests).

const encoder = new TextEncoder();

export const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const MEDIA_TYPE = "application/http-message-signatures-directory+json";
export const TAG = "http-message-signatures-directory";

export function base64(bytes) {
	let s = "";
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s);
}

export function base64url(bytes) {
	return base64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// RFC 7638 JWK thumbprint of an Ed25519 key (RFC 8037 Appendix A.3): the
// Web Bot Auth keyid.
export async function thumbprint(x) {
	const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
	return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(canonical))));
}

// Imports the signing keys from the Worker secret: one private Ed25519 JWK
// (what `wincrawl-botauth keygen` writes) or {"keys":[...]} of them, for
// rotation. Each key must sign something its own "x" verifies.
export async function loadKeys(secret) {
	let parsed;
	try {
		parsed = JSON.parse(secret);
	} catch {
		throw new Error("the key secret is not JSON");
	}
	const jwks = Array.isArray(parsed?.keys) ? parsed.keys : [parsed];
	if (jwks.length === 0) throw new Error("the key secret has no keys");
	const keys = [];
	for (const jwk of jwks) {
		if (jwk?.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || typeof jwk.d !== "string") {
			throw new Error("every key must be a private OKP/Ed25519 JWK (kty, crv, x, d)");
		}
		const algorithm = { name: "Ed25519" };
		const mismatch = new Error("a key's \"d\" does not match its \"x\", or is not 32 bytes of base64url");
		let signingKey;
		let publicKey;
		try {
			signingKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, algorithm, false, [
				"sign",
			]);
			publicKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, algorithm, false, ["verify"]);
		} catch {
			// Some runtimes check d against x on import (Node does); never echo the key.
			throw mismatch;
		}
		const probe = encoder.encode("bot-auth-directory key check");
		const sig = await crypto.subtle.sign(algorithm, signingKey, probe);
		if (!(await crypto.subtle.verify(algorithm, publicKey, sig, probe))) throw mismatch;
		keys.push({ x: jwk.x, keyid: await thumbprint(jwk.x), signingKey });
	}
	return keys;
}

// The JWK Set: public members only, "kid" set to the thumbprint as the draft
// requires at the well-known URI. Same bytes as `wincrawl-botauth jwks`.
export function directoryBody(keys) {
	return JSON.stringify({
		keys: keys.map((k) => ({ kty: "OKP", crv: "Ed25519", kid: k.keyid, x: k.x, use: "sig" })),
	});
}

// Content-Digest, Signature-Input and Signature for a directory response with
// `body`, fetched with Host `authority` (host[:port], lowercase). Labels are
// binding0, binding1, ... (one per key), parameters in the order Cloudflare's
// reference implementation uses.
export async function signDirectory({ authority, body, keys, created, ttl }) {
	const digest = `sha-256=:${base64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(body))))}:`;
	const inputs = [];
	const signatures = [];
	for (const [i, key] of keys.entries()) {
		const label = `binding${i}`;
		const params =
			`("@authority";req "content-digest");created=${created};keyid="${key.keyid}";alg="ed25519";` +
			`expires=${created + ttl};tag="${TAG}"`;
		const base = `"@authority";req: ${authority}\n"content-digest": ${digest}\n"@signature-params": ${params}`;
		const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.signingKey, encoder.encode(base)));
		inputs.push(`${label}=${params}`);
		signatures.push(`${label}=:${base64(sig)}:`);
	}
	return {
		"Content-Digest": digest,
		"Signature-Input": inputs.join(", "),
		Signature: signatures.join(", "),
	};
}
