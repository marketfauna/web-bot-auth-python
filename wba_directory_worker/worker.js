// Signed Web Bot Auth key directory for MarketfaunaBot, as a Cloudflare Worker.
//
// Serves GET /.well-known/http-message-signatures-directory with the response signature
// Cloudflare requires (developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/,
// read 2026-09-13): Content-Type application/http-message-signatures-directory+json,
// one Ed25519 signature per key over ("@authority";req), tag http-message-signatures-directory,
// keyid = RFC 7638 thumbprint, created/expires as Unix seconds.
//
// The private key arrives only as the secret WBA_PRIVATE_KEY_PKCS8_B64 (base64 of the DER
// PKCS#8 key). Only kty, crv and x are ever written to a response.
// Mirrors tools/wba.py, whose tests cover the same signature base.

const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
const MEDIA_TYPE = "application/http-message-signatures-directory+json";

const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function loadKey(env) {
  if (!env.WBA_PRIVATE_KEY_PKCS8_B64) throw new Error("secret WBA_PRIVATE_KEY_PKCS8_B64 not set");
  const der = Uint8Array.from(atob(env.WBA_PRIVATE_KEY_PKCS8_B64), (c) => c.charCodeAt(0));
  const priv = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
  const exported = await crypto.subtle.exportKey("jwk", priv); // contains d; used only to read x
  const jwk = { kty: "OKP", crv: "Ed25519", x: exported.x };
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const kid = b64url(await crypto.subtle.digest("SHA-256", enc.encode(canonical)));
  return { priv, jwk, kid };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== DIRECTORY_PATH) {
      return Response.redirect(env.PURPOSE_URL || "https://marketfauna.com/bot.html", 302);
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405 });
    }
    const { priv, jwk, kid } = await loadKey(env);
    const authority = (request.headers.get("host") || url.host).toLowerCase();
    const now = Math.floor(Date.now() / 1000);
    const nonce = b64(crypto.getRandomValues(new Uint8Array(48)));
    const params =
      `("@authority";req);alg="ed25519";keyid="${kid}";nonce="${nonce}";` +
      `tag="http-message-signatures-directory";created=${now};expires=${now + 300}`;
    const base = `"@authority";req: ${authority}\n"@signature-params": ${params}`;
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, priv, enc.encode(base));
    const body = JSON.stringify({ keys: [jwk] });
    return new Response(request.method === "HEAD" ? null : body, {
      status: 200,
      headers: {
        "Content-Type": MEDIA_TYPE,
        "Signature-Input": `sig1=${params}`,
        "Signature": `sig1=:${b64(sig)}:`,
        // Regenerate short-lived signatures rather than cache expired responses.
        "Cache-Control": "no-store",
      },
    });
  },
};
