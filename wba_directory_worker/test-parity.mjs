// Runs the Worker locally under Node's WebCrypto with a throwaway key, prints the signed
// directory response as JSON, and (when invoked from tools/test_wba_worker.py) the Python
// verifier checks it. Usage: node test-parity.mjs <base64 PKCS8 DER> <authority>
import worker from "./worker.js";

const [, , pkcs8b64, authority] = process.argv;
if (!pkcs8b64 || !authority) {
  console.error("usage: node test-parity.mjs <base64 PKCS8 DER> <authority>");
  process.exit(2);
}
const env = { WBA_PRIVATE_KEY_PKCS8_B64: pkcs8b64, PURPOSE_URL: "https://marketfauna.com/bot.html" };
const req = new Request(`https://${authority}/.well-known/http-message-signatures-directory`, {
  headers: { host: authority, accept: "application/http-message-signatures-directory+json" },
});
const res = await worker.fetch(req, env);
const headers = {};
for (const [k, v] of res.headers) headers[k] = v;
const other = await worker.fetch(new Request(`https://${authority}/`), env);
console.log(JSON.stringify({ status: res.status, headers, body: await res.text(), redirect: other.status }));
