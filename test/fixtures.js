// Test fixtures. Fake secrets are assembled at runtime so this repository never contains
// strings that look like real keys (and push protection stays quiet).
"use strict";
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = (role) => b64({ alg: "HS256", typ: "JWT" }) + "." + b64({ iss: "supabase", ref: "abcdefghijklmnop", role, iat: 1700000000, exp: 2000000000 }) + "." + "x".repeat(43);
const fake = {
  serviceRole: fakeJwt("service" + "_role"),
  anon: fakeJwt("anon"),
  stripeLive: "sk" + "_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
  stripeTest: "sk" + "_test_" + "A1b2C3d4E5f6G7h8I9j0K1l2",
  openai: "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
  aws: "AK" + "IA" + "ABCDEFGHIJKLMNOP",
  github: "gh" + "p_" + "a".repeat(36),
};
module.exports = { fake, fakeJwt };
