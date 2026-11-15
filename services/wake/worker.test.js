import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { handle, resetTokenCache } from "./worker.js";

// A throwaway key standing in for the Firebase service account.
const pair = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", pair.privateKey)).toString("base64");
const pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----\n`;

let env, calls, fcmStatus;

beforeEach(() => {
  const store = new Map();
  env = {
    FCM_PROJECT_ID: "proj",
    FCM_CLIENT_EMAIL: "svc@proj.iam.gserviceaccount.com",
    FCM_PRIVATE_KEY: pem,
    DEVICES: {
      get: async (k) => store.get(k) ?? null,
      put: async (k, v) => void store.set(k, v),
      delete: async (k) => void store.delete(k),
      size: () => store.size,
    },
  };
  calls = [];
  fcmStatus = 200;
  resetTokenCache();
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).includes("oauth2")) {
      // Google would verify the signature; so does this.
      const [header, claims, signature] = new URLSearchParams(init.body).get("assertion").split(".");
      const ok = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5", pair.publicKey, Buffer.from(signature, "base64url"), Buffer.from(`${header}.${claims}`));
      assert.ok(ok, "the token request is signed with the service account key");
      assert.equal(JSON.parse(Buffer.from(claims, "base64url")).iss, env.FCM_CLIENT_EMAIL);
      return Response.json({ access_token: "access-1", expires_in: 3600 });
    }
    return new Response("{}", { status: fcmStatus });
  };
});

const post = (path, body, now) =>
  handle(new Request(`https://gw.example${path}`, { method: "POST", body: JSON.stringify(body) }), env, now);

const pushToken = "f".repeat(140);

test("register is idempotent and wake sends one empty push", async () => {
  const { id } = await (await post("/register", { token: pushToken })).json();
  assert.match(id, /^[0-9a-f]{32}$/);
  assert.equal((await (await post("/register", { token: pushToken })).json()).id, id);

  assert.equal((await post("/wake", { id }, 100_000)).status, 204);
  const push = calls.find((c) => c.url.includes("fcm.googleapis.com"));
  assert.equal(push.url, "https://fcm.googleapis.com/v1/projects/proj/messages:send");
  assert.equal(push.init.headers.authorization, "Bearer access-1");
  assert.deepEqual(JSON.parse(push.init.body), {
    message: { token: pushToken, android: { priority: "HIGH" }, data: { wake: "1" } },
  });
});

test("wakes are rate limited and the access token is reused", async () => {
  const { id } = await (await post("/register", { token: pushToken })).json();
  assert.equal((await post("/wake", { id }, 100_000)).status, 204);
  assert.equal((await post("/wake", { id }, 102_000)).status, 429);
  assert.equal((await post("/wake", { id }, 106_000)).status, 204);
  assert.equal(calls.filter((c) => c.url.includes("oauth2")).length, 1);
  assert.equal(calls.filter((c) => c.url.includes("fcm")).length, 2);
});

test("unknown, malformed and wrong-method requests are refused", async () => {
  assert.equal((await post("/wake", { id: "0".repeat(32) })).status, 404);
  assert.equal((await post("/wake", { id: "../etc" })).status, 400);
  assert.equal((await post("/register", { token: "short" })).status, 400);
  assert.equal((await post("/elsewhere", {})).status, 404);
  assert.equal((await handle(new Request("https://gw.example/wake"), env)).status, 405);
  const garbage = new Request("https://gw.example/wake", { method: "POST", body: "not json" });
  assert.equal((await handle(garbage, env)).status, 400);
  assert.equal(calls.length, 0, "nothing was pushed");
});

test("a phone that uninstalled the app is forgotten", async () => {
  const { id } = await (await post("/register", { token: pushToken })).json();
  fcmStatus = 404;
  assert.equal((await post("/wake", { id }, 100_000)).status, 410);
  assert.equal((await post("/wake", { id }, 200_000)).status, 404);
  fcmStatus = 500;
  const again = await (await post("/register", { token: pushToken })).json();
  assert.notEqual(again.id, id);
  assert.equal((await post("/wake", { id: again.id }, 300_000)).status, 502);
});
