// The wake-up gateway. See README.md.

const MIN_INTERVAL_MS = 5000;
const FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL = "https://oauth2.googleapis.com/token";

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

const base64url = (data) => {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// One access token serves many pushes; it is kept until shortly before it expires.
let cached = { token: null, expiresAt: 0 };

async function accessToken(env, now) {
  if (cached.token && now < cached.expiresAt) return cached.token;
  const seconds = Math.floor(now / 1000);
  const claims = { iss: env.FCM_CLIENT_EMAIL, scope: FCM_SCOPE, aud: TOKEN_URL, iat: seconds, exp: seconds + 3600 };
  const unsigned = `${base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${base64url(JSON.stringify(claims))}`;
  const pem = env.FCM_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${unsigned}.${base64url(signature)}`,
    }),
  });
  if (!response.ok) throw new Error(`token exchange failed: ${response.status}`);
  const body = await response.json();
  cached = { token: body.access_token, expiresAt: now + (body.expires_in - 60) * 1000 };
  return cached.token;
}

async function register(request, env) {
  const { token } = await request.json();
  if (typeof token !== "string" || token.length < 20 || token.length > 4096) return json({ error: "bad token" }, 400);
  const digest = hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  const existing = await env.DEVICES.get(`token:${digest}`);
  if (existing) return json({ id: existing });
  const id = hex(crypto.getRandomValues(new Uint8Array(16)));
  await env.DEVICES.put(`wake:${id}`, token);
  await env.DEVICES.put(`token:${digest}`, id);
  return json({ id });
}

async function wake(request, env, now) {
  const { id } = await request.json();
  if (typeof id !== "string" || !/^[0-9a-f]{32}$/.test(id)) return json({ error: "bad id" }, 400);
  const token = await env.DEVICES.get(`wake:${id}`);
  if (!token) return json({ error: "unknown device" }, 404);
  const last = Number(await env.DEVICES.get(`last:${id}`)) || 0;
  if (now - last < MIN_INTERVAL_MS) return json({ error: "too soon" }, 429);
  await env.DEVICES.put(`last:${id}`, String(now));

  // A data message with nothing to say: its arrival is the whole signal.
  const response = await fetch(`https://fcm.googleapis.com/v1/projects/${env.FCM_PROJECT_ID}/messages:send`, {
    method: "POST",
    headers: { authorization: `Bearer ${await accessToken(env, now)}`, "content-type": "application/json" },
    body: JSON.stringify({ message: { token, android: { priority: "HIGH" }, data: { wake: "1" } } }),
  });
  if (response.status === 404) {
    // The app was uninstalled: forget the device.
    const digest = hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
    await env.DEVICES.delete(`wake:${id}`);
    await env.DEVICES.delete(`token:${digest}`);
    return json({ error: "device gone" }, 410);
  }
  if (!response.ok) return json({ error: "push failed" }, 502);
  return new Response(null, { status: 204 });
}

export async function handle(request, env, now = Date.now()) {
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  const path = new URL(request.url).pathname;
  try {
    if (path === "/register") return await register(request, env);
    if (path === "/wake") return await wake(request, env, now);
  } catch (e) {
    return json({ error: "bad request" }, 400);
  }
  return json({ error: "not found" }, 404);
}

export function resetTokenCache() {
  cached = { token: null, expiresAt: 0 };
}

export default { fetch: (request, env) => handle(request, env) };
