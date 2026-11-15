# Wake-up gateway

A phone that is asleep cannot be reached over the network. A machine that
needs it asks this gateway to send the phone an empty push; the phone wakes,
and the machine connects to it directly. The gateway never sees a request,
a secret, or which machine is asking: only "wake the device with this id".

It is optional. Without it, a phone answers only while it is awake.

## What it stores

For each registered phone: a random id and the phone's Firebase push token.

## Setting it up

You need a Firebase project (for Firebase Cloud Messaging) and a Cloudflare
account.

1. In the Firebase console, add an Android app with package `dev.mayi.android`
   and put its `google-services.json` in `apps/android/app/`.
2. Create a service account key for the project (Project settings → Service
   accounts → Generate new private key).
3. Create the KV namespace and put its id in `wrangler.toml`:
   `npx wrangler kv namespace create DEVICES`
4. Set the secrets from the service account file:
   ```sh
   npx wrangler secret put FCM_PROJECT_ID      # project_id
   npx wrangler secret put FCM_CLIENT_EMAIL    # client_email
   npx wrangler secret put FCM_PRIVATE_KEY     # private_key, including the BEGIN/END lines
   ```
5. `npx wrangler deploy`, then build the Android app with the URL it prints:
   `./gradlew assembleDebug -Pmayi.wakeUrl=https://mayi-wake.<you>.workers.dev`

## API

- `POST /register` with `{"token": "<FCM token>"}` returns `{"id": "<wake id>"}`.
  Registering the same token again returns the same id.
- `POST /wake` with `{"id": "<wake id>"}` returns 204. At most one push per
  device every 5 seconds (429 otherwise); 404 for an unknown id; 410 if the
  phone has uninstalled the app.

Tests: `node --test` in this folder.
