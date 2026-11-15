# Mayi protocol

How a requester (the `mayi` CLI) talks to a vault device. Version 1. It is
not compatible with Bitwarden Agent Access, whose structure it borrows.

## Messages

Every message is a frame: a 4-byte big-endian length, then that many bytes of
JSON. Frames are at most 1 MiB. Each JSON object has a `type` field.

Requester to device:

| `type` | Fields | Meaning |
|---|---|---|
| `run` | `bindings`, `argv`, `cwd`, `reason`, `agent`, `session`, `host`, optional `site` | Ask to run `argv` with secrets, or with `site`, to type a login into a page. Each binding is `{env, item, field}`. |
| `list` | | Ask for secret names, levels and field names. |
| `done` | `exit` | The command of a released run ended. |
| `pair` | `name` | Enrol this machine. Only valid in a pairing tunnel. |
| `peers` | | Ask which devices hold the vault and where they are. |

Device to requester:

| `type` | Fields | Meaning |
|---|---|---|
| `released` | `run_id`, `env` | The values to inject, by environment variable. |
| `denied` | `reason` | The request was refused. |
| `secrets` | `secrets` | Reply to `list`: name, level, field names, and for a login `login: true` and its `sites`. Never contains a value. |
| `stop` | | The user pressed Stop: kill the command. |
| `paired` | `device` | Pairing succeeded; `device` is the vault device's name. |
| `peers` | `devices` | Each device's name, tunnel key, port, addresses and optional wake-up address. |
| `error` | `message` | The request could not be handled. |

A connection carries at most one `run`. After `released`, the requester keeps
the connection open until the command ends, so the device can send `stop`,
then sends `done`. A requester that closes the connection before a decision
withdraws its request, and any prompt for it is taken down.

`cwd`, `reason`, `agent`, `session` and `host` are whatever the requester
says. A device shows them as claims. What a device knows for certain is the
command (`argv`) and which transport and key the request arrived on.

### Sign-ins

A `run` with `site` set is a sign-in. `site` is the origin of the page, as
the requester's browser reported it (`https://github.com`). Then `argv` is
empty, every binding names the same login, and each binding's `env` is
simply the key its value comes back under in `released`. The fields of a
login are `username`, `password` and `totp`.

The device refuses, before asking anyone, a sign-in whose origin is not
https (plain http is accepted for `localhost`, `*.localhost`, `127.0.0.1`
and `[::1]` only) or does not match one of the login's sites; a sign-in that
names a secret that is not a login; and a command `run` that names a login.
For `totp` the device returns the current code, never the key. Grants for a
sign-in are keyed on the login, the session and `sign in to <origin>`, and
an "allow once" also covers the next two minutes of the same sign-in.

After typing, the requester sends `done` with exit 0 if the form was
submitted and 1 otherwise. A device older than this answers a sign-in with
"no command given".

## Local transport

On the vault device's own machine, frames travel over a unix socket
(`~/.mayi/mayi.sock` by default) that only the owning user can open. There is
no further encryption or authentication: the kernel provides both.

## Network transport

From another machine, frames travel inside a Noise tunnel over TCP (default
port 7462). The requester opens the connection and is the Noise initiator.

1. The caller sends one byte: `1` for a machine's session, `2` for a machine
   pairing, `3` for a new vault device enrolling, `4` for two vault devices
   syncing. Modes 3 and 4 use the same handshakes as 2 and 1, with their own
   mode byte in the prologue.
2. Both sides run a two-message Noise handshake. Each handshake message is
   sent as a 2-byte big-endian length followed by the message.
3. Frames then flow in both directions. The sender splits its bytes into
   chunks of at most 65519 bytes, encrypts each as one Noise transport
   message, and sends it as a 2-byte length followed by the ciphertext.
   Nonces count up from 0 in each direction, so a dropped, repeated or
   reordered record fails to decrypt and ends the connection.

| | Session | Pairing |
|---|---|---|
| Pattern | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` |
| Prologue | `mayi/1` then byte `1` | `mayi/1` then byte `2` |
| Pre-shared key | none | the 32-byte secret from the pairing token |

In both patterns the requester already knows the device's static key and
encrypts its first message to it, so it cannot be made to talk to an
impostor, and the device learns the requester's static key from that message.

### Pairing

The vault device creates a pairing token after its owner confirms with a
biometric check. The token is text meant to be pasted on the other machine:

```
mayi1.<base64url, no padding>
```

The decoded bytes are the device's static public key (32), a random one-time
secret (32), the TCP port (2, big-endian) and a comma-separated list of
addresses (UTF-8, the rest).

The other machine runs `mayi pair <token>`. It generates its own static key
on first use, opens a pairing tunnel to one of the addresses, and sends
`pair` with a name for itself. The device stores the machine's static key and
name and replies `paired`. The token is spent as soon as a handshake using
its secret completes, and expires after 10 minutes otherwise.

The secret is a full 256-bit key rather than a short code. A short code
would need a password-authenticated key exchange to resist an attacker who
intercepts one pairing attempt; a pasted token avoids that.

Whoever holds an unused token can pair a machine, so it must reach the other
machine over a channel the owner trusts, such as their own SSH session.

### Sessions

For each request the machine opens a session tunnel using its static key.
After the handshake the device looks the key up among paired machines. If it
is unknown or revoked the device sends `error` and closes. Otherwise the
connection is served exactly like a local one, except that the request is
marked remote: silent (level 1) secrets are raised to a notification, and
prompts and logs name the machine.

### What a machine stores

Its static private key and, for each device it is paired with, the device's
name, static public key, port and addresses, in
`~/.config/mayi/requester.json` (mode 600). No secret from the vault is
written to disk; values exist in the environment of the command they were
released to, for as long as it runs.

### Keys

- A machine's static key identifies it. Stealing `requester.json` lets the
  thief send requests as that machine until it is revoked. Requests still go
  through each secret's level, so levels 3 and 4 still need the owner.
- A device's static key is a software X25519 key sealed under the vault key.
  It authenticates the device to machines and protects nothing at rest.
- Noise gives each connection fresh keys: recording traffic and later
  stealing a static key does not reveal past sessions' secrets, with the
  usual caveat for the first IK message, which is only protected by the
  device's static key. That message carries the requester's identity, not a
  request.

## Several devices

A vault can live on more than one device. There is no server between them.

### Finding devices

Each device publishes, in its own record in the vault, its tunnel key, port,
network addresses and (for a phone) a wake-up address. Records sync like
everything else, so every device knows where the others were last seen.

A machine asks the device it reaches for `peers` at the start of every
connection and stores the answer, so it learns about devices added after it
was paired, new addresses, and removals. A list that does not include its
sender is ignored.

### Waking a phone

A phone cannot keep a port open while it sleeps. If a machine cannot connect
to a device that has a wake-up address `{url, id}`, it sends
`POST url` with `{"id": id}` and retries the connection for up to 20 seconds.
The gateway behind the URL (`services/wake`) sends the phone a push with no
content; the phone starts listening, and the machine connects to it directly.
The gateway learns only that a device was woken.

### Enrolling a device (mode 3)

A device creates an enrolment token (`mayid1.…`, same layout as a pairing
token) after its owner confirms with a biometric check. The new device opens
an enrolment tunnel with the token's secret and sends:

| `type` | Fields |
|---|---|
| `enrol` | `name`, `device_pub`, `biometric_pub` (P-256, hex), `noise_public` (hex) |

The existing device wraps the vault key to `device_pub` and every level 4
data key to `biometric_pub`. The second step needs its own biometric check if
any level 4 secret exists. It replies `enrolled` with `device_id` and
`wrapped_vk`. The new device unwraps the vault key with its hardware key,
creates its copy of the vault, and syncs.

### Joining by code (mode 5)

The same exchange with the connection the other way round, so that the
device that shows a code can be the one with a screen (a Mac) and the one
that scans it the one with a camera (a phone), whichever of them is new.

A device with no vault opens a listening port (any free one) and shows a
join code, `mayij1.…`: the same layout as the other tokens, carrying the new
device's static key, a one-time secret, the port and its addresses. A device
that holds the vault redeems it: it connects in mode 5 with an `IKpsk2`
handshake keyed by the secret, using its own vault static key. The new
device then sends `enrol` and the existing one answers `enrolled`, exactly as
in mode 3, including the biometric check for level 4 keys. Because the new
device does not yet know where the other one listens, the first sync runs
over the same tunnel, with the new device as caller.

A join code lasts ten minutes, and a connection that fails the handshake
does not end the wait. Each kind of code is refused in the wrong place: an
invitation (`mayid1.`) is entered on the new device, a join code on the
device that has the vault.

### Sync (mode 4)

Either device can call the other. The callee accepts only tunnel keys that
belong to a device of the vault that has not been removed.

1. Caller: `digest`, mapping each record (`member:<id>`, `item:<id>`,
   `requester:<id>`) to its stamp `{version, author}` and, for items, the set
   of recipients its data key is wrapped to.
2. Callee: `reply` with its own digest and the records the caller lacks.
3. Caller: `records` with the records the callee lacks.
4. Callee: `done`.

A record is sent when the other side has none, has a lower stamp, or (for an
item at the same stamp) lacks some wraps. On receipt:

- A record that does not open under the vault key is refused and the sync
  aborts. Nothing from outside the vault can be merged in.
- The higher stamp wins. Stamps compare by version, then author. Versions are
  wall-clock milliseconds pushed past every version the device has seen, so a
  slow clock cannot make a new change lose to an old one.
- When an item loses, the losing version is kept in history on the device
  that had it.
- At equal stamps, wraps are merged, which is how a device that joined later
  receives level 4 keys.
- Two secrets created with the same name on different devices both survive
  in the file; every device shows the one with the higher stamp.

Deletions are records too (tombstones), so they propagate. The audit log and
each device's tunnel key are not synced.

Removing a device marks its record removed: other devices stop syncing with
it, refuse its tunnel key, drop its level 4 wraps and wrap no new ones to it.
It keeps whatever it could already decrypt.

## Not covered yet

- Discovery on the local network (mDNS). Devices rely on published
  addresses, which works when at least one side keeps its address, as with
  Tailscale. If both change at once they lose each other until one is told
  the other's address again.
- Frames are limited to 1 MiB, so a first sync of a very large vault would
  need chunking.
