# Mayi protocol

How a requester (the `mayi` CLI) talks to a vault device. Version 1. It is
not compatible with Bitwarden Agent Access, whose structure it borrows.

## Messages

Every message is a frame: a 4-byte big-endian length, then that many bytes of
JSON. Frames are at most 1 MiB. Each JSON object has a `type` field.

Requester to device:

| `type` | Fields | Meaning |
|---|---|---|
| `run` | `bindings`, `argv`, `cwd`, `reason`, `agent`, `session`, `host`, optional `site` and `program` | Ask to run `argv` with secrets, or with `site`, to type a login into a page. Each binding is `{env, item, field}`. |
| `list` | | Ask for secret names, levels and field names. |
| `done` | `exit` | The command of a released run ended. |
| `pair` | `name` | Enrol this machine. Only valid in a pairing tunnel. |
| `peers` | | Ask which devices hold the vault and where they are. |
| `enrol_local` | `name`, `public` | Enrol this machine's tunnel key as a requester. Only valid on the local socket. |

Device to requester:

| `type` | Fields | Meaning |
|---|---|---|
| `released` | `run_id`, `env` | The values to inject, by environment variable. |
| `denied` | `reason` | The request was refused. |
| `secrets` | `secrets` | Reply to `list`, for each secret the requester's ACL allows: name, level, field names, for a login `login: true` and its `sites`, and for an AWS sign-in `aws` (its `start_url`, `region` and `profiles`, each with `name`, `level`, `account_id`, `account_name` and `role`). Never contains a value. |
| `stop` | | The user pressed Stop: kill the command. |
| `paired` | `device` | Pairing succeeded; `device` is the vault device's name. |
| `peers` | `devices`, `sender`, `sender_active` | Each device's name, tunnel key, port and addresses; the replying device's own tunnel key; and whether its owner is using it right now. |
| `error` | `message` | The request could not be handled. |

A connection carries at most one `run`. After `released`, the requester keeps
the connection open until the command ends, so the device can send `stop`,
then sends `done`. A requester that closes the connection before a decision
withdraws its request, and any prompt for it is taken down.

`cwd`, `reason`, `agent`, `session` and `host` are whatever the requester
says. A device shows them as claims. What a device knows for certain is
which transport and key the request arrived on. The command (`argv`) is what
the requester says it will run; the real `mayi` runs exactly that, but a
device cannot check that the requester is the real `mayi`.

`program` is the absolute path the requester found `argv[0]` at, looking it
up without the working folder and temporary folders. Devices show the
command with it in place of `argv[0]`, record it so in Activity, and key
grants on that form. An expected command written by name (`gh *`) matches
the command with `argv[0]` as given, only when `argv[0]` is a bare name and
`program` is outside temporary folders. Without `program` (requesters before
alpha.9) the command is matched as given.

### AWS sign-ins

A binding for an AWS sign-in names a profile and a field: `field` is
`PROFILE/access_key_id`, `PROFILE/secret_access_key`, `PROFILE/session_token`
or `PROFILE/expiration`, and every binding of one sign-in in a request names
the same profile. The device fetches that role's credentials from AWS and
releases them; the sign-in's own session is never released. The profile's
level decides, and grants are kept per profile and level. `mayi aws
credentials` sends such a request with the command of the AWS tool that
started it as `argv`, and sends `done` as soon as it has the answer.

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

### ACLs

Each requester has an ACL, held on the vault side only: `all`, a list of
tags and a list of secret names. A secret is allowed when the ACL is `all`,
names it, or shares one of its tags (tags compare without case).

- A paired machine's ACL is in its requester record. The device keeps the
  ACL chosen for an invitation with the pending token and gives it to the
  machine's record when `pair` succeeds. The token carries nothing about it,
  and the machine is never told its ACL.
- The requester on a vault device's own machine, over the socket or enrolled
  with `enrol_local`, uses that device's `agents` ACL, kept in the device's
  member record. A device sets it to `all` the first time it serves its
  socket.
- A `run` that names a secret outside the ACL is answered `denied` with
  `NAME is not in this machine's ACL` before levels are considered and
  without asking anyone. It is logged with outcome `denied: …`.
- `list` returns only the secrets the ACL allows.

ACLs live in requester and member records, so they sync like any other change
and every device enforces the same lists.

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

Each device publishes, in its own record in the vault, its tunnel key, port
and network addresses, leaving out those of virtual machine and container
networks. It publishes them again whenever its network changes (a new
Wi-Fi, Ethernet, a VPN coming up) and before each sync. Records sync like
everything else, so every device knows where the others were last seen.

To reach a device, a requester or another device tries all its addresses at
once: the one that worked last first, each other 250 ms later. The first to
complete the handshake is kept and the others are dropped, so at home the
local network usually wins, away a VPN such as Tailscale, and either may be
down. One-time tokens (pairing, enrolment, joining) are tried one address at
a time instead, so that a second handshake cannot reach the other side.

A machine asks the device it reaches for `peers` at the start of every
connection and stores the answer, so it learns about devices added after it
was paired, new addresses, and removals. A list that does not include its
sender is ignored.

### Reaching devices

There is no push service. A phone keeps its port open while it sleeps,
through a foreground service that Android lets keep the network, and is
otherwise reached when it comes back. A request goes to every device of the
vault the requester can reach, each over its own connection:

1. The requester connects to the device on its own machine, if any, and to
   every paired device, in parallel. A device it cannot reach is tried again
   every 5 seconds for the first minute, then every 15, until the request
   is decided or `wait` runs out (1 hour by default, 10 minutes for a sign-in).
2. Once the devices that answer quickly have answered (up to 1 second after
   the first), it chooses whom to ask first: the devices whose `peers` reply
   says `sender_active`; otherwise the device on its own machine; otherwise
   the one it reached most recently. It sends them the `run`.
3. The others get the `run` 30 seconds later if a device in use was asked
   first, otherwise 2 seconds later: long enough for a release that needs no
   answer, so it does not happen on two devices. A device that comes online
   later is asked under the same rule, and at once if its owner is using it.
4. The wait for a decision (`timeout`, 15 minutes by default) starts when the
   first `run` is sent. The first `released` or `denied` wins; the requester
   closes every other connection, which takes their prompts down and logs
   them as `withdrawn`. An `error` takes only that device out of the search.
   A device that closes its connection before deciding, or answers `denied`
   with a reason starting `withdrawn` (it dropped the request on its own), is
   tried again.

### The requester on a vault device's machine

A requester that finds a vault device on its own machine asks it for `peers`
over the socket. If the vault has other devices and the requester knows none
of them, it sends `enrol_local` with its tunnel key: the device enrols it as a
requester marked as that device's machine, syncs, and replies `paired`. From
then on requests made on that machine also reach the other devices, as
from any paired machine (so at least at level 2 there). The device refuses
`enrol_local` over a tunnel, and when its owner has turned it off; turning it
off revokes the requesters it enrolled this way.

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
   of recipients its data key is wrapped to; and, for every device of the
   vault, `log:<id>` with the number of the newest activity entry it holds
   from that device (0 for none).
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

Deletions are records too (tombstones), so they propagate. Each device's
tunnel key is not synced.

Activity is synced as `log` records: an entry from one device's audit log,
numbered in order by that device and sealed under the vault key with the
associated data `mayi/log/<device>/<number>`. A side sends the entries the
other's `log:` markers show it lacks, oldest first and at most 300 per sync,
so a long backlog arrives over several syncs. A device keeps others' entries
apart from its own, ignores its own coming back, and drops any older than 90
days, as it does its own. A device whose digest has no `log:` markers (from
before alpha.8) is sent none.

A secret's rules carry its tags and its rotation notes. Removing a device
or revoking a machine adds a note (who, removed or revoked, when) to each
secret it could read or was given; saving a new value clears the notes, and
so does dismissing them. Both are changes to the item, so they sync as one.

After a sync, each side records, for that device, the stamp of every item it
now holds. A device counts an item's copies as itself, the device that wrote
its current version, and every device recorded at that stamp, removed
devices excluded. The apps mark an item with one copy: it is lost with the
device it is on.

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
