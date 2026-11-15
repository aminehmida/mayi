# Mayi: a secrets manager for AI agents

> This is the plan the project was built from. All five milestones are done.
> Where the result differs, the code and the other documents are right:
> pairing uses a pasted token rather than a short code, devices publish their
> addresses instead of using mDNS, notices are a floating panel rather than
> system notifications, and the wake-up gateway lives in `services/wake`.

## Context

AI agents need credentials to do real work, but today a secret either sits in the agent's context (and on the model provider's servers) or in an env file the agent can read freely. Existing tools each cover a piece: 1Password and Bitwarden Agent Access inject secrets without showing them to the model, Opaque and Jitpass gate on Touch ID. None combines per-secret access levels, a hardware-bound tier that still syncs, and approval on a phone for agents running anywhere.

Mayi ("May I?") is that combination. An agent asks for a secret by name, with the command it wants to run and a reason. A device you own decides whether to release it, and the value is injected into the command without entering the model's context.

## Decisions from the brainstorm

| Area | Decision |
|---|---|
| Audience, threat | Solo developers. Main threat: a hijacked or misbehaving agent. |
| Levels | 1 log · 2 notify (with Stop) · 3 approve · 4 biometric (hardware-bound encryption) |
| Level rules | Per-secret minimum level; context rules (remote host, unknown command, new session) can raise it, never lower it |
| Request | Names the secret(s), exact command, reason, agent, session, host. Per-secret command allowlist can skip prompts. |
| Grants | Once / session / time window chosen at the prompt, capped per secret. Level 4: one session + command pattern, a few minutes. |
| Vault devices | macOS with Touch ID, Android. Hold the encrypted vault. Must have biometrics + hardware key. |
| Requesters | Every agent session and every headless or Linux machine. Thin CLI, nothing stored. Paired per machine by a code confirmed with biometrics. |
| Sync | Peer to peer between vault devices: mDNS on LAN, known addresses over Tailscale. Last write wins with history. Signed device list. |
| Transport | Own protocol modelled on Bitwarden Agent Access (pairing code, Noise tunnel), using an existing Noise library |
| Phone wake-up | Tiny gateway sending a contentless push; all data stays peer to peer |
| Offline | Request waits while the phone is woken, then fails with a clear error |
| Recovery | Optional offline recovery key for level 4 secrets |
| Agent surface | `mayi` CLI + skill file; MCP server that never returns values |
| Stack | Rust core via UniFFI; Swift Mac app; Kotlin Android app; static CLI |
| Scope | Agent secrets only. No browser or Android autofill. |

## Architecture

```
requester (any machine)                 vault device (Mac / Android)
┌──────────────────────┐   request     ┌─────────────────────────────┐
│ agent → mayi run ... │ ────────────► │ policy → prompt/biometric   │
│ child process gets   │ ◄──────────── │ decrypt → release → log     │
│ env vars, masked out │  Noise tunnel └──────────────┬──────────────┘
└──────────────────────┘  (unix socket when local)    │ p2p sync
                                                      ▼
                                              other vault devices
```

One code path: a Claude session on the Mac is a requester talking to the Mac app over a unix socket; a remote VM sends the same messages over a Noise tunnel on LAN or tailnet.

### Repository layout

```
mayi/
  Cargo.toml                 workspace
  crates/
    mayi-core/               items, crypto, policy, grants, audit log, storage, sync
    mayi-proto/              request/response messages, pairing, Noise sessions
    mayi-ffi/                UniFFI bindings (Swift + Kotlin)
    mayi-cli/                `mayi` binary: run, pair, list, mcp
    mayi-wake/               push gateway (Cloudflare Worker)
  apps/
    macos/                   SwiftPM menu-bar app (vault device)
    android/                 Kotlin app (vault device)
  skill/SKILL.md             teaches agents the CLI
  docs/protocol.md, docs/threat-model.md
```

### Key hierarchy

- **Vault key:** random 256-bit. Wrapped once per vault device by that device's hardware key, unlocked when the app starts.
- **Levels 1 to 3:** each item has its own data key, wrapped by the vault key. XChaCha20-Poly1305, HKDF-SHA256.
- **Level 4:** each item's data key is wrapped once per vault device to that device's biometric-gated P-256 key (ECIES). Not wrapped by the vault key, so an unlocked vault cannot read it.
  - macOS: Secure Enclave key with `biometryCurrentSet` access control.
  - Android: Keystore key with `setUserAuthenticationRequired`, StrongBox where present; level 4 refused on devices without hardware-backed biometric keys.
- **Hardware operations** are a trait in `mayi-core` implemented by each app through a UniFFI callback interface; a software implementation backs tests.
- **Enrolling a vault device:** an existing device unlocks biometrically and re-wraps the vault key and all level 4 keys for the newcomer. Writing a level 4 item needs only public keys.
- **Recovery key (optional):** an extra offline keypair treated as one more wrap target.

### Policy engine (`mayi-core`)

Input: request (secrets, argv, cwd, reason, agent, session, requester identity, local or remote). Output: effective level per secret = max(secret floor, escalation rules), then an existing-grant check, then log / notify / prompt / biometric. The reason, agent and session are self-reported and shown as such; the requester machine identity is cryptographic.

### Requester CLI (`mayi-cli`)

- `mayi run --secret ENV_NAME=item[/field] --reason "..." -- cmd args`: sends the request, receives values over the tunnel, spawns the child with env vars, pipes stdout/stderr through a masker (exact value plus common encodings; best effort, documented as such).
- `mayi pair`: shows a short code; a vault device confirms it with biometrics and stores the requester's public key.
- `mayi list`: secret names and levels only.
- `mayi mcp`: MCP server over stdio exposing `list_secrets` and `run_with_secrets`; never returns a value.

### Sync (`mayi-core`)

Item versions stamped with a hybrid logical clock and device ID; last write wins, previous versions kept as history; tombstones for deletes. The device list is a signed append-only log. Peers found by mDNS (`_mayi._tcp`) and by addresses learned at pairing and passed between peers (needed over Tailscale). Sync runs inside a Noise session between enrolled devices.

### Phone wake-up (`mayi-wake`)

A Cloudflare Worker that accepts a signed "wake device X" call and sends a high-priority FCM data message with no request content. The phone wakes, connects to the requester over LAN or tailnet, and handles the request (silently for levels 1 and 2). Requester and vault device must share a LAN or tailnet.

## Milestones

**M1. Core and local loop (Rust only).** Workspace scaffold; item model, crypto, SQLite storage, policy engine, grants, audit log; software hardware-key backend; a dev daemon with terminal prompts; `mayi run` over a unix socket with masking.
*Verify:* `cargo test` (crypto round trips, policy table tests, grant expiry, masking); manual run where `mayi run -- env` shows the secret masked and the log records the request.

**M2. Mac vault device.** UniFFI bindings; SwiftPM menu-bar app hosting the core; Secure Enclave backend; notification with Stop (revokes grant, kills child); approval window showing command, host, agent, reason; Touch ID for level 4; secret management UI.
*Verify:* run a Claude Code session that calls `mayi run` at each of the four levels; confirm level 4 ciphertext cannot be decrypted with the vault key alone (test in core).

**M3. Remote requesters.** `docs/protocol.md`; pairing with a short code; Noise sessions via the `snow` crate; static Linux build of the CLI; escalation rule for remote hosts; wait-then-fail timeout.
*Verify:* pair a Linux VM on the tailnet, run `mayi run` there, approve on the Mac; confirm nothing is written to the VM's disk; packet capture shows only ciphertext.

**M4. Android vault device and sync.** Kotlin app on the same core; Keystore biometric backend; device enrolment and re-wrapping; peer-to-peer sync; `mayi-wake` Worker and FCM handling; background serving of levels 1 and 2.
*Verify:* add a secret on the Mac and see it on the phone; with the Mac asleep and phone locked, a VM request raises a prompt on the phone and a level 4 request needs a fingerprint; concurrent edits resolve with the loser kept in history.

**M5. Agent surface and hardening.** `mayi mcp`; `skill/SKILL.md`; recovery key; device and requester revocation with a "rotate these secrets" list; `docs/threat-model.md`.
*Verify:* an MCP client lists and uses secrets with no value in any tool result; restore level 4 secrets on a fresh device from the recovery key.

## Risks carried into implementation

- **Levels 1 to 3 are policy, not cryptography:** they stop a hijacked agent, not malware on a vault device. State this in the UI and docs.
- **Reason text is untrusted:** the prompt gives the command and host visual priority over the reason.
- **Masking is best effort:** the approved command is the real control; document that an approved command can do anything with the secret.
- **Android hardware varies:** gate level 4 on hardware-backed biometric keys and test on real devices early in M4.
- **Revocation is rotation:** a removed device keeps what it could decrypt.
- **Cryptography is unaudited:** use `snow` and RustCrypto primitives only, no custom constructions, and say so in the README.

## Open points to settle during the milestone they belong to

- Exact Noise patterns for pairing and for paired sessions (M3).
- Whether the wake push carries a requester hint so the phone knows whom to dial (M4).
- The name "Mayi" has not been checked for trademark, domain or package-name conflicts.
