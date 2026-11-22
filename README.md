# Mayi

"May I?" A secrets manager for AI agents. An agent asks for a secret by name,
with the command it wants to run and a reason. A device you own decides
whether to release it, and the value is injected into the command without
entering the model's context. Website logins work the same way: Mayi types
them into the sign-in page open in the agent's browser, two-factor code
included.

Mayi complements an agent sandbox; it does not replace one. It decides which
secrets an agent may use, asks you as you choose, records every use, and
keeps values out of the model's context. An agent that has been compromised
and runs as you can still keep a value you let it use; a sandbox with a
network policy (Docker's agent sandboxes, OpenShell) is what stops it going
anywhere. Use both for agents you cannot fully trust, and keep the secrets
that matter most at level 4, where each use needs your fingerprint.

Status: all five milestones of the [design](docs/design.md) are built, and
website logins after them. What
it protects and where it stops is in the [threat model](docs/threat-model.md);
how the pieces talk is in the [protocol](docs/protocol.md). Nothing has been
audited, and several things have only been tested with stand-ins for real
hardware: see [docs/manual-checks.md](docs/manual-checks.md) before trusting
it with secrets that matter. What comes next (AWS SSO, SSH signing, a token
proxy) is planned in [docs/providers.md](docs/providers.md).

## Install

The current release is an alpha, `v0.1.0-alpha.3`. Downloads are on the
[releases page](https://github.com/aminehmida/mayi/releases).

### Mac (Homebrew)

```sh
brew tap aminehmida/mayi https://github.com/aminehmida/mayi
brew install --cask aminehmida/mayi/mayi        # Mayi.app, and the mayi command
```

The repository is its own tap, which is why `brew tap` needs its URL. The
app is for Apple silicon and macOS 14 or later. It is signed ad hoc, not
notarized by Apple; the cask clears its quarantine flag so that it opens.
Without Homebrew, unzip `Mayi-….zip` from the releases page into
Applications, then run `xattr -dr com.apple.quarantine /Applications/Mayi.app`
once.

### Other machines

`brew install aminehmida/mayi/mayi-cli` installs only the `mayi` command, on a
server or a Mac without the app (macOS on Apple silicon, Linux on x86_64 or
ARM). Without Homebrew, the Linux builds are static binaries:

```sh
curl -fsSL https://github.com/aminehmida/mayi/releases/download/v0.1.0-alpha.3/mayi-0.1.0-alpha.3-x86_64-unknown-linux-musl.tar.gz | tar xz
sudo install mayi-0.1.0-alpha.3-x86_64-unknown-linux-musl/mayi /usr/local/bin/
```

### Android (Obtainium)

In [Obtainium](https://github.com/ImranR98/Obtainium), add an app with the URL
`https://github.com/aminehmida/mayi` and turn on **Include prereleases**:
alpha releases are marked as pre-releases. Or download the APK from the
releases page.

Every release is signed with the same key, so the app updates in place. It
needs Android 12 or later and a phone that can keep keys in secure hardware.

### Making a release

```sh
# bump the version in Cargo.toml, apps/android/app/build.gradle.kts and apps/macos/Info.plist,
# and write docs/releases/vVERSION.md
git commit -am "Release VERSION" && git push
git tag vVERSION && git push origin vVERSION
```

Pushing the tag runs [the release workflow](.github/workflows/release.yml)
on a macOS runner: it builds every file with `scripts/release.sh`, publishes
the GitHub release with `scripts/publish.py`, and commits the Homebrew update
to `main`. Started by hand from the Actions tab, it builds without
publishing and attaches the files to the run.

By hand instead, on a Mac with the Android SDK:

```sh
scripts/release.sh                       # builds everything into dist/VERSION
git tag vVERSION && git push origin vVERSION
scripts/publish.py                       # GitHub release, then rewrites Formula/ and Casks/
git commit -am "Point Homebrew at VERSION" && git push
```

The Android signing key is `~/.android/mayi-release.jks`. `release.sh` reads
its password from `MAYI_KEYSTORE_PASSWORD`, or else the keychain item
`mayi-android-release`; with Mayi, `mayi run -s
MAYI_KEYSTORE_PASSWORD=mayi-android-release-password -r "…" --
scripts/release.sh`. The workflow has both as the repository secrets
`MAYI_KEYSTORE_BASE64` and `MAYI_KEYSTORE_PASSWORD`. Keep a copy of the key
and its password somewhere safe: a release signed with another key cannot
update installed copies.

## Levels

| Level | Behaviour |
|---|---|
| 1 log | Released silently and recorded |
| 2 notify | Released at once; you are notified and can stop the command |
| 3 approve | Held until you approve |
| 4 biometric | Encrypted to a hardware key that needs you for every use: a fingerprint on the phone; Touch ID, your Apple Watch or your password on a Mac |

Levels 1 to 3 are rules the vault device follows; they stop a misbehaving
agent, not malware on the vault device. Only level 4 is enforced by
encryption.

Approving a request gives the secret to that agent session; it does not
control what the session does with it. Prompts and Activity show the full
path of the program that will run (`/opt/homebrew/bin/gh pr list`): `mayi`
looks it up itself, not in the working folder or temporary folders, and
runs it without the variables that make programs load other code.

## Mac app

Rust is managed with mise (`mise install`). The app builds with the Xcode
Command Line Tools; full Xcode is not needed.

```sh
apps/macos/build.sh            # builds apps/macos/build/Mayi.app
apps/macos/build.sh test       # Swift tests, including end-to-end runs
open apps/macos/build/Mayi.app
```

Mayi appears as a key icon in the menu bar. Add secrets under "Secrets and
Activity…", then from any terminal or agent:

```sh
apps/macos/build/Mayi.app/Contents/Resources/mayi list
apps/macos/build/Mayi.app/Contents/Resources/mayi run -s GH_TOKEN -r "list open PRs" -- gh pr list
```

The app keeps its vault in `~/Library/Application Support/Mayi` and its keys
in the Secure Enclave. Level 4 secrets need Touch ID, your Apple Watch or
your login password for every unlock, so a closed lid does not block them.
A Mac set up before v0.1.0-alpha.3 keeps its fingerprint-only key, which
changed fingerprints make unusable, until its vault is set up again.

Mayi asks for Touch ID or your password once, when you open its window, and
stays unlocked until the Mac locks or sleeps; the phone asks for your
fingerprint when you open it, and locks with the screen or after five minutes
in the background. Unlocked, it shows values, pairs machines and adds devices
without asking again. Level 4 secrets still ask on every use: that is what
level 4 means.

To read a secret yourself, edit it and press the eye next to a value, or
choose Show Values: the current values appear, ready to change or copy (the
clipboard is cleared after a minute). A login shows its
current two-factor code, never the key behind it; to replace the key, type or
paste a new one, or copy its QR code (Control-Shift-Command-4) and paste it
with the QR button. The phone scans it with the camera. Each view is listed in
Activity. An orange dot next to a secret means it is only on this Mac: it
gets a second copy when another of your devices syncs.

Search the Secrets list by name, website or tag. A secret can carry several
tags, typed or picked when you add or edit it; tags appear in the sidebar on
the Mac and as filters above the list on the phone. Tags also decide which
machines may use a secret (see [ACLs](#acls)), so the editor shows who could
use it as you type them.

Activity is shared: each device sends what it recorded to the others when
they sync, so any of them shows every request, which machine made it, and
which device answered. Entries are kept for 90 days.

The app's own keys are sealed with an item in your keychain that only Mayi
can read. Until Mayi is signed with an Apple Developer ID, macOS asks once
after each update whether Mayi may use it: type your password and choose
Always Allow.

Mayi lives in the menu bar, and in the Dock while one of its windows is
open. Opening it from Finder or Spotlight shows its window, which helps when
the notch hides the menu-bar icon. It starts at login; "Open at Login" in its
menu turns that off.

## Website logins

A login is a second kind of secret: websites, a username, a password and
optionally a two-factor key. It is never given to a command. Mayi types it
into the page itself, and only into one of its websites, over https.

```sh
mayi browser                          # Chrome with its own profile and a debugging port
# point the agent's browser tool at it, e.g. Playwright MCP with --cdp-endpoint http://127.0.0.1:9222
mayi fill github -r "Download this month's invoice"
```

The agent opens the sign-in page, then runs `mayi fill`. Mayi reads the
page's address from the browser, the vault device checks it against the
login's websites and asks you according to the level, and the username,
password or current two-factor code is typed in and submitted. A site that
asks on several pages gets `mayi fill` once per page; one approval covers
two minutes of the same sign-in. The two-factor key never leaves your
devices: the page gets the six-digit code.

Logins are added in the app (Secrets → Add → Website Login) or with
`mayi-devd add NAME --login --site github.com`.

What this does not stop is in the [threat model](docs/threat-model.md#website-logins):
mainly, an agent that can run scripts in its own browser can read a password
as it is typed, and once signed in the agent can act as you on that site.

## AWS sign-ins

Mayi can hold an AWS IAM Identity Center (SSO) sign-in, so agents get the
temporary keys of one role and never the session that reaches all of them.

In the app, Secrets → Add → AWS Sign-In. Mayi suggests the portals your AWS
CLI already knows; pick one and your browser opens AWS's own sign-in, with
your usual login and two-factor. Allow "Mayi", then choose which roles agents
may use, each as a profile with its own level: read-only roles at 1, roles
that can change production at 4, the others at 3, as suggested. Mayi then
removes the sign-in the AWS CLI saved in a plain file, which any program
could read, and adds the profiles to `~/.aws/config`.

```sh
aws s3 ls --profile mawaqit-production-ro          # level 1: answers at once
aws s3 rm s3://… --profile mawaqit-production-admin  # level 4: Touch ID, showing this command
mayi run --aws mawaqit/production-ro -r "List the buckets" -- aws s3 ls
```

The profiles run `mayi aws credentials` for each command (AWS's
`credential_process`), so the AWS CLI, Terraform and the SDKs work as before.
The prompt shows the AWS command that asked. On another machine, `mayi aws
setup` writes the same profiles; nothing is stored there.

- The sign-in is refreshed silently, as the AWS CLI does, until AWS ends the
  session (8 hours by default). The next request then asks you to sign in
  again, and carries on once you have.
- Level 4 on a profile means Touch ID, your Apple Watch or your password for
  every use. It is a check, not encryption: one sign-in serves all its roles,
  so it cannot be encrypted for one of them.
- Adding a profile, or lowering one's level, asks for Touch ID, even with
  Mayi's window unlocked.
- A command you approve can keep its role's keys until they expire (1 to 12
  hours, set by your AWS administrators).

More in the [threat model](docs/threat-model.md#aws-sign-ins).

## Other machines

A server or VM can ask a vault device for secrets without storing any.

```sh
scripts/build-linux.sh                 # static binaries, no dependencies
scp target/x86_64-unknown-linux-musl/release/mayi server:/usr/local/bin/
```

In the Mac app, open the Machines tab and choose "Pair a Machine…". Choose
what the machine may use, then paste the command it shows on the other
machine (`mayi pair mayi1.…`). After that,
`mayi run` and `mayi list` work there as they do locally, as long as it can
reach the Mac on port 7462 over the local network or a VPN such as Tailscale.

Requests from another machine are marked as such, and level 1 secrets are
raised to a notification. Revoke a machine from the same tab.

### ACLs

Each paired machine has an ACL: the secrets it may use, as whole tags, single
secrets, or all secrets. Pairing asks for it first, with nothing ticked.
Anything outside it is refused at once, without asking you, and the refusal
is listed in Activity; `mayi list` on that machine shows only what it may
use. A tag covers secrets you tag later too.

Agents on a Mac with the app have an ACL as well, "Agents on <Mac>", for
their requests through the app and, from there, to your other devices. It
starts with all secrets.

Change an ACL under Machines on the Mac or Devices on the phone. It reaches
your other devices with the next sync, and each of them enforces it. An ACL
limits which machine may use a secret, not what an agent on that machine
does with it; that is the agent sandbox's job.

A request waits for you rather than failing at once: `mayi` keeps trying your
devices for up to an hour (`--wait`), then gives you 15 minutes to answer
(`--timeout`) once one of them shows the prompt. It fails with exit code 69 if
no device could be reached, or 75 if nobody answered.

## More than one device

Either device can come first. The new one receives the whole vault; after
that, a change on either reaches the other the next time they can connect
(at start, every five minutes, and after each change).

- **The phone has the vault, the Mac is new:** on first launch the Mac app
  shows a QR code under "Join Your Vault". On the phone, open Devices, tap +,
  then "Add a device", and scan it (or type the code).
- **The Mac has the vault, the phone is new:** in the Mac app, Devices, "Add a
  Device…" shows a QR code. On the phone, choose "Scan code from another
  device".
- **Two Macs:** paste one Mac's code into the other, either way round.

- **Two phones:** the new phone chooses "Show a code for your other
  device"; the other scans it from Devices, +, "Add a device".

A Mac or phone that already started an empty vault of its own shows "Join
Another Vault…" in Devices: Mayi sets the empty vault aside and restarts
into setup.

A request goes to all your devices that can be reached, and the first answer
counts; the others take their prompt down. The device you are using is asked
first (a Mac unlocked with recent input, or a phone unlocked with the screen
on), and the others 30 seconds later, so you are not asked twice. An agent on
a Mac with the app reaches your phone too: `mayi` there pairs the Mac with
the vault the first time it needs to. Devices, "Agents on this Mac can also
ask your other devices" turns that off.

No push service is involved, Google's or anyone's: a machine connects to the
phone directly, over the same network or [Tailscale](https://tailscale.com).

The phone app does what the Mac app does: add, view, search and tag secrets
and logins (values show after your fingerprint, and an orange dot marks a
secret that is only on this phone), pair machines and edit their ACLs, add
and remove devices,
and make a recovery key. Tapping a request's notification opens it. It starts
serving again after the phone restarts, unless you chose Exit in its
notification (then it stays off until you open Mayi), and warns when notifications are
off or Android may stop it in the background, since requests could not reach
you. It needs no Google services: the QR scanner uses the camera directly.

The Android app is in `apps/android`:

```sh
apps/android/build-core.sh          # Rust core for Android + Kotlin bindings
cd apps/android && ./gradlew assembleDebug
```

For requests to reach the phone while it sleeps:

- Let Mayi run in the background. Setup asks; it is the phone's battery
  setting "Unrestricted". Mayi only listens, so it costs almost no battery.
  Some makers (Samsung, Xiaomi and others) stop apps anyway; the app links to
  [dontkillmyapp.com](https://dontkillmyapp.com) for those.
- Away from home, keep Tailscale on: in Android's VPN settings, turn on
  Always-on VPN for Tailscale.

## For agents

Give the agent `skill/mayi/SKILL.md` (for Claude Code, copy the `skill/mayi`
folder into `~/.claude/skills/`; it is also in the app, under
`Mayi.app/Contents/Resources/skill`). It teaches the `mayi run` syntax and the
rules: narrow requests, readable commands, never extract a value, a denial is
final, and AWS through profiles rather than `aws sso login`. Agents use Mayi through their shell; there is no MCP server, as it
would hand apps without a shell a way to run commands on your Mac.

## If something is lost

- **Recovery key:** Devices → "Recovery Key…" creates an offline key, shown
  once. With it and the vault file, a Mac whose keys were lost (for example
  after its fingerprints changed) is restored at next launch. Anyone holding
  it and a copy of the vault file can read everything, so keep it offline.
- **A device or machine you no longer trust:** remove or revoke it in the
  app. Each secret it could read or was given gets a ⚠️ on every device;
  open the secret to see who may still have it. Replace the value at its
  source, because removal cannot take back what was already seen, and save
  the new value: that clears the warning. Dismiss it if the value needs no
  replacing.

## Without the app

`mayi-devd` is a terminal stand-in for a vault device, for development and
for machines without the app. Its keys live in a plain file and its biometric
check is a typed answer, so do not store real secrets in it.

```sh
cargo build
target/debug/mayi-devd init
target/debug/mayi-devd add GH_TOKEN --level 3
target/debug/mayi-devd add github --login --site github.com   # asks for username, password, two-factor key
target/debug/mayi-devd serve          # keep open: prompts appear here
target/debug/mayi-devd serve --listen 0.0.0.0:7462   # also accept paired machines; type `pair` (all secrets) or `pair TAG…`
```

## Limits to know about

- The command you approve can do anything with the secret. Output masking
  only catches accidental leaks.
- The reason, agent and session shown in a prompt are written by the
  requester. The command is what to read. For a sign-in, the website is
  reported by the requester's browser.
- The cryptography uses standard primitives (XChaCha20-Poly1305, P-256 ECDH,
  HKDF-SHA256 from RustCrypto) but has not been audited.

## Layout

- `crates/mayi-proto`: messages between requester and vault device
- `crates/mayi-core`: vault, key hierarchy, policy, grants, audit log, broker, providers
- `crates/mayi-cli`: `mayi`, the requester, including the browser filler (`fill.rs`, `fill.js`, `cdp.rs`)
- `crates/mayi-ffi`: the core's API for the apps, through UniFFI
- `crates/mayi-devd`: development vault device with terminal prompts
- `apps/macos`: the Mac menu-bar app (SwiftPM)
- `apps/android`: the Android app (Kotlin, Compose)
- `skill/mayi`: instructions that teach an agent to use `mayi`
- `scripts/test-fill.py`: end-to-end test of `mayi fill` against a local test site and headless Chrome
- `scripts/release.sh`, `scripts/publish.py`: build and publish a release
- `Formula/`, `Casks/`: the Homebrew tap, written by `scripts/publish.py`
- `docs/releases/`: release notes
- `assets/logo`: the logo; the look is described in [docs/design-language.md](docs/design-language.md)
