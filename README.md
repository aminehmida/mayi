# Mayi

"May I?" A secrets manager for AI agents. An agent asks for a secret by name,
with the command it wants to run and a reason. A device you own decides
whether to release it, and the value is injected into the command without
entering the model's context. Website logins work the same way: Mayi types
them into the sign-in page open in the agent's browser, two-factor code
included.

Status: all five milestones of the [design](docs/design.md) are built, and
website logins after them. What
it protects and where it stops is in the [threat model](docs/threat-model.md);
how the pieces talk is in the [protocol](docs/protocol.md). Nothing has been
audited, and several things have only been tested with stand-ins for real
hardware: see [docs/manual-checks.md](docs/manual-checks.md) before trusting
it with secrets that matter.

## Install

The current release is an alpha: `v0.1.0-alpha.2`. This repository is
private, so every installer needs a GitHub token that can read it.

### Mac (Homebrew)

```sh
brew tap aminehmida/mayi https://aminehmida@github.com/aminehmida/mayi.git
brew install --cask aminehmida/mayi/mayi        # Mayi.app, and the mayi command
```

The repository is its own tap: `Formula/` and `Casks/` are read from the
default branch. Two things need to reach it as aminehmida:

- **The download** of release files goes through the GitHub API with
  `HOMEBREW_GITHUB_API_TOKEN` if it is set, or else
  `gh auth token --user aminehmida`. With the GitHub CLI signed in to that
  account, nothing else is needed, for upgrades too.
- **Cloning the tap** uses git's own credentials. If git on your machine signs
  in to GitHub as another account, tell it how to get the aminehmida token for
  URLs that name that user, once:

  ```sh
  git config --global --add 'credential.https://aminehmida@github.com.helper' ''
  git config --global --add 'credential.https://aminehmida@github.com.helper' \
    '!f() { test "$1" = get && echo username=aminehmida && echo "password=$(gh auth token --user aminehmida)"; }; f'
  ```

  It applies only to URLs that start with `https://aminehmida@github.com`, and
  stores nothing. Remove it with
  `git config --global --remove-section 'credential.https://aminehmida@github.com'`.

On a server or a Mac without the app, `brew install aminehmida/mayi/mayi-cli`
installs only the `mayi` command (macOS on Apple silicon, Linux on x86_64 or
ARM). Without Homebrew:
`gh release download v0.1.0-alpha.2 -R aminehmida/mayi -p 'mayi-*-x86_64-unknown-linux-musl.tar.gz'`.

### Android (Obtainium)

1. On GitHub, create a fine-grained personal access token limited to the
   repository `aminehmida/mayi`, with **Contents: Read-only**.
2. In Obtainium, open Settings, find the GitHub source, and paste the token.
3. Add an app with the URL `https://github.com/aminehmida/mayi`, and turn on
   **Include prereleases**: alpha releases are marked as pre-releases.

Every release is signed with the same key, so Obtainium can update the app in
place. The app needs Android 12 or later and a phone that can keep keys in
secure hardware.

### Making a release

```sh
# bump the version in Cargo.toml, apps/android/app/build.gradle.kts and apps/macos/Info.plist
scripts/release.sh                       # builds everything into dist/VERSION
git tag vVERSION && git push origin vVERSION
scripts/publish.py                       # GitHub release, then rewrites Formula/ and Casks/
git commit -am "Point Homebrew at VERSION" && git push
```

The Android signing key is `~/.android/mayi-release.jks`, with its password
in the keychain item `mayi-android-release`. Keep a copy of both somewhere
safe: a release signed with another key cannot update installed copies.

## Levels

| Level | Behaviour |
|---|---|
| 1 log | Released silently and recorded |
| 2 notify | Released at once; you are notified and can stop the command |
| 3 approve | Held until you approve |
| 4 biometric | Encrypted to a biometric-gated hardware key |

Levels 1 to 3 are rules the vault device follows; they stop a misbehaving
agent, not malware on the vault device. Only level 4 is enforced by
encryption.

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
in the Secure Enclave. Level 4 secrets need Touch ID for every unlock, and
are lost on this Mac if the enrolled fingerprints change.

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

## Other machines

A server or VM can ask a vault device for secrets without storing any.

```sh
scripts/build-linux.sh                 # static binaries, no dependencies
scp target/x86_64-unknown-linux-musl/release/mayi server:/usr/local/bin/
```

In the Mac app, open the Machines tab and choose "Pair a Machine…". Paste the
command it shows on the other machine (`mayi pair mayi1.…`). After that,
`mayi run` and `mayi list` work there as they do locally, as long as it can
reach the Mac on port 7462 over the local network or a VPN such as Tailscale.

Requests from another machine are marked as such, level 1 secrets are raised
to a notification, and a request that gets no decision within 120 seconds
(`--timeout`) fails with exit code 75. Revoke a machine from the same tab.

## More than one device

Either device can come first. The new one receives the whole vault; after
that, a change on either reaches the other the next time they can connect
(at start, every five minutes, and after each change).

- **The phone has the vault, the Mac is new:** on first launch the Mac app
  shows a QR code under "Join Your Vault". On the phone, open Devices, choose
  "Add device" and scan it (or type the code).
- **The Mac has the vault, the phone is new:** in the Mac app, Devices, "Add a
  Device…" shows a QR code. On the phone, choose "Scan code from another
  device".
- **Two Macs:** paste one Mac's code into the other, either way round.

A Mac that already started an empty vault of its own shows "Join Another
Vault…" in Devices: Mayi sets the empty vault aside and restarts into setup.

The Android app is in `apps/android`:

```sh
apps/android/build-core.sh          # Rust core for Android + Kotlin bindings
cd apps/android && ./gradlew assembleDebug
```

A phone answers requests while it is awake. To have machines wake it, deploy
the gateway in `services/wake` (it needs your own Firebase project).

## For agents

- **With a shell:** give the agent `skill/mayi/SKILL.md` (for Claude Code,
  copy the `skill/mayi` folder into `~/.claude/skills/`). It teaches the
  `mayi run` syntax and the rules: narrow requests, readable commands, never
  extract a value, a denial is final.
- **Without a shell:** `mayi mcp` is an MCP server on stdin/stdout with three
  tools, `list_secrets`, `run_with_secrets` and `fill_login`. None returns a
  value.

## If something is lost

- **Recovery key:** Devices → "Recovery Key…" creates an offline key, shown
  once. With it and the vault file, a Mac whose keys were lost (for example
  after its fingerprints changed) is restored at next launch. Anyone holding
  it and a copy of the vault file can read everything, so keep it offline.
- **A device or machine you no longer trust:** remove or revoke it in the
  app. Mayi lists the secrets it could read or was given; rotate those at
  their source, because removal cannot take back what was already seen.

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
target/debug/mayi-devd serve --listen 0.0.0.0:7462   # also accept paired machines; type `pair`
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
- `crates/mayi-core`: vault, key hierarchy, policy, grants, audit log, broker
- `crates/mayi-cli`: `mayi`, the requester, including the browser filler (`fill.rs`, `fill.js`, `cdp.rs`)
- `crates/mayi-ffi`: the core's API for the apps, through UniFFI
- `crates/mayi-devd`: development vault device with terminal prompts
- `apps/macos`: the Mac menu-bar app (SwiftPM)
- `apps/android`: the Android app (Kotlin, Compose)
- `services/wake`: the optional wake-up gateway (Cloudflare Worker)
- `skill/mayi`: instructions that teach an agent to use `mayi`
- `scripts/test-fill.py`: end-to-end test of `mayi fill` against a local test site and headless Chrome
- `scripts/release.sh`, `scripts/publish.py`: build and publish a release
- `Formula/`, `Casks/`: the Homebrew tap, written by `scripts/publish.py`
- `docs/releases/`: release notes
- `assets/logo`: the logo; the look is described in [docs/design-language.md](docs/design-language.md)
