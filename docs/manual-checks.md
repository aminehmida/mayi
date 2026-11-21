# Checks that need a person

Automated tests cover the core, the Secure Enclave device key, and the whole
request path from the CLI to the app's model. These are the parts they cannot
reach. They are collected here to be done once, at the end of the project.

## Mac app (milestone 2)

Build and open the app first: `apps/macos/build.sh && open apps/macos/build/Mayi.app`.
Below, `mayi` is `apps/macos/build/Mayi.app/Contents/Resources/mayi`.

### Touch ID (needs the Touch ID keyboard connected)

- [x] Add a level 4 secret `PROD` in the app. No fingerprint is asked for.
- [x] `mayi run -s PROD -r test -- sh -c 'echo ${#PROD}'` shows the Touch ID
      dialog with the command in its text, and prints the length after a touch.
- [x] The same command again within 5 minutes does not ask. A different
      command does.
- [x] Cancelling the dialog makes the command fail with exit code 77.
- [x] Two level 4 secrets in one command (`-s A -s B`) ask for one touch, not two.
- [x] With the keyboard disconnected, the request fails cleanly instead of hanging.
      (Not applicable: the MacBook's Touch ID is built in.)

### Windows

- [x] A level 3 request shows the approval panel above other apps without
      taking keyboard focus: typing continues to go to the app you were in.
- [x] Each button works on the first click: Deny, Allow Once, and both
      entries under Allow for This Session.
- [x] Pressing Return in another app does not answer the prompt.
- [x] A level 2 request shows a notice at the top right; Stop kills a
      long-running command (`-- sleep 30`) and the notice says it was stopped.
- [x] Secrets window: add, edit rules without re-entering values, replace
      values, delete. The Activity tab lists what happened.
- [x] Quitting and reopening the app keeps the secrets.

## Other machines (milestone 3)

Automated tests paired the CLI with the app's model over loopback, and a
static Linux binary in a container with the dev daemon on the Mac, with a
packet capture showing no plaintext. Still to do by hand:

- [x] In the app, Machines → "Pair a Machine…" asks for Touch ID, then shows
      the command. Cancelling Touch ID shows "Pairing needs your fingerprint."
      (Since alpha.6 the app asks once when it opens, not per action.)
- [x] The first pairing opens TCP port 7462. If the macOS firewall is on, it
      asks whether Mayi may accept incoming connections: allow it.
      (Reached over Tailscale from another Mac.)
- [x] Pair a real machine over Tailscale: copy `mayi` to it
      (`scripts/build-linux.sh`), paste the command, and check it appears in
      the Machines tab. The token lists this Mac's IPv4 addresses, including
      its Tailscale address.
- [x] From that machine, a level 1 secret shows a notice naming the machine,
      and a level 3 secret shows the approval panel with "Another machine".
- [x] Revoke the machine; its next request fails with "this machine is not paired".
      (Found: alpha.7 kept retrying and blamed a timed-out address; alpha.8
      stops at once and says the machine is not paired.)
- [x] With the Mac asleep or the app closed, a request from the machine fails
      within a few seconds with "no vault device reachable".
      (Since alpha.4 it waits for any of your devices instead; the phone answers.)

## Several devices and Android (milestone 4)

Automated tests cover sync and enrolment in the core, two app models syncing
on the Mac, and the Android app's logic on a desktop JVM. The Android app
was also run on an emulator (Android 15, with a fingerprint enrolled) against
a dev daemon playing the Mac, driven through its real screens:

- joined the vault from an invitation and received the secrets;
- served a paired machine at all four levels: notice with a working Stop,
  approval and denial, fingerprint prompt accepted and cancelled;
- raised a notification for an approval while in the background;
- synced a secret added on the phone back to the other device;
- kept its vault and resumed serving after being killed and restarted.

An emulator has no secure hardware and never sleeps, so these remain:

### On a real Android phone

- [x] `apps/android/build-core.sh && cd apps/android && ./gradlew installDebug`.
      On a real phone the keys must land in secure hardware; the app refuses
      to set up otherwise. (On the emulator a debug build accepts software
      keys, which is the only reason it could be tested there.)
      (Installed from the release APK; level 4 works with the phone's fingerprint.)
- [x] Join the Mac app's vault by scanning the QR code from Devices → "Add a
      Device…". The emulator test pasted the text and used the dev daemon,
      so the scanner and the Mac app's side of this are untested.
- [ ] After adding or removing a fingerprint on the phone, level 4 secrets
      can no longer be unlocked on it (by design).
- [x] The phone still answers after several minutes with the screen off.
      (See "Reaching your devices without Google" below.)
- [ ] The emulator, its Android 15 image and the virtual device `mayi` take
      about 6 GB. Remove them when no longer needed with
      `sdkmanager --uninstall emulator "system-images;android-35;google_apis;arm64-v8a"`
      and by deleting `~/.android/avd/mayi.avd` and `~/.android/avd/mayi.ini`.

## Agents, recovery and revocation (milestone 5)

Automated tests cover creating a recovery key and recovering after the
device keys were deleted, and the rotation lists. Still to do by hand:

- [x] Copy `skill/mayi` to `~/.claude/skills/` and ask Claude Code to do
      something that needs a secret. Check it uses `mayi run` with a sensible
      reason, and that it does not retry after you deny.
- [x] The MCP server (`mayi mcp`) was removed in alpha.8: agents use the
      shell, and an MCP tool would give apps without one a way to run
      commands.
- [x] In the Mac app, Devices → "Recovery Key…" (Touch ID) shows a key once.
      Store it for the next check.
- [x] Recovery for real (found: the key field wrapped and Command-V did not
      paste, as the app had no Edit menu; fixed for alpha.8). Quit the app, move
      `~/Library/Application Support/Mayi/keys` aside, relaunch. The app
      should say it can no longer open the vault and accept the recovery key.
      Level 4 secrets should work again afterwards.
- [ ] Removing a device and revoking a machine each show which secrets to rotate.
      (Revoking: done. Removing a device: not tried on your real phone.)
- [x] The Android app has no screen for the recovery key or for recovering;
      on a phone, recovery means joining again from another device.
      (Out of date: since alpha.3 the phone makes recovery keys; recovering a phone means joining again.)

## Website logins

`scripts/test-fill.py` signs in to a local test site in headless Chrome:
one-page, three-page with a two-factor code, a code in six boxes, a
script-driven form, shadow DOM, a decoy field, a form that only a button
submits, and the refusals (password change form, another host, a login given
to a command). With `MAYI_PLAYWRIGHT_DIR` set it also checks, with
Playwright's own snapshot, that no password is left where an agent's browser
tool would read it. The real Mac app (with Secure Enclave keys) served a
sign-in, and on the emulator the phone approved a three-page sign-in and a
level 4 one with a fingerprint. Two public practice sites were signed in to.
Still to do by hand:

- [x] Sign in to a real account of yours that has two-factor, for example
      GitHub: add the login in the app (scan or paste the two-factor key when
      you set it up), then `mayi browser` and `mayi fill`.
- [x] The same from a real agent: Claude Code with Playwright MCP started as
      `npx @playwright/mcp@latest --cdp-endpoint http://127.0.0.1:9222`, the
      skill installed, and a task that needs the sign-in.
- [x] Level 4 sign-in with Touch ID on the Mac, and with a real phone.
- [x] The QR scanner for a two-factor key on a real phone.
- [ ] `mayi fill` on a Linux machine or container with its own Chromium. I
      built the static binaries, but Docker Desktop did not start for me (it
      seemed to wait on something in its window, which is still open).
- [ ] Decide whether `mayi fill` should also work with your everyday Chrome
      through a Mayi browser extension, which tools like Claude in Chrome
      would need. Not built.

## Design

Both apps now use their platform's own components (`docs/design-language.md`).
The Mac main window was captured as a real window in tests, and the Android
app was run on the emulator. Not yet tried by hand on the Mac:

- [x] The approval panel: the "Allow for This Session" pull-down opens and
      works even though the panel never takes keyboard focus.
- [x] The toolbar buttons (edit, delete, add) and double-click to edit in the
      Secrets list.
- [x] The menu-bar icon (the logo as a template) at real size, and the app
      icon in the Dock and Finder.
- [x] On Android, the launcher icon and the themed (monochrome) icon.

## The first release (v0.1.0-alpha.1)

Built by `scripts/release.sh` and published by `scripts/publish.py` to
`aminehmida/mayi` (private at first, public since alpha.3). The release APK was installed on the
emulator and starts (it then refuses to create a vault, as it should without
secure hardware). Still to do by hand:

- [ ] Back up the Android signing key `~/.android/mayi-release.jks` and its
      password (keychain item `mayi-android-release`). Losing either means
      the next release cannot update installed copies.
- [x] `brew tap` and `brew install --cask aminehmida/mayi/mayi`, then open
      Mayi from Applications.
- [x] Obtainium on your phone: the repository URL, "Include prereleases",
      install, and later an update.

## Joining a vault from either side (v0.1.0-alpha.2)

Tested: the core in both directions over real connections, the Mac setup
model joining by showing a code, the phone adding a device by code on the
emulator (with a fingerprint for a level 4 secret, the dev daemon playing
the new device), and refusals of codes used the wrong way round. Still to do
by hand:

- [x] Your case: on the Mac, Devices, "Join Another Vault…", then on the phone
      Devices, "Add device", scan the Mac's code. The Mac should open with the
      phone's secrets. (This needs both updated to alpha.2.)
- [ ] The Mac's first launch with no vault shows the setup window, and
      "Create New Vault…" still works.
- [x] Scanning with the phone's camera (the emulator could only type the code).
      (Done for a two-factor key.)

## Fixes from the experience review (v0.1.0-alpha.3)

Tested: approvals "for this session" now hold across separate commands from
one Claude Code session (two commands from this session reported the same
`claude (pid …)`); a paired machine keeps reaching a device through an
address the device does not announce; on the emulator, the phone showed a
join code and was added, paired a machine, edited a secret, made a recovery
key, removed a device, warned with notifications off, served again after a
reboot without being opened, and set aside an empty vault into setup; the
Mac picks the password-accepting level 4 key for a new vault (tested on the
real Secure Enclave). Still to do by hand:

- [ ] On the MacBook, with the lid closed on a display: Add a Device,
      Pair a Machine and a level 4 secret each accept your password.
- [x] Mayi appears in the Dock while its window is open and leaves it when
      the window closes; opening Mayi from Spotlight shows the window; it is
      in System Settings, General, Login Items, and "Open at Login" in its
      menu turns that off.
- [x] In a real Claude Code session, "Allow for This Session" covers the
      next commands, and the prompt names the session `claude (pid …)`.
- [ ] On the phone: restart it and, without opening Mayi, use a paired
      machine; the QR codes it shows scan from another phone.

## Reaching your devices without Google

Automated tests run the real `mayi` against two vault devices: a request
waits for a device that comes online later, gives up after `--wait` naming
each device and when it was last reached, asks the device in use first and
the other only after 30 seconds, takes the first answer and takes the other
prompt down, times out from when a device had the request, and, from a
machine with a vault device, pairs itself through the socket and reaches the
other device.

On the emulator: the APK holds no Firebase, Play services or ML Kit code;
setup asks to run in the background and the banner offers it until allowed;
in forced deep Doze with the screen off a request from this Mac reached the
phone, raised the notification, and was approved; it also reached it without
the battery exemption (stock Android keeps a foreground service's network);
the restart check brought back a stopped service from the background; each
connection holds the phone awake for 30 seconds; the camera scanner opens
(decoding is tested on generated codes). Still to do by hand:

- [ ] Real phone over Tailscale, screen off for an hour or more: a request
      from a machine still notifies, and the approval goes through.
- [ ] Scan a join code or invitation with the new scanner on a real phone.
- [ ] After a day, Mayi's battery use in Settings, Battery is negligible.
- [ ] On a Samsung or Xiaomi phone, if you have one: with Unrestricted set
      and the maker's own setting from dontkillmyapp.com, Mayi keeps serving.
- [x] An agent on the MacBook while you are away with the phone: the phone
      asks; while you are typing on the Mac, only the Mac asks.
- [x] Answering from a phone whose screen was off: pulling down the
      notification used to drop the request on both devices (found in
      alpha.6, fixed in alpha.7, retested).
- [x] In Claude Code, a long `mayi run` started in the background with a
      75-minute timeout wakes the agent when you answer.

## Viewing secrets and single copies

Automated tests cover the copy count (one copy until a sync, two after,
back to one when the other device is removed, known on both sides), showing
values only after the owner confirms, logging each view without the value,
and saving shown values unchanged as a rules-only change. On the emulator the
dot, the fingerprint prompt, the shown value with its copy button, and the
"You viewed" entry in Activity were checked. Still to do by hand:

- [x] On the MacBook: Show Values asks for Touch ID (or your password) for a
      level 1 to 3 secret, and only the Secure Enclave prompt for level 4.
      (Found: on level 4 the eye needed a second press; fixed for alpha.7.)
- [x] A copied value is gone from the clipboard a minute later, on the Mac
      and on a real phone. (On Samsung phones it stays in Samsung's own
      clipboard history, which One UI keeps outside any app's reach and which
      ignores the sensitive flag; left as is, by your choice.)
- [x] Add a secret on the Mac: its orange dot goes once the phone has synced,
      and the phone shows no dot for it.
- [x] Opening Mayi asks once (Touch ID or password on the MacBook, a
      fingerprint on the phone); after that, showing values and pairing ask
      nothing until the Mac locks or the phone's screen goes off. Opening the
      phone app from a request notification does not ask.
- [x] A shown login's two-factor code matches your authenticator app, and the
      site accepts it; replacing the key by pasting a QR code on the Mac and
      by scanning on a real phone both work.

## Folders, search, rotation warnings and shared activity (v0.1.0-alpha.8)

Automated tests cover activity reaching every device (in batches of 300,
none sent to a device from before alpha.8), rotation notes set by removing a
device or revoking a machine, synced, cleared by a new value and dismissed,
and folders kept through rule changes, in Rust, Swift and on the JVM. On the
emulator: search and the folder filters, folder suggestions, the ⚠️ row and
its card with Dismiss after revoking a machine, the amber "From doze-test"
chip on a request, a request notification opening the Requests tab from the
Secrets tab, and the camera picture inside the scanner opened from the edit
sheet. On the Mac, snapshots of the folder sidebar, the ⚠️ row and the
editor scrolled to its warning. Still to do by hand:

- [ ] Mayi asks for Touch ID or your password as soon as it opens, without
      opening its window first.
- [ ] The recovery key field stays on one line, and Command-V pastes into it.
- [ ] A request on the Mac shows the machine's name in an orange capsule,
      large enough to notice; the phone shows the same.
- [ ] Tapping a request's notification on your phone opens the request,
      whichever tab Mayi was on.
- [ ] Scanning a two-factor QR code from the phone's edit sheet shows the
      camera picture.
- [ ] Revoke a machine that was given a secret: the secret shows ⚠️ on both
      the Mac and the phone; its warning explains what to do; saving a new
      value clears it everywhere; Dismiss clears it too.
- [ ] Put secrets in folders on one device: the other shows the same
      folders after a sync. Search finds a secret by name, website or folder.
- [ ] Activity on the phone lists a request answered on the Mac ("answered
      on …"), and the Mac lists one answered on the phone, after a sync. A
      prompt taken down because the other device answered does not appear
      twice.

## The program's full path and sealed keys (v0.1.0-alpha.9)

Automated tests cover a program named like an expected one in a temporary
folder first in PATH (not looked up, nothing asked), the same program given
by path (asked, shown by its full path), an expected command matched by name
for an ordinary program, the command's PATH and variables cleaned, and key
blobs sealed with a keychain key and refused without it. Checked on this Mac:
another program could use a Secure Enclave key blob before; a keychain item
made by one program is refused to another; code loaded into a program reads
its items unless the program uses the hardened runtime. Still to do by hand:

- [ ] After installing alpha.9, macOS asks once whether Mayi may use its
      keychain item: allow it with your password. The vault opens, level 4
      works, and `~/Library/Application Support/Mayi/keys` holds only
      `.sealed` files.
- [ ] The next update asks once again, and nothing else changes.
- [ ] Requests from Claude Code on the MacBook show the program's full path
      in the panel and in Activity, and secrets with expected commands
      (`gh *`) still skip the prompt.
- [ ] A tool only in the project (`node_modules/.bin`) fails with "give its
      path", and works when given as `./node_modules/.bin/…`.

## Providers and AWS sign-ins (v0.1.0-alpha.10 and alpha.11)

Automated tests cover a secret of a newer kind listed, synced and kept
intact but never opened; AWS profiles at their own levels (silent, approved,
fingerprinted), approvals that do not cross profiles, a remote level 1
profile notifying once per session, an ended session signed in again while
the request waits, a replaced refresh token kept, loosening a profile or a
secret asking for the fingerprint, AWS CLI profiles written and replaced,
and `PROFILE/FIELD` requests checked. AWS itself is a stand-in in those
tests. Still to do by hand, against a real portal:

- [ ] Secrets → Add → AWS Sign-In suggests your portals; the browser opens
      AWS's page with the code filled in, and the page names Mayi.
- [ ] After allowing, every account and role is listed with the suggested
      levels; saving removes the AWS CLI's files for that portal from
      `~/.aws/sso/cache` and adds `NAME-PROFILE` profiles to `~/.aws/config`.
- [ ] `aws sts get-caller-identity --profile NAME-production-ro` answers at
      once; a level 4 profile asks for Touch ID, with the AWS command in the
      dialog; a level 3 one shows the approval panel with the AWS command.
- [ ] From Claude Code, an approval "for this session" covers the next
      `aws` commands of that session.
- [ ] Lowering a profile's level, or adding a role with Find More Roles, asks
      for Touch ID even with the window unlocked; cancelling changes nothing.
- [ ] After AWS ends the session (8 hours), the next request shows "Sign in
      to NAME again?"; signing in lets the waiting command finish.
- [ ] The phone answers a request for a level 1 and a level 4 profile when
      the Mac is away (fingerprint for level 4).
- [ ] From a paired machine, `mayi aws setup` writes the profiles there, and
      a level 1 profile notifies once per agent session, not per command.
- [ ] Running `aws sso login` again shows a warning on the sign-in, and
      Remove deletes the file.

## Decisions waiting for you

- [x] The repository `aminehmida/mayi` is public.
- [ ] The name "Mayi" is unchecked for trademark, domain and package conflicts.
- [ ] No licence has been chosen.
- [x] Level 4 on the Mac accepts Touch ID, an Apple Watch or the login
      password (your choice, alpha.3), and so does pairing; fingerprint
      changes no longer lock level 4 secrets on a newly set-up Mac.
- [ ] Pairing tokens are long text to paste, not a short code to type. A
      short code would need an extra cryptographic library (a PAKE).
- [ ] The vault key is never rotated, so removing a device or replacing the
      recovery key cannot revoke access to secrets below level 4 that they
      could already read. Rotating the vault key would close that; it is a
      sizeable change (every device must receive the new key).
- [ ] Devices do not find each other by mDNS yet; they use the addresses each
      device publishes. That is reliable over Tailscale and on a network
      where at least one side keeps its address.
- [ ] On Android the biometric key stays usable for 10 seconds after a
      fingerprint, because binding each single use to a fingerprint needs
      Android 15. The Mac's key is per use.
- [x] The phone can now pair machines and add, remove and invite devices.
- [ ] The app does not start at login and is signed ad hoc, which is enough to
      run it locally but not to distribute it.
