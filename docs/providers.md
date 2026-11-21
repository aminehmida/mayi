# Providers: beyond stored secrets

> A plan. Step 1 is built; the rest is not. Where the code differs, the code
> is right.

Mayi releases values it stores. Some credentials cannot work that way: an
AWS SSO token is rewritten by the AWS CLI as it refreshes, and anything a
command can use from a file on the agent's machine, the agent can read. The
answer is to keep the long-lived credential on the vault device and release
only what is derived from it: short-lived keys, a token added to a request,
a signature.

## Two questions about every secret

| | Where the values go (destination) | What produces them (source) |
|---|---|---|
| Secret | a command's environment | stored values |
| Website login | a sign-in form | stored values; the two-factor key is released as the current code |
| AWS SSO | a command's environment | the vault device fetches role credentials with its SSO token |

In the code these are `Destination` (still stored as `kind`, with its old
values `secret` and `login`) and `Source` (left out of the record when the
values are stored) in `model.rs`. Each source has a provider in
`provider.rs`. Keeping them apart means AWS SSO is a new source and
provider and nothing else: levels, prompts, grants, allowlists, the activity
log, output masking, sync and `mayi run` stay as they are.

## Providers

Rust code in `mayi-core`, compiled into every vault device and reaching the
apps through `mayi-ffi`. Not plugins: the vault device holds every key, the
worst place for code from elsewhere.

A provider can:

1. **Sign in**: describe the steps ("ask for these fields", "open this URL
   and wait") so the apps draw them without a screen per provider.
2. **Check** what is about to be stored.
3. **Release**: turn the stored state into the values a request asked for,
   with an expiry.
4. **Refresh** its stored state silently, and say when the owner must sign
   in again.
5. **Offer targets**: choices inside one secret, each with its own level,
   such as an AWS read-only role at level 1 and an admin role at level 4.

Step 1 built the `Provider` trait with check and release, for stored values
and logins. Sign-in, refresh, expiry and targets come with AWS SSO.

Planned: AWS SSO and AWS IAM keys (step 2), RDS IAM database passwords
(step 4), then gcloud, Azure, kubectl OIDC, GitHub App and OAuth refresh
tokens (step 6).

## Destinations

- **Command environment** and **sign-in form**: today.
- **Temporary file**: a kubeconfig or service-account JSON, deleted when the
  command ends.
- **Local proxy**: the command holds a placeholder; the token is added only
  to requests for the secret's hosts.
- **Signing**: an SSH agent; the key never leaves the device, only
  signatures do.

## How the main flows work

### AWS SSO

Sign-in, once per portal session:

1. The owner adds an AWS SSO secret on the vault device: start URL, region.
2. The device registers with AWS and opens the sign-in page in its own
   browser. The owner signs in and allows it.
3. AWS returns an access token and a refresh token. They stay in the vault.

Each run:

1. `mayi run --aws work/111122223333:ReadOnly -r "…" -- aws s3 ls`
2. `mayi` sends the request (target, command, reason). No secret yet.
3. The device applies the target's level. The owner sees the `aws` command.
4. The device calls `GetRoleCredentials` with its token and gets temporary
   keys for that one role.
5. Only those keys go back. `mayi` puts them in the environment
   (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) and
   masks them in the output.

The device refreshes the token silently, and asks the owner to sign in
again when the portal session ends. Nothing is written to `~/.aws` on the
agent's machine.

Limits: role keys last the permission set's session length (1 to 12 hours)
and an approved command can see them. The agent can still start its own
`aws sso login` and wait for the owner to click Allow: approve AWS sign-ins
only when Mayi started them.

### Local proxy

1. `mayi run --proxy -s OPENAI_KEY -r "…" -- python script.py`
2. `mayi` starts a proxy and a certificate authority for this run only, and
   points the command at them (`HTTPS_PROXY`, `REQUESTS_CA_BUNDLE`,
   `AWS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`).
3. The command's environment holds a placeholder.
4. A request to one of the secret's hosts gets the placeholder replaced;
   requests elsewhere never get the token.
5. With AWS: the command holds dummy keys and the proxy signs each request
   again (SigV4) with the real ones.

Limits: HTTPS only. Clients that pin certificates refuse the proxy, and Go
programs on macOS ignore `SSL_CERT_FILE`. The command can still use the API
as the owner; it cannot take the token away.

### Signing

1. `mayi ssh-agent` gives the agent an `SSH_AUTH_SOCK`.
2. `ssh` or `git` asks for a signature; `mayi` forwards it to the device.
3. The device asks according to the key's level, naming the host (OpenSSH
   tells the agent which host it is connecting to).
4. The Secure Enclave or Android keystore signs; only the signature returns.

Keys are P-256, the type both support; GitHub and GitLab accept it. Git
commit signing works through the same agent, though the prompt cannot show
the commit: the agent receives only a hash of it.

## Mixed versions

A Mac and a phone update separately, so every step must keep working with a
vault shared with an older device:

- New metadata fields are optional and left out when unused, so an older
  device reads the same records it did before.
- A device keeps the fields it does not know when it edits a secret, so it
  never strips what a newer version added.
- A secret of a destination or source a device does not know is listed and
  synced, but never released or opened there, and its rules cannot be
  changed there.
- A new source binds its name into the encryption of the values, as logins
  do, so a device that does not know it cannot open them either.

The first three hold from step 1 on. A device older than step 1 fails to
list or sync a vault holding a destination it does not know, and drops a
source it does not know when it edits that secret, leaving it unopenable.
Every device should run step 1 before any later step ships.

## Steps

Each step is one release, from 0.1.0-alpha.10, and something the owner can
use every day.

| Step | Ships | Tested with |
|---|---|---|
| 1 | Destination and provider split; providers become a Rust trait; the two-factor code moves into one. Older devices tolerate unknown destinations and providers. No visible change. | Existing tests, `scripts/test-fill.py`, daily use |
| 2 | AWS SSO provider (sign-in on the device, a level per role); AWS IAM keys to 15-minute assumed-role keys | Real AWS accounts, with `~/.aws/sso/cache` deleted |
| 3 | `mayi ssh-agent` with Secure Enclave keys on the Mac | `ssh` to a server, `git push`, commit signing |
| 4 | RDS IAM database passwords; the temporary file destination | `psql` against RDS; a tool that reads a config file |
| 5 | Local proxy: token injection, then AWS re-signing | `curl` and Python, then the `aws` CLI with dummy keys |
| 6 | gcloud, Azure, kubectl OIDC, GitHub App, marked experimental | Free personal accounts, or early users |

Each step adds an end-to-end test like `scripts/test-fill.py`: a local
`sshd` for signing, a local HTTPS server for the proxy. Signing on Android
waits for a real phone, since the emulator keeps keys in software.
Experimental providers sit behind a switch in the apps and are listed in
[manual-checks.md](manual-checks.md) until tested against real accounts.
