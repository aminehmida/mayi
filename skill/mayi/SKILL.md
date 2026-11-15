---
name: mayi
description: Use the user's secrets (API keys, tokens, passwords) in commands, and sign in to websites with the user's logins, without ever seeing the values, through the `mayi` CLI. Use whenever a command needs a credential, when an environment variable holding a secret is missing, when a website in your browser asks you to sign in, or when the user mentions Mayi. Never ask the user to paste a secret or password into the conversation if Mayi is available.
---

# Using secrets with Mayi

Mayi is the user's secrets manager. You ask for a secret by name; the user's
device decides whether to release it; the value goes straight into the
command's environment. You never see it, and you should never try to.

## Find out what exists

```sh
mayi list
```

Each line is `NAME`, a level, and the field names. A line ending in
`login for github.com` is a website login: it can only be typed into that
website with `mayi fill` (below), never given to a command. Levels:

| Level | What happens when you ask |
|---|---|
| 1 | Released at once and logged. |
| 2 | Released at once; the user is notified and can stop your command. |
| 3 | The user must approve. They see your exact command and your reason. |
| 4 | The user must confirm on their device: a fingerprint, or on a Mac Touch ID or their password. |

## Run a command with secrets

```sh
mayi run -s GITHUB_TOKEN -r "List open pull requests for the release notes" -- gh pr list
```

- `-s NAME` puts the secret in an environment variable of the same name.
  `-s ENV=NAME` chooses the variable; `-s ENV=NAME/FIELD` picks a field other
  than `value`, such as `-s PGUSER=prod_db/user -s PGPASSWORD=prod_db/password`.
- `-r` is required. Write one honest sentence saying what you are doing and
  why it needs the secret. The user reads it when deciding, and it is logged.
- Everything after `--` is the command, run directly without a shell. For
  pipes or variable expansion, run a shell yourself:
  `mayi run -s API_KEY -r "..." -- sh -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com/v1/items'`
- The command's own exit code is returned. Output passes through with any
  secret value replaced by `[masked]`.

## Sign in to a website

You need a browser tool that drives a browser with a debugging port on this
machine, such as Playwright MCP started with `--cdp-endpoint
http://127.0.0.1:9222`. If none is running, `mayi browser` starts one and
prints how to connect your tool to it.

1. Open the site's sign-in page with your browser tool.
2. Run, with the login's name from `mayi list`:
   ```sh
   mayi fill github -r "Download this month's invoice from the billing page"
   ```
   Mayi reads the page's address from the browser, checks it is one of the
   login's websites, asks the user if needed, types what the page asks for
   (username, password or two-factor code), and submits.
3. Look at the page. If it now asks for something else (a password after the
   username, or a code), run the same `mayi fill` again. One approval covers
   the next pages for two minutes.

- Never type a password or a code yourself, and never read a password field
  or run scripts that look at what was typed.
- If Mayi says it found no field, name it: `--username-selector`,
  `--password-selector` or `--code-selector` take a CSS selector. If the form
  needs a button clicked rather than Enter, pass `--submit-selector`.
- Several tabs on the same site: `--tab TEXT` picks the one whose address or
  title contains the text.
- Mayi refuses sign-up and password change forms, pages on other websites,
  and plain http. That is not something to work around.
- SMS or email codes, push approvals and security keys are not in Mayi: ask
  the user.

## When the user takes a while to answer

The request goes to all of the user's devices and waits: up to an hour for
one of them to be reachable (a phone may be out of range; `--wait SECONDS`),
then up to 15 minutes for the answer (`--timeout SECONDS`). `mayi` prints a
line only when something changes, such as
`mayi: asked Pixel; waiting up to 15 min for your answer`.

- Waiting costs nothing. Do not poll, and do not retry in a loop.
- If your tool cuts off long commands, run `mayi` in the background and let
  it tell you when it ends. In Claude Code: the Bash tool with
  `run_in_background: true` and `timeout: 4500000` (75 minutes). Carry on with
  other work meanwhile.
- If you need to know quickly, pass shorter limits, such as
  `--wait 60 --timeout 120`.

## Rules

1. **Ask for the narrowest thing.** Request only the secrets the command
   needs, and run only the command that needs them. Do not wrap a whole
   script or a long shell session in one `mayi run`.
2. **Keep the command readable.** The user approves what they can read. Prefer
   `mayi run ... -- terraform apply` to an opaque `sh -c` blob, and never
   hide what a command does.
3. **Never extract a value.** Do not echo, print, encode, write to a file, or
   send a secret anywhere except to the tool it is for. Do not try to defeat
   the masking. If you believe you need the raw value, stop and tell the user.
4. **Reuse the same command.** An approval often covers the same command
   again in the same session, so repeating it exactly avoids a new prompt.
   Changing the command asks again.
5. **A denial is an answer.** If the user denies a request, do not retry it or
   rephrase the reason. Say what you were trying to do and ask how to proceed.

## Exit codes from mayi itself

| Code | Meaning | What to do |
|---|---|---|
| 77 | Denied by the user, the fingerprint check failed, or the secret cannot be used that way (a login with `mayi run`). | Do not retry. Tell the user. |
| 75 | A device showed the request but nobody answered in time (default 15 min; `--timeout SECONDS`). | Tell the user a request is waiting; retry once if they ask. |
| 69 | None of the user's devices could be reached in time (default 1 hour; `--wait SECONDS`), or this machine is not paired. The message says when each device was last reached. | Tell the user; they may need to open Mayi on their phone, connect Tailscale, or run `mayi pair`. |
| 65 | `mayi fill` could not fill the page: no sign-in field, another website, a refused form, or the page changed. | Read the message; fix the page or the selector, or ask the user. |
| 64 | Bad arguments, or `mayi fill` given a secret that is not a login. | Fix the command. |

Any other code is the command's own.

## Without a shell

If you cannot run commands but have MCP tools, `mayi mcp` offers the same
operations as `list_secrets`, `run_with_secrets` and `fill_login`.
