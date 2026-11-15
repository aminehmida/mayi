# Design language

Mayi should look like it shipped with the computer. It asks for a security
decision many times a day, and a prompt that looks like the system's own is
one people read the way they read the system's own. So the rule is: use the
platform, and add almost nothing.

## The rule

- **Mac:** system fonts, system controls, system colours and materials.
  A standard window with a sidebar and a unified toolbar; grouped forms;
  SF Symbols. Controls take the user's accent colour. Light and dark come
  from the system.
- **Android:** stock Material 3. Its type scale, shapes, top app bar,
  navigation bar, list items, cards, sheets and buttons, with Material icons.
  One colour scheme, built from the logo's blue.

Nothing is custom unless it has to be. There is no bundled typeface, no
bespoke button, no decorative rule or badge.

## The logo

A speech bubble with a keyhole: a request, for access. That is the whole
product. It is one flat shape, so it works at 16 points in the menu bar and
at 1024 in the Dock.

- Source: `assets/logo/mayi-glyph.svg`, on a 24-unit grid.
- Colour: `#1F4FD8`, on a white plate for the app icon; the system's
  template colour in the menu bar.
- The same path is drawn in `Theme.swift` (`MayiGlyph`) and in
  `ic_mayi_glyph.xml` / `ic_launcher_foreground.xml` on Android.
  `apps/macos/make-icon.swift` builds the Mac icon from the SVG.

The blue belongs to the logo. On the Mac it appears nowhere else. On Android
it seeds the colour scheme, because Material expects one.

## What the app adds to the platform

Three things, each because the task needs it:

1. **The command is set apart.** Wherever a command, token or key appears it
   is monospaced, selectable, and sits in a filled well. On a request it
   comes directly under the question.
2. **Claims are boxed and labelled.** The reason, agent, session and folder
   come from the requester and are not checked. They are grouped under
   "Stated by the requester, not verified", below the command, in ordinary
   text.
3. **Levels have a symbol and a name.** Log (a list), Notify (a bell),
   Approve (a raised hand), Biometric (a fingerprint). No colour coding.

## Requests

- Laid out like a system permission prompt: app icon and question, the
  command, the secrets, the claims, a caution, then the buttons.
- The question names the secret: "Allow this command to use GITHUB_TOKEN?"
- A sign-in names the website instead: "Allow signing in to github.com?",
  with the origin in the well, which fields will be typed, and the caution
  "Once signed in, the agent can act as you on this site." Its session
  choice is a single button, since there is no "any command".
- A login is marked with a globe in lists and prompts; a secret with a key.
- No default button: Return does nothing. Escape denies.
- The panel does not take keyboard focus.

## Words

- Buttons say what they do and keep that name everywhere: "Allow Once",
  "Deny", "Stop".
- Title case on the Mac, sentence case on Android, as each platform does.
- Red means stop, deny or remove, and nothing else.

## Tried and dropped

- A dark green ground with a brass accent. Costume, not class, and wrong for
  a security tool.
- A monochrome "editorial" look: a serif for titles, italics for claims,
  a row of diamonds for levels, hairline rules. It read as generated.
- Request cards that stayed dark in light mode.
- A logo of four diamonds. It said nothing about the product.
