# Keytap

Press a key in any Windows program and Keytap types your Bitwarden login
there: game launchers, desktop apps, remote desktops, anything with a
username box. Part of the same suite as Homework Hub, Grabbit and Dropshift.

Keytap reads your vault through Bitwarden's own command-line tool, which
comes with it. It never talks to Bitwarden's servers itself, never saves a
password, and never writes to your vault.

## Installing

Through [Hanami](https://github.com/blossqt/hanami), the suite's launcher:
click **Install** on Keytap's card, and Hanami keeps it up to date. Or
download `Keytap-<version>-win64.zip` from the
[latest release](https://github.com/blossqt/keytap/releases/latest), unzip it
somewhere of your own and run `Keytap.exe`.

## Using it

Keytap sits in the tray. Click into the username box of a program, then press:

| Hotkey | What it does |
|--------|--------------|
| **Ctrl+Alt+A** | Types the login that goes with this program - username, Tab, password, Enter. If Keytap is not sure which login, it asks. |
| **Ctrl+Alt+Shift+A** | Always asks: search your vault and choose. |

If the vault is locked, Keytap asks for your master password first, then
carries on typing into the window you were in.

In the list, **Enter** types it all, **Ctrl+U** just the username, **Ctrl+P**
just the password, **Ctrl+T** the verification code. Right-click a login to
copy from it instead (a copied password is kept out of Windows' clipboard
history and cleared after 30 seconds). Tick **Always use this login in…**
(Alt+A) and Keytap will not ask again for that program.

After typing a login that has an authenticator key, Keytap copies its current
verification code, ready to paste on the next screen, as Bitwarden does.

## The pop-up in login boxes

Like Bitwarden's extension in a browser, Keytap lists your logins under a
login box as soon as you click into it - a password box, or a text box with a
password box beside it. Click a login and it is typed in. Clicked into the
password box, only the password (and Enter) is typed. The pop-up never takes
the keyboard, so the cursor stays where it was; Esc or clicking elsewhere
hides it. While the vault is locked it offers to unlock instead, then lists
the logins.

It works in ordinary Windows programs, Store apps, and Chromium/Electron apps
(Discord, Slack, many game launchers). It stays out of browsers, where the
Bitwarden extension does this. Games that draw their own screens don't tell
Windows where their boxes are, so nothing can pop up there - the hotkey still
works. **Don't pop up in…** at the bottom of the list keeps it out of one
program; the tray menu's **Pop up in login boxes** turns it off altogether.

Keytap learns which box has the keyboard from Windows' focus notices, and
asks a program about its boxes (through UI Automation, the interface screen
readers use) only once it has passed those filters. Asking makes
Chromium-based apps switch on their accessibility support, which costs them a
little memory and CPU.

## Telling Keytap which login goes where

Keytap types without asking only when it is sure:

- **Remembered** - you ticked *Always use* in the list. This is kept on this
  PC only (Settings → Remembered programs). Browsers, terminals and remote
  desktops are remembered per window title rather than per program.
- **A URI on the login**, set in Bitwarden on any device:
  - `app://steam.exe` - this program (a full path works too)
  - `title://Sign in to Steam` - a window whose title contains that text
    (`*` and `?` work as wildcards)

Otherwise Keytap suggests logins whose name or website matches the program or
window title, and lets you choose. It never types a guess: a password typed
into the wrong window could end up in a chat box.

## What gets typed

The default is `{USERNAME}{TAB}{PASSWORD}{ENTER}` (Settings → Typing). A
login with no username just gets `{PASSWORD}{ENTER}`. A login can have its
own sequence: add a custom field named `autotype`, for example
`{USERNAME}{ENTER}{DELAY 1500}{PASSWORD}{ENTER}` for a two-page sign-in.

| Placeholder | Types |
|-------------|-------|
| `{USERNAME}` `{PASSWORD}` | the login's |
| `{TOTP}` | the current verification code |
| `{FIELD:name}` | a custom field |
| `{TAB}` `{ENTER}` `{SPACE}` `{BACKSPACE}` `{DELETE}` `{ESC}` `{UP}` `{DOWN}` `{LEFT}` `{RIGHT}` `{HOME}` `{END}` `{PGUP}` `{PGDN}` `{INSERT}` `{F1}`-`{F16}` | that key; `{TAB 3}` presses it three times |
| `{CLEARFIELD}` | empties the field first |
| `{DELAY 500}` | waits half a second |
| `{DELAY=50}` | 50 ms between keys from there on |
| `{{}` `{}}` | a brace |

Typing stops at once if another program comes to the front. Some games,
remote desktops and virtual machines read keys rather than characters: turn on
**Type as key presses** in Settings for those.

Windows does not let an ordinary program type into one running as
administrator. Keytap says so and offers to copy the password instead.

## Signing in

The first time, Keytap opens Bitwarden's own sign-in in a console window
(choose bitwarden.com, bitwarden.eu or your own server first). Two-step login
and new-device codes work there exactly as Bitwarden made them. API key and
single sign-on logins are under *Use an API key or single sign-on instead*.
Then unlock with your master password.

Keytap keeps its own Bitwarden sign-in in `%APPDATA%\Keytap\bw`, apart from
any Bitwarden apps you use. It shows in your account as another device.

## Locking

The vault locks when Windows locks or sleeps, and after 30 minutes of the PC
being idle (both in Settings), from the tray menu, and when Keytap quits.
Locking drops everything from memory and has Bitwarden destroy the session
key. Logins set to ask for the master password again (Bitwarden's *Master
password re-prompt*) ask each time.

## Building

```
powershell -ExecutionPolicy Bypass -File build\bootstrap.ps1
powershell -ExecutionPolicy Bypass -File build\build_app.ps1
```

`bootstrap.ps1` makes a Python venv and fetches Bitwarden's CLI (pinned
version, checked against its SHA-256) into `%LOCALAPPDATA%\KeytapBuild`.
`build_app.ps1` builds `dist\Keytap\Keytap.exe` with the CLI in
`dist\Keytap\tools\bw\`, then runs it with `--self-test` to prove it starts.

Run from source with `%LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe app\main.py`.

Tests: `tests\test_core.py` covers codes, sequences, matching and the vault
(against a fake bw, and the real one for its signed-out answers).
`tests\type_test.py` drives the real thing with real keystrokes and clicks
against a fake vault and test windows of its own, pop-up included. It waits
for the PC to be idle for 20 seconds, won't start over a full-screen program,
and stops if anything but its own windows comes to the front; it takes the
keyboard and mouse for about a minute and a half.

## Releasing

```
powershell -ExecutionPolicy Bypass -File build\release.ps1 --notes "What's new"
```

Builds, checks the exe is the version in `app\keytap\__init__.py` (keep
`build\version_info.txt` in step), zips it, signs `latest.json` with the key in
`~\.keytap\release\`, and publishes the release Hanami installs from. See the
top of `build\release.py`. The script is Hanami's, copied here.
