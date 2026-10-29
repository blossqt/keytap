# Keytap

Press a key in any Windows program and Keytap types your Bitwarden login
there: game launchers, desktop apps, remote desktops, anything with a
username box. Part of the same suite as Homework Hub, Grabbit and Dropshift.

Keytap reaches your vault through Bitwarden's own command-line tool, which
comes with it, and does what Bitwarden's apps do: it makes and changes logins,
cards, identities, notes and SSH keys, and has the generator, Send, the vault
health report, and export and import. It never talks to Bitwarden's servers
itself. It saves no passwords, except your master password sealed for Windows
Hello if you turn that on.

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
| **Ctrl+Alt+A** | Fills in the login that goes with this program - the username in the username box, the password in the password box - and signs in. If Keytap is not sure which login, it asks. |
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

## The vault window

Open Keytap from Start, from Hanami, or from the tray's **Open Keytap**, and it
shows your vault the way Bitwarden's apps do:

- **Filters** on the left: everything, favourites, those with a verification
  code, each kind of item, your folders and collections, the archive and the
  trash.
- **Items** in the middle, with a search box (Ctrl+F). It searches names,
  usernames and websites.
- **The chosen item** on the right:
  - a login's username, password (hidden until you click the eye) and
    verification code, counting down; a card's number, expiry and security
    code; an identity's details; an SSH key;
  - websites and programs, custom fields, notes, attachments, and a login's
    earlier passwords;
  - a button to copy each part. **Ctrl+U**, **Ctrl+P** and **Ctrl+T** copy the
    username, password and code.

Copies are kept out of Windows' clipboard history and cleared after 30 seconds.
An item set to ask for your master password again shows nothing until you
give it. **Ctrl+L** locks and **Ctrl+R** syncs.

### Changing the vault

- **New** (Ctrl+N for a login) makes a login, card, identity, note, SSH key
  (a new Ed25519 key comes with it) or folder.
- **Edit** (Ctrl+E, or double-click) changes any part of an item: websites
  and their match detection, custom fields of every kind, its folder, whether
  it asks for your master password. The dice beside a password or username
  makes one up.
- **Favourite**, and under **⋯**: clone, archive, attach a file, move to an
  organization or change its collections, open it in Bitwarden's web vault,
  and delete. Deleted items go to the trash, where they can be restored or
  deleted for good. Right-click a folder to rename or delete it.
- In the picker, **New login** (Ctrl+N) makes a login for the program or page
  you were in.

**⋯** at the top holds the tools:

- **Generator**: passwords, passphrases (from EFF's word list, as Bitwarden's)
  and usernames. What it makes is listed until Keytap locks.
- **Send**: share a text or a file through a link that is deleted after a
  while, with a password or a limit on views if you like.
- **Vault health**: passwords that leaked in a data breach (checked with Have I
  Been Pwned, which is sent only the start of each password's hash), are used
  by more than one login, or are weak, and websites that aren't https.
- **Export vault** and **Import data** (from Bitwarden or another password
  manager).

Everything goes through Bitwarden's command-line tool, which encrypts it
before it leaves this PC. What is saved is handed to it on its standard input,
never on a command line where other programs could read it.

While the vault is locked, the window shows the lock screen. Locking, whether
by hand, when idle or with Windows, clears every item off it and closes the
editor and the tools.

Started with Windows, Keytap stays in the background until you open it.

## The pop-up in login boxes

Like Bitwarden's extension in a browser, Keytap lists your logins under a
login box as soon as you click into it - a password box, or a text box with a
password box beside it. Click a login and it is typed in. Clicked into the
password box, only the password (and Enter) is typed.

Some sign-ins ask for the email first and the password on the next page, like
Google's and Microsoft's. Their email box gets the pop-up too, on a page whose
address says it is a sign-in or on a website you have a login for. There
Keytap types the username and Enter. On the password page, the login you just
chose comes first, marked *Just used*. The pop-up never takes
the keyboard, so the cursor stays where it was; Esc or clicking elsewhere
hides it. While the vault is locked it offers to unlock instead, then lists
the logins.

It works in ordinary Windows programs, Store apps, and Chromium/Electron apps
(Discord, Slack, many game launchers). It stays out of browsers, where the
Bitwarden extension does this.

A login box on a web page inside a program goes by the page's website, as in a
browser. That covers a built-in browser (like the one in Claude's desktop app)
and an app made of web pages (like Discord, whose sign-in is discord.com).
There Keytap lists the logins saved for that website and remembers an
*Always use* choice for the website rather than the program. A choice made for
the program before still holds on that login's own website. A page a program
serves itself (Steam's own screens, an app's `localhost` page) goes by the
program, as other programs do. A login saved
only for an Android app names no website, so it is only suggested, when its
name has the website's in it.

Games that draw their own screens don't tell
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
  desktops are remembered per window title rather than per program, and a
  web page inside a program per website.
- **A URI on the login**, set in Bitwarden on any device:
  - `app://steam.exe` - this program (a full path works too)
  - `title://Sign in to Steam` - a window whose title contains that text
    (`*` and `?` work as wildcards)
- **The website**, for a login box on a web page inside a program: the one
  login saved for that website, as Bitwarden's extension would fill it. Keytap
  sees which page the box is on while the pop-up in login boxes is on.

Websites follow the match detection set on each address in Bitwarden: the
base domain unless you chose host, starts with, exact or a regular expression.
An address set to *Never* is never matched. Websites that are one account
count as one, like Bitwarden's equivalent domains: Google and YouTube;
Microsoft, Xbox and Minecraft; Riot's games; Steam's sites; and a few more.
Keytap keeps its own list of these, because Bitwarden's command-line tool
doesn't share the ones in your account.

Otherwise Keytap suggests logins whose name or website matches the program or
window title, and lets you choose. It never types a guess: a password typed
into the wrong window could end up in a chat box.

## Filling in, box by box

Keytap finds the login form in the window: the box Windows marks as a password
box gets the password, and the text box just before it the username, wherever
the keyboard was. Each box gets its value set directly, through UI Automation
(what screen readers use): no keys are pressed and nothing goes on the
clipboard, so a busy program can't drop or swap characters and the keyboard
layout doesn't matter. Then Keytap presses the form's sign-in button (**Log
in**, **Sign in**, **Next** and the like, by its whole name: never **Can't log
in?**), or Enter in the password box if it has none. A search box above the
form is left alone, a username shown but not asked for is skipped, and on a
page that asks for the email first, only the email goes in.

This works in ordinary Windows programs, WPF and Qt ones, and apps made of web
pages: Electron, CEF (Ubisoft Connect, say) and WebView2. A box that won't
take a value set is clicked into and typed into instead. Some pages drop a set
value: Ubisoft Connect's empties its password box again at once. A web page's
password box shows a dot for each character it holds, so Keytap checks for
them, and types the password where they aren't there. A program that shows
Windows no boxes at all - a game drawing its own, a remote desktop - gets the
sequence typed, as below.

## What gets typed

The default is `{USERNAME}{TAB}{PASSWORD}{ENTER}` (Settings → Typing), which
fills in box by box as above wherever it can; so does any part of it, such as
`{PASSWORD}{ENTER}`. Any other sequence is typed as it is. A
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

## Unlocking with Windows Hello

In Settings → Locking, **Turn on** Windows Hello: type your master password
once, then confirm with your fingerprint, face or PIN. From then on, Keytap
asks Windows Hello first when it needs unlocking: on the unlock card, and as
soon as you open Keytap while it is locked. The master password still works,
and cancelling Windows Hello leaves you to type it.

It works as in Bitwarden's desktop app:

- **The key:** Windows makes a Windows Hello key for Keytap and keeps it in the
  PC's security chip where there is one. The key works only once Windows
  Hello has checked it is you.
- **The seal:** Keytap seals your master password with that key and with your
  Windows account, in `%APPDATA%\Keytap\hello.json`. Nothing else can open it.

If you change your master password, Windows Hello turns itself off until you
turn it on again. Logins that ask for the master password again still ask for
it.

## Passkeys

Keytap can sign you in with the passkeys in your Bitwarden vault, and save new
ones to it, without Bitwarden's own app. When a website or app asks for a
passkey, Windows' passkey window lists Keytap. Choose it:

1. Unlock Keytap if it's locked.
2. If the site has several accounts, choose one.
3. Confirm with Windows Hello. Logins that ask for your master password again
   ask for it instead.

This works wherever Windows' passkey window comes up: Edge and Chrome without
Bitwarden's extension, and apps built on web pages.

**Saving a new passkey.** When a site offers to make you a passkey, choose
Keytap in Windows' passkey window. Unlock Keytap if it's locked, and confirm
with Windows Hello. The passkey goes to your vault:

- **With the site's login for that account,** if it has one without a passkey.
  Logins that ask for your master password again ask for it here too.
- **Otherwise, in a new login** named after the site.

It is saved to Bitwarden before the site hears of it, so a site never keeps a
passkey your vault doesn't have. It then works in Bitwarden's own apps too.
Keytap makes the kind of passkey Bitwarden makes (ES256), and turns down a
site that asks for another kind.

A passkey that counts its uses (a counter above 0, from an import) is left to
Bitwarden, which saves the count.

**Setting it up.** In Settings, go to **Passkeys** and choose **Set up passkeys**:

- **Trust Keytap's certificate.** Windows asks an administrator once. Windows
  takes passkey providers only from signed app packages, and Keytap ships a
  small one, signed with its own certificate.
- **Register the package.** The package gives Keytap.exe that identity without
  moving any files.
- **Restart.** Keytap starts again, now as a passkey provider.
- **Switch it on.** Turn Keytap on in Windows Settings → Accounts → Passkeys →
  Advanced options. Keytap opens that page for you.

Keytap gives Windows only your passkeys' websites and account names, so its
passkey window can list them. The keys stay in your vault and in Keytap while
it's unlocked. Each request is checked to be signed by Windows before Keytap
answers it.

## Building

```
powershell -ExecutionPolicy Bypass -File build\bootstrap.ps1
powershell -ExecutionPolicy Bypass -File build\build_app.ps1
```

`bootstrap.ps1` makes a Python venv into `%LOCALAPPDATA%\KeytapBuild`. It also
fetches Bitwarden's CLI and Microsoft's SDK build tools (makeappx and
signtool), each pinned and checked against its SHA-256. `build_app.ps1` builds
`dist\Keytap\Keytap.exe` with the CLI in `dist\Keytap\tools\bw\`.
`make_package.py` then signs Keytap's package into `dist\Keytap\package\`.
Finally the build runs the exe with `--self-test` to prove it starts.

The package-signing certificate was made once with
`build\make_package.py --make-key`. Its key is in `~\.keytap\release\` and must
never be replaced: PCs that trust the certificate would refuse packages signed
by a new one. Its public half is `build\package\Keytap.cer`.

Run from source with `%LOCALAPPDATA%\KeytapBuild\venv\Scripts\python.exe app\main.py`.

Tests:
- `tests\test_core.py` covers codes, sequences, matching and the vault (against
  a fake bw, and the real one for its signed-out answers).
- `tests\test_passkeys.py` covers CBOR, P-256 signing (RFC 6979's vector) and
  passkey answers, checked byte for byte against Windows' own encoder.
- `tests\test_signins.py` runs the sign-in flow against stand-ins for Windows
  and the person.
- `tests\test_filling.py` covers filling in box by box: which boxes and which
  button, what is set and what is typed, with UI Automation stood in for.
`tests\fill_test.py` fills real login windows - classic Windows, Qt, WPF and
Chromium pages drawn as React draws them - through UI Automation. Their windows
come up without the keyboard for a few seconds each; nothing is typed. Its
`typed-password` case (a page that drops a set password, as Ubisoft Connect's
does) types with real keys, so it runs only when named.
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

## Photo

The cherry blossom faintly behind Keytap's vault and settings windows is a photo by AJ on Unsplash
(https://unsplash.com/photos/McsNra2VRQQ), used under the Unsplash License.

## Word list

The generator's passphrases use EFF's long word list (https://www.eff.org/dice), under CC BY 3.0
US - the list Bitwarden uses, in `app\keytap\words.txt`.
