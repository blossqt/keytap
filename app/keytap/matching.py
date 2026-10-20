"""Which logins belong to the window being typed into.

A login is tied to a program in one of three ways, strongest first:
- remembered: chosen in Keytap's picker with "Always use" ticked (kept on
  this PC, never written to the vault);
- a URI on the login in Bitwarden: app://steam.exe for a program (a full
  path works too), or title://Sign in to Steam for a window whose title
  contains that text (* and ? as wildcards);
- a hint: the login's name, or its website's name, appears in the window's
  title or is the program's name. Hints are only ever suggestions in the
  picker - typing a password into the wrong window can send it somewhere
  it should never go, so Keytap types straight away only for the first two.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PureWindowsPath
from urllib.parse import urlparse

LINKED, URI, HINT = 'linked', 'uri', 'hint'
_ORDER = {LINKED: 0, URI: 1, HINT: 2}

# Browsers have Bitwarden's own extension for this; Keytap's pop-up stays out of them.
BROWSERS = {
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'opera_gx.exe',
    'vivaldi.exe', 'arc.exe', 'iexplore.exe', 'librewolf.exe', 'waterfox.exe', 'zen.exe',
}

# Programs that show many different things, so the program alone says nothing
# about which login is wanted: browsers, terminals, remote desktops, runtimes.
# Keytap remembers a choice in these per window title instead.
SHARED_PROGRAMS = BROWSERS | {
    'windowsterminal.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'conhost.exe', 'openconsole.exe',
    'mstsc.exe', 'msrdc.exe', 'vmconnect.exe', 'vmware.exe', 'virtualboxvm.exe',
    'java.exe', 'javaw.exe', 'python.exe', 'pythonw.exe', 'electron.exe', 'node.exe',
    'explorer.exe', 'applicationframehost.exe', 'rundll32.exe', 'dllhost.exe',
}

_COMMON_HOST_LABELS = {'www', 'com', 'net', 'org', 'app', 'login', 'accounts', 'account', 'auth',
                       'signin', 'secure', 'my', 'id', 'sso', 'portal', 'co', 'io'}


@dataclass(frozen=True)
class Match:
    login: object
    strength: str


def link_key(window) -> str:
    """What a remembered choice is filed under for this window."""
    if window.exe in SHARED_PROGRAMS or not window.exe:
        return f'{window.exe}|{window.title.strip()}'
    return window.exe


def describe(window) -> str:
    """'steam.exe', or for a browser and the like, its window's title."""
    if window.exe in SHARED_PROGRAMS or not window.exe:
        title = window.title.strip() or 'this window'
        return f'“{title}”'
    return window.exe


def _exe_matches(target: str, window) -> bool:
    target = target.strip().strip('"').replace('/', '\\').lower()
    if not target:
        return False
    if not target.endswith('.exe'):
        target += '.exe'
    if '\\' in target:
        return window.exe_path.lower() == target or (
            not target.startswith('\\') and ':' not in target
            and window.exe_path.lower().endswith('\\' + target))
    return window.exe == target


def _title_matches(pattern: str, title: str) -> bool:
    pattern, title = pattern.strip().lower(), title.lower()
    if not pattern:
        return False
    if '*' in pattern or '?' in pattern:
        return fnmatch.fnmatchcase(title, pattern)
    return pattern in title


def uri_matches(uri: str, window) -> bool:
    text = uri.strip()
    lower = text.lower()
    for scheme in ('app://', 'app:', 'exe://', 'exe:'):
        if lower.startswith(scheme):
            return _exe_matches(text[len(scheme):], window)
    for scheme in ('title://', 'title:', 'window://', 'window:'):
        if lower.startswith(scheme):
            return _title_matches(text[len(scheme):], window.title)
    if lower.endswith('.exe') and '://' not in lower:
        return _exe_matches(text, window)
    return False


def _word_in(word: str, text: str) -> bool:
    return bool(word) and re.search(rf'(?<![\w]){re.escape(word)}(?![\w])', text) is not None


def _site_name(uri: str) -> str:
    """'github' for https://github.com/login - the part of a website's name people see."""
    try:
        host = urlparse(uri if '://' in uri else f'https://{uri}').hostname or ''
    except ValueError:
        return ''
    labels = [label for label in host.split('.') if label and label not in _COMMON_HOST_LABELS]
    if not labels or host.replace('.', '').isdigit():
        return ''
    return labels[-1] if len(labels) == 1 else labels[-2] if len(labels[-1]) <= 3 else labels[-1]


def hints_at(login, window) -> bool:
    title = window.title.lower()
    stem = PureWindowsPath(window.exe).stem.lower() if window.exe else ''
    name = login.name.strip().lower()
    if len(name) >= 3 and (name == stem or _word_in(name, title)):
        return True
    if len(stem) >= 4 and _word_in(stem, name):     # "Steam (alt)" for steam.exe
        return True
    for uri in login.uris:
        if uri.lower().startswith(('http://', 'https://')) or ('.' in uri and '://' not in uri):
            site = _site_name(uri)
            if len(site) >= 4 and (site == stem or _word_in(site, title)):
                return True
    return False


def find(window, logins, links: dict[str, str]) -> list[Match]:
    """The logins that go with this window, strongest first."""
    linked_id = links.get(link_key(window))
    found = []
    for login in logins:
        if linked_id and login.id == linked_id:
            found.append(Match(login, LINKED))
        elif any(uri_matches(uri, window) for uri in login.uris):
            found.append(Match(login, URI))
        elif hints_at(login, window):
            found.append(Match(login, HINT))
    found.sort(key=lambda m: (_ORDER[m.strength], not m.login.favorite, m.login.name.lower()))
    return found


def sure_choice(matches: list[Match]):
    """The one login to type without asking, if there is exactly one sure one."""
    linked = [m.login for m in matches if m.strength == LINKED]
    if len(linked) == 1:
        return linked[0]
    tied = [m.login for m in matches if m.strength == URI]
    if not linked and len(tied) == 1:
        return tied[0]
    return None
