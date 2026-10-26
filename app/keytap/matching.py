"""Which logins belong to the window being typed into.

A login is tied to a program in one of these ways, strongest first:
- remembered: chosen in Keytap's picker with "Always use" ticked (kept on
  this PC, never written to the vault) - that login, or, ticked for its
  website, every login for that website (SITE_LINK);
- a URI on the login in Bitwarden: app://steam.exe for a program (a full
  path works too), or title://Sign in to Steam for a window whose title
  contains that text (* and ? as wildcards);
- the web page: for a box on a web page inside a program (an app's built-in
  browser, or an app made of web pages, like Discord), saved for that page's
  website, as Bitwarden's extension matches logins in a browser - by each
  address's match detection there (base domain, host, starts with, exact,
  regular expression; an address set to never match counts nowhere). A page
  the program serves itself (Steam's own screens, say) counts as no page;
- the same website: saved for the website of a login tied the first or second
  way - another account there. Steam's sign-in window is steamwebhelper.exe
  and its logins are saved for steampowered.com, so remembering one of them
  brings in the rest;
- a hint: the login's name, or its website's name, appears in the window's
  title or is the program's name - or, on a web page, is the website's name.

On a web page, a choice is remembered for that website rather than for the
program, which can show any website at all.

The last two are only ever suggestions - typing a password into the wrong
window can send it somewhere it should never go, so Keytap types straight
away only for the first three.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PureWindowsPath
from urllib.parse import urlparse

JUST, LINKED, URI, PAGE, SITE, HINT = 'just', 'linked', 'uri', 'page', 'site', 'hint'
_ORDER = {JUST: 0, LINKED: 1, URI: 2, PAGE: 3, SITE: 4, HINT: 5}

# Bitwarden's match detection, set per address on a login. None is the default:
# the base domain, which is also what Bitwarden's apps use unless told otherwise.
DOMAIN, HOST, STARTS_WITH, EXACT, REGEX, NEVER = 0, 1, 2, 3, 4, 5

# Websites that are one account under several names, like Bitwarden's
# equivalent domains. They count only for base-domain matching, as there.
_SAME_SITES = tuple(frozenset(group) for group in (
    {'steampowered.com', 'steamcommunity.com', 'steamgames.com'},
    {'google.com', 'youtube.com', 'gmail.com', 'google.co.uk', 'google.ca', 'google.com.au', 'google.de',
     'google.fr'},
    {'microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com', 'xbox.com', 'skype.com', 'bing.com',
     'msn.com', 'onedrive.com', 'minecraft.net'},
    {'apple.com', 'icloud.com'},
    {'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp',
     'amazon.com.au', 'amazon.in'},
    {'riotgames.com', 'leagueoflegends.com', 'playvalorant.com', 'lolesports.com'},
    {'epicgames.com', 'unrealengine.com', 'fortnite.com'},
    {'battle.net', 'blizzard.com'},
    {'ea.com', 'origin.com'},
    {'ubisoft.com', 'ubi.com'},
    {'playstation.com', 'sony.com', 'sonyentertainmentnetwork.com'},
    {'discord.com', 'discordapp.com'},
    {'twitter.com', 'x.com'},
    {'facebook.com', 'messenger.com'},
))

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

# Pages a program serves itself, which say nothing about whose login it wants:
# Steam draws its own screens as https://steamloopback.host/...
_OWN_HOSTS = {'localhost', 'steamloopback.host'}

_COMMON_HOST_LABELS = {'www', 'com', 'net', 'org', 'app', 'login', 'accounts', 'account', 'auth',
                       'signin', 'secure', 'my', 'id', 'sso', 'portal', 'co', 'io'}


@dataclass(frozen=True)
class Match:
    login: object
    strength: str


SITE_LINK = 'site:'      # a remembered choice for a website, 'site:riotgames.com', rather than a login's id


def main_site(login) -> str:
    """The website a login is first saved for ('' for none) - what tying a program to its website
    ties it to."""
    return next((site for site in (site_of(uri) for uri, _ in _rules(login)) if site), '')


def page_site(page: str) -> str:
    """The website of a web page inside a program, or '' for none. A page the program serves
    itself (localhost, a private address, Steam's steamloopback.host) counts as none: then
    the program, not the page, says which login it wants."""
    try:
        host = (urlparse(page).hostname or '').strip('.').lower() if page else ''
    except ValueError:
        return ''
    if not host or host in _OWN_HOSTS or host.endswith('.localhost'):
        return ''
    try:
        if not ipaddress.ip_address(host).is_global:
            return ''
    except ValueError:
        pass                        # a name, not an address
    return site_of(page)


def link_key(window, page: str = '') -> str:
    """What a remembered choice is filed under for this window, or for the web page in it."""
    site = page_site(page)
    if site:
        return f'{window.exe}|site:{site}'
    if window.exe in SHARED_PROGRAMS or not window.exe:
        return f'{window.exe}|{window.title.strip()}'
    return window.exe


def describe(window, page: str = '') -> str:
    """'steam.exe'; for a browser and the like, its window's title; on a web page, its website."""
    site = page_site(page)
    if site:
        return site
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
    """Whether word is in text as a whole word, as (?<!\\w)word(?!\\w) would find it - without
    the regular expression, which was compiled anew for each login's name, each time."""
    if not word:
        return False
    at = text.find(word)
    while at != -1:
        end = at + len(word)
        if not (at and _wordy(text[at - 1])) and not (end < len(text) and _wordy(text[end])):
            return True
        at = text.find(word, at + 1)
    return False


def _wordy(char: str) -> bool:
    return char.isalnum() or char == '_'            # what \w matches


@lru_cache(maxsize=8192)
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


@lru_cache(maxsize=8192)
def site_of(uri: str) -> str:
    """'steampowered.com' for https://store.steampowered.com/login - the website a URI is
    on, without its subdomains - or '' for a program, a window title or no website at all."""
    text = uri.strip()
    lower = text.lower()
    if lower.startswith(('app:', 'exe:', 'title:', 'window:')) or (
            '://' in lower and not lower.startswith(('http://', 'https://'))):
        return ''
    if '://' not in lower and ('.' not in lower or lower.endswith('.exe')):
        return ''
    try:
        host = (urlparse(text if '://' in text else f'https://{text}').hostname or '').strip('.')
    except ValueError:
        return ''
    if '.' not in host:
        return ''
    if host.replace('.', '').isdigit():
        return host
    labels = host.split('.')
    # example.co.uk, example.com.au: the country's own second level counts as the ending.
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
    return '.'.join(labels[-keep:])


@lru_cache(maxsize=4096)
def _also(site: str) -> frozenset[str]:
    """A website with the names it also goes by."""
    return next((group for group in _SAME_SITES if site in group), frozenset({site}))


def _rules(login) -> list[tuple[str, int | None]]:
    """A login's addresses, each with its match detection - leaving out those set to never match."""
    kinds = tuple(getattr(login, 'uri_match', ()) or ())
    pairs = [(uri, kinds[i] if i < len(kinds) else None) for i, uri in enumerate(login.uris)]
    return [(uri, kind) for uri, kind in pairs if kind != NEVER]


@lru_cache(maxsize=8192)
def _host(uri: str) -> str:
    """'github.com' or 'example.com:8443' - the host and any port, as Bitwarden's host matching
    compares them."""
    try:
        parsed = urlparse(uri if '://' in uri else f'http://{uri}')
        host = (parsed.hostname or '').lower()
        return f'{host}:{parsed.port}' if host and parsed.port else host
    except ValueError:
        return ''


def address_matches(uri: str, kind: int | None, page: str, page_sites: set[str]) -> bool:
    """Whether one of a login's addresses goes with a web page, by the rule set for it in
    Bitwarden. page_sites: the page's website, with the names it also goes by."""
    if kind == NEVER:
        return False
    if kind == HOST:
        return bool(_host(uri)) and _host(uri) == _host(page)
    if kind == STARTS_WITH:
        return page.startswith(uri)
    if kind == EXACT:
        return page == uri
    if kind == REGEX:
        try:
            return re.search(uri, page, re.IGNORECASE) is not None
        except re.error:
            return False
    site = site_of(uri)                 # the base domain: the default
    return bool(site) and site in page_sites


def _sites(login) -> set[str]:
    """The websites a login is saved for, each with the names it also goes by."""
    found = set()
    for uri, _ in _rules(login):
        site = site_of(uri)
        if site:
            found |= _also(site)
    return found


def _is_web(uri: str) -> bool:
    return uri.lower().startswith(('http://', 'https://')) or ('.' in uri and '://' not in uri)


def hints_at(login, window, page: str = '') -> bool:
    return _hints(window, page)(login)


def _hints(window, page: str = ''):
    """hints_at for one window (or page), as a test of a login: what the window says worked out
    once, not again for each login."""
    if page:
        # On a web page the program says nothing: it could be showing any website.
        named = _site_name(page)
        return lambda login: len(named) >= 4 and (_word_in(named, login.name.lower()) or any(
            _site_name(uri) == named for uri, _ in _rules(login) if _is_web(uri)))
    title = window.title.lower()
    stem = PureWindowsPath(window.exe).stem.lower() if window.exe else ''
    return lambda login: _hinted(login, title, stem)


def _hinted(login, title: str, stem: str) -> bool:
    name = login.name.strip().lower()
    if len(name) >= 3 and (name == stem or _word_in(name, title)):
        return True
    if len(stem) >= 4 and _word_in(stem, name):     # "Steam (alt)" for steam.exe
        return True
    for uri, _ in _rules(login):
        if _is_web(uri):
            site = _site_name(uri)
            if len(site) >= 4 and (site == stem or _word_in(site, title)):
                return True
    return False


def find(window, logins, links: dict[str, str], page: str = '', just: str = '') -> list[Match]:
    """The logins that go with this window - or with the web page in it, for a box on one -
    strongest first. just: a login typed a moment ago into the step before (the username page
    of a sign-in that asks for the password next), which goes first."""
    site = page_site(page)
    page = page if site else ''               # a page the program serves itself: go by the program
    on_page = _also(site) if site else set()
    linked_id = links.get(link_key(window, page))
    if not linked_id and on_page:
        # Chosen for the program before Keytap knew the page: still good on its own website.
        earlier = links.get(link_key(window), '')
        if earlier.startswith(SITE_LINK) and _also(earlier[len(SITE_LINK):]) & on_page or any(
                login.id == earlier and _sites(login) & on_page for login in logins):
            linked_id = earlier
    # Tied to a website: every login for it (by the names it also goes by, too).
    linked_sites = _also(linked_id[len(SITE_LINK):]) if linked_id and linked_id.startswith(SITE_LINK) else set()
    strength = {}
    for login in logins:
        if just and login.id == just:
            strength[login.id] = JUST
        elif linked_id and login.id == linked_id or linked_sites and _sites(login) & linked_sites:
            strength[login.id] = LINKED
        elif any(uri_matches(uri, window) for uri, _ in _rules(login)):
            strength[login.id] = URI
        elif on_page and any(address_matches(uri, kind, page, on_page) for uri, kind in _rules(login)):
            strength[login.id] = PAGE
    # Other accounts on the websites of the logins tied to this program.
    sites = set().union(*(_sites(login) for login in logins if login.id in strength))
    hints = _hints(window, page)
    found = []
    for login in logins:
        if login.id not in strength:
            if sites and _sites(login) & sites:
                strength[login.id] = SITE
            elif hints(login):
                strength[login.id] = HINT
        if login.id in strength:
            found.append(Match(login, strength[login.id]))
    found.sort(key=lambda m: (_ORDER[m.strength], not m.login.favorite, m.login.name.lower()))
    return found


def sure_choice(matches: list[Match]):
    """The one login to type without asking, if there is exactly one sure one."""
    for strength in (JUST, LINKED, URI, PAGE):
        logins = [m.login for m in matches if m.strength == strength]
        if logins:
            return logins[0] if len(logins) == 1 else None
    return None
