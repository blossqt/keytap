"""Everything a Bitwarden vault holds - logins, cards, identities, notes and SSH keys - as the vault
window shows and edits it.

Each Item keeps the item as bw gave it (raw) and is never changed in place: an edit starts from a
copy (editable()), and what bw saves comes back as a new Item. A login's Login (vault.py) is what
auto-type uses; Items are for the window.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime

from .vault import Login

LOGIN, NOTE, CARD, IDENTITY, SSH_KEY = 1, 2, 3, 4, 5
KINDS = (LOGIN, CARD, IDENTITY, NOTE, SSH_KEY)          # in the order Bitwarden lists them
NAMES = {LOGIN: 'Login', CARD: 'Card', IDENTITY: 'Identity', NOTE: 'Note', SSH_KEY: 'SSH key'}
PLURALS = {LOGIN: 'Logins', CARD: 'Cards', IDENTITY: 'Identities', NOTE: 'Notes', SSH_KEY: 'SSH keys'}
GLYPHS = {LOGIN: 'globe', CARD: 'card', IDENTITY: 'person', NOTE: 'note', SSH_KEY: 'terminal'}

# Custom fields' kinds, and what a linked one can stand for in each kind of item.
TEXT, HIDDEN, BOOLEAN, LINKED = 0, 1, 2, 3
FIELD_KINDS = {TEXT: 'Text', HIDDEN: 'Hidden', BOOLEAN: 'Checkbox', LINKED: 'Linked'}
LINKS = {
    LOGIN: {100: 'Username', 101: 'Password'},
    CARD: {300: 'Cardholder name', 301: 'Expiry month', 302: 'Expiry year', 303: 'Security code',
           304: 'Brand', 305: 'Number'},
    IDENTITY: {400: 'Title', 416: 'First name', 401: 'Middle name', 417: 'Last name', 418: 'Full name',
               413: 'Username', 409: 'Company', 412: 'National insurance / social security number',
               414: 'Passport number', 415: 'Licence number', 410: 'Email', 411: 'Phone', 402: 'Address 1',
               403: 'Address 2', 404: 'Address 3', 405: 'City / town', 406: 'County / state',
               407: 'Postcode / ZIP', 408: 'Country'},
}

# A website's match detection (None: the account's default, the base domain).
MATCHES = ((None, 'Default'), (0, 'Base domain'), (1, 'Host'), (2, 'Starts with'), (4, 'Regular expression'),
           (3, 'Exact'), (5, 'Never'))

CARD_BRANDS = ('Visa', 'Mastercard', 'Amex', 'Discover', 'Diners Club', 'JCB', 'Maestro', 'UnionPay', 'RuPay',
               'Other')
TITLES = ('Mr', 'Mrs', 'Ms', 'Mx', 'Dr')

# (key in the identity, label), in the order Bitwarden shows them, by section.
IDENTITY_PARTS = (
    ('Personal details', (('title', 'Title'), ('firstName', 'First name'), ('middleName', 'Middle name'),
                          ('lastName', 'Last name'), ('username', 'Username'), ('company', 'Company'))),
    ('Identification', (('ssn', 'National insurance / social security number'),
                        ('passportNumber', 'Passport number'), ('licenseNumber', 'Licence number'))),
    ('Contact info', (('email', 'Email'), ('phone', 'Phone'), ('address1', 'Address 1'),
                      ('address2', 'Address 2'), ('address3', 'Address 3'), ('city', 'City / town'),
                      ('state', 'County / state'), ('postalCode', 'Postcode / ZIP'), ('country', 'Country'))),
)
SECRET_IDENTITY = frozenset({'ssn', 'passportNumber', 'licenseNumber'})
CARD_PARTS = (('cardholderName', 'Cardholder name'), ('number', 'Number'), ('brand', 'Brand'),
              ('expMonth', 'Expiry month'), ('expYear', 'Expiry year'), ('code', 'Security code'))


def _text(value) -> str:
    return '' if value is None else str(value)


def brand_of(number: str) -> str:
    """A card's brand from its number, as Bitwarden guesses it - '' when unsure."""
    digits = re.sub(r'\D', '', number or '')
    rules = (('Amex', r'3[47]'), ('Diners Club', r'3(0[0-5]|[68])'), ('JCB', r'35'),
             ('Visa', r'4'), ('Mastercard', r'(5[1-5]|2(2[2-9]|[3-6]|7[01]|720))'),
             ('Discover', r'(6011|65|64[4-9])'), ('UnionPay', r'62'), ('RuPay', r'(60|65|81|82|508)'),
             ('Maestro', r'(5[06-9]|6)'))
    for brand, prefix in rules:
        if digits and re.match(prefix, digits):
            return brand
    return ''


def last_four(number: str) -> str:
    digits = re.sub(r'\D', '', number or '')
    return digits[-4:] if len(digits) >= 4 else ''


def when(stamp: str) -> str:
    """'27 Oct 2026, 14:05' from bw's '2026-10-27T13:05:00.000Z', in this PC's time."""
    try:
        moment = datetime.fromisoformat(stamp.replace('Z', '+00:00')).astimezone()
    except (AttributeError, ValueError):
        return ''
    return f'{moment.day} {moment:%b %Y}, {moment:%H:%M}'


class Item:
    """One item of the vault, as bw gave it. partial: made from a login Windows Hello kept, while bw
    unlocks - shown, but not yet editable."""

    __slots__ = ('raw', 'partial', 'id', 'type', 'name', 'favorite', 'folder_id', 'organization_id',
                 'collection_ids', 'reprompt', 'notes', 'deleted', 'archived', 'login', 'subtitle', '_words')

    def __init__(self, raw: dict, partial: bool = False, login: Login | None = None):
        self.raw = raw
        self.partial = partial
        self.id = _text(raw.get('id'))
        self.type = raw.get('type') if raw.get('type') in KINDS else NOTE
        self.name = _text(raw.get('name')) or '(no name)'
        self.favorite = bool(raw.get('favorite'))
        self.folder_id = _text(raw.get('folderId'))
        self.organization_id = _text(raw.get('organizationId'))
        self.collection_ids = tuple(_text(c) for c in raw.get('collectionIds') or ())
        self.reprompt = raw.get('reprompt') == 1
        self.notes = _text(raw.get('notes'))
        self.deleted = _text(raw.get('deletedDate'))
        self.archived = _text(raw.get('archivedDate'))
        self.login = login if login is not None else \
            Login.from_item(raw, live_only=False) if self.type == LOGIN else None
        self.subtitle = self._subtitle()
        self._words = ' '.join((self.name, self.subtitle, *(self.login.uris if self.login else ()))).lower()

    @classmethod
    def from_login(cls, login: Login) -> Item:
        """A login Windows Hello kept, shown while bw unlocks."""
        raw = {'id': login.id, 'type': LOGIN, 'name': login.name, 'favorite': login.favorite,
               'folderId': login.folder_id or None, 'reprompt': 1 if login.reprompt else 0, 'notes': login.notes,
               'fields': [{'name': name, 'value': value, 'type': HIDDEN if name in login.hidden else TEXT}
                          for name, value in login.fields],
               'login': {'username': login.username, 'password': login.password, 'totp': login.totp,
                         'uris': [{'uri': uri, 'match': match} for uri, match in zip(login.uris, login.uri_match)]}}
        return cls(raw, partial=True, login=login)

    def part(self, kind: str) -> dict:
        """The kind's own part of the item: raw['card'], raw['identity'] and so on."""
        value = self.raw.get(kind)
        return value if isinstance(value, dict) else {}

    @property
    def card(self) -> dict:
        return self.part('card')

    @property
    def identity(self) -> dict:
        return self.part('identity')

    @property
    def ssh_key(self) -> dict:
        return self.part('sshKey')

    @property
    def fields(self) -> list[dict]:
        """Custom fields, every kind: name, value, type (TEXT...), linkedId."""
        return [f for f in self.raw.get('fields') or [] if isinstance(f, dict)]

    @property
    def attachments(self) -> list[dict]:
        return [a for a in self.raw.get('attachments') or [] if isinstance(a, dict) and a.get('id')]

    @property
    def password_history(self) -> list[dict]:
        """Passwords the login had before, the latest first."""
        found = [p for p in self.raw.get('passwordHistory') or [] if isinstance(p, dict) and p.get('password')]
        return sorted(found, key=lambda p: _text(p.get('lastUsedDate')), reverse=True)

    @property
    def has_code(self) -> bool:
        return bool(self.login and self.login.totp)

    def full_name(self) -> str:
        identity = self.identity
        return ' '.join(_text(identity.get(key)) for key in ('title', 'firstName', 'middleName', 'lastName')
                        if identity.get(key))

    def _subtitle(self) -> str:
        """The line under its name in the list."""
        if self.type == LOGIN and self.login is not None:
            return self.login.username
        if self.type == CARD:
            card = self.card
            digits = last_four(_text(card.get('number')))
            return ', '.join(part for part in (_text(card.get('brand')), f'*{digits}' if digits else '') if part)
        if self.type == IDENTITY:
            return self.full_name()
        if self.type == SSH_KEY:
            return _text(self.ssh_key.get('keyFingerprint'))
        return ''

    def matches(self, words: list[str]) -> bool:
        return all(word in self._words for word in words)

    def editable(self) -> dict:
        """A copy of the item to change and hand to bw."""
        return copy.deepcopy(self.raw)

    def clone(self) -> dict:
        """A new item like this one (Bitwarden's Clone): without its id, history, passkeys or attachments."""
        made = self.editable()
        for key in ('id', 'revisionDate', 'creationDate', 'deletedDate', 'archivedDate', 'passwordHistory',
                    'attachments'):
            made.pop(key, None)
        made['name'] = f'{self.name} - Clone'
        if isinstance(made.get('login'), dict):
            made['login'].pop('fido2Credentials', None)
            made['login'].pop('passwordRevisionDate', None)
        return made


def blank(kind: int, name: str = '', folder_id: str = '') -> dict:
    """A new item of that kind, as bw takes it."""
    item = {'type': kind, 'name': name, 'notes': None, 'favorite': False, 'fields': [], 'reprompt': 0,
            'folderId': folder_id or None, 'organizationId': None, 'collectionIds': []}
    if kind == LOGIN:
        item['login'] = {'username': None, 'password': None, 'totp': None, 'uris': []}
    elif kind == CARD:
        item['card'] = {key: None for key, _ in CARD_PARTS}
    elif kind == IDENTITY:
        item['identity'] = {key: None for _, parts in IDENTITY_PARTS for key, _ in parts}
    elif kind == NOTE:
        item['secureNote'] = {'type': 0}
    elif kind == SSH_KEY:
        item['sshKey'] = {'privateKey': None, 'publicKey': None, 'keyFingerprint': None}
    return item


def of(raw_items: list[dict]) -> list[Item]:
    return [Item(raw) for raw in raw_items if isinstance(raw, dict) and raw.get('id')]
