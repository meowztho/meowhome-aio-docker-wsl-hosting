"""Conservative ServerAlias editor for unambiguous custom Apache VirtualHosts.

Only direct aliases are replaced. All other bytes remain unchanged.
"""
from dataclasses import dataclass
import difflib
import re

class UnsupportedVhost(ValueError):
    """Refuse configurations that cannot be transformed losslessly."""

@dataclass(frozen=True)
class AliasPlan:
    before: str
    after: str
    aliases: tuple[str, ...]
    diff: str

_OPEN = re.compile(r'^[ \t]*<VirtualHost\b[^\r\n>]*>[ \t]*(?:\r?\n|$)', re.I)
_CLOSE = re.compile(r'^[ \t]*</VirtualHost[ \t]*>[ \t]*(?:\r?\n|$)', re.I)
_SERVER = re.compile(r'^([ \t]*)ServerName[ \t]+([^\s#]+)[ \t]*(?:#.*)?(?:\r?\n|$)', re.I)
_ALIAS = re.compile(r'^([ \t]*)ServerAlias[ \t]+([^\r\n#]+?)[ \t]*(?:\r?\n|$)', re.I)
_DIRECTIVE = re.compile(r'^[ \t]*(ServerName|ServerAlias)\b', re.I)
_TAG = re.compile(r'^[ \t]*<(\/)?([A-Za-z][\w-]*)\b', re.I)

def plan_alias_edit(content: str, host: str, aliases: list[str] | tuple[str, ...]) -> AliasPlan:
    if not isinstance(content, str) or '\x00' in content or not content:
        raise UnsupportedVhost('Konfiguration ist leer oder enthält ungültige Bytes')
    newline = '\r\n' if '\r\n' in content else '\n'
    if '\r\n' in content and re.search(r'(?<!\r)\n', content):
        raise UnsupportedVhost('Gemischte Zeilenenden werden nicht verändert')
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host or ''):
        raise UnsupportedVhost('Ungültiger Haupt-Hostname')
    wanted = tuple(aliases)
    if any(not re.fullmatch(r'[a-z0-9.-]{1,253}', a) or a == host.lower() for a in wanted):
        raise UnsupportedVhost('Aliases müssen einfache, unterschiedliche Hostnamen sein')
    if len(set(wanted)) != len(wanted):
        raise UnsupportedVhost('Doppelte Aliases')
    lines = content.splitlines(keepends=True)
    blocks = []
    opener = None
    depth = 0
    server_index = None
    alias_index = None
    old_aliases = ()
    indent = ''
    for i, line in enumerate(lines):
        if line.lstrip().startswith('#'):
            continue
        if _OPEN.fullmatch(line):
            if opener is not None or depth:
                raise UnsupportedVhost('Verschachtelte oder bedingte VirtualHosts')
            opener = i
            server_index, alias_index, old_aliases, indent = None, None, (), ''
            continue
        if _CLOSE.fullmatch(line):
            if opener is None or depth or server_index is None:
                raise UnsupportedVhost('VirtualHost-Struktur ist nicht eindeutig')
            blocks.append((opener, i, server_index, alias_index, old_aliases, indent))
            opener = None
            continue
        if opener is None:
            if _DIRECTIVE.match(line):
                raise UnsupportedVhost('Hostname-Direktive außerhalb eines VirtualHost')
            if _TAG.match(line):
                raise UnsupportedVhost('Zusätzlicher Apache-Kontext außerhalb des VirtualHost')
            continue
        tag = _TAG.match(line)
        if tag:
            depth += -1 if tag.group(1) else 1
            if depth < 0:
                raise UnsupportedVhost('Apache-Blockstruktur nicht eindeutig')
            continue
        if _DIRECTIVE.match(line):
            if depth:
                raise UnsupportedVhost('Bedingte oder verschachtelte Hostnamen-Direktive')
            match = _SERVER.fullmatch(line)
            if match:
                if server_index is not None or match.group(2).lower() != host.lower():
                    raise UnsupportedVhost('Mehrere oder andere ServerName-Direktiven')
                server_index = i
                indent = match.group(1)
                continue
            match = _ALIAS.fullmatch(line)
            if not match or alias_index is not None:
                raise UnsupportedVhost('Komplexe oder mehrere ServerAlias-Direktiven')
            alias_values = tuple(match.group(2).split())
            if not alias_values or any('*' in a or '?' in a or '\\' in a for a in alias_values):
                raise UnsupportedVhost('Wildcard- oder Escape-Aliases erfordern Advanced VHost')
            if any(not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', a) for a in alias_values):
                raise UnsupportedVhost('Nicht unterstützte Alias-Syntax')
            alias_index = i
            old_aliases = tuple(a.lower() for a in alias_values)
    if opener is not None or depth or not 1 <= len(blocks) <= 4:
        raise UnsupportedVhost('VirtualHost-Blöcke nicht eindeutig (1–4 erwartet)')
    if any(set(b[4]) != set(blocks[0][4]) for b in blocks):
        raise UnsupportedVhost('Aliases unterscheiden sich zwischen HTTP und HTTPS')
    if any(b[3] is not None and b[3] < b[2] for b in blocks):
        raise UnsupportedVhost('ServerAlias vor ServerName wird nicht verändert')
    updated = list(lines)
    for _start, _end, server_idx, alias_idx, _old, whitespace in reversed(blocks):
        if alias_idx is not None:
            indent_alias = re.match(r'^[ \t]*', lines[alias_idx]).group(0)
            updated[alias_idx:alias_idx + 1] = ([indent_alias + 'ServerAlias ' + ' '.join(wanted) + newline] if wanted else [])
        elif wanted:
            if not lines[server_idx].endswith(('\n', '\r')):
                raise UnsupportedVhost('ServerName hat keinen Zeilenabschluss')
            updated[server_idx + 1:server_idx + 1] = [whitespace + 'ServerAlias ' + ' '.join(wanted) + newline]
    after = ''.join(updated)
    diff = ''.join(difflib.unified_diff(content.splitlines(keepends=True), after.splitlines(keepends=True),
                                         fromfile='Aktueller VHost', tofile='Vorschlag', n=0))
    return AliasPlan(content, after, wanted, diff)
