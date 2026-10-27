"""Credential-free, tracked-file-only tool implementation.

Production use additionally requires a proved OS-isolated broker, with no
network, credentials, host mounts or privileged socket. This module alone is
not that OS boundary. It never launches a shell or executes repository files.
"""
import fnmatch
from pathlib import Path

from .snapshot import relative, sha


class Broker:
    def __init__(self, root, receipt):
        self.root = Path(root).resolve(strict=True)
        self.files = {r['path']: r for r in receipt['files']}
        if receipt.get('complete') is not True or len(self.files) != receipt['file_count']:
            raise ValueError('Complete unique tracked inventory required')
        for name in self.files:
            relative(name)
        self.calls = []

    def content(self, name):
        relative(name)
        if name not in self.files:
            raise ValueError('Only exact tracked snapshot files are readable')
        path = self.root / name
        if any(p.is_symlink() for p in [path, *path.parents] if p != self.root.parent):
            raise ValueError('Filesystem aliases refused')
        if not path.is_relative_to(self.root) or path.resolve(strict=True) != path:
            raise ValueError('Snapshot escape')
        value = path.read_bytes()
        row = self.files[name]
        if len(value) != row['bytes'] or sha(value) != row['sha256']:
            raise ValueError('Snapshot changed')
        return value

    @staticmethod
    def number(value, lo, hi):
        if type(value) is not int or not lo <= value <= hi:
            raise ValueError('Invalid bounded range')
        return value

    def view(self, path, start_line=1, end_line=None, column=0):
        start_line = self.number(start_line, 1, 10000000)
        column = self.number(column, 0, 536870912)
        if end_line is None:
            end_line = start_line + 199
        end_line = self.number(end_line, start_line, start_line + 399)
        raw = self.content(path)
        try:
            lines = raw.decode('utf-8', errors='strict').split('\n')
        except UnicodeDecodeError:
            return {'path': path, 'binary': True, 'bytes': len(raw), 'sha256': sha(raw),
                    'source_not_text': True}
        result = []; size = 0; next_cursor = None
        for n in range(start_line, min(end_line, len(lines)) + 1):
            text = lines[n - 1]
            begin = column if n == start_line else 0
            if begin > len(text):
                raise ValueError('Column outside historical line')
            # Split long source lines explicitly, on Unicode character boundaries.
            chunk = text[begin:begin + 8192]
            if size + len(chunk.encode()) > 49152:
                next_cursor = {'start_line': n, 'column': begin}; break
            result.append({'line': n, 'column': begin, 'text': chunk,
                           'line_complete': begin == 0 and len(chunk) == len(text)})
            size += len(chunk.encode())
            if begin + len(chunk) < len(text):
                next_cursor = {'start_line': n, 'column': begin + len(chunk)}; break
        if next_cursor is None and end_line < len(lines):
            next_cursor = {'start_line': end_line + 1, 'column': 0}
        value = {'path': path, 'blob_oid': self.files[path]['blob_oid'],
                 'source_sha256': sha(raw), 'lines': result, 'next_cursor': next_cursor,
                 'partial': next_cursor is not None}
        self.calls.append({'tool': 'view', 'path': path, 'start_line': start_line,
                           'end_line': result[-1]['line'] if result else None,
                           'start_column': column, 'source_sha256': sha(raw)})
        return value

    def glob(self, pattern='*', cursor=0, limit=100):
        if not isinstance(pattern, str) or len(pattern) > 500 or '\x00' in pattern:
            raise ValueError('Invalid pattern')
        cursor = self.number(cursor, 0, len(self.files)); limit = self.number(limit, 1, 200)
        matches = [p for p in sorted(self.files) if fnmatch.fnmatchcase(p, pattern)]
        batch = matches[cursor:cursor + limit]
        self.calls.append({'tool': 'glob', 'pattern': pattern, 'returned_paths': batch})
        return {'paths': batch, 'next_cursor': cursor + len(batch) if cursor + len(batch) < len(matches) else None,
                'total_matches': len(matches)}

    def grep(self, query, pattern='*', cursor=0, limit=100):
        if not isinstance(query, str) or not 1 <= len(query) <= 500 or '\n' in query:
            raise ValueError('Literal single-line query required')
        self.number(cursor, 0, 10000000); self.number(limit, 1, 200)
        if not isinstance(pattern, str) or len(pattern) > 500:
            raise ValueError('Invalid pattern')
        matches = []; binary = []; inspected = []; more = False
        for path in sorted(self.files):
            if not fnmatch.fnmatchcase(path, pattern):
                continue
            raw = self.content(path); inspected.append(path)
            try:
                text = raw.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                binary.append(path); continue
            for number, text in enumerate(text.split('\n'), 1):
                at = text.find(query)
                if at >= 0:
                    # Explicit bounded match window, never an entire unbounded line.
                    start = max(0, at - 80); end = min(len(text), at + len(query) + 80)
                    matches.append({'path': path, 'line': number, 'column': at,
                                    'text': text[start:end], 'window_start_column': start,
                                    'line_complete': start == 0 and end == len(text),
                                    'source_sha256': sha(raw)})
                    if len(matches) > cursor + limit:
                        more = True; break
            if more:
                break
        batch = matches[cursor:cursor + limit]
        self.calls.append({'tool': 'grep', 'query': query, 'inspected_paths': inspected,
                           'matches': [{k: row[k] for k in ('path', 'line', 'source_sha256')} for row in batch]})
        return {'matches': batch, 'total_matches': None if more else len(matches),
                'search_complete': not more, 'binary_paths_not_text_searched': binary,
                'next_cursor': cursor + len(batch) if more else None}

    def call(self, name, arguments):
        if name not in ('view', 'glob', 'grep') or not isinstance(arguments, dict):
            raise ValueError('Only three fixed readonly tools are implemented')
        return getattr(self, name)(**arguments)
