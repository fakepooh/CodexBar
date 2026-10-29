"""Authenticated remote create-only ledger. No mutation retries or redirects."""
import json
import re
import ssl
import urllib.error
import urllib.request

from .snapshot import canonical


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('GitHub ledger redirect refused')


class RefAlreadyExists(ValueError):
    """An explicit atomic create-ref conflict, not rate limiting or validation."""


class GitHubStore:
    def __init__(self, token, workflow_sha):
        if not isinstance(token, str) or not token or not re.fullmatch('[0-9a-f]{40}', workflow_sha):
            raise ValueError('Exact credential and workflow identity required')
        self.token = token
        self.workflow_sha = workflow_sha
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def request(self, method, path, value=None):
        allowed = (method == 'POST' and path in ('/git/tags', '/git/refs')) or (
            method == 'GET' and re.fullmatch(
                r'/git/(tags/[0-9a-f]{40}|ref/tags/repo-wide-readonly-[A-Za-z0-9-]+)', path))
        if not allowed:
            raise ValueError('Only exact repository Git endpoints allowed')
        url = 'https://api.github.com/repos/fakepooh/CodexBar' + path
        data = canonical(value).encode() if value is not None else None
        request = urllib.request.Request(url, data=data, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'User-Agent': 'copilot-repo-wide-ledger',
            'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with self.opener.open(request, timeout=30) as response:
                if response.status != (201 if method == 'POST' else 200):
                    raise ValueError('Remote ledger status rejected')
                data = response.read(1048577)
                if len(data) > 1048576:
                    raise ValueError('Remote ledger response limit')
                return json.loads(data)
        except urllib.error.HTTPError as error:
            if method == 'POST' and path == '/git/refs' and error.code in (409, 422):
                try:
                    detail = json.loads(error.read(65536))
                    exists = detail.get('message') == 'Reference already exists' or any(
                        item.get('resource') == 'Reference' and item.get('code') == 'already_exists'
                        for item in detail.get('errors', []) if isinstance(item, dict))
                    if exists:
                        raise RefAlreadyExists('Remote ledger reference already exists') from None
                except (json.JSONDecodeError, UnicodeDecodeError, OSError, TypeError, AttributeError):
                    pass
            # No complete response/header/error containing credential material.
            raise ValueError('Remote ledger HTTP ' + str(error.code)) from None

    def create_ref(self, ref, value):
        if not re.fullmatch(r'refs/tags/repo-wide-readonly-[A-Za-z0-9-]+', ref):
            raise ValueError('Outside ledger namespace')
        tag = self.request('POST', '/git/tags', {'tag': ref[len('refs/tags/'):],
            'message': canonical(value), 'object': self.workflow_sha, 'type': 'commit'})
        if not re.fullmatch('[0-9a-f]{40}', tag.get('sha', '')):
            raise ValueError('Invalid reservation tag object')
        result = self.request('POST', '/git/refs', {'ref': ref, 'sha': tag['sha']})
        if result.get('ref') != ref or result.get('object', {}).get('sha') != tag['sha']:
            raise ValueError('Unexpected exclusive reservation response')
        if canonical(self.read(ref)) != canonical(value):
            raise ValueError('Remote readback does not match immutable intent')
        return {'created': True, 'ref': ref, 'intent': value}

    def read(self, ref):
        if not re.fullmatch(r'refs/tags/repo-wide-readonly-[A-Za-z0-9-]+', ref):
            raise ValueError('Outside exact ledger namespace')
        value = self.request('GET', '/git/ref/' + ref[len('refs/'):])
        obj = value['object']
        if obj.get('type') != 'tag' or not re.fullmatch('[0-9a-f]{40}', obj.get('sha', '')):
            raise ValueError('Annotated reservation tag required')
        tag = self.request('GET', '/git/tags/' + obj['sha'])
        if tag['object'] != {'sha': self.workflow_sha,
                             'type': 'commit',
                             'url': 'https://api.github.com/repos/fakepooh/CodexBar/git/commits/' + self.workflow_sha}:
            # Validate identity fields, not an undocumented extra server field.
            if tag['object'].get('sha') != self.workflow_sha or tag['object'].get('type') != 'commit':
                raise ValueError('Reservation points to a different workflow commit')
        return json.loads(tag['message'])
