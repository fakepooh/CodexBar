"""Offline publication shim: credentials are never available in this package."""
import contextlib

class KeychainBlocked(RuntimeError):
    pass

@contextlib.contextmanager
def pat(*args, **kwargs):
    raise KeychainBlocked("Credential access is disabled in the offline publication package")
    yield  # Never reached; retain the context-manager interface.
