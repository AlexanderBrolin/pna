"""
Blacklist module for filtering system noise domains/patterns.
"""

import fnmatch
import threading


DEFAULT_PATTERNS = [
    # Windows telemetry
    "*.microsoft.com",
    "*.windows.com",
    "*.windowsupdate.com",
    "*.msftconnecttest.com",
    "*.msedge.net",
    "*.bing.com",
    "*.live.com",
    "*.outlook.com",
    "*.office.com",
    "*.office365.com",
    "*.microsoftonline.com",
    # Certificates / OCSP / CRL
    "*.digicert.com",
    "*.globalsign.com",
    "*.letsencrypt.org",
    "*.sectigo.com",
    "ocsp.*",
    "crl.*",
    # Local
    "localhost",
    "*.local",
    "*.internal",
    "*.lan",
    "wpad",
    "wpad.*",
    # Common Windows services
    "*.aka.ms",
    "*.trafficmanager.net",
]


class Blacklist:
    def __init__(self):
        self._lock = threading.Lock()
        self._patterns = list(DEFAULT_PATTERNS)

    @property
    def patterns(self):
        with self._lock:
            return list(self._patterns)

    @patterns.setter
    def patterns(self, new_patterns):
        with self._lock:
            self._patterns = list(new_patterns)

    def is_blacklisted(self, domain: str) -> bool:
        if not domain:
            return True
        domain_lower = domain.lower().rstrip(".")
        with self._lock:
            for pattern in self._patterns:
                if fnmatch.fnmatch(domain_lower, pattern.lower()):
                    return True
        return False

    def add_pattern(self, pattern: str):
        with self._lock:
            if pattern not in self._patterns:
                self._patterns.append(pattern)

    def remove_pattern(self, pattern: str):
        with self._lock:
            if pattern in self._patterns:
                self._patterns.remove(pattern)
