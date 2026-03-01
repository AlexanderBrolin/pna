"""
Windows DNS cache poller.
Periodically reads ipconfig /displaydns to build IP→domain mappings.
This is the most reliable source of domain resolution on Windows,
as it captures all forward DNS lookups made by the system.
"""

import logging
import re
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

POLL_INTERVAL = 2.0  # seconds between polls
IP4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
CREATE_NO_WINDOW = 0x08000000


class DnsCachePoller:
    """Polls Windows DNS cache and reports new domain→IP mappings via callback."""

    def __init__(self, on_mapping):
        """
        on_mapping(domain: str, ips: list[str]) -> None
            Called when new DNS mappings are discovered.
        """
        self._on_mapping = on_mapping
        self._running = False
        self._thread = None
        # Track known ip→domain to avoid duplicate callbacks
        self._known = {}  # ip -> domain

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def clear(self):
        """Called when capture resets. Keep known mappings (DNS cache persists)."""
        pass

    def _poll_loop(self):
        while self._running:
            try:
                self._poll()
            except Exception as e:
                logger.debug(f"DNS cache poll error: {e}")
            time.sleep(POLL_INTERVAL)

    def _poll(self):
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            return

        # Parse and report new mappings
        for domain, ips in self._parse(result.stdout):
            new_ips = []
            for ip in ips:
                if self._known.get(ip) != domain:
                    self._known[ip] = domain
                    new_ips.append(ip)
            if new_ips:
                try:
                    self._on_mapping(domain, new_ips)
                except Exception as e:
                    logger.debug(f"DNS cache callback error: {e}")

    @staticmethod
    def _parse(output):
        """Parse ipconfig /displaydns output. Locale-independent.

        Output format (blocks separated by dashes):
            domainname.com
            ----------------------------------------
            Key . . . : value
            ...
            A (Host) Record . . . : 1.2.3.4

        Yields (domain, [ips]) tuples.
        """
        # Split into blocks by separator lines (10+ dashes)
        blocks = re.split(r"\n\s*-{10,}\s*\n", output)

        for block in blocks:
            lines = block.strip().split("\n")
            if not lines:
                continue

            # Find domain: standalone line before the dash separator
            # It's the last non-empty line in the pre-dash part
            domain = None
            ips = []

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue

                if ": " in stripped:
                    # Key-value line — extract value after last ': '
                    value = stripped.rsplit(": ", 1)[1].strip()
                    if IP4_RE.match(value):
                        ips.append(value)
                elif domain is None:
                    # First non-key-value line = domain name
                    candidate = stripped.rstrip(".")
                    if ("." in candidate
                            and not IP4_RE.match(candidate)
                            and not candidate.endswith(".in-addr.arpa")
                            and not candidate.endswith(".ip6.arpa")):
                        domain = candidate.lower()

            if domain and ips:
                yield domain, ips
