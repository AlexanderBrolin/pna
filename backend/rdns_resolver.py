"""
Reverse DNS resolver — looks up hostnames for IP-only entries.
Uses a thread pool so socket.gethostbyaddr() never blocks the main path.
"""

import socket
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

RESOLVE_TIMEOUT = 3.0   # seconds per lookup
MAX_WORKERS = 8          # simultaneous rDNS threads
NEGATIVE_TTL = 300       # seconds before retrying a failed lookup


class ReverseDNSResolver:
    """
    Submit IPs for reverse DNS resolution. Results delivered via callback.
    Uses ThreadPoolExecutor with per-call timeout via inner daemon thread.
    """

    def __init__(self, on_resolved):
        """
        on_resolved(ip: str, hostname: str | None) -> None
            Called from a worker thread when rDNS completes.
            hostname is None if resolution failed or timed out.
        """
        self._on_resolved = on_resolved
        self._executor = None
        self._lock = threading.Lock()
        self._cache = {}       # ip -> hostname (positive, permanent per session)
        self._failed = {}      # ip -> monotonic timestamp (negative, retried after TTL)
        self._in_flight = set()

    def start(self):
        self._executor = ThreadPoolExecutor(
            max_workers=MAX_WORKERS,
            thread_name_prefix="rdns",
        )

    def stop(self):
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
        with self._lock:
            self._in_flight.clear()

    def clear(self):
        """Called when capture data is cleared. Keep DNS caches."""
        with self._lock:
            self._in_flight.clear()

    def submit(self, ip: str):
        """Queue rDNS lookup for ip. No-op if cached, in-flight, or recently failed."""
        if not self._executor:
            return

        with self._lock:
            if ip in self._cache:
                return
            if ip in self._in_flight:
                return
            if ip in self._failed:
                if time.monotonic() - self._failed[ip] < NEGATIVE_TTL:
                    return
                del self._failed[ip]
            self._in_flight.add(ip)

        self._executor.submit(self._resolve, ip)

    def _resolve(self, ip: str):
        hostname = None
        done = threading.Event()

        def _lookup():
            nonlocal hostname
            try:
                result = socket.gethostbyaddr(ip)
                hostname = result[0].lower().rstrip(".")
            except (socket.herror, socket.gaierror, OSError):
                pass
            except Exception as e:
                logger.debug(f"rDNS unexpected error for {ip}: {e}")
            finally:
                done.set()

        t = threading.Thread(target=_lookup, daemon=True)
        t.start()
        done.wait(timeout=RESOLVE_TIMEOUT)

        with self._lock:
            self._in_flight.discard(ip)
            if hostname:
                self._cache[ip] = hostname
            else:
                self._failed[ip] = time.monotonic()

        try:
            self._on_resolved(ip, hostname)
        except Exception as e:
            logger.debug(f"rDNS callback error: {e}")
