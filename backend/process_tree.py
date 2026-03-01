"""
Process tree tracking module.
Monitors target processes and all their child processes recursively.
Supports tracking multiple root PIDs simultaneously.
"""

import threading
import time
import psutil


class ProcessTree:
    def __init__(self):
        self._lock = threading.Lock()
        self._target_pids = set()
        self._tracked_pids = set()
        self._target_name = None  # exe name for auto-discovery
        self._update_thread = None
        self._running = False

    @property
    def target_pids(self):
        with self._lock:
            return set(self._target_pids)

    @property
    def tracked_pids(self):
        """Return all currently tracked PIDs (target + discovered children)."""
        with self._lock:
            return set(self._tracked_pids)

    def start_tracking(self, pids, process_name=None):
        """Start tracking one or more PIDs and their children.
        pids: int or list of ints
        process_name: if set, auto-discover new processes with this name
        """
        self.stop_tracking()
        if isinstance(pids, int):
            pids = [pids]
        self._target_pids = set(pids)
        self._target_name = process_name.lower() if process_name else None
        self._running = True
        self._update_tracked_pids()
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()

    def stop_tracking(self):
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)
            self._update_thread = None
        with self._lock:
            self._target_pids.clear()
            self._tracked_pids.clear()
        self._target_name = None

    def is_tracked(self, pid: int) -> bool:
        with self._lock:
            return pid in self._tracked_pids

    def _update_tracked_pids(self):
        if not self._target_pids and not self._target_name:
            return
        new_pids = set()

        # Auto-discover new processes matching target name
        if self._target_name:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    info = proc.info
                    if info["name"] and info["name"].lower() == self._target_name:
                        self._target_pids.add(info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        # Track all target PIDs and their children
        for target_pid in set(self._target_pids):
            try:
                proc = psutil.Process(target_pid)
                new_pids.add(target_pid)
                for child in proc.children(recursive=True):
                    new_pids.add(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if new_pids:
            with self._lock:
                self._tracked_pids = new_pids

    def _update_loop(self):
        while self._running:
            time.sleep(2)
            if self._running:
                self._update_tracked_pids()

    @staticmethod
    def get_process_list():
        """Return list of running processes with basic info."""
        processes = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                if info["pid"] == 0:
                    continue
                processes.append({
                    "pid": info["pid"],
                    "name": info["name"] or "Unknown",
                    "exe": info["exe"] or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        processes.sort(key=lambda p: p["name"].lower())
        return processes
