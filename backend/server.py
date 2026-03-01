"""
WebSocket server — entry point for the Python backend.
Communicates with the Electron frontend via JSON messages.
"""

import asyncio
import json
import logging
import signal
import sys
import threading
import time

import websockets

from process_tree import ProcessTree
from aggregator import Aggregator
from blacklist import Blacklist
from etw_tracer import ETW_AVAILABLE, ETWTracer, PsutilFallbackTracer
from rdns_resolver import ReverseDNSResolver
from dns_cache import DnsCachePoller

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("server")

HOST = "localhost"
PORT = 18765


class Backend:
    def __init__(self):
        self.process_tree = ProcessTree()
        self.aggregator = Aggregator()
        self.blacklist = Blacklist()
        self.tracer = None
        self.capturing = False
        self.target_pids = []
        self.target_name = ""
        self.capture_start_time = None
        self.ws_client = None

        # Reverse DNS resolver for ip-only entries
        self._rdns = ReverseDNSResolver(self._on_rdns_result)
        # DNS cache poller for reliable domain resolution
        self._dns_cache = DnsCachePoller(self._on_dns_cache_mapping)

        # Batching: accumulate updates and flush periodically
        self._pending_updates = []
        self._pending_removes = []
        self._pending_lock = threading.Lock()
        self._batch_thread = None
        self._batch_running = False

    # --- Event callbacks (called from tracer threads) ---

    def _on_dns_event(self, domain, ips, client_pid=0):
        # Check if the DNS query came from a tracked process
        from_tracked = self.process_tree.is_tracked(client_pid) if client_pid else False
        entry = self.aggregator.handle_dns_event(domain, ips, from_tracked)
        if entry:
            self._queue_update(entry)

    def _on_connection_event(self, ip, port, protocol):
        entry = self.aggregator.handle_connection_event(ip, port, protocol)
        if entry:
            self._queue_update(entry)
            if entry.get("resolve_status") == "pending":
                self._rdns.submit(entry["ips"][0])

    def _on_rdns_result(self, ip, hostname):
        if hostname:
            entry = self.aggregator.promote_ip_to_domain(ip, hostname)
            if entry:
                self._queue_update(entry)
                self._queue_remove(ip)
        else:
            entry = self.aggregator.mark_ip_resolve_failed(ip)
            if entry:
                self._queue_update(entry)

    def _on_dns_cache_mapping(self, domain, ips):
        """Called by DnsCachePoller when new domain→IP mappings are found in DNS cache."""
        # Snapshot ip_only keys before to detect merges
        ip_only_before = self.aggregator.get_ip_only_keys()
        entry = self.aggregator.handle_dns_event(domain, ips, from_tracked=False)
        if entry:
            self._queue_update(entry)
            # Check which ip_only entries were merged (removed from ip_only)
            ip_only_after = self.aggregator.get_ip_only_keys()
            merged_ips = ip_only_before - ip_only_after
            for ip in merged_ips:
                self._queue_remove(ip)

    def _on_connection_failed(self, ip, port, protocol):
        """Called when a TCP connection failed (SYN_SENT timeout)."""
        entry = self.aggregator.mark_connection_failed(ip)
        if entry:
            self._queue_update(entry)

    def _queue_update(self, entry):
        with self._pending_lock:
            self._pending_updates.append(entry)

    def _queue_remove(self, domain_key):
        with self._pending_lock:
            self._pending_removes.append(domain_key)

    def _start_batch_sender(self):
        self._batch_running = True
        self._batch_thread = threading.Thread(target=self._batch_loop, daemon=True)
        self._batch_thread.start()

    def _stop_batch_sender(self):
        self._batch_running = False
        if self._batch_thread:
            self._batch_thread.join(timeout=3)
            self._batch_thread = None

    def _batch_loop(self):
        loop = None
        last_tracked_count = 0
        tick = 0
        while self._batch_running:
            time.sleep(0.5)
            tick += 1

            # Send process count updates every 2 seconds (4 ticks * 0.5s)
            if tick % 4 == 0 and self.capturing and self.ws_client:
                try:
                    current_count = len(self.process_tree.tracked_pids)
                    if current_count != last_tracked_count:
                        last_tracked_count = current_count
                        msg = json.dumps({
                            "type": "process_count_updated",
                            "count": current_count,
                            "process_name": self.target_name,
                        })
                        if loop is None:
                            loop = asyncio.new_event_loop()
                        loop.run_until_complete(self.ws_client.send(msg))
                except Exception as e:
                    logger.debug(f"Process count update error: {e}")
            with self._pending_lock:
                updates = self._pending_updates[:]
                removes = self._pending_removes[:]
                self._pending_updates.clear()
                self._pending_removes.clear()
            if not self.ws_client:
                continue
            if updates:
                # Deduplicate: keep latest entry per domain
                seen = {}
                for entry in updates:
                    seen[entry["domain"]] = entry
                for entry in seen.values():
                    is_bl = self.blacklist.is_blacklisted(entry.get("domain", ""))
                    entry["blacklisted"] = is_bl
                    msg = json.dumps({"type": "entry_updated", "entry": entry})
                    try:
                        if loop is None:
                            loop = asyncio.new_event_loop()
                        loop.run_until_complete(self.ws_client.send(msg))
                    except Exception as e:
                        logger.debug(f"Send error: {e}")
            for key in removes:
                msg = json.dumps({"type": "entry_removed", "domain": key})
                try:
                    if loop is None:
                        loop = asyncio.new_event_loop()
                    loop.run_until_complete(self.ws_client.send(msg))
                except Exception as e:
                    logger.debug(f"Send remove error: {e}")

    # --- Message handlers ---

    async def handle_message(self, ws, raw):
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            await ws.send(json.dumps({"type": "error", "message": "Invalid JSON"}))
            return

        msg_type = msg.get("type", "")

        if msg_type == "get_processes":
            processes = ProcessTree.get_process_list()
            await ws.send(json.dumps({"type": "process_list", "processes": processes}))

        elif msg_type == "start_capture":
            pids = msg.get("pids") or []
            # Backward compat: single pid field
            if not pids and msg.get("pid"):
                pids = [msg["pid"]]
            pids = [int(p) for p in pids]
            if not pids:
                await ws.send(json.dumps({"type": "error", "message": "No PIDs provided"}))
                return
            await self._start_capture(ws, pids)

        elif msg_type == "stop_capture":
            await self._stop_capture(ws)

        elif msg_type == "get_snapshot":
            snapshot = self.aggregator.get_snapshot()
            for entry in snapshot:
                entry["blacklisted"] = self.blacklist.is_blacklisted(entry.get("domain", ""))
            await ws.send(json.dumps({"type": "snapshot", "entries": snapshot}))

        elif msg_type == "clear_data":
            self.aggregator.clear()
            await ws.send(json.dumps({"type": "data_cleared"}))

        elif msg_type == "update_blacklist":
            patterns = msg.get("patterns", [])
            self.blacklist.patterns = patterns
            await ws.send(json.dumps({
                "type": "blacklist_updated",
                "patterns": self.blacklist.patterns,
            }))

        elif msg_type == "get_blacklist":
            await ws.send(json.dumps({
                "type": "blacklist_patterns",
                "patterns": self.blacklist.patterns,
            }))

        elif msg_type == "export_subnets":
            ips = msg.get("ips", [])
            subnets = Aggregator.aggregate_ips_to_subnets(ips)
            await ws.send(json.dumps({"type": "subnets", "subnets": subnets}))

        elif msg_type == "update_tunnel_networks":
            networks = msg.get("networks", [])
            self.aggregator.set_tunnel_networks(networks)
            await ws.send(json.dumps({
                "type": "tunnel_networks_updated",
                "networks": self.aggregator.get_tunnel_networks(),
            }))

        else:
            await ws.send(json.dumps({"type": "error", "message": f"Unknown type: {msg_type}"}))

    async def _start_capture(self, ws, pids):
        if self.capturing:
            await self._stop_capture(ws)

        self.target_pids = pids
        # Resolve process name from first PID
        try:
            import psutil
            proc = psutil.Process(pids[0])
            self.target_name = proc.name()
        except Exception:
            self.target_name = f"PID {pids[0]}"

        # Pass process_name so ProcessTree auto-discovers new processes
        # with the same name (e.g. new Chrome windows opened during capture)
        self.process_tree.start_tracking(pids, process_name=self.target_name)
        self.aggregator.clear()
        self._rdns.clear()
        self._rdns.start()
        self._dns_cache.start()
        self.capture_start_time = time.time()

        use_etw = ETW_AVAILABLE
        if use_etw:
            try:
                self.tracer = ETWTracer(
                    self.process_tree,
                    self._on_dns_event,
                    self._on_connection_event,
                    self._on_connection_failed,
                )
                self.tracer.start()
            except Exception as e:
                logger.warning(f"ETW failed, falling back to psutil: {e}")
                use_etw = False

        if not use_etw:
            self.tracer = PsutilFallbackTracer(
                self.process_tree,
                self._on_connection_event,
            )
            self.tracer.start()
            await ws.send(json.dumps({
                "type": "warning",
                "message": "ETW недоступен (нужны права администратора). Режим psutil: только IP, без DNS.",
            }))

        self.capturing = True
        self._start_batch_sender()

        await ws.send(json.dumps({
            "type": "capture_started",
            "pids": pids,
            "process_name": self.target_name,
            "etw_mode": use_etw,
        }))
        logger.info(f"Capture started for {self.target_name} (PIDs: {pids}), ETW={use_etw}")

    async def _stop_capture(self, ws):
        if not self.capturing:
            return

        self._dns_cache.stop()
        self._rdns.stop()
        self._stop_batch_sender()
        if self.tracer:
            self.tracer.stop()
            self.tracer = None
        self.process_tree.stop_tracking()
        self.capturing = False

        await ws.send(json.dumps({"type": "capture_stopped"}))
        logger.info("Capture stopped")

    # --- WebSocket server ---

    async def handler(self, ws):
        self.ws_client = ws
        logger.info("Client connected")
        try:
            async for message in ws:
                await self.handle_message(ws, message)
        except websockets.ConnectionClosed:
            logger.info("Client disconnected")
        finally:
            if self.capturing:
                self._dns_cache.stop()
                self._rdns.stop()
                self._stop_batch_sender()
                if self.tracer:
                    self.tracer.stop()
                self.process_tree.stop_tracking()
                self.capturing = False
            self.ws_client = None


async def main():
    backend = Backend()
    stop = asyncio.get_event_loop().create_future()

    # Handle graceful shutdown
    def handle_signal():
        if not stop.done():
            stop.set_result(True)

    try:
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, handle_signal)
        loop.add_signal_handler(signal.SIGINT, handle_signal)
    except NotImplementedError:
        # Windows doesn't support add_signal_handler
        pass

    async with websockets.serve(backend.handler, HOST, PORT):
        logger.info(f"WebSocket server running on ws://{HOST}:{PORT}")
        # Print marker for Electron to detect readiness
        print(f"READY:{PORT}", flush=True)
        try:
            await stop
        except asyncio.CancelledError:
            pass

    logger.info("Server shut down")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
