"""
ETW Tracer module.
Uses DNS-Client ETW for domain name resolution (IP→domain mapping).
Uses GetExtendedTcpTable/UdpTable for fast connection tracking (50ms polling).
Falls back to psutil polling when WinAPI is unavailable.
"""

import ctypes
import ctypes.wintypes as wintypes
import ipaddress
import socket
import struct
import threading
import time
import logging

logger = logging.getLogger(__name__)

ETW_AVAILABLE = False
try:
    from etw import ETW, ProviderInfo
    from etw.GUID import GUID
    ETW_AVAILABLE = True
except ImportError:
    logger.warning("pywintrace not available, will use psutil-only fallback")

try:
    import psutil
except ImportError:
    psutil = None


# ETW Provider GUIDs
DNS_CLIENT_GUID = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"


def is_admin():
    """Check if the process is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# WinAPI structures for GetExtendedTcpTable / GetExtendedUdpTable
# ---------------------------------------------------------------------------

AF_INET = 2
AF_INET6 = 23

# TCP_TABLE_OWNER_PID_ALL = 5  (includes all TCP states with owning PID)
TCP_TABLE_OWNER_PID_ALL = 5
# UDP_TABLE_OWNER_PID = 1
UDP_TABLE_OWNER_PID = 1

_iphlpapi = ctypes.windll.iphlpapi
_ws2_32 = ctypes.windll.ws2_32


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * 1),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_UDPROW_OWNER_PID * 1),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_UDP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_UDP6ROW_OWNER_PID * 1),
    ]


def _ipv4_from_dword(dw):
    """Convert a DWORD (network byte order) to IPv4 string."""
    return socket.inet_ntoa(struct.pack('<I', dw))


def _ipv6_from_bytes(addr_bytes):
    """Convert 16 bytes to IPv6 string."""
    return str(ipaddress.IPv6Address(bytes(addr_bytes)))


def _port_from_dword(dw):
    """Convert port from network byte order DWORD to host int."""
    return _ws2_32.ntohs(dw & 0xFFFF)


def _get_extended_table(func, table_class, row_class, family, table_type):
    """Generic helper to call GetExtendedTcpTable or GetExtendedUdpTable."""
    size = wintypes.DWORD(0)
    # First call: get required buffer size
    func(None, ctypes.byref(size), False, family, table_type, 0)
    if size.value == 0:
        return []

    buf = (ctypes.c_byte * size.value)()
    ret = func(buf, ctypes.byref(size), False, family, table_type, 0)
    if ret != 0:
        return []

    # Parse the table header to get entry count
    table = ctypes.cast(buf, ctypes.POINTER(table_class)).contents
    count = table.dwNumEntries
    if count == 0:
        return []

    # Calculate offset past the dwNumEntries field to the first row
    row_array_type = row_class * count
    offset = ctypes.sizeof(wintypes.DWORD)  # skip dwNumEntries
    row_array = (row_array_type).from_buffer_copy(
        buf, offset
    )
    return list(row_array)


class FastConnectionPoller:
    """Fast network connection tracker using GetExtendedTcpTable/UdpTable (50ms polling).

    Much faster than psutil.net_connections() — direct WinAPI calls via ctypes.
    Polls every 50ms to catch short-lived connections that 500ms polling misses.
    """

    POLL_INTERVAL = 0.05  # 50ms

    def __init__(self, process_tree, on_connection_event):
        self._process_tree = process_tree
        self._on_connection = on_connection_event
        self._running = False
        self._thread = None
        self._seen_connections = set()

    def start(self):
        self._running = True
        self._seen_connections.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("FastConnectionPoller started (50ms interval)")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._seen_connections.clear()

    def _poll_loop(self):
        while self._running:
            try:
                self._poll_tcp4()
                self._poll_tcp6()
            except Exception as e:
                logger.debug(f"FastConnectionPoller error: {e}")

            # Prevent unbounded growth of dedup set
            if len(self._seen_connections) > 50000:
                self._seen_connections.clear()

            time.sleep(self.POLL_INTERVAL)

    def _poll_tcp4(self):
        rows = _get_extended_table(
            _iphlpapi.GetExtendedTcpTable,
            MIB_TCPTABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
        )
        for row in rows:
            if not self._running:
                break
            pid = row.dwOwningPid
            if not pid or not self._process_tree.is_tracked(pid):
                continue
            remote_addr = row.dwRemoteAddr
            if remote_addr == 0:  # no remote connection yet
                continue
            ip = _ipv4_from_dword(remote_addr)
            port = _port_from_dword(row.dwRemotePort)
            if port == 0:
                continue
            key = (pid, ip, port)
            if key not in self._seen_connections:
                self._seen_connections.add(key)
                self._on_connection(ip, port, "TCP")

    def _poll_tcp6(self):
        rows = _get_extended_table(
            _iphlpapi.GetExtendedTcpTable,
            MIB_TCP6TABLE_OWNER_PID,
            MIB_TCP6ROW_OWNER_PID,
            AF_INET6,
            TCP_TABLE_OWNER_PID_ALL,
        )
        for row in rows:
            if not self._running:
                break
            pid = row.dwOwningPid
            if not pid or not self._process_tree.is_tracked(pid):
                continue
            remote_bytes = bytes(row.ucRemoteAddr)
            if remote_bytes == b'\x00' * 16:
                continue
            ip = _ipv6_from_bytes(remote_bytes)
            port = _port_from_dword(row.dwRemotePort)
            if port == 0:
                continue
            key = (pid, ip, port)
            if key not in self._seen_connections:
                self._seen_connections.add(key)
                self._on_connection(ip, port, "TCP")

class RawSocketUdpCapture:
    """Captures UDP traffic via raw socket + maps to PIDs via GetExtendedUdpTable.

    GetExtendedUdpTable only gives local port → PID (no remote addresses).
    Raw socket captures actual packets with remote IP:port.
    We combine both: raw socket for packet data, UDP table for PID mapping.
    """

    SIO_RCVALL = 0x98000001
    RCVALL_ON = 1
    RCVALL_OFF = 0
    UDP_TABLE_REFRESH = 0.2  # refresh local_port→PID map every 200ms

    def __init__(self, process_tree, on_connection_event):
        self._process_tree = process_tree
        self._on_connection = on_connection_event
        self._running = False
        self._capture_thread = None
        self._table_thread = None
        self._raw_sock = None
        self._seen_connections = set()
        self._local_port_to_pid = {}  # {local_port: pid}
        self._port_lock = threading.Lock()

    def start(self):
        self._running = True
        self._seen_connections.clear()

        # Start UDP table poller (builds local_port → PID mapping)
        self._table_thread = threading.Thread(target=self._udp_table_loop, daemon=True)
        self._table_thread.start()

        # Start raw socket capture
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        logger.info("RawSocketUdpCapture started")

    def stop(self):
        self._running = False
        # Close socket to unblock recv()
        if self._raw_sock:
            try:
                self._raw_sock.ioctl(self.SIO_RCVALL, self.RCVALL_OFF)
            except Exception:
                pass
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
            self._capture_thread = None
        if self._table_thread:
            self._table_thread.join(timeout=5)
            self._table_thread = None
        self._seen_connections.clear()
        self._local_port_to_pid.clear()

    def _udp_table_loop(self):
        """Periodically poll GetExtendedUdpTable to build local_port → PID map."""
        while self._running:
            try:
                port_map = {}
                # IPv4 UDP
                rows = _get_extended_table(
                    _iphlpapi.GetExtendedUdpTable,
                    MIB_UDPTABLE_OWNER_PID,
                    MIB_UDPROW_OWNER_PID,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                )
                for row in rows:
                    pid = row.dwOwningPid
                    if pid and self._process_tree.is_tracked(pid):
                        port = _port_from_dword(row.dwLocalPort)
                        if port:
                            port_map[port] = pid
                # IPv6 UDP
                rows6 = _get_extended_table(
                    _iphlpapi.GetExtendedUdpTable,
                    MIB_UDP6TABLE_OWNER_PID,
                    MIB_UDP6ROW_OWNER_PID,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                )
                for row in rows6:
                    pid = row.dwOwningPid
                    if pid and self._process_tree.is_tracked(pid):
                        port = _port_from_dword(row.dwLocalPort)
                        if port:
                            port_map[port] = pid

                with self._port_lock:
                    self._local_port_to_pid = port_map
            except Exception as e:
                logger.debug(f"UDP table poll error: {e}")

            time.sleep(self.UDP_TABLE_REFRESH)

    def _capture_loop(self):
        """Capture raw IP packets and extract UDP traffic."""
        try:
            # Determine local IP for binding
            host_ip = self._get_local_ip()
            self._raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._raw_sock.bind((host_ip, 0))
            # Enable promiscuous mode to receive all packets
            self._raw_sock.ioctl(self.SIO_RCVALL, self.RCVALL_ON)
            self._raw_sock.settimeout(1.0)  # timeout for clean shutdown
            logger.info(f"Raw socket bound to {host_ip}, capturing UDP packets")
        except Exception as e:
            logger.error(f"Failed to open raw socket: {e}")
            return

        while self._running:
            try:
                data = self._raw_sock.recv(65535)
                if len(data) < 28:  # minimum IP(20) + UDP(8) header
                    continue
                self._process_packet(data)
            except socket.timeout:
                continue
            except OSError:
                if not self._running:
                    break
                logger.debug("Raw socket recv error")
                break

    def _process_packet(self, data):
        """Parse IP packet and handle UDP."""
        # IP header
        ihl = (data[0] & 0x0F) * 4
        protocol = data[9]

        if protocol != 17:  # Not UDP
            return

        if len(data) < ihl + 4:
            return

        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        src_port, dst_port = struct.unpack('!HH', data[ihl:ihl + 4])

        # Skip local/multicast/broadcast
        try:
            dst_addr = ipaddress.ip_address(dst_ip)
            src_addr = ipaddress.ip_address(src_ip)
            if dst_addr.is_loopback or dst_addr.is_multicast or dst_addr.is_link_local:
                return
            if src_addr.is_loopback or src_addr.is_multicast or src_addr.is_link_local:
                return
        except ValueError:
            return

        # Match packet to tracked process via local port
        with self._port_lock:
            port_map = self._local_port_to_pid

        # Check if src_port (outgoing) or dst_port (incoming) belongs to tracked process
        pid = port_map.get(src_port) or port_map.get(dst_port)
        if not pid:
            return

        # Determine remote IP:port (the other end)
        if src_port in port_map:
            # Outgoing: src is local, dst is remote
            remote_ip, remote_port = dst_ip, dst_port
        else:
            # Incoming: dst is local, src is remote
            remote_ip, remote_port = src_ip, src_port

        if remote_port == 0:
            return

        # Deduplicate
        key = (pid, remote_ip, remote_port)
        if key in self._seen_connections:
            return

        if len(self._seen_connections) > 50000:
            self._seen_connections.clear()

        self._seen_connections.add(key)
        self._on_connection(remote_ip, remote_port, "UDP")

    @staticmethod
    def _get_local_ip():
        """Get the primary local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"


class ETWTracer:
    """Hybrid tracer: DNS ETW + GetExtendedTcpTable (TCP) + raw socket (UDP)."""

    def __init__(self, process_tree, on_dns_event, on_connection_event):
        self._process_tree = process_tree
        self._on_dns = on_dns_event
        self._on_connection = on_connection_event
        self._running = False
        self._dns_etw = None
        self._dns_thread = None
        self._connection_poller = None
        self._udp_capture = None

    def start(self):
        if not ETW_AVAILABLE:
            raise RuntimeError("ETW not available")
        if not is_admin():
            raise RuntimeError("ETW requires administrator privileges")
        self._running = True

        # Start DNS ETW for domain name resolution
        self._dns_thread = threading.Thread(target=self._run_dns_trace, daemon=True)
        self._dns_thread.start()

        # Start fast TCP connection poller (GetExtendedTcpTable, 50ms)
        self._connection_poller = FastConnectionPoller(
            self._process_tree, self._on_connection
        )
        self._connection_poller.start()

        # Start raw socket UDP capture
        try:
            self._udp_capture = RawSocketUdpCapture(
                self._process_tree, self._on_connection
            )
            self._udp_capture.start()
        except Exception as e:
            logger.warning(f"UDP raw socket capture failed: {e}")
            self._udp_capture = None

        logger.info("ETW tracer started: DNS ETW + TCP poller + UDP capture")

    def stop(self):
        self._running = False
        if self._dns_etw is not None:
            try:
                self._dns_etw.stop()
            except Exception as e:
                logger.debug(f"Error stopping DNS ETW: {e}")
            self._dns_etw = None
        if self._connection_poller:
            self._connection_poller.stop()
            self._connection_poller = None
        if self._udp_capture:
            self._udp_capture.stop()
            self._udp_capture = None
        if self._dns_thread:
            self._dns_thread.join(timeout=5)
            self._dns_thread = None

    def _run_dns_trace(self):
        try:
            providers = [ProviderInfo("Microsoft-Windows-DNS-Client",
                                      GUID(DNS_CLIENT_GUID))]
            self._dns_etw = ETW(providers=providers,
                                event_callback=self._handle_dns_event)
            self._dns_etw.start()
        except Exception as e:
            logger.error(f"DNS ETW trace failed: {e}")

    def _handle_dns_event(self, event_tufo):
        if not self._running:
            return
        try:
            if isinstance(event_tufo, (tuple, list)):
                event_id, event = event_tufo
            elif isinstance(event_tufo, dict):
                event = event_tufo
            else:
                event = event_tufo

            if not isinstance(event, dict):
                return

            query_name = event.get("QueryName", "")
            query_results = event.get("QueryResults", "")
            if not query_name:
                return

            # ClientPID = PID of the app that made the DNS query
            client_pid = int(event.get("ClientPID", 0))

            ips = []
            if query_results:
                for part in str(query_results).split(";"):
                    part = part.strip()
                    if part and not part.startswith("type"):
                        ips.append(part)

            self._on_dns(query_name, ips, client_pid)
        except Exception as e:
            logger.debug(f"Error processing DNS event: {e}")


class PsutilFallbackTracer:
    """Network connection tracker using psutil polling (fallback when WinAPI unavailable)."""

    def __init__(self, process_tree, on_connection_event):
        self._process_tree = process_tree
        self._on_connection = on_connection_event
        self._running = False
        self._thread = None
        self._seen_connections = set()

    def start(self):
        self._running = True
        self._seen_connections.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._seen_connections.clear()

    def _poll_loop(self):
        while self._running:
            try:
                connections = psutil.net_connections(kind="inet")
                for conn in connections:
                    if not self._running:
                        break
                    if conn.pid and self._process_tree.is_tracked(conn.pid):
                        if conn.raddr:
                            ip = conn.raddr.ip
                            port = conn.raddr.port
                            key = (conn.pid, ip, port)
                            if key not in self._seen_connections:
                                self._seen_connections.add(key)
                                proto = "TCP" if conn.type == 1 else "UDP"
                                self._on_connection(ip, port, proto)
            except Exception as e:
                logger.debug(f"Psutil polling error: {e}")
            time.sleep(0.5)
