"""
Aggregator module: deduplication, IP-to-domain mapping, grouping.
"""

import threading
import ipaddress
from datetime import datetime, timezone

import tldextract


# Default AntiZapret-VPN tunnel IP ranges
_DEFAULT_TUNNEL_NETWORKS = [
    ipaddress.ip_network("10.29.0.0/16"),
    ipaddress.ip_network("10.30.0.0/15"),
]


def _normalize_ip(ip_str: str) -> str:
    """Normalize IP: strip ::ffff: prefix, whitespace, trailing dots."""
    ip_str = ip_str.strip().rstrip(".")
    # Handle IPv4-mapped IPv6 (::ffff:1.2.3.4 → 1.2.3.4)
    if ip_str.startswith("::ffff:"):
        ip_str = ip_str[7:]
    return ip_str


class Aggregator:
    def __init__(self):
        self._lock = threading.Lock()
        # domain -> entry dict
        self._entries = {}
        # ip -> domain mapping from DNS events
        self._ip_to_domain = {}
        # ip-only entries (no domain resolved yet), keyed by ip string
        self._ip_only = {}
        # Tunnel networks for VPN detection
        self._tunnel_networks = list(_DEFAULT_TUNNEL_NETWORKS)

    def set_tunnel_networks(self, cidrs):
        """Replace tunnel networks with given CIDR list and re-evaluate all entries."""
        with self._lock:
            nets = []
            for cidr in cidrs:
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
            self._tunnel_networks = nets if nets else list(_DEFAULT_TUNNEL_NETWORKS)
            for entry in self._entries.values():
                entry["tunneled"] = self._check_tunneled(entry["ips"])
            for entry in self._ip_only.values():
                entry["tunneled"] = self._check_tunneled(entry["ips"])

    def get_tunnel_networks(self):
        """Return current tunnel networks as CIDR strings."""
        with self._lock:
            return [str(n) for n in self._tunnel_networks]

    def _is_tunneled(self, ip_str):
        """Check if a single IP falls within tunnel networks."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self._tunnel_networks)
        except ValueError:
            return False

    def _check_tunneled(self, ips):
        """Check if any IP in the list is tunneled."""
        return any(self._is_tunneled(ip) for ip in ips)

    def clear(self):
        with self._lock:
            self._entries.clear()
            # Keep _ip_to_domain — DNS mapping persists across captures
            self._ip_only.clear()

    def get_snapshot(self):
        with self._lock:
            result = list(self._entries.values())
            result.extend(self._ip_only.values())
            return [dict(e) for e in result]

    def handle_dns_event(self, domain: str, resolved_ips: list, from_tracked: bool = False):
        """Process a DNS resolution event.
        Always builds IP→domain mapping.
        Creates/updates table entries only if from_tracked=True (query from tracked process)
        or if there's an existing ip_only entry to merge.
        """
        if not domain:
            return None
        domain = domain.lower().rstrip(".")
        now = datetime.now(timezone.utc).isoformat()
        result_entry = None

        # Normalize all IPs
        resolved_ips = [_normalize_ip(ip) for ip in resolved_ips if _normalize_ip(ip)]

        with self._lock:
            # Always map IPs to this domain
            for ip in resolved_ips:
                self._ip_to_domain[ip] = domain

            # Merge any ip_only entries under this domain
            for ip in resolved_ips:
                if ip in self._ip_only:
                    ip_entry = self._ip_only.pop(ip)
                    entry = self._entries.get(domain)
                    if entry is None:
                        reg_domain = self._get_registered_domain(domain)
                        entry = {
                            "domain": domain,
                            "registered_domain": reg_domain,
                            "ips": list(set(resolved_ips)),
                            "ports": list(ip_entry["ports"]),
                            "protocol": ip_entry.get("protocol", ""),
                            "first_seen": ip_entry["first_seen"],
                            "last_seen": now,
                            "hit_count": ip_entry["hit_count"],
                            "source": "both",
                            "resolve_status": "resolved",
                            "tunneled": self._check_tunneled(resolved_ips),
                            "conn_failed": ip_entry.get("conn_failed", False),
                        }
                        self._entries[domain] = entry
                    else:
                        existing_ports = set(entry["ports"])
                        existing_ports.update(ip_entry["ports"])
                        entry["ports"] = sorted(existing_ports)
                        existing_ips = set(entry["ips"])
                        existing_ips.add(ip)
                        entry["ips"] = list(existing_ips)
                        if ip_entry.get("protocol"):
                            if entry["protocol"] and entry["protocol"] != ip_entry["protocol"]:
                                entry["protocol"] = "TCP/UDP"
                            else:
                                entry["protocol"] = ip_entry["protocol"]
                        entry["hit_count"] += ip_entry["hit_count"]
                        entry["last_seen"] = now
                        entry["source"] = "both"
                        entry["tunneled"] = self._check_tunneled(entry["ips"])
                        if ip_entry.get("conn_failed"):
                            entry["conn_failed"] = True
                    result_entry = dict(entry)

            # If DNS query came from a tracked process, create entry even without connection
            if from_tracked and resolved_ips:
                entry = self._entries.get(domain)
                if entry is None:
                    reg_domain = self._get_registered_domain(domain)
                    entry = {
                        "domain": domain,
                        "registered_domain": reg_domain,
                        "ips": list(set(resolved_ips)),
                        "ports": [],
                        "protocol": "",
                        "first_seen": now,
                        "last_seen": now,
                        "hit_count": 1,
                        "source": "dns",
                        "resolve_status": "resolved",
                        "tunneled": self._check_tunneled(resolved_ips),
                        "conn_failed": False,
                    }
                    self._entries[domain] = entry
                else:
                    existing_ips = set(entry["ips"])
                    existing_ips.update(resolved_ips)
                    entry["ips"] = list(existing_ips)
                    entry["last_seen"] = now
                    entry["hit_count"] += 1
                    entry["tunneled"] = self._check_tunneled(entry["ips"])
                result_entry = dict(entry)

        return result_entry

    def handle_connection_event(self, dest_ip: str, dest_port: int, protocol: str):
        """Process a TCP/UDP connection event."""
        if not dest_ip:
            return None
        dest_ip = _normalize_ip(dest_ip)
        if not dest_ip:
            return None
        # Skip local/multicast
        try:
            addr = ipaddress.ip_address(dest_ip)
            if addr.is_loopback or addr.is_multicast or addr.is_link_local:
                return None
        except ValueError:
            return None

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            domain = self._ip_to_domain.get(dest_ip)
            if domain:
                entry = self._entries.get(domain)
                if entry:
                    existing_ports = set(entry["ports"])
                    existing_ports.add(dest_port)
                    entry["ports"] = sorted(existing_ports)
                    existing_ips = set(entry["ips"])
                    existing_ips.add(dest_ip)
                    entry["ips"] = list(existing_ips)
                    if entry["protocol"] and entry["protocol"] != protocol:
                        entry["protocol"] = "TCP/UDP"
                    else:
                        entry["protocol"] = protocol
                    entry["last_seen"] = now
                    entry["hit_count"] += 1
                    if entry["source"] == "dns":
                        entry["source"] = "both"
                    entry["tunneled"] = self._check_tunneled(entry["ips"])
                    return dict(entry)
                else:
                    # Domain known from DNS but no entry yet — create it
                    reg_domain = self._get_registered_domain(domain)
                    entry = {
                        "domain": domain,
                        "registered_domain": reg_domain,
                        "ips": [dest_ip],
                        "ports": [dest_port],
                        "protocol": protocol,
                        "first_seen": now,
                        "last_seen": now,
                        "hit_count": 1,
                        "source": "both",
                        "resolve_status": "resolved",
                        "tunneled": self._is_tunneled(dest_ip),
                        "conn_failed": False,
                    }
                    self._entries[domain] = entry
                    return dict(entry)

            # No domain mapping — store as ip_only
            if dest_ip in self._ip_only:
                entry = self._ip_only[dest_ip]
                existing_ports = set(entry["ports"])
                existing_ports.add(dest_port)
                entry["ports"] = sorted(existing_ports)
                if entry["protocol"] and entry["protocol"] != protocol:
                    entry["protocol"] = "TCP/UDP"
                else:
                    entry["protocol"] = protocol
                entry["last_seen"] = now
                entry["hit_count"] += 1
                return dict(entry)
            else:
                entry = {
                    "domain": dest_ip,
                    "registered_domain": dest_ip,
                    "ips": [dest_ip],
                    "ports": [dest_port],
                    "protocol": protocol,
                    "first_seen": now,
                    "last_seen": now,
                    "hit_count": 1,
                    "source": "connection",
                    "resolve_status": "pending",
                    "tunneled": self._is_tunneled(dest_ip),
                    "conn_failed": False,
                }
                self._ip_only[dest_ip] = entry
                return dict(entry)

    def promote_ip_to_domain(self, ip: str, hostname: str):
        """Called when rDNS resolves ip to hostname.
        Moves ip_only entry into _entries under the hostname.
        Returns the resulting entry dict, or None.
        """
        ip = _normalize_ip(ip)
        hostname = hostname.lower().rstrip(".")
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            # If ETW already resolved this IP, skip
            if ip in self._ip_to_domain:
                return None

            ip_entry = self._ip_only.pop(ip, None)
            if ip_entry is None:
                return None

            self._ip_to_domain[ip] = hostname
            reg_domain = self._get_registered_domain(hostname)
            existing = self._entries.get(hostname)

            if existing is None:
                entry = {
                    "domain": hostname,
                    "registered_domain": reg_domain,
                    "ips": list(set(ip_entry["ips"])),
                    "ports": list(ip_entry["ports"]),
                    "protocol": ip_entry.get("protocol", ""),
                    "first_seen": ip_entry["first_seen"],
                    "last_seen": now,
                    "hit_count": ip_entry["hit_count"],
                    "source": ip_entry.get("source", "connection"),
                    "resolve_status": "resolved",
                    "tunneled": self._check_tunneled(ip_entry["ips"]),
                    "conn_failed": ip_entry.get("conn_failed", False),
                }
                self._entries[hostname] = entry
            else:
                existing_ports = set(existing["ports"])
                existing_ports.update(ip_entry["ports"])
                existing["ports"] = sorted(existing_ports)
                existing_ips = set(existing["ips"])
                existing_ips.add(ip)
                existing["ips"] = list(existing_ips)
                if ip_entry.get("protocol"):
                    if existing["protocol"] and existing["protocol"] != ip_entry["protocol"]:
                        existing["protocol"] = "TCP/UDP"
                    else:
                        existing["protocol"] = ip_entry["protocol"]
                existing["hit_count"] += ip_entry["hit_count"]
                existing["last_seen"] = now
                existing["resolve_status"] = "resolved"
                existing["tunneled"] = self._check_tunneled(existing["ips"])
                if ip_entry.get("conn_failed"):
                    existing["conn_failed"] = True
                entry = existing

            return dict(entry)

    def mark_connection_failed(self, dest_ip: str):
        """Mark entry containing this IP as having failed connections.
        Returns updated entry dict or None.
        """
        dest_ip = _normalize_ip(dest_ip)
        with self._lock:
            # Check domain entries
            domain = self._ip_to_domain.get(dest_ip)
            if domain and domain in self._entries:
                self._entries[domain]["conn_failed"] = True
                return dict(self._entries[domain])
            # Check ip_only entries
            if dest_ip in self._ip_only:
                self._ip_only[dest_ip]["conn_failed"] = True
                return dict(self._ip_only[dest_ip])
        return None

    def get_ip_only_keys(self):
        """Return current set of ip_only keys (for detecting merges)."""
        with self._lock:
            return set(self._ip_only.keys())

    def mark_ip_resolve_failed(self, ip: str):
        """Marks a pending ip_only entry as resolve_status='failed'.
        Returns updated entry dict or None.
        """
        ip = _normalize_ip(ip)
        with self._lock:
            entry = self._ip_only.get(ip)
            if entry is None:
                return None
            entry["resolve_status"] = "failed"
            return dict(entry)

    @staticmethod
    def _get_registered_domain(domain: str) -> str:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return domain

    @staticmethod
    def aggregate_ips_to_subnets(ips: list) -> list:
        """Group IPs into /24 subnets if 3+ IPs share it, else keep as /32."""
        subnet_map = {}
        for ip_str in ips:
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version == 4:
                    network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                    key = str(network)
                    subnet_map.setdefault(key, []).append(ip_str)
                else:
                    subnet_map[f"{ip_str}/128"] = [ip_str]
            except ValueError:
                continue

        result = []
        for subnet, addrs in subnet_map.items():
            if len(addrs) >= 3:
                result.append(subnet)
            else:
                for a in addrs:
                    try:
                        addr = ipaddress.ip_address(a)
                        if addr.version == 4:
                            result.append(f"{a}/32")
                        else:
                            result.append(f"{a}/128")
                    except ValueError:
                        pass

        # Collapse overlapping networks
        try:
            networks = [ipaddress.ip_network(n) for n in result]
            collapsed = list(ipaddress.collapse_addresses(networks))
            return sorted([str(n) for n in collapsed])
        except Exception:
            return sorted(result)
