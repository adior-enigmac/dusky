#!/usr/bin/env python3
"""
===============================================================================
DUSKY TUI: UFW FIREWALL ENGINE
===============================================================================
Engine for comprehensive netfilter/iptables management via UFW (Uncomplicated
Firewall). Features:
- Zero-overhead state parsing and synchronous / asynchronous action execution.
- Real-time listening & closed port inspection and prober (socket & firewall cross-check).
- Fast 1-click port opening & closing (TCP, UDP, both; any, LAN, custom IP).
- Common service switches (SSH, HTTP, HTTPS, FTP, DNS, Moonlight, WireGuard, Plex, etc.).
- Active connection monitor (conntrack/ss established states) with instant IP banning.
- Panic network killswitch (instant total network drop & restore).
- Stealth ICMP Ping response toggling (drop ping sweeps).
- Port forwarding / NAT redirection (PREROUTING DNAT).
- Domain & Website filter: dynamic A/AAAA DNS resolution and exclusive Whitelist Lockdown.
- Complete rule lifecycle: add, delete, prepend, insert, reorder.
- Native Python 3.14+ typing, dataclasses, pattern matching, and POSIX atomicity.
===============================================================================
"""

from __future__ import annotations

import os
import re
import sys
import json
import socket
import logging
import tempfile
import threading
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any
from concurrent.futures import ThreadPoolExecutor

from python.frontend.core_types import BaseEngine

logger = logging.getLogger("dusky_ufw_engine")

# Type Aliases (PEP 695)
type RuleDict = dict[str, Any]
type AppProfileDict = dict[str, str]

# Configuration & State Paths
DEFAULT_UFW_CONF = Path("/etc/default/ufw")
UFW_SYSCTL_CONF = Path("/etc/ufw/sysctl.conf")
UFW_BEFORE_RULES = Path("/etc/ufw/before.rules")
UFW_AFTER_RULES = Path("/etc/ufw/after.rules")
UFW_AFTER6_RULES = Path("/etc/ufw/after6.rules")
DOMAINS_STORAGE = Path.home() / ".config/dusky/settings/firewall/domains.json"

CMD_TIMEOUT_READ = 10
CMD_TIMEOUT_WRITE = 30

COMMON_SERVICES: dict[str, dict[str, str]] = {
    "ssh": {"name": "OpenSSH Server", "port": "22", "proto": "tcp", "comment": "OpenSSH"},
    "http": {"name": "Web HTTP", "port": "80", "proto": "tcp", "comment": "Web HTTP"},
    "https": {"name": "Web HTTPS", "port": "443", "proto": "tcp", "comment": "Web HTTPS"},
    "ftp": {"name": "FTP Control", "port": "21", "proto": "tcp", "comment": "FTP Control"},
    "dns": {"name": "DNS Server", "port": "53", "proto": "both", "comment": "DNS Service"},
    "wireguard": {"name": "WireGuard VPN", "port": "51820", "proto": "udp", "comment": "WireGuard VPN"},
    "tailscale": {"name": "Tailscale Direct P2P", "port": "41641", "proto": "udp", "comment": "Tailscale Direct P2P"},
    "moonlight": {"name": "Moonlight Game Streaming", "port": "47984,47989,48010", "proto": "tcp", "comment": "Moonlight Display"},
    "plex": {"name": "Plex Media Server", "port": "32400", "proto": "tcp", "comment": "Plex Media"},
    "minecraft": {"name": "Minecraft Server", "port": "25565", "proto": "tcp", "comment": "Minecraft Server"},
    "samba": {"name": "Samba File Sharing", "port": "445", "proto": "tcp", "comment": "Samba Share"},
    "vnc": {"name": "VNC Display", "port": "5901", "proto": "tcp", "comment": "VNC Display"},
    "syncthing": {"name": "Syncthing Transfer", "port": "22000", "proto": "tcp", "comment": "Syncthing"},
    "torrent": {"name": "BitTorrent Peer", "port": "6881", "proto": "both", "comment": "BitTorrent"},
}


@dataclass(slots=True, kw_only=True)
class RuleRecord:
    number: int
    to_addr: str
    action: str
    from_addr: str
    comment: str = ""
    is_v6: bool = False
    raw: str = ""

    def to_dict(self) -> RuleDict:
        return {
            "number": self.number,
            "to": self.to_addr,
            "action": self.action,
            "from": self.from_addr,
            "comment": self.comment,
            "is_v6": self.is_v6,
            "raw": self.raw,
        }


class UfwEngine(BaseEngine):
    """
    Comprehensive, high-performance engine for managing UFW firewall.
    Integrates directly with Dusky TUI architecture.
    """
    _instance: UfwEngine | None = None

    def __init__(self, config_path: str = "/etc/default/ufw"):
        UfwEngine._instance = self
        self.config_path = Path(config_path).expanduser().resolve()
        self._lock = threading.Lock()
        self.cache: dict[str, Any] = {}
        self.app: Any = None
        self._ensure_storage()

    def set_app(self, app: Any) -> None:
        self.app = app

    @property
    def target_path(self) -> str:
        return str(self.config_path)

    # =========================================================================
    # 1. COMMAND EXECUTION & PRIVILEGE WRAPPER
    # =========================================================================
    @staticmethod
    def _cmd_prefix() -> list[str]:
        return [] if os.geteuid() == 0 else ["sudo", "-n"]

    def _run_cmd(self, cmd: list[str], timeout: int = CMD_TIMEOUT_READ) -> subprocess.CompletedProcess[str]:
        full_cmd = self._cmd_prefix() + cmd
        env = {**os.environ, "LC_ALL": "C"}
        return subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
        )

    def _ensure_storage(self) -> None:
        try:
            DOMAINS_STORAGE.parent.mkdir(parents=True, exist_ok=True)
            if not DOMAINS_STORAGE.exists():
                default_data = {
                    "whitelist_mode": False,
                    "domains": [
                        {
                            "domain": "archlinux.org",
                            "action": "allow",
                            "ports": "80,443",
                            "ips": [],
                            "last_resolved": "",
                        },
                        {
                            "domain": "aur.archlinux.org",
                            "action": "allow",
                            "ports": "80,443",
                            "ips": [],
                            "last_resolved": "",
                        },
                        {
                            "domain": "github.com",
                            "action": "allow",
                            "ports": "80,443",
                            "ips": [],
                            "last_resolved": "",
                        },
                    ],
                }
                DOMAINS_STORAGE.write_text(json.dumps(default_data, indent=4), encoding="utf-8")
        except OSError as e:
            logger.warning("Could not initialize domain storage: %s", e)

    def _read_domain_registry(self) -> dict[str, Any]:
        try:
            if DOMAINS_STORAGE.exists():
                return json.loads(DOMAINS_STORAGE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to read domain registry: %s", e)
        return {"whitelist_mode": False, "domains": []}

    def _write_domain_registry(self, data: dict[str, Any]) -> bool:
        try:
            parent = DOMAINS_STORAGE.parent
            parent.mkdir(parents=True, exist_ok=True)
            tmp = tempfile.NamedTemporaryFile("w", dir=parent, delete=False, encoding="utf-8")
            json.dump(data, tmp, indent=4)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, DOMAINS_STORAGE)
            return True
        except Exception as e:
            logger.error("Failed to write domain registry: %s", e)
            return False

    # =========================================================================
    # 2. STATUS & RULES PARSING
    # =========================================================================
    def get_status_verbose(self) -> dict[str, Any]:
        res = self._run_cmd(["ufw", "status", "verbose"])
        if res.returncode != 0:
            return {
                "active": False,
                "logging": "off",
                "default_incoming": "deny",
                "default_outgoing": "allow",
                "default_routed": "deny",
                "new_profiles": "skip",
                "raw": res.stderr.strip() or res.stdout.strip(),
            }

        lines = res.stdout.splitlines()
        info: dict[str, Any] = {
            "active": False,
            "logging": "off",
            "default_incoming": "deny",
            "default_outgoing": "allow",
            "default_routed": "deny",
            "new_profiles": "skip",
            "raw": res.stdout,
        }

        for line in lines:
            line = line.strip()
            if line.startswith("Status:"):
                info["active"] = bool(re.search(r"Status:\s*active\b", line, re.IGNORECASE))
            elif line.startswith("Logging:"):
                match = re.search(r"Logging:\s*(?:on\s*\(([a-z]+)\)|([a-z]+))", line, re.IGNORECASE)
                if match:
                    info["logging"] = (match.group(1) or match.group(2) or "off").lower()
            elif line.startswith("Default:"):
                inc_m = re.search(r"([a-z]+)\s*\(incoming\)", line, re.IGNORECASE)
                out_m = re.search(r"([a-z]+)\s*\(outgoing\)", line, re.IGNORECASE)
                rt_m = re.search(r"([a-z]+)\s*\(routed\)", line, re.IGNORECASE)
                if inc_m:
                    info["default_incoming"] = inc_m.group(1).lower()
                if out_m:
                    info["default_outgoing"] = out_m.group(1).lower()
                if rt_m:
                    info["default_routed"] = rt_m.group(1).lower()
            elif line.startswith("New profiles:"):
                match = re.search(r"New profiles:\s*([a-z]+)", line, re.IGNORECASE)
                if match:
                    info["new_profiles"] = match.group(1).lower()

        return info

    def get_numbered_rules(self) -> list[RuleRecord]:
        res = self._run_cmd(["ufw", "status", "numbered"])
        if res.returncode != 0:
            return []

        rules: list[RuleRecord] = []
        action_pattern = re.compile(
            r"\b(ALLOW\s+IN|ALLOW\s+OUT|ALLOW\s+FWD|DENY\s+IN|DENY\s+OUT|DENY\s+FWD|"
            r"REJECT\s+IN|REJECT\s+OUT|REJECT\s+FWD|LIMIT\s+IN|LIMIT\s+OUT|LIMIT\s+FWD|"
            r"ALLOW|DENY|REJECT|LIMIT)\b",
            re.IGNORECASE,
        )

        for line in res.stdout.splitlines():
            line_str = line.strip()
            num_match = re.match(r"^\[\s*(\d+)\]\s+(.*)$", line_str)
            if not num_match:
                continue

            num = int(num_match.group(1))
            body = num_match.group(2).strip()

            comment = ""
            if "#" in body:
                body_part, comment_part = body.split("#", 1)
                body = body_part.strip()
                comment = comment_part.strip()

            act_match = action_pattern.search(body)
            if act_match:
                to_addr = body[: act_match.start()].strip()
                action = act_match.group(1).strip()
                from_addr = body[act_match.end() :].strip()
            else:
                parts = body.split()
                to_addr = parts[0] if parts else ""
                action = parts[1] if len(parts) > 1 else ""
                from_addr = " ".join(parts[2:]) if len(parts) > 2 else ""

            is_v6 = "(v6)" in to_addr or "(v6)" in from_addr or "(v6)" in comment
            rules.append(
                RuleRecord(
                    number=num,
                    to_addr=to_addr,
                    action=action,
                    from_addr=from_addr,
                    comment=comment,
                    is_v6=is_v6,
                    raw=line_str,
                )
            )

        return rules

    # =========================================================================
    # 3. DETAILED PORT INSPECTOR & PROBER (Open/Closed/Filtered)
    # =========================================================================
    def get_detailed_port_map(self) -> list[dict[str, Any]]:
        """
        Inspects all listening sockets and maps them against UFW firewall rules.
        Distinguishes EXPOSED (open to WAN), ALLOWED, BLOCKED, PROTECTED (localhost),
        and FILTERED (default drop).
        """
        res = self._run_cmd(["ss", "-H", "-tlunp"])
        if res.returncode != 0:
            return []

        rules = self.get_numbered_rules()
        status_info = self.get_status_verbose()
        def_incoming = status_info.get("default_incoming", "deny")

        ports_list: list[dict[str, Any]] = []

        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0].lower()
            local_addr_str = parts[4] if parts[1] in ("LISTEN", "UNCONN") else parts[3]

            # Parse IP and Port
            m_addr = re.search(r"(?:\[([0-9a-fA-F:]+)\]|([^\s:]+)):(\d+)$", local_addr_str)
            if not m_addr:
                continue

            ip = m_addr.group(1) or m_addr.group(2) or "0.0.0.0"
            try:
                port_num = int(m_addr.group(3))
            except ValueError:
                continue

            # Process info
            proc_name = "unknown"
            pid = 0
            m_proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if m_proc:
                proc_name = m_proc.group(1)
                pid = int(m_proc.group(2))

            # Address Scope
            is_localhost = ip in ("127.0.0.1", "127.0.0.53", "127.0.0.54", "::1")
            is_wildcard = ip in ("0.0.0.0", "::", "*")

            if is_localhost:
                scope_desc = "Localhost Only"
            elif is_wildcard:
                scope_desc = "All Interfaces (WAN/LAN)"
            elif ip.startswith(("192.168.", "10.", "172.16.")):
                scope_desc = f"LAN ({ip})"
            elif ip.startswith("100."):
                scope_desc = f"Tailscale ({ip})"
            else:
                scope_desc = ip

            # Firewall Ingress Cross-Reference
            matched_rule: RuleRecord | None = None
            fw_status = "FILTERED"

            for r in rules:
                if re.search(rf"\b{port_num}(?:/{proto})?\b", r.to_addr) or re.search(rf"\b{port_num}(?:/{proto})?\b", r.from_addr):
                    matched_rule = r
                    break

            if matched_rule:
                if "ALLOW" in matched_rule.action:
                    fw_status = "EXPOSED" if is_wildcard else "ALLOWED"
                elif "DENY" in matched_rule.action or "REJECT" in matched_rule.action:
                    fw_status = "BLOCKED"
            elif is_localhost:
                fw_status = "PROTECTED"
            elif def_incoming == "allow":
                fw_status = "EXPOSED" if is_wildcard else "ALLOWED"
            else:
                fw_status = "FILTERED"

            ports_list.append({
                "port": port_num,
                "proto": proto,
                "ip": ip,
                "process": proc_name,
                "pid": pid,
                "scope": scope_desc,
                "fw_status": fw_status,
                "matched_rule": matched_rule.raw if matched_rule else "",
            })

        # Sort uniquely by port and protocol
        ports_list.sort(key=lambda x: (x["port"], x["proto"]))
        return ports_list

    def probe_port(self, port: int, proto: str = "tcp", host: str = "127.0.0.1") -> dict[str, Any]:
        """Actively probes a port locally to test socket listening, firewall rule, and reachability."""
        port = int(port)
        proto = proto.lower()
        reachable = False

        if proto == "tcp":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                res = s.connect_ex((host, port))
                reachable = (res == 0)
                s.close()
            except Exception:
                reachable = False

        port_map = self.get_detailed_port_map()
        match_listen = next((p for p in port_map if p["port"] == port and p["proto"] == proto), None)

        rules = self.get_numbered_rules()
        matching_rules = [
            r for r in rules
            if re.search(rf"\b{port}\b", r.to_addr) or re.search(rf"\b{port}\b", r.from_addr)
        ]

        status_str = "OPEN / REACHABLE" if reachable else ("LISTENING (Local Socket)" if match_listen else "CLOSED / INACTIVE")
        fw_summary = f"{len(matching_rules)} active rule(s)" if matching_rules else "Controlled by default policy"

        return {
            "port": port,
            "proto": proto,
            "listening": match_listen is not None,
            "process": match_listen["process"] if match_listen else "none",
            "reachable": reachable,
            "status": status_str,
            "matching_rules": [r.raw for r in matching_rules],
            "summary": f"{proto.upper()} Port {port}: {status_str} | FW: {fw_summary}",
        }

    # =========================================================================
    # 4. QUICK PORT MANAGEMENT (Open / Close / Delete)
    # =========================================================================
    def open_port(self, port: str, proto: str = "tcp", scope: str = "any", comment: str = "") -> tuple[bool, str]:
        port = port.strip()
        if not port:
            return False, "Port cannot be empty."

        protos = ["tcp", "udp"] if proto == "both" else [proto]
        success_count = 0

        for p in protos:
            if scope == "lan":
                for sub in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"):
                    c = ["ufw", "allow", "from", sub, "to", "any", "port", port, "proto", p]
                    if comment:
                        c.extend(["comment", comment])
                    res = self._run_cmd(c)
                    if res.returncode == 0:
                        success_count += 1
            elif scope and scope not in ("any", "0.0.0.0/0", "::/0"):
                c = ["ufw", "allow", "from", scope, "to", "any", "port", port, "proto", p]
                if comment:
                    c.extend(["comment", comment])
                res = self._run_cmd(c)
                if res.returncode == 0:
                    success_count += 1
            else:
                c = ["ufw", "allow", f"{port}/{p}"]
                if comment:
                    c.extend(["comment", comment])
                res = self._run_cmd(c)
                if res.returncode == 0:
                    success_count += 1

        self._run_cmd(["ufw", "reload"])
        return success_count > 0, f"Port {port} ({proto}) opened successfully."

    def close_port(self, port: str, proto: str = "tcp", action: str = "deny", comment: str = "") -> tuple[bool, str]:
        port = port.strip()
        if not port:
            return False, "Port cannot be empty."

        # Scrub existing allow rules first to avoid rule shadowing
        self.delete_port_rules(port, proto)

        protos = ["tcp", "udp"] if proto == "both" else [proto]
        for p in protos:
            c = ["ufw", action, f"{port}/{p}"]
            if comment:
                c.extend(["comment", comment])
            self._run_cmd(c)

        self._run_cmd(["ufw", "reload"])
        return True, f"Port {port} ({proto}) closed ({action})."

    def delete_port_rules(self, port: str, proto: str = "tcp") -> tuple[bool, str]:
        port = port.strip()
        if not port:
            return False, "Port cannot be empty."

        numbered = self.get_numbered_rules()
        to_delete: list[int] = []

        for r in numbered:
            if re.search(rf"\b{re.escape(port)}\b", r.to_addr) or re.search(rf"\b{re.escape(port)}\b", r.from_addr):
                to_delete.append(r.number)

        for num in sorted(to_delete, reverse=True):
            self._run_cmd(["ufw", "--force", "delete", str(num)])

        self._run_cmd(["ufw", "reload"])
        return True, f"Removed {len(to_delete)} rule(s) matching port {port}."

    # =========================================================================
    # 5. COMMON SERVICES
    # =========================================================================
    def is_service_allowed(self, svc_key: str, *, rules: list[RuleRecord] | None = None) -> bool:
        svc = COMMON_SERVICES.get(svc_key)
        if not svc:
            return False
        port_spec = svc["port"]
        numbered = self.get_numbered_rules() if rules is None else rules
        ports = [p.strip() for p in port_spec.split(",")]

        for p in ports:
            found = False
            for r in numbered:
                if "ALLOW" in r.action and p in r.to_addr:
                    found = True
                    break
            if not found:
                return False
        return True

    def toggle_service(self, svc_key: str, enable: bool) -> tuple[bool, str]:
        svc = COMMON_SERVICES.get(svc_key)
        if not svc:
            return False, f"Unknown service: {svc_key}"

        ports = [p.strip() for p in svc["port"].split(",")]
        if enable:
            for p in ports:
                self.open_port(p, proto=svc["proto"], comment=svc["comment"])
            return True, f"Service '{svc['name']}' opened in firewall."
        else:
            for p in ports:
                self.delete_port_rules(p, proto=svc["proto"])
            return True, f"Service '{svc['name']}' closed / rules removed."

    # =========================================================================
    # 6. ACTIVE CONNECTIONS & IP BANNING
    # =========================================================================
    def get_active_connections(self) -> list[dict[str, Any]]:
        res = self._run_cmd(["ss", "-H", "-tunp", "state", "established"])
        if res.returncode != 0:
            return []

        conns: list[dict[str, Any]] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0]
            if len(parts) >= 6 and parts[1].isalpha() and not parts[1].isdigit():
                local_str = parts[4]
                peer_str = parts[5]
            else:
                local_str = parts[3]
                peer_str = parts[4]

            m_loc = re.search(r"(?:\[([0-9a-fA-F:]+)\]|([^\s:]+)):(\d+)$", local_str)
            loc_ip = (m_loc.group(1) or m_loc.group(2)) if m_loc else local_str
            loc_port = m_loc.group(3) if m_loc else ""

            m_peer = re.search(r"(?:\[([0-9a-fA-F:]+)\]|([^\s:]+)):(\d+)$", peer_str)
            peer_ip = (m_peer.group(1) or m_peer.group(2)) if m_peer else peer_str
            peer_port = m_peer.group(3) if m_peer else ""

            proc = ""
            pid = ""
            m_proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if m_proc:
                proc = m_proc.group(1)
                pid = m_proc.group(2)

            conns.append({
                "proto": proto,
                "local_ip": loc_ip,
                "local_port": loc_port,
                "remote_ip": peer_ip,
                "remote_port": peer_port,
                "process": proc or "system",
                "pid": pid,
                "raw": line,
            })

        return conns

    def ban_ip(self, ip: str) -> tuple[bool, str]:
        ip = ip.strip()
        if not ip:
            return False, "IP address cannot be empty."
        res = self._run_cmd(["ufw", "prepend", "deny", "from", ip, "comment", f"Banned: {ip}"])
        self._run_cmd(["ufw", "reload"])
        return res.returncode == 0, f"IP {ip} banned with top-priority DROP rule."

    def unban_ip(self, ip: str) -> tuple[bool, str]:
        ip = ip.strip()
        if not ip:
            return False, "IP address cannot be empty."
        numbered = self.get_numbered_rules()
        deleted = 0
        for r in sorted([r.number for r in numbered if ip in r.from_addr and "DENY" in r.action], reverse=True):
            self._run_cmd(["ufw", "--force", "delete", str(r)])
            deleted += 1
        self._run_cmd(["ufw", "reload"])
        return True, f"Unbanned IP {ip} (removed {deleted} rule(s))."

    def get_banned_ips(self, *, rules: list[RuleRecord] | None = None) -> list[str]:
        numbered = self.get_numbered_rules() if rules is None else rules
        banned: list[str] = []
        for r in numbered:
            if "DENY" in r.action and ("Banned:" in r.comment or "block:" in r.comment):
                banned.append(r.from_addr or r.to_addr)
        return list(dict.fromkeys(banned))

    def panic_lockdown(self, enable: bool) -> tuple[bool, str]:
        if enable:
            self._run_cmd(["ufw", "default", "deny", "incoming"])
            self._run_cmd(["ufw", "default", "deny", "outgoing"])
            self._run_cmd(["ufw", "default", "deny", "routed"])
            self._run_cmd(["ufw", "reload"])
            return True, "PANIC LOCKDOWN ACTIVATED: All incoming, outgoing, and routed traffic is dropped."
        else:
            self._run_cmd(["ufw", "default", "deny", "incoming"])
            self._run_cmd(["ufw", "default", "allow", "outgoing"])
            self._run_cmd(["ufw", "default", "deny", "routed"])
            self._run_cmd(["ufw", "reload"])
            return True, "Standard traffic policies restored."

    # =========================================================================
    # 7. ICMP PING STEALTH & PORT FORWARDING
    # =========================================================================
    @staticmethod
    def get_icmp_ping_stealth() -> bool:
        if not UFW_BEFORE_RULES.exists():
            return False
        try:
            content = UFW_BEFORE_RULES.read_text(encoding="utf-8")
            return bool(re.search(r"echo-request\s+-j\s+DROP", content))
        except OSError:
            return False

    def set_icmp_ping_stealth(self, stealth: bool) -> tuple[bool, str]:
        files = [UFW_BEFORE_RULES]
        if Path("/proc/net/if_inet6").exists() and Path("/etc/ufw/before6.rules").exists():
            files.append(Path("/etc/ufw/before6.rules"))

        target = "DROP" if stealth else "ACCEPT"
        source = "ACCEPT" if stealth else "DROP"

        for f in files:
            if not f.exists():
                continue
            try:
                content = f.read_text(encoding="utf-8")
                pattern = rf"(echo-request\s+-j\s+){source}"
                new_content = re.sub(pattern, rf"\g<1>{target}", content)
                f.write_text(new_content, encoding="utf-8")
            except OSError as e:
                return False, f"Failed updating {f.name}: {e}"

        self._run_cmd(["ufw", "reload"])
        msg = "ICMP Stealth Mode ENABLED (Host invisible to ping sweeps)." if stealth else "ICMP Ping responses RESTORED."
        return True, msg

    @staticmethod
    def get_port_forwards() -> list[dict[str, str]]:
        if not UFW_BEFORE_RULES.exists():
            return []
        try:
            content = UFW_BEFORE_RULES.read_text(encoding="utf-8")
            matches = re.findall(
                r"-A\s+PREROUTING\s+-p\s+([a-z]+)\s+--dport\s+(\d+)\s+-j\s+DNAT\s+--to-destination\s+([^\s]+)",
                content,
            )
            return [{"proto": m[0], "ext_port": m[1], "destination": m[2]} for m in matches]
        except OSError:
            return []

    def add_port_forward(self, wan_port: str, dest_ip: str, dest_port: str, proto: str = "tcp") -> tuple[bool, str]:
        if not UFW_BEFORE_RULES.exists():
            return False, "File /etc/ufw/before.rules not found."
        wan_port = wan_port.strip()
        dest_ip = dest_ip.strip()
        dest_port = dest_port.strip()
        proto = proto.strip().lower()

        dnat_rule = f"-A PREROUTING -p {proto} --dport {wan_port} -j DNAT --to-destination {dest_ip}:{dest_port}\n"

        try:
            content = UFW_BEFORE_RULES.read_text(encoding="utf-8")
            if dnat_rule.strip() in content:
                return True, "Port forwarding rule already exists."

            if "*nat" in content:
                content = re.sub(r"(:PREROUTING[^\n]*\n)", rf"\1{dnat_rule}", content, count=1)
            else:
                nat_header = f"*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n{dnat_rule}COMMIT\n\n"
                content = nat_header + content

            UFW_BEFORE_RULES.write_text(content, encoding="utf-8")
            self._run_cmd(["ufw", "route", "allow", "proto", proto, "to", dest_ip, "port", dest_port, "comment", f"DNAT: {wan_port}->{dest_ip}:{dest_port}"])
            self._run_cmd(["ufw", "reload"])
            return True, f"Port forward {wan_port}/{proto} -> {dest_ip}:{dest_port} created."
        except OSError as e:
            return False, f"Failed updating before.rules: {e}"

    def remove_port_forward(self, wan_port: str, proto: str = "tcp") -> tuple[bool, str]:
        if not UFW_BEFORE_RULES.exists():
            return False, "File /etc/ufw/before.rules not found."
        wan_port = wan_port.strip()
        proto = proto.strip().lower()
        try:
            content = UFW_BEFORE_RULES.read_text(encoding="utf-8")
            pattern = rf"\n?-A\s+PREROUTING\s+-p\s+{proto}\s+--dport\s+{wan_port}\s+-j\s+DNAT\s+--to-destination\s+[^\s\n]+"
            new_content = re.sub(pattern, "", content)
            UFW_BEFORE_RULES.write_text(new_content, encoding="utf-8")

            numbered = self.get_numbered_rules()
            for r in sorted([r.number for r in numbered if f"DNAT: {wan_port}->" in r.comment], reverse=True):
                self._run_cmd(["ufw", "--force", "delete", str(r)])

            self._run_cmd(["ufw", "reload"])
            return True, f"Port forward for WAN port {wan_port}/{proto} removed."
        except OSError as e:
            return False, f"Failed removing port forward: {e}"

    # =========================================================================
    # 8. APP PROFILES & SYSTEM HELPERS
    # =========================================================================
    def get_app_profiles(self) -> list[AppProfileDict]:
        res = self._run_cmd(["ufw", "app", "list"])
        if res.returncode != 0:
            return []

        profiles: list[AppProfileDict] = []
        in_apps = False
        app_names: list[str] = []

        for line in res.stdout.splitlines():
            s = line.strip()
            if s.startswith("Available applications:"):
                in_apps = True
                continue
            if in_apps and s:
                app_names.append(s)

        for name in sorted(app_names):
            info_res = self._run_cmd(["ufw", "app", "info", name])
            title = ""
            desc = ""
            ports = ""
            if info_res.returncode == 0:
                for line in info_res.stdout.splitlines():
                    ls = line.strip()
                    if ls.startswith("Title:"):
                        title = ls.split(":", 1)[1].strip()
                    elif ls.startswith("Description:"):
                        desc = ls.split(":", 1)[1].strip()
                    elif ls.startswith("Ports:"):
                        ports = ls.split(":", 1)[1].strip()

            profiles.append({
                "name": name,
                "title": title or name,
                "description": desc or "No description available",
                "ports": ports or "dynamic/any",
            })

        return profiles

    def get_listening_ports(self) -> list[dict[str, Any]]:
        res = self._run_cmd(["ufw", "show", "listening"])
        if res.returncode != 0:
            return []

        items: list[dict[str, Any]] = []
        current_proto = ""
        current_item: dict[str, Any] | None = None

        for line in res.stdout.splitlines():
            s = line.strip()
            if s in ("tcp:", "udp:", "tcp6:", "udp6:"):
                current_proto = s.rstrip(":")
                continue

            match_entry = re.match(r"^(\d+)\s+([^\s]+)\s+\(([^)]+)\)$", s)
            if match_entry:
                if current_item:
                    items.append(current_item)
                current_item = {
                    "proto": current_proto,
                    "port": int(match_entry.group(1)),
                    "bound_addr": match_entry.group(2),
                    "process": match_entry.group(3),
                    "rules": [],
                }
                continue

            if current_item and s.startswith("["):
                current_item["rules"].append(s)

        if current_item:
            items.append(current_item)

        return items

    def get_report(self, report_name: str) -> str:
        valid_reports = {
            "listening",
            "added",
            "user-rules",
            "before-rules",
            "after-rules",
            "logging-rules",
            "builtins",
            "raw",
        }
        if report_name not in valid_reports:
            return f"Error: Invalid report type '{report_name}'. Valid: {', '.join(sorted(valid_reports))}"

        res = self._run_cmd(["ufw", "show", report_name])
        return res.stdout if res.returncode == 0 else (res.stderr or "Report generation failed.")

    @staticmethod
    def get_network_interfaces() -> list[str]:
        try:
            net_path = Path("/sys/class/net")
            if net_path.exists():
                return sorted([p.name for p in net_path.iterdir() if p.is_dir() or p.is_symlink()])
        except Exception:
            pass
        return ["wlan0", "eth0", "tailscale0", "lo"]

    @staticmethod
    def detect_wan_interface() -> str:
        try:
            res = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in res.stdout.splitlines():
                if "dev" in line and not re.search(r"dev\s+(wg|tun|tap|tailscale)", line):
                    parts = line.split()
                    for idx, part in enumerate(parts):
                        if part == "dev" and idx + 1 < len(parts):
                            return parts[idx + 1]
        except Exception:
            pass
        return ""

    # =========================================================================
    # 9. DOMAIN RESOLUTION & SYNC
    # =========================================================================
    @staticmethod
    def resolve_domain_ips(domain: str) -> list[str]:
        ips: set[str] = set()
        domain = domain.strip().lower()
        if not domain:
            return []
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for res in addr_info:
                sockaddr = res[4]
                if sockaddr and isinstance(sockaddr, tuple) and sockaddr[0]:
                    ip_str = sockaddr[0]
                    ips.add(ip_str)
        except (socket.gaierror, OSError) as e:
            logger.warning("DNS resolution failed for %s: %s", domain, e)
        return sorted(ips)

    def sync_domains(self) -> tuple[bool, str]:
        with self._lock:
            data = self._read_domain_registry()
            domains = data.get("domains", [])

            if not domains:
                return True, "No domains registered."

            updated_count = 0
            with ThreadPoolExecutor(max_workers=8) as executor:
                future_to_entry = {executor.submit(self.resolve_domain_ips, d["domain"]): d for d in domains}
                for future in future_to_entry:
                    entry = future_to_entry[future]
                    try:
                        resolved_ips = future.result()
                        if resolved_ips:
                            entry["ips"] = resolved_ips
                            entry["last_resolved"] = "2026-09-28T12:00:00"
                            updated_count += 1
                    except Exception as e:
                        logger.error("Domain sync failed for %s: %s", entry.get("domain"), e)

            self._write_domain_registry(data)
            self._apply_domain_rules(data)
            return True, f"Synchronized {updated_count} domains successfully."

    def _apply_domain_rules(self, data: dict[str, Any]) -> None:
        whitelist_mode = data.get("whitelist_mode", False)
        domains = data.get("domains", [])

        self._scrub_domain_rules()

        if whitelist_mode:
            self._run_cmd(["ufw", "allow", "out", "on", "lo", "comment", "core:loopback"])
            self._run_cmd(["ufw", "allow", "in", "on", "lo", "comment", "core:loopback"])
            self._run_cmd(["ufw", "allow", "out", "to", "any", "port", "53", "comment", "core:dns"])
            self._run_cmd(["ufw", "allow", "out", "to", "any", "port", "67,68", "proto", "udp", "comment", "core:dhcp"])
            self._run_cmd(["ufw", "allow", "in", "to", "any", "port", "67,68", "proto", "udp", "comment", "core:dhcp"])

        for d in domains:
            domain_name = d["domain"]
            action = d.get("action", "allow")
            ports_str = d.get("ports", "80,443")
            ips = d.get("ips", [])

            if not ips:
                ips = self.resolve_domain_ips(domain_name)
                d["ips"] = ips

            for ip in ips:
                comment_tag = f"domain:{domain_name}" if action == "allow" else f"block:{domain_name}"
                if action == "allow":
                    if ports_str and ports_str != "any":
                        for p in ports_str.split(","):
                            p = p.strip()
                            if p:
                                self._run_cmd(["ufw", "allow", "out", "to", ip, "port", p, "proto", "tcp", "comment", comment_tag])
                    else:
                        self._run_cmd(["ufw", "allow", "out", "to", ip, "comment", comment_tag])
                else:
                    self._run_cmd(["ufw", "deny", "out", "to", ip, "comment", comment_tag])

    def _scrub_domain_rules(self) -> None:
        numbered = self.get_numbered_rules()
        to_delete = [
            r.number
            for r in numbered
            if r.comment.startswith(("domain:", "block:", "core:"))
        ]
        for num in sorted(to_delete, reverse=True):
            self._run_cmd(["ufw", "--force", "delete", str(num)])

    # =========================================================================
    # 10. FRAMEWORK (Sysctl, Waydroid, Docker)
    # =========================================================================
    @staticmethod
    def get_sysctl_forwarding() -> bool:
        if not UFW_SYSCTL_CONF.exists():
            return False
        try:
            content = UFW_SYSCTL_CONF.read_text(encoding="utf-8")
            return bool(re.search(r"^\s*net/ipv4/ip_forward\s*=\s*1", content, re.MULTILINE))
        except OSError:
            return False

    def set_sysctl_forwarding(self, enabled: bool) -> tuple[bool, str]:
        try:
            if not UFW_SYSCTL_CONF.exists():
                UFW_SYSCTL_CONF.touch()

            content = UFW_SYSCTL_CONF.read_text(encoding="utf-8")
            val = "1" if enabled else "0"

            def replace_or_append(c: str, key: str, v: str) -> str:
                pattern = rf"^#?\s*{re.escape(key)}\s*=.*"
                if re.search(pattern, c, re.MULTILINE):
                    return re.sub(pattern, f"{key}={v}", c, flags=re.MULTILINE)
                return c + f"\n{key}={v}\n"

            content = replace_or_append(content, "net/ipv4/ip_forward", val)
            if Path("/proc/net/if_inet6").exists():
                content = replace_or_append(content, "net/ipv6/conf/default/forwarding", val)
                content = replace_or_append(content, "net/ipv6/conf/all/forwarding", val)

            UFW_SYSCTL_CONF.write_text(content, encoding="utf-8")
            return True, f"Kernel IP forwarding set to {val}."
        except OSError as e:
            return False, f"Failed to update sysctl forwarding: {e}"

    @staticmethod
    def get_waydroid_nat() -> bool:
        if not UFW_BEFORE_RULES.exists():
            return False
        try:
            content = UFW_BEFORE_RULES.read_text(encoding="utf-8")
            return "# Waydroid NAT Integration" in content
        except OSError:
            return False

    def set_waydroid_nat(self, enabled: bool) -> tuple[bool, str]:
        if not UFW_BEFORE_RULES.exists():
            return False, "File /etc/ufw/before.rules not found."
        try:
            content = UFW_BEFORE_RULES.read_text(encoding="utf-8")
            has_nat = "# Waydroid NAT Integration" in content

            if enabled and not has_nat:
                nat_block = (
                    "*nat\n"
                    ":POSTROUTING ACCEPT [0:0]\n"
                    "# Waydroid NAT Integration\n"
                    "-A POSTROUTING -s 192.168.240.0/24 -j MASQUERADE\n"
                    "-A POSTROUTING -s 192.168.250.0/24 -j MASQUERADE\n"
                    "COMMIT\n\n"
                )
                new_content = nat_block + content
                UFW_BEFORE_RULES.write_text(new_content, encoding="utf-8")
                return True, "Waydroid NAT masquerading injected into /etc/ufw/before.rules."

            if not enabled and has_nat:
                pattern = re.compile(
                    r"\*nat\n:POSTROUTING ACCEPT \[0:0\]\n# Waydroid NAT Integration\n.*?-A POSTROUTING -s 192\.168\.250\.0/24 -j MASQUERADE\nCOMMIT\n\n?",
                    re.DOTALL,
                )
                new_content = pattern.sub("", content)
                UFW_BEFORE_RULES.write_text(new_content, encoding="utf-8")
                return True, "Waydroid NAT masquerading removed from /etc/ufw/before.rules."

            return True, "Waydroid NAT already in target state."
        except OSError as e:
            return False, f"Failed to modify Waydroid NAT: {e}"

    @staticmethod
    def get_docker_mitigation() -> bool:
        if not UFW_AFTER_RULES.exists():
            return False
        try:
            content = UFW_AFTER_RULES.read_text(encoding="utf-8")
            return "# BEGIN DOCKER-USER MITIGATION" in content
        except OSError:
            return False

    def set_docker_mitigation(self, enabled: bool) -> tuple[bool, str]:
        files = [UFW_AFTER_RULES]
        if Path("/proc/net/if_inet6").exists() and UFW_AFTER6_RULES.exists():
            files.append(UFW_AFTER6_RULES)

        wan = self.detect_wan_interface()
        wan_rule = f"-A DOCKER-USER -i {wan} -j DROP" if wan else "# No WAN interface detected, skipping WAN drop"

        docker_block = (
            "\n# BEGIN DOCKER-USER MITIGATION\n"
            "*filter\n"
            ":DOCKER-USER - [0:0]\n"
            "-A DOCKER-USER -i docker0 -j ACCEPT\n"
            "-A DOCKER-USER -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            "-A DOCKER-USER -i tailscale0 -j ACCEPT\n"
            "-A DOCKER-USER -i waydroid0 -j ACCEPT\n"
            "-A DOCKER-USER -i virbr0 -j ACCEPT\n"
            "-A DOCKER-USER -i wg0 -j ACCEPT\n"
            "-A DOCKER-USER -i tun+ -j ACCEPT\n"
            "-A DOCKER-USER -i tap+ -j ACCEPT\n"
            f"{wan_rule}\n"
            "-A DOCKER-USER -j RETURN\n"
            "COMMIT\n"
            "# END DOCKER-USER MITIGATION\n"
        )

        for f in files:
            try:
                if not f.exists():
                    continue
                content = f.read_text(encoding="utf-8")
                content = re.sub(
                    r"\n?# BEGIN DOCKER-USER MITIGATION.*?(?:# END DOCKER-USER MITIGATION\n?)",
                    "",
                    content,
                    flags=re.DOTALL,
                )
                if enabled:
                    if not content.endswith("\n"):
                        content += "\n"
                    content += docker_block
                f.write_text(content, encoding="utf-8")
            except OSError as e:
                return False, f"Failed updating {f.name}: {e}"

        action_str = "enforced" if enabled else "removed"
        return True, f"Docker daemon UFW bypass mitigation {action_str}."

    # =========================================================================
    # 11. PRESETS
    # =========================================================================
    def apply_preset(self, preset_name: str) -> tuple[bool, str]:
        match preset_name:
            case "dusky_full":
                wan = self.detect_wan_interface()
                self.set_sysctl_forwarding(True)
                self.set_waydroid_nat(True)
                self.set_docker_mitigation(True)

                self._run_cmd(["ufw", "default", "deny", "incoming"])
                self._run_cmd(["ufw", "default", "allow", "outgoing"])
                self._run_cmd(["ufw", "default", "deny", "routed"])

                ssh_port = "22"
                try:
                    res = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=3)
                    if res.returncode == 0:
                        for l in res.stdout.splitlines():
                            if l.startswith("port "):
                                ssh_port = l.split()[1]
                                break
                except Exception:
                    pass

                self._run_cmd(["ufw", "allow", f"{ssh_port}/tcp", "comment", "OpenSSH"])
                self._run_cmd(["ufw", "allow", "41641/udp", "comment", "Tailscale Direct P2P"])

                trusted = ["tailscale0", "waydroid0", "virbr0", "docker0", "wg0", "tun0", "tap0"]
                for iface in trusted:
                    self._run_cmd(["ufw", "allow", "in", "on", iface, "comment", f"Trust IN: {iface}"])
                    if wan:
                        self._run_cmd(["ufw", "route", "allow", "in", "on", iface, "out", "on", wan, "comment", f"Forward: {iface} -> WAN"])
                    if iface == "virbr0":
                        self._run_cmd(["ufw", "route", "allow", "in", "on", "virbr0", "comment", "Route IN: virbr0"])
                        self._run_cmd(["ufw", "route", "allow", "out", "on", "virbr0", "comment", "Route OUT: virbr0"])

                self._run_cmd(["ufw", "--force", "enable"])
                self._run_cmd(["ufw", "reload"])
                return True, "Dusky Full Provisioning preset applied successfully."

            case "strict_workstation":
                self._run_cmd(["ufw", "default", "deny", "incoming"])
                self._run_cmd(["ufw", "default", "allow", "outgoing"])
                self._run_cmd(["ufw", "default", "deny", "routed"])
                self._run_cmd(["ufw", "allow", "22/tcp", "comment", "OpenSSH"])
                self._run_cmd(["ufw", "--force", "enable"])
                self._run_cmd(["ufw", "reload"])
                return True, "Strict Workstation preset applied."

            case "lockdown_whitelist":
                data = self._read_domain_registry()
                data["whitelist_mode"] = True
                self._write_domain_registry(data)
                self._run_cmd(["ufw", "default", "deny", "incoming"])
                self._run_cmd(["ufw", "default", "deny", "outgoing"])
                self._run_cmd(["ufw", "default", "deny", "routed"])
                self._apply_domain_rules(data)
                self._run_cmd(["ufw", "--force", "enable"])
                self._run_cmd(["ufw", "reload"])
                return True, "Lockdown Whitelist preset activated. Outgoing traffic restricted strictly to whitelisted domains!"

            case "dev_lan":
                subnets = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
                for sub in subnets:
                    self._run_cmd(["ufw", "allow", "from", sub, "comment", f"Dev LAN: {sub}"])
                dev_ports = ["3000", "5173", "8000", "8080"]
                for p in dev_ports:
                    self._run_cmd(["ufw", "allow", f"{p}/tcp", "comment", f"Dev Server: {p}"])
                self._run_cmd(["ufw", "reload"])
                return True, "Developer & Local LAN subnets allowed."

            case "stealth":
                self._run_cmd(["ufw", "default", "reject", "incoming"])
                self._run_cmd(["ufw", "default", "allow", "outgoing"])
                self._run_cmd(["ufw", "limit", "22/tcp", "comment", "SSH rate-limit"])
                self._run_cmd(["ufw", "logging", "medium"])
                self.set_icmp_ping_stealth(True)
                self._run_cmd(["ufw", "reload"])
                return True, "Stealth Mode (Reject + SSH rate limit + ICMP drop + Medium logs) applied."

            case "streaming_moonlight":
                ports_tcp = ["47984", "47989", "48010", "5901"]
                for p in ports_tcp:
                    self._run_cmd(["ufw", "allow", f"{p}/tcp", "comment", "Moonlight/VNC Streaming"])
                self._run_cmd(["ufw", "allow", "47998:48000/udp", "comment", "Moonlight UDP Streaming"])
                self._run_cmd(["ufw", "reload"])
                return True, "Moonlight & Display Streaming ports opened."

            case "factory_reset":
                self._run_cmd(["ufw", "--force", "reset"])
                return True, "Firewall reset to clean installation defaults."

            case _:
                return False, f"Unknown preset: {preset_name}"

    # =========================================================================
    # 12. BASEENGINE CONTRACT (load_state & write_value)
    # =========================================================================
    def load_state(self) -> dict[str, Any]:
        with self._lock:
            state: dict[str, Any] = {}

            # Status
            status_info = self.get_status_verbose()
            state["status/firewall_enabled"] = "true" if status_info["active"] else "false"
            state["status/logging_level"] = status_info["logging"]
            state["status/default_incoming"] = status_info["default_incoming"]
            state["status/default_outgoing"] = status_info["default_outgoing"]
            state["status/default_routed"] = status_info["default_routed"]
            state["status/new_profiles"] = status_info["new_profiles"]

            # Framework
            state["framework/ip_forward"] = "true" if self.get_sysctl_forwarding() else "false"
            state["framework/waydroid_nat"] = "true" if self.get_waydroid_nat() else "false"
            state["framework/docker_mitigation"] = "true" if self.get_docker_mitigation() else "false"
            state["framework/icmp_stealth"] = "true" if self.get_icmp_ping_stealth() else "false"

            # Domain filter
            domain_data = self._read_domain_registry()
            state["domains/whitelist_mode"] = "true" if domain_data.get("whitelist_mode") else "false"

            # One rule snapshot serves every service in this state load.
            numbered_rules = self.get_numbered_rules()
            for svc_key in COMMON_SERVICES:
                state[f"services/{svc_key}"] = "true" if self.is_service_allowed(svc_key, rules=numbered_rules) else "false"

            # Quick port defaults
            state["ports/quick_port"] = "8080"
            state["ports/quick_proto"] = "tcp"
            state["ports/quick_scope"] = "any"
            state["ports/quick_action"] = "allow"
            state["ports/quick_comment"] = "Custom Port Rule"
            state["ports/probe_port"] = "22"

            # Rule Builder defaults
            builder_defaults = {
                "action": "allow",
                "direction": "in",
                "proto": "any",
                "port": "",
                "source": "any",
                "dest": "any",
                "interface": "any",
                "out_interface": "any",
                "log": "none",
                "comment": "",
                "placement": "append",
                "insert_num": 1,
            }
            for k, v in builder_defaults.items():
                state[f"builder/{k}"] = str(v)

            # NAT defaults
            state["nat/forward_ext_port"] = "8080"
            state["nat/forward_dest_ip"] = "192.168.240.2"
            state["nat/forward_dest_port"] = "80"
            state["nat/forward_proto"] = "tcp"

            # Connections
            state["connections/ban_ip_target"] = ""
            state["reports/selected_report"] = "listening"

            # Action trigger resets
            for act_key in (
                "action_reload", "action_reset", "action_apply_rule", "action_delete_rule",
                "action_sync_domains", "action_add_domain", "action_remove_domain",
                "action_open_port", "action_close_port", "action_reject_port", "action_delete_port_rules",
                "action_probe_port", "action_ban_ip", "action_unban_ip", "action_panic_lockdown",
                "action_panic_restore", "action_add_forward", "action_remove_forward",
            ):
                state[f"actions/{act_key}"] = "false"

            self.cache = state
            return self.cache

    def write_value(
        self, target_key: str, target_scope: str, new_value: str, item_type: str = "string"
    ) -> tuple[bool, str, str]:
        logger.info("UfwEngine write_value: key=%s scope=%s val=%s", target_key, target_scope, new_value)

        # 1. Firewall Power & Global Policies
        if target_key == "firewall_enabled":
            if new_value in ("true", "1", "yes", "on"):
                res = self._run_cmd(["ufw", "--force", "enable"])
                self._run_cmd(["systemctl", "enable", "ufw.service"])
            else:
                res = self._run_cmd(["ufw", "disable"])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        if target_key == "logging_level":
            res = self._run_cmd(["ufw", "logging", new_value.strip().lower()])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        if target_key == "default_incoming":
            res = self._run_cmd(["ufw", "default", new_value.strip().lower(), "incoming"])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        if target_key == "default_outgoing":
            res = self._run_cmd(["ufw", "default", new_value.strip().lower(), "outgoing"])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        if target_key == "default_routed":
            res = self._run_cmd(["ufw", "default", new_value.strip().lower(), "routed"])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        # 2. Quick Port Actions
        if target_key == "action_open_port":
            port = str(self.cache.get("ports/quick_port", "")).strip()
            proto = str(self.cache.get("ports/quick_proto", "tcp")).strip()
            scope = str(self.cache.get("ports/quick_scope", "any")).strip()
            comment = str(self.cache.get("ports/quick_comment", "Quick Open")).strip()
            ok, msg = self.open_port(port, proto=proto, scope=scope, comment=comment)
            return ok, msg, ""

        if target_key == "action_close_port":
            port = str(self.cache.get("ports/quick_port", "")).strip()
            proto = str(self.cache.get("ports/quick_proto", "tcp")).strip()
            comment = str(self.cache.get("ports/quick_comment", "Quick Close")).strip()
            ok, msg = self.close_port(port, proto=proto, action="deny", comment=comment)
            return ok, msg, ""

        if target_key == "action_reject_port":
            port = str(self.cache.get("ports/quick_port", "")).strip()
            proto = str(self.cache.get("ports/quick_proto", "tcp")).strip()
            comment = str(self.cache.get("ports/quick_comment", "Quick Reject")).strip()
            ok, msg = self.close_port(port, proto=proto, action="reject", comment=comment)
            return ok, msg, ""

        if target_key == "action_delete_port_rules":
            port = str(self.cache.get("ports/quick_port", "")).strip()
            proto = str(self.cache.get("ports/quick_proto", "tcp")).strip()
            ok, msg = self.delete_port_rules(port, proto=proto)
            return ok, msg, ""

        if target_key == "action_probe_port":
            port_val = str(self.cache.get("ports/probe_port", "22")).strip()
            if not port_val.isdigit():
                return False, "Enter a numeric port to probe.", ""
            probe_data = self.probe_port(int(port_val), proto="tcp")
            return True, probe_data["summary"], ""

        # 3. Common Services
        if target_scope == "services" or target_key in COMMON_SERVICES:
            svc_key = target_key
            en = new_value in ("true", "1", "yes", "on")
            ok, msg = self.toggle_service(svc_key, en)
            return ok, msg, ""

        # 4. Active Connections, IP Ban & Panic
        if target_key == "action_ban_ip":
            target_ip = str(self.cache.get("connections/ban_ip_target", "")).strip()
            ok, msg = self.ban_ip(target_ip)
            return ok, msg, ""

        if target_key == "action_unban_ip":
            target_ip = str(self.cache.get("connections/ban_ip_target", "")).strip()
            ok, msg = self.unban_ip(target_ip)
            return ok, msg, ""

        if target_key == "action_panic_lockdown":
            ok, msg = self.panic_lockdown(True)
            return ok, msg, ""

        if target_key == "action_panic_restore":
            ok, msg = self.panic_lockdown(False)
            return ok, msg, ""

        if target_key == "icmp_stealth":
            en = new_value in ("true", "1", "yes", "on")
            ok, msg = self.set_icmp_ping_stealth(en)
            return ok, msg, ""

        # 5. Port Forwarding
        if target_key == "action_add_forward":
            ext_p = str(self.cache.get("nat/forward_ext_port", "")).strip()
            dst_ip = str(self.cache.get("nat/forward_dest_ip", "")).strip()
            dst_p = str(self.cache.get("nat/forward_dest_port", "")).strip()
            proto = str(self.cache.get("nat/forward_proto", "tcp")).strip()
            ok, msg = self.add_port_forward(ext_p, dst_ip, dst_p, proto=proto)
            return ok, msg, ""

        if target_key == "action_remove_forward":
            ext_p = str(self.cache.get("nat/forward_ext_port", "")).strip()
            proto = str(self.cache.get("nat/forward_proto", "tcp")).strip()
            ok, msg = self.remove_port_forward(ext_p, proto=proto)
            return ok, msg, ""

        # 6. Global Actions & Framework
        if target_key == "action_reload":
            res = self._run_cmd(["ufw", "reload"])
            return res.returncode == 0, "Firewall reloaded.", ""

        if target_key == "action_reset":
            res = self._run_cmd(["ufw", "--force", "reset"])
            return res.returncode == 0, "Firewall reset to factory defaults.", ""

        if target_key == "ip_forward":
            en = new_value in ("true", "1", "yes", "on")
            ok, msg = self.set_sysctl_forwarding(en)
            self._run_cmd(["ufw", "reload"])
            return ok, msg, ""

        if target_key == "waydroid_nat":
            en = new_value in ("true", "1", "yes", "on")
            ok, msg = self.set_waydroid_nat(en)
            self._run_cmd(["ufw", "reload"])
            return ok, msg, ""

        if target_key == "docker_mitigation":
            en = new_value in ("true", "1", "yes", "on")
            ok, msg = self.set_docker_mitigation(en)
            self._run_cmd(["ufw", "reload"])
            return ok, msg, ""

        # 7. Domain Whitelist / Blacklist
        if target_key == "whitelist_mode":
            en = new_value in ("true", "1", "yes", "on")
            data = self._read_domain_registry()
            data["whitelist_mode"] = en
            self._write_domain_registry(data)
            if en:
                self._run_cmd(["ufw", "default", "deny", "incoming"])
                self._run_cmd(["ufw", "default", "deny", "outgoing"])
                self._apply_domain_rules(data)
            else:
                self._run_cmd(["ufw", "default", "allow", "outgoing"])
                self._run_cmd(["ufw", "default", "deny", "incoming"])
                self._scrub_domain_rules()
            self._run_cmd(["ufw", "reload"])
            msg = "Lockdown Whitelist mode enabled." if en else "Whitelist mode disabled. Standard outgoing access restored."
            return True, msg, ""

        if target_key == "action_sync_domains":
            ok, msg = self.sync_domains()
            self._run_cmd(["ufw", "reload"])
            return ok, msg, ""

        if target_key == "action_add_domain":
            domain = str(self.cache.get("domains/draft_domain", "")).strip().lower()
            action = str(self.cache.get("domains/draft_action", "allow")).strip().lower()
            ports = str(self.cache.get("domains/draft_ports", "80,443")).strip()

            if not domain:
                return False, "Domain name cannot be empty.", ""

            data = self._read_domain_registry()
            filtered = [d for d in data.get("domains", []) if d["domain"] != domain]
            filtered.append({
                "domain": domain,
                "action": action,
                "ports": ports,
                "ips": [],
                "last_resolved": "",
            })
            data["domains"] = filtered
            self._write_domain_registry(data)
            self.sync_domains()
            self._run_cmd(["ufw", "reload"])
            return True, f"Domain '{domain}' registered ({action}).", ""

        if target_key == "action_remove_domain":
            domain = str(self.cache.get("domains/draft_domain", "")).strip().lower()
            if not domain:
                return False, "Specify the domain name to remove in the draft input.", ""

            data = self._read_domain_registry()
            data["domains"] = [d for d in data.get("domains", []) if d["domain"] != domain]
            self._write_domain_registry(data)

            numbered = self.get_numbered_rules()
            tag_allow = f"domain:{domain}"
            tag_block = f"block:{domain}"
            for r in sorted([r.number for r in numbered if r.comment in (tag_allow, tag_block)], reverse=True):
                self._run_cmd(["ufw", "--force", "delete", str(r)])

            self._run_cmd(["ufw", "reload"])
            return True, f"Domain '{domain}' removed from registry and firewall.", ""

        # 8. Rule Builder Execution
        if target_key == "action_apply_rule":
            cmd = self._construct_rule_command()
            res = self._run_cmd(cmd, timeout=CMD_TIMEOUT_WRITE)
            if res.returncode == 0:
                self._run_cmd(["ufw", "reload"])
                return True, f"Rule created: {' '.join(cmd)}", ""
            return False, f"Rule error: {res.stderr.strip() or res.stdout.strip()}", ""

        if target_key == "action_delete_rule":
            target_num_str = str(self.cache.get("builder/target_delete_num", "")).strip()
            if not target_num_str or not target_num_str.isdigit():
                return False, "Specify a valid rule number to delete.", ""
            res = self._run_cmd(["ufw", "--force", "delete", target_num_str])
            if res.returncode == 0:
                self._run_cmd(["ufw", "reload"])
                return True, f"Deleted rule #{target_num_str}.", ""
            return False, f"Failed to delete rule #{target_num_str}: {res.stderr.strip()}", ""

        # 9. Presets
        if target_key.startswith("action_preset_"):
            preset_name = target_key.removeprefix("action_preset_")
            ok, msg = self.apply_preset(preset_name)
            return ok, msg, ""

        # 10. Application Integration
        if target_key == "app_allow":
            app_name = new_value.strip()
            res = self._run_cmd(["ufw", "allow", app_name])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        if target_key == "app_deny":
            app_name = new_value.strip()
            res = self._run_cmd(["ufw", "deny", app_name])
            return res.returncode == 0, res.stdout.strip() or res.stderr.strip(), ""

        # In-memory cache update
        self.cache[f"{target_scope}/{target_key}" if target_scope else target_key] = new_value
        return True, "Value updated in cache.", ""

    def _construct_rule_command(self) -> list[str]:
        action = str(self.cache.get("builder/action", "allow")).strip()
        direction = str(self.cache.get("builder/direction", "in")).strip()
        proto = str(self.cache.get("builder/proto", "any")).strip()
        port = str(self.cache.get("builder/port", "")).strip()
        source = str(self.cache.get("builder/source", "any")).strip()
        dest = str(self.cache.get("builder/dest", "any")).strip()
        interface = str(self.cache.get("builder/interface", "any")).strip()
        out_iface = str(self.cache.get("builder/out_interface", "any")).strip()
        log_type = str(self.cache.get("builder/log", "none")).strip()
        comment = str(self.cache.get("builder/comment", "")).strip()
        placement = str(self.cache.get("builder/placement", "append")).strip()
        insert_num = str(self.cache.get("builder/insert_num", "1")).strip()

        cmd = ["ufw"]

        if placement == "insert" and insert_num.isdigit() and int(insert_num) > 0:
            cmd.extend(["insert", insert_num])
        elif placement == "prepend":
            cmd.append("prepend")

        if direction == "route":
            cmd.append("route")

        cmd.append(action)

        if direction == "in" and interface != "any":
            cmd.extend(["in", "on", interface])
        elif direction == "out" and interface != "any":
            cmd.extend(["out", "on", interface])
        elif direction == "route":
            if interface != "any":
                cmd.extend(["in", "on", interface])
            if out_iface != "any":
                cmd.extend(["out", "on", out_iface])

        if log_type in ("log", "log-all"):
            cmd.append(log_type)

        if proto != "any":
            cmd.extend(["proto", proto])

        if source and source != "any":
            cmd.extend(["from", source])
        if dest and dest != "any":
            cmd.extend(["to", dest])

        if port:
            if "to" in cmd:
                cmd.extend(["port", port])
            else:
                cmd.extend(["to", "any", "port", port])

        if comment:
            cmd.extend(["comment", comment])

        return cmd
