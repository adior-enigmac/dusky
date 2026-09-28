#!/usr/bin/env python3
"""
Unit and regression tests for UfwEngine.
Exercises parsing, rule generation, domain management, framework toggles, and presets.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from python.engines.ufw import UfwEngine, RuleRecord


class TestUfwEngine(unittest.TestCase):

    def setUp(self):
        self.engine = UfwEngine(config_path="/tmp/test_default_ufw")

    def test_status_verbose_parsing_active(self):
        sample_output = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere                   # OpenSSH
"""
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, sample_output, "")):
            status = self.engine.get_status_verbose()

        self.assertTrue(status["active"])
        self.assertEqual(status["logging"], "low")
        self.assertEqual(status["default_incoming"], "deny")
        self.assertEqual(status["default_outgoing"], "allow")
        self.assertEqual(status["default_routed"], "deny")
        self.assertEqual(status["new_profiles"], "skip")

    def test_status_verbose_parsing_inactive(self):
        sample_output = "Status: inactive\n"
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, sample_output, "")):
            status = self.engine.get_status_verbose()

        self.assertFalse(status["active"])
        self.assertEqual(status["logging"], "off")

    def test_numbered_rules_parsing(self):
        sample_output = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # OpenSSH
[ 2] 41641/udp                  ALLOW IN    Anywhere                   # Tailscale Direct P2P
[ 3] Anywhere on tailscale0     ALLOW IN    Anywhere                   # Trust IN: tailscale0
[ 4] Anywhere on wlan0          ALLOW FWD   Anywhere on tailscale0     # Forward: tailscale0 -> WAN
[ 5] Anywhere on virbr0         ALLOW FWD   Anywhere                   (out)
[ 6] 80/tcp (v6)                DENY IN     Anywhere (v6)              # Block IPv6 HTTP
"""
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, sample_output, "")):
            rules = self.engine.get_numbered_rules()

        self.assertEqual(len(rules), 6)
        
        # Rule 1
        self.assertEqual(rules[0].number, 1)
        self.assertEqual(rules[0].to_addr, "22/tcp")
        self.assertEqual(rules[0].action, "ALLOW IN")
        self.assertEqual(rules[0].from_addr, "Anywhere")
        self.assertEqual(rules[0].comment, "OpenSSH")
        self.assertFalse(rules[0].is_v6)

        # Rule 4 (Route rule)
        self.assertEqual(rules[3].number, 4)
        self.assertEqual(rules[3].to_addr, "Anywhere on wlan0")
        self.assertEqual(rules[3].action, "ALLOW FWD")
        self.assertEqual(rules[3].from_addr, "Anywhere on tailscale0")
        self.assertEqual(rules[3].comment, "Forward: tailscale0 -> WAN")

        # Rule 6 (IPv6)
        self.assertEqual(rules[5].number, 6)
        self.assertTrue(rules[5].is_v6)
        self.assertEqual(rules[5].action, "DENY IN")

    def test_rule_command_construction(self):
        # 1. Simple rule
        self.engine.cache = {
            "builder/action": "allow",
            "builder/direction": "in",
            "builder/proto": "tcp",
            "builder/port": "22",
            "builder/source": "any",
            "builder/dest": "any",
            "builder/interface": "any",
            "builder/log": "none",
            "builder/comment": "SSH Inbound",
            "builder/placement": "append",
        }
        cmd = self.engine._construct_rule_command()
        self.assertEqual(cmd, ["ufw", "allow", "proto", "tcp", "to", "any", "port", "22", "comment", "SSH Inbound"])

        # 2. Insert rule with specific interface and subnet
        self.engine.cache = {
            "builder/action": "deny",
            "builder/direction": "in",
            "builder/proto": "udp",
            "builder/port": "53",
            "builder/source": "192.168.1.0/24",
            "builder/dest": "any",
            "builder/interface": "eth0",
            "builder/log": "log",
            "builder/comment": "Block Local DNS",
            "builder/placement": "insert",
            "builder/insert_num": "3",
        }
        cmd = self.engine._construct_rule_command()
        self.assertEqual(
            cmd,
            ["ufw", "insert", "3", "deny", "in", "on", "eth0", "log", "proto", "udp", "from", "192.168.1.0/24", "to", "any", "port", "53", "comment", "Block Local DNS"],
        )

        # 3. Route forwarding rule
        self.engine.cache = {
            "builder/action": "allow",
            "builder/direction": "route",
            "builder/proto": "any",
            "builder/port": "",
            "builder/source": "any",
            "builder/dest": "any",
            "builder/interface": "tailscale0",
            "builder/out_interface": "wlan0",
            "builder/log": "none",
            "builder/comment": "Forward Tailscale to WAN",
            "builder/placement": "prepend",
        }
        cmd = self.engine._construct_rule_command()
        self.assertEqual(
            cmd,
            ["ufw", "prepend", "route", "allow", "in", "on", "tailscale0", "out", "on", "wlan0", "comment", "Forward Tailscale to WAN"],
        )

    def test_listening_ports_parsing(self):
        sample_output = """tcp:
  21 * (vsftpd)
   [19] allow from 192.168.29.0/24 to any port 21 proto tcp comment 'LAN FTP Control'

  22 * (sshd)
   [ 1] allow 22/tcp comment 'OpenSSH'

udp:
  41641 * (tailscaled)
   [ 2] allow 41641/udp comment 'Tailscale Direct P2P'
"""
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, sample_output, "")):
            listening = self.engine.get_listening_ports()

        self.assertEqual(len(listening), 3)
        self.assertEqual(listening[0]["port"], 21)
        self.assertEqual(listening[0]["process"], "vsftpd")
        self.assertEqual(listening[0]["proto"], "tcp")
        self.assertTrue(len(listening[0]["rules"]) > 0)

        self.assertEqual(listening[1]["port"], 22)
        self.assertEqual(listening[1]["process"], "sshd")

        self.assertEqual(listening[2]["port"], 41641)
        self.assertEqual(listening[2]["process"], "tailscaled")
        self.assertEqual(listening[2]["proto"], "udp")

    def test_domain_ips_resolution_mock(self):
        fake_addrinfo = [
            (2, 1, 6, '', ('93.184.216.34', 0)),
            (10, 1, 6, '', ('2606:2800:220:1:248:1893:25c8:1946', 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            ips = self.engine.resolve_domain_ips("example.com")

        self.assertIn("93.184.216.34", ips)
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", ips)

    def test_presets_validation(self):
        valid_presets = [
            "dusky_full",
            "strict_workstation",
            "lockdown_whitelist",
            "dev_lan",
            "stealth",
            "streaming_moonlight",
            "factory_reset",
        ]
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch.object(self.engine, "set_sysctl_forwarding", return_value=(True, "")), \
             patch.object(self.engine, "set_waydroid_nat", return_value=(True, "")), \
             patch.object(self.engine, "set_docker_mitigation", return_value=(True, "")):
            for preset in valid_presets:
                ok, msg = self.engine.apply_preset(preset)
                self.assertTrue(ok, f"Preset '{preset}' failed: {msg}")

        ok_bad, _ = self.engine.apply_preset("non_existent_preset")
        self.assertFalse(ok_bad)

    def test_reports_validation(self):
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, "dummy report", "")):
            content = self.engine.get_report("listening")
            self.assertEqual(content, "dummy report")

        invalid_rep = self.engine.get_report("not_a_report")
        self.assertIn("Error: Invalid report type", invalid_rep)

    def test_domain_rules_application(self):
        data = {
            "whitelist_mode": True,
            "domains": [
                {
                    "domain": "test.com",
                    "action": "allow",
                    "ports": "80,443",
                    "ips": ["1.2.3.4"],
                },
                {
                    "domain": "blocked.com",
                    "action": "deny",
                    "ports": "any",
                    "ips": ["5.6.7.8"],
                },
            ],
        }
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, "", "")) as mock_cmd, \
             patch.object(self.engine, "get_numbered_rules", return_value=[]):
            self.engine._apply_domain_rules(data)
            calls = [call.args[0] for call in mock_cmd.call_args_list]

            # Core rules when whitelist_mode is True
            self.assertIn(["ufw", "allow", "out", "on", "lo", "comment", "core:loopback"], calls)
            self.assertIn(["ufw", "allow", "out", "to", "any", "port", "53", "comment", "core:dns"], calls)
            # Whitelisted domain rule
            self.assertIn(["ufw", "allow", "out", "to", "1.2.3.4", "port", "80", "proto", "tcp", "comment", "domain:test.com"], calls)
            self.assertIn(["ufw", "allow", "out", "to", "1.2.3.4", "port", "443", "proto", "tcp", "comment", "domain:test.com"], calls)
            # Blocked domain rule
            self.assertIn(["ufw", "deny", "out", "to", "5.6.7.8", "comment", "block:blocked.com"], calls)

    def test_detailed_port_map(self):
        sample_ss = """tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=4))
tcp LISTEN 0 128 127.0.0.1:40723 0.0.0.0:* users:(("codex",pid=456,fd=5))
udp UNCONN 0 0 192.168.29.125:9580 0.0.0.0:* users:(("qbittorrent",pid=789,fd=6))
"""
        sample_rules = [
            RuleRecord(number=1, to_addr="22/tcp", action="ALLOW IN", from_addr="Anywhere", comment="OpenSSH")
        ]
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, sample_ss, "")), \
             patch.object(self.engine, "get_numbered_rules", return_value=sample_rules), \
             patch.object(self.engine, "get_status_verbose", return_value={"default_incoming": "deny"}):
            port_map = self.engine.get_detailed_port_map()

        self.assertEqual(len(port_map), 3)

        # Port 22 should be EXPOSED (listening on 0.0.0.0 and allowed in UFW)
        p22 = next(p for p in port_map if p["port"] == 22)
        self.assertEqual(p22["fw_status"], "EXPOSED")
        self.assertEqual(p22["process"], "sshd")

        # Port 40723 should be PROTECTED (bound to 127.0.0.1)
        p_codex = next(p for p in port_map if p["port"] == 40723)
        self.assertEqual(p_codex["fw_status"], "PROTECTED")

        # Port 9580 should be FILTERED (listening on LAN, but dropped by default incoming policy)
        p_qbit = next(p for p in port_map if p["port"] == 9580)
        self.assertEqual(p_qbit["fw_status"], "FILTERED")

    def test_open_and_close_port(self):
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, "", "")) as mock_cmd, \
             patch.object(self.engine, "get_numbered_rules", return_value=[]):
            # Open port
            ok, msg = self.engine.open_port("8080", proto="tcp", scope="any", comment="Test Web")
            self.assertTrue(ok)
            calls = [call.args[0] for call in mock_cmd.call_args_list]
            self.assertIn(["ufw", "allow", "8080/tcp", "comment", "Test Web"], calls)

            # Close port
            mock_cmd.reset_mock()
            ok_c, msg_c = self.engine.close_port("8080", proto="tcp", action="deny", comment="Block Web")
            self.assertTrue(ok_c)
            calls_c = [call.args[0] for call in mock_cmd.call_args_list]
            self.assertIn(["ufw", "deny", "8080/tcp", "comment", "Block Web"], calls_c)

    def test_service_switches(self):
        sample_rules = [
            RuleRecord(number=1, to_addr="22/tcp", action="ALLOW IN", from_addr="Anywhere", comment="OpenSSH")
        ]
        with patch.object(self.engine, "get_numbered_rules", return_value=sample_rules), \
             patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, "", "")):
            # SSH is currently allowed
            self.assertTrue(self.engine.is_service_allowed("ssh"))
            # HTTP is currently not allowed
            self.assertFalse(self.engine.is_service_allowed("http"))

            # Toggle HTTP on
            ok, msg = self.engine.toggle_service("http", True)
            self.assertTrue(ok)

    def test_active_connections_and_ban(self):
        sample_conns = """tcp ESTAB 0 0 192.168.29.125:50640 104.18.32.47:443 users:(("firefox",pid=4178,fd=663))
tcp ESTAB 0 0 192.168.29.125:22 192.168.29.50:54321 users:(("sshd",pid=123,fd=3))
"""
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, sample_conns, "")) as mock_cmd:
            conns = self.engine.get_active_connections()
            self.assertEqual(len(conns), 2)
            self.assertEqual(conns[0]["remote_ip"], "104.18.32.47")
            self.assertEqual(conns[0]["process"], "firefox")

            # Ban IP
            mock_cmd.reset_mock()
            ok, msg = self.engine.ban_ip("192.168.29.50")
            self.assertTrue(ok)
            calls = [call.args[0] for call in mock_cmd.call_args_list]
            self.assertIn(["ufw", "prepend", "deny", "from", "192.168.29.50", "comment", "Banned: 192.168.29.50"], calls)

    def test_panic_lockdown(self):
        with patch.object(self.engine, "_run_cmd", return_value=subprocess.CompletedProcess([], 0, "", "")) as mock_cmd:
            ok, msg = self.engine.panic_lockdown(True)
            self.assertTrue(ok)
            calls = [call.args[0] for call in mock_cmd.call_args_list]
            self.assertIn(["ufw", "default", "deny", "incoming"], calls)
            self.assertIn(["ufw", "default", "deny", "outgoing"], calls)
            self.assertIn(["ufw", "default", "deny", "routed"], calls)

            mock_cmd.reset_mock()
            ok_r, _ = self.engine.panic_lockdown(False)
            self.assertTrue(ok_r)
            calls_r = [call.args[0] for call in mock_cmd.call_args_list]
            self.assertIn(["ufw", "default", "allow", "outgoing"], calls_r)


if __name__ == "__main__":
    unittest.main()
