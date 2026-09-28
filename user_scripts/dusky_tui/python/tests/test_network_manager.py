"""Focused network manager tests; no live connections are changed."""

from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from python.engines import network_manager as nm, rich_speedtest


class NetworkManagerTests(unittest.TestCase):
    def engine(self):
        engine = object.__new__(nm.NetworkManagerEngine)
        engine.rescan_event = threading.Event()
        engine._profile_lock = threading.Lock()
        engine._uplinks_cache = []
        engine._cached_scans = []
        engine.shutdown_event = threading.Event()
        return engine

    def test_scan_group_retains_devices_bssids_and_mixed_security(self):
        engine = self.engine()
        engine._run_cmd = lambda *args, **kwargs: (
            " :Same:WPA2:70:wlan0:00\\:11\\:22\\:33\\:44\\:55\n"
            "*:Same:WPA2:50:wlan1:00\\:11\\:22\\:33\\:44\\:66\n"
            " :Same:--:90:wlan0:00\\:11\\:22\\:33\\:44\\:77\n"
        )
        group, = engine._get_scanned_wifi()
        self.assertEqual(len(group["access_points"]), 3)
        self.assertEqual(group["device"], "wlan1")
        self.assertEqual(group["bssid"], "00:11:22:33:44:66")
        self.assertEqual(group["security"], "Mixed")
        engine._cached_scans = [group]
        with patch.object(nm.subprocess, "run") as run:
            self.assertFalse(engine._async_connect("Same", None)[0])
            run.assert_not_called()

    def test_schema_targets_each_active_adapter_by_uuid(self):
        engine = nm.NetworkManagerEngine()
        connections = [
            {"uuid": "first", "ssid": "Same", "device": "wlan0", "name": "One"},
            {"uuid": "second", "ssid": "Same", "device": "wlan1", "name": "Two"},
        ]
        engine._radio_on = True
        engine._active_wifi_connections = connections
        engine._active_wifi = connections[0]
        engine._saved_wifi = [{**connection, "autoconnect": True} for connection in connections]
        engine._cached_scans = [{"ssid": "Same", "security": "WPA2", "signal": 60}]
        app = SimpleNamespace(schema={i: [] for i in range(6)}, tabs={3: "Devices"})
        app._replace_dynamic_tabs = lambda items: app.schema.update(items) or True
        engine.app = app
        engine._rebuild_schema()
        for tab in (0, 1, 2):
            keys = {item.key for item in app.schema[tab]}
            self.assertTrue({"dc__first", "dc__second", "rc__first", "rc__second"} <= keys)
        for tab in (0, 1):
            keys = {item.key for item in app.schema[tab]}
            self.assertTrue({"band__first", "band__second"} <= keys)

    def test_duplicate_profile_labels_and_enterprise_setup_are_explicit(self):
        engine = nm.NetworkManagerEngine()
        engine._radio_on = True
        engine._saved_wifi = [
            {"uuid": "00000001-one", "name": "Duplicate", "ssid": "Same", "autoconnect": True},
            {"uuid": "00000002-two", "name": "Duplicate", "ssid": "Same", "autoconnect": False},
        ]
        engine._cached_scans = [{"ssid": "Same", "security": "WPA2", "signal": 80},
                                {"ssid": "Office", "security": "WPA2 802.1X", "signal": 60}]
        app = SimpleNamespace(schema={i: [] for i in range(6)}, tabs={3: "Devices"})
        app._replace_dynamic_tabs = lambda items: app.schema.update(items) or True
        engine.app = app
        engine._rebuild_schema()
        parents = [item.label for item in app.schema[1] if item.is_parent]
        self.assertEqual(len(set(parents)), 2)
        self.assertTrue(any(item.key == "enterprise__Office" and item.read_only for item in app.schema[0]))
        self.assertFalse(any(item.key == "pw__Office" for item in app.schema[0]))
        labels = [item.label for item in app.schema[0] if item.key.startswith("cn__")]
        self.assertEqual(len(set(labels)), 2)

    def test_hotspot_auto_retains_active_adapter(self):
        engine = nm.NetworkManagerEngine()
        engine._hotspot_ssid = "Active"
        engine._hotspot_password = "password"
        active = {"uuid": "ap-id", "device": "wlan1"}
        engine._hotspot_devices = lambda: [
            {"device": "wlan0", "state": "disconnected", "2.4": "yes", "5": "yes"},
            {"device": "wlan1", "state": "connected", "2.4": "yes", "5": "yes"},
        ]
        engine._hotspot_profile = lambda active_only=False, uuid_filter="": active if active_only else {"uuid": "ap-id", "ssid": "Active", "password": "password"}
        engine._run_cmd = lambda args, **kwargs: "enabled" if "radio" in args else "ap\nActive\nbg\nwpa-psk\npassword\nshared\ndisabled\nno\n"
        with patch.object(nm.shutil, "which", return_value="/usr/bin/dnsmasq"), \
             patch.object(engine, "_prepare_hotspot_firewall", return_value="") as firewall, \
             patch.object(nm.subprocess, "run") as run:
            ok, message, _ = engine._handle_hotspot("start_hotspot_24", "true")
        self.assertTrue(ok)
        self.assertIn("already active on wlan1", message)
        firewall.assert_called_once_with("wlan1")
        run.assert_not_called()

    def test_ipv6_dns_fallback_reads_unescaped_values(self):
        engine = self.engine()
        def output(args, **kwargs):
            if args[0] == "resolvectl":
                return ""
            self.assertIn("-e", args)
            self.assertEqual(args[args.index("-e") + 1], "no")
            return "\n2606:4700:4700::1111\n"
        engine._run_cmd = output
        self.assertEqual(engine._get_active_dns_provider("wlan0"), "Cloudflare")

    def test_reconnect_keeps_the_original_adapter(self):
        engine = self.engine()
        engine._get_active_wifi_connections = lambda: [{"uuid": "second", "device": "wlan1"}]
        engine.shutdown_event.set()
        with patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=0, stderr="")) as run:
            self.assertTrue(engine._async_reconnect("Second", "second")[0])
        self.assertEqual(run.call_args_list[-1].args[0][-2:], ["ifname", "wlan1"])
        with patch.object(nm.subprocess, "run") as run:
            self.assertFalse(engine._async_reconnect("Missing", "missing")[0])
            run.assert_not_called()

    def test_scan_failure_keeps_last_successful_inventory(self):
        engine = nm.NetworkManagerEngine()
        previous = [{"ssid": "Last known", "security": "Open", "signal": 60, "in_use": False}]
        engine._cached_scans = previous
        engine.app = None
        with patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=1, stderr="Unavailable")), self.assertLogs("dusky_network_engine", level="ERROR"):
            engine._async_rescan_wifi()
        self.assertIs(engine._cached_scans, previous)
        self.assertFalse(engine._scan_running)

    def test_failed_ping_counts_as_loss_and_gateway_change_resets_history(self):
        state = None
        sample = {"iface": "wlan0", "gateway": "192.0.2.1", "internet_ping_ms": "10"}
        state = nm.ping_latency_state(state, sample)
        self.assertEqual(state["internet_ping_packet_loss"], 0)
        state = nm.ping_latency_state(state, {**sample, "internet_ping_ms": None})
        self.assertEqual(state["internet_ping_packet_loss"], 50)
        state = nm.ping_latency_state(state, {"iface": "wlan0", "gateway": "192.0.2.2", "internet_ping_ms": None})
        self.assertEqual(state["internet_ping_packet_loss"], 100)
        self.assertEqual(state["internet_ping_latency"], -1)

    def test_unattempted_ping_has_no_packet_loss_measurement(self):
        state = nm.ping_latency_state(None, {})
        self.assertIsNone(state["internet_ping_packet_loss"])
        self.assertEqual(nm.format_packet_loss(state["internet_ping_packet_loss"]), "N/A")

    def test_ping_probes_are_bound_to_displayed_ipv6_interface(self):
        engine = self.engine()
        engine._devices_cache = [{"device": "test0", "type": "wireguard", "connection": "VPN"}]
        engine._route_choice = lambda: {}
        engine._run_cmd = lambda args, **kwargs: (
            '[{"dev":"test0","gateway":"2001:db8::1"}]' if args[:3] == ["ip", "-j", "-6"] else
            "[]" if args[:3] == ["ip", "-j", "-4"] else
            "inet6 2001:db8::2/64 scope global" if "addr" in args else ""
        )
        with patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="time=12.5 ms")) as run:
            result = engine._enrich_network_status({}, None)
        self.assertEqual(result["type"], "wireguard")
        self.assertEqual(result["internet_ping_target"], "2606:4700:4700::1111")
        self.assertEqual(result["internet_ping_ms"], "12.5")
        self.assertTrue(all(call.args[0][:4] == ["ping", "-6", "-I", "test0"] for call in run.call_args_list))

    def test_nmcli_parser_preserves_escaped_backslashes_and_colons(self):
        self.assertEqual(
            nm._split_nmcli_line(r"Office\: Guest\\:uuid:wifi"),
            ["Office: Guest\\", "uuid", "wifi"],
        )
        self.assertEqual(nm._split_nmcli_line(r"literal\x41:name"), [r"literal\x41", "name"])

    def test_device_multiline_details_preserve_literal_colons_and_backslashes(self):
        engine = self.engine()
        engine._run_cmd = lambda *args, **kwargs: (
            "GENERAL.DEVICE:wlan0\n"
            "GENERAL.DRIVER:driver\\\n"
            "GENERAL.HWADDR:00:11:22:33:44:55\n"
            "IP4.GATEWAY:192.0.2.1\n"
        )
        details = engine._get_device_details_map()["wlan0"]
        self.assertEqual(details["GENERAL.DRIVER"], "driver\\")
        self.assertEqual(details["GENERAL.HWADDR"], "00:11:22:33:44:55")

    def test_profile_name_and_wireless_ssid_are_distinct(self):
        engine = self.engine()
        engine._profile_ssids = {}

        def output(args, timeout=5, required=False):
            if "--active" in args:
                return "Friendly name:00000000-0000-0000-0000-000000000001:802-11-wireless:wlan0\n"
            if any("AUTOCONNECT" in arg for arg in args):
                return "Friendly name:00000000-0000-0000-0000-000000000001:802-11-wireless:yes\n"
            if "802-11-wireless.mode" in args:
                return "802-11-wireless.mode:infra\n"
            return "Actual SSID\n"

        engine._run_cmd = output
        self.assertEqual(engine._get_saved_wifi()[0]["ssid"], "Actual SSID")
        self.assertEqual(engine._get_saved_wifi()[0]["name"], "Friendly name")
        self.assertEqual(engine._get_active_wifi_connection()["ssid"], "Actual SSID")

    def test_qr_credentials_preserve_significant_spaces(self):
        engine = self.engine()
        uuid = "00000000-0000-0000-0000-000000000001"
        engine._run_cmd = lambda *args, **kwargs: " Office Wi-Fi \nwpa-psk\n password \n\nno\nFriendly name\n"
        self.assertEqual(engine._get_wifi_credentials(uuid)[:2], (" Office Wi-Fi ", " password "))

    def test_profile_qr_rejects_unavailable_password(self):
        engine = self.engine()
        engine._get_wifi_credentials = lambda uuid: ("Example", "", "WPA-PSK", False)
        engine._trigger_qr_viewer = lambda *args: self.fail("must not share incomplete credentials")
        ok, message, _ = engine._share_profile_qr("uuid")
        self.assertFalse(ok)
        self.assertIn("unavailable", message)

    def test_speedtest_runner_handles_partial_lines_and_failed_child(self):
        class FakeLive:
            def update(self, renderable):
                pass

        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "sample"
            command.write_text("#!/bin/sh\nprintf 42.5\n", encoding="utf-8")
            command.chmod(0o700)
            with patch.object(rich_speedtest, "check_cancel_key", return_value=False):
                self.assertEqual(rich_speedtest.run_phase("down", str(command), FakeLive()), (42.5, False))
                command.write_text("#!/bin/sh\nprintf '42.5\\n'\nexit 1\n", encoding="utf-8")
                self.assertEqual(rich_speedtest.run_phase("down", str(command), FakeLive()), (None, False))
                command.write_text("#!/bin/sh\nprintf 42.5\nsleep 5\n", encoding="utf-8")
                with patch.object(rich_speedtest, "PHASE_TIMEOUT_SECONDS", 0.2):
                    self.assertEqual(rich_speedtest.run_phase("down", str(command), FakeLive()), (42.5, False))

    def test_speedtest_interrupt_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "sample"
            command.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
            command.chmod(0o700)
            spawned = []
            original = rich_speedtest.subprocess.Popen
            def spawn(*args, **kwargs):
                process = original(*args, **kwargs)
                spawned.append(process)
                return process
            with patch.object(rich_speedtest.subprocess, "Popen", side_effect=spawn), \
                 patch.object(rich_speedtest, "check_cancel_key", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    rich_speedtest.run_phase("down", str(command), SimpleNamespace(update=lambda value: None))
            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(spawned[0].poll())
            self.assertTrue(spawned[0].stdout.closed)

    def test_interactive_speedtest_uses_only_valid_current_run_results(self):
        for result, expected in ((None, "Failed"), ({"status": "complete", "down": 12}, "Complete"),
                                 ({"status": "complete", "down": float("nan")}, "Failed"),
                                 ({"status": "cancelled"}, "Cancelled")):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                engine = self.engine()
                engine.cache_dir = Path(directory)
                (engine.cache_dir / "speedtest_last.json").write_text(json.dumps({"status": "complete", "down": 999}))
                engine._speedtest_running = False
                engine._rebuild_schema = lambda: None
                engine.app = SimpleNamespace(call_from_thread=lambda function: function(), suspend=nullcontext,
                    _rebuild_indexes=lambda: None, _refresh_all_ui=lambda: None)
                def spawn(command):
                    if result is not None:
                        Path(command[-1]).write_text(json.dumps(result))
                    return SimpleNamespace(returncode=0, wait=lambda timeout: 0)
                with patch.object(nm.subprocess, "Popen", side_effect=spawn), patch.object(nm.logger, "error"):
                    ok, message, _ = engine._handle_speedtest_action("speedtest_down")
                self.assertEqual(engine._speedtest_status, expected)
                self.assertEqual(ok, expected != "Failed")
                self.assertFalse(engine._speedtest_running)
                if expected == "Failed":
                    self.assertEqual(engine._speedtest_down_val, "--")

    def test_speedtest_without_attached_ui_fails_without_worker(self):
        engine = self.engine()
        engine.app = None
        engine._speedtest_running = False
        ok, message, _ = engine._handle_speedtest_action("speedtest_full")
        self.assertFalse(ok)
        self.assertFalse(engine._speedtest_running)
        self.assertIn("not attached", message)

    def test_native_speedtest_failure_is_not_a_zero_speed_success(self):
        live = SimpleNamespace(update=lambda renderable: None)
        with patch("urllib.request.urlopen", side_effect=OSError("offline")), \
             patch.object(rich_speedtest, "check_cancel_key", return_value=False), \
             patch.object(rich_speedtest.console, "print"):
            self.assertEqual(rich_speedtest.run_phase_native("down", live), (None, False))
            self.assertEqual(rich_speedtest.run_phase_native("up", live), (None, False))

    def test_hotspot_profile_selects_active_uuid_when_names_duplicate(self):
        engine = self.engine()
        engine._run_cmd = lambda args, **kwargs: (
            "Dusky Hotspot:old-id:802-11-wireless\nDusky Hotspot:active-id:802-11-wireless\n"
            if "connection" in args and "show" in args and "-f" in args else
            "ap\n" if "802-11-wireless.mode" in args else
            " Active SSID " if "802-11-wireless.ssid" in args else
            " secret "
        )
        profile = engine._hotspot_profile(uuid_filter="active-id")
        self.assertEqual(profile["uuid"], "active-id")
        self.assertEqual(profile["ssid"], " Active SSID ")
        self.assertEqual(profile["password"], " secret ")

    def test_duplicate_inactive_hotspots_do_not_choose_a_profile_arbitrarily(self):
        engine = self.engine()
        engine._run_cmd = lambda args, **kwargs: (
            "Dusky Hotspot:one:802-11-wireless\nDusky Hotspot:two:802-11-wireless\n"
            if "-f" in args else "ap\n"
        )
        with self.assertRaisesRegex(RuntimeError, "Multiple profiles"):
            engine._hotspot_profile()
        self.assertEqual(engine._hotspot_profile(uuid_filter="two")["uuid"], "two")

    def test_connect_action_reports_actual_command_failure(self):
        engine = self.engine()
        engine._get_saved_wifi = lambda: []
        with patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=10, stderr="No AP", stdout="")):
            ok, message, _ = engine._handle_network_action("cn__Example", "true")
        self.assertFalse(ok)
        self.assertIn("No AP", message)
        self.assertTrue(engine.rescan_event.is_set())

    def test_required_inventory_command_distinguishes_failure_from_empty_output(self):
        engine = self.engine()
        with patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=10, stderr="manager unavailable", stdout="")):
            with self.assertRaisesRegex(RuntimeError, "manager unavailable"):
                engine._run_cmd(["nmcli", "radio", "wifi"], required=True)
        with patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=0, stderr="", stdout="")):
            self.assertEqual(engine._run_cmd(["nmcli", "device", "status"], required=True), "")

    def test_connect_timeout_is_reported(self):
        engine = self.engine()
        with patch.object(nm.subprocess, "run", side_effect=nm.subprocess.TimeoutExpired("nmcli", 30)):
            ok, message, _ = engine._async_connect("Example", None)
        self.assertFalse(ok)
        self.assertIn("timed out", message)

    def test_band_failure_reports_verified_rollback(self):
        engine = self.engine()
        uuid = "00000000-0000-0000-0000-000000000001"
        engine._verbose_info = {"band": "2.4"}
        engine._get_saved_wifi = lambda: [{"uuid": uuid, "ssid": "Example"}]
        engine._get_active_wifi_connections = lambda: [{"uuid": uuid, "ssid": "Example", "device": "wlan0"}]
        engine.get_available_bands_for_ssid = lambda *args: ["2.4", "5"]
        outcomes = [
            SimpleNamespace(returncode=0, stdout="\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="a\n", stderr=""),
            SimpleNamespace(returncode=4, stdout="", stderr="No AP on 5 GHz"),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="\n", stderr=""),
        ]
        with patch.object(nm.subprocess, "run", side_effect=outcomes) as run:
            ok, message = engine.set_wifi_band_with_rollback(uuid, "5 GHz")
        self.assertFalse(ok)
        self.assertIn("previous band restored", message)
        self.assertEqual(run.call_count, 7)

    def test_band_edit_on_inactive_profile_does_not_activate_it(self):
        engine = self.engine()
        uuid = "00000000-0000-0000-0000-000000000001"
        engine._verbose_info = {"band": "2.4"}
        engine._get_saved_wifi = lambda: [{"uuid": uuid, "ssid": "Other network"}]
        engine._get_active_wifi_connections = lambda: [{"uuid": "active-id", "ssid": "Current", "device": "wlan0"}]
        engine._get_wifi_device = lambda: "wlan0"
        engine.get_available_bands_for_ssid = lambda *args: ["2.4", "5"]
        outcomes = [
            SimpleNamespace(returncode=0, stdout="\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="a\n", stderr=""),
        ]
        with patch.object(nm.subprocess, "run", side_effect=outcomes) as run:
            ok, message = engine.set_wifi_band_with_rollback(uuid, "5 GHz")
        self.assertTrue(ok)
        self.assertIn("inactive profile", message)
        self.assertFalse(any(call.args[0][1:3] == ["connection", "up"] for call in run.call_args_list))

    def test_dns_provider_uses_selected_link_only(self):
        engine = self.engine()
        seen = []

        def output(args, timeout=5, required=False):
            seen.append(args)
            return "Link 2 (wlan0): 192.0.2.1\n" if args[:2] == ["resolvectl", "dns"] else ""

        engine._run_cmd = output
        self.assertEqual(engine._get_active_dns_provider("wlan0", "192.0.2.1"), "Router (192.0.2.1)")
        self.assertEqual(seen[0], ["resolvectl", "dns", "wlan0"])

    def test_attaching_engine_waits_for_observed_state_before_rebuilding(self):
        engine = nm.NetworkManagerEngine()
        with patch.object(engine, "_rebuild_schema") as rebuild, patch.object(nm.threading, "Thread") as worker:
            engine.set_app(SimpleNamespace())
        rebuild.assert_not_called()
        worker.return_value.start.assert_called_once()
        self.assertTrue(engine.rescan_event.is_set())
        engine.shutdown()
        self.assertTrue(engine.shutdown_event.is_set())

    def test_redraw_uses_cached_snapshot_without_running_commands(self):
        engine = nm.NetworkManagerEngine()

        class FakeApp:
            schema = {index: [] for index in range(6)}
            tabs = dict(enumerate(("Networks", "Saved", "Status", "Devices", "Speed Test", "Hotspot")))

            def _replace_dynamic_tabs(self, items):
                self.schema.update(items)
                return True

            def _rebuild_indexes(self):
                pass

            def _refresh_all_ui(self):
                pass

        engine.app = FakeApp()
        with patch.object(nm.subprocess, "run", side_effect=AssertionError("redraw launched a command")):
            engine._rebuild_schema()
        self.assertTrue(engine.app.schema[3])

    def test_refresh_preserves_hotspot_batch_draft_and_unavailable_adapter(self):
        engine = nm.NetworkManagerEngine()
        draft = nm.ConfigItem(label="SSID", key="hotspot_ssid", scope="hotspot", type_="string", default="old")
        draft.value = "pending draft"
        adapter = nm.ConfigItem(label="Adapter", key="hotspot_device", scope="hotspot", type_="cycle", default="wlan9")
        engine._hotspot_device = "wlan9"
        app = SimpleNamespace(
            schema={index: [] for index in range(6)},
            tabs=dict(enumerate(("Networks", "Saved", "Status", "Devices", "Speed Test", "Hotspot"))),
            pending_commits={(5, 0)}, _replace_dynamic_tabs=lambda replacements: False,
        )
        app.schema[5] = [draft, adapter]
        engine.app = app
        engine._rebuild_schema()
        self.assertEqual(draft.value, "pending draft")
        app.pending_commits.clear()
        engine._rebuild_schema()
        self.assertEqual(engine._hotspot_device, "wlan9")
        self.assertIn("unavailable", adapter.label)

    def test_saved_hotspot_is_loaded_once_without_overwriting_later_draft(self):
        engine = nm.NetworkManagerEngine()
        engine._run_cmd = lambda *args, **kwargs: "enabled\n"
        engine._get_saved_wifi = lambda: []
        engine._get_active_wifi_connection = lambda: None
        engine._hotspot_profile = lambda active_only=False: None if active_only else {"ssid": "Saved", "password": "savedpass"}
        state = engine.load_state()
        self.assertEqual(state["hotspot/hotspot_ssid"], "Saved")
        self.assertEqual(state["hotspot/hotspot_password"], "savedpass")
        engine._handle_hotspot("hotspot_ssid", "Draft")
        self.assertEqual(engine.load_state()["hotspot/hotspot_ssid"], "Draft")

    def test_device_rows_include_all_addresses_and_copy_structured_values(self):
        engine = nm.NetworkManagerEngine()
        engine._devices_cache = [{"device": "test0", "type": "ethernet", "state": "connected", "connection": "A profile"}]
        engine._device_details = {"test0": {
            "IP4.ADDRESS[1]": "192.0.2.2/24", "IP4.ADDRESS[2]": "192.0.2.3/24",
            "IP6.ADDRESS[1]": "2001:db8::2/64", "IP6.DNS[1]": "2001:db8::53",
        }}

        class FakeApp:
            schema = {index: [] for index in range(6)}
            tabs = dict(enumerate(("Networks", "Saved", "Status", "Devices", "Speed Test", "Hotspot")))

            def _replace_dynamic_tabs(self, replacements):
                self.schema.update(replacements)
                return True

        engine.app = FakeApp()
        engine._rebuild_schema()
        rows = [item for item in engine.app.schema[3] if item.scope == "clipboard"]
        self.assertEqual(sum(item.label.startswith("IPv4 address:") for item in rows), 2)
        ipv6 = next(item for item in rows if item.label.startswith("IPv6 address:"))
        ipv6.label = "Truncated presentation..."
        with patch.object(nm, "copy_to_clipboard", return_value=True) as copy:
            self.assertTrue(engine._handle_clipboard(ipv6.key)[0])
        copy.assert_called_once_with("2001:db8::2/64")

    def test_ipv6_default_route_is_used_when_ipv4_is_absent(self):
        engine = self.engine()
        engine._devices_cache = [{"device": "wlan0", "connection": "Example"}]
        engine._uplinks_cache = []
        engine._route_choice = lambda: {}

        def output(args, timeout=5, required=False):
            if args[:4] == ["ip", "-j", "-4", "route"]:
                return "[]"
            if args[:4] == ["ip", "-j", "-6", "route"]:
                return '[{"dev":"wlan0","gateway":"2001:db8::1"}]'
            if args[:4] == ["ip", "-o", "-6", "addr"]:
                return "2: wlan0 inet6 2001:db8::2/64 scope global dynamic\n"
            return ""

        engine._run_cmd = output
        with patch.object(nm.Path, "exists", return_value=False):
            result = engine._enrich_network_status({"router_ping_ms": "1", "internet_ping_ms": "1"}, None)
        self.assertEqual((result["iface"], result["ip"], result["prefix"]), ("wlan0", "2001:db8::2", "64"))

    def test_uplink_candidates_include_local_only_and_exclude_shared_profiles(self):
        engine = self.engine()
        active = "WiFi:wifi-id:802-11-wireless:wlan0\nUSB:usb-id:802-3-ethernet:usb0\nLocal:local-id:802-3-ethernet:usb1\nAP:ap-id:802-11-wireless:wlan1\nPPP:ppp-id:ppp:ppp0\n"
        properties = {
            "wifi-id": "auto\nno\nauto\nno\n",
            "usb-id": "auto\nno\ndisabled\nno\n",
            "local-id": "auto\nyes\ndisabled\nno\n",
            "ap-id": "shared\nno\ndisabled\nno\n",
            "ppp-id": "auto\nno\ndisabled\nno\n",
        }
        gateways = {"wlan0": "192.0.2.1\n\n", "usb0": "198.51.100.1\n\n",
                    "usb1": "203.0.113.1\n\n", "wlan1": "\n\n", "ppp0": "\n\n"}

        def output(args, timeout=5):
            if args[0] == "ip":
                return '[{"dev":"ppp0"}]' if "-4" in args else '[]'
            if "--active" in args:
                return active
            if "connection" in args:
                return properties[args[-1]]
            return gateways[args[-1]]

        engine._run_cmd = output
        uplinks = engine._active_uplinks()
        self.assertEqual([item["uuid"] for item in uplinks], ["wifi-id", "usb-id", "local-id", "ppp-id"])
        self.assertEqual(uplinks[2]["ipv4_never_default"], "yes")
        self.assertEqual(uplinks[-1]["ipv4_gateway"], "on-link")

    def test_choose_switch_and_restore_original_route_settings(self):
        engine = self.engine()
        settings = {"a": ("-1", "-1", "no", "no"), "b": ("200", "300", "yes", "no")}
        engine._active_uplinks = lambda: [
            {"name": "Ethernet", "uuid": "a", "device": "eth0", "ipv4_method": "auto", "ipv6_method": "disabled", "ipv4_gateway": "192.0.2.1", "ipv6_gateway": ""},
            {"name": "USB", "uuid": "b", "device": "usb0", "ipv4_method": "auto", "ipv6_method": "disabled", "ipv4_gateway": "198.51.100.1", "ipv6_gateway": ""},
        ]
        engine._profile_route_settings = lambda uuid: settings[uuid]
        engine._set_profile_route_settings = lambda uuid, value: (settings.__setitem__(uuid, value) or SimpleNamespace(returncode=0, stderr=""))
        engine._reapply_device = lambda device: SimpleNamespace(returncode=0, stderr="")
        engine._active_device_for_uuid = lambda uuid: {"a": "eth0", "b": "usb0"}[uuid]
        engine._default_route = lambda family: "usb0 via 198.51.100.1"

        with tempfile.TemporaryDirectory() as directory, patch.object(nm, "ROUTE_CHOICE_FILE", Path(directory) / "choice.json"):
            self.assertTrue(engine._handle_route_choice("use__a")[0])
            self.assertEqual(settings["a"], ("1", "-1", "no", "no"))
            self.assertEqual(settings["b"], ("200", "300", "yes", "no"))
            self.assertTrue(engine._handle_route_choice("use__b")[0])
            self.assertEqual(settings["a"], ("-1", "-1", "no", "no"))
            self.assertEqual(settings["b"], ("1", "300", "no", "no"))
            self.assertTrue(engine._handle_route_choice("automatic")[0])
            self.assertEqual(settings["a"], ("-1", "-1", "no", "no"))
            self.assertEqual(settings["b"], ("200", "300", "yes", "no"))
            self.assertFalse(nm.ROUTE_CHOICE_FILE.exists())

    def test_ipv4_preference_retains_ipv6_and_failover_eligibility(self):
        selected = {"ipv4_method": "auto", "ipv4_gateway": "192.0.2.1", "ipv6_method": "disabled"}
        original = ("600", "0", "no", "no")
        self.assertEqual(nm.NetworkManagerEngine._preferred_route_settings(original, selected, True, {4}),
                         ("1", "0", "no", "no"))
        self.assertEqual(nm.NetworkManagerEngine._preferred_route_settings(("0", "0", "no", "no"), {}, False, {4}),
                         ("2", "0", "no", "no"))

    def test_route_preference_without_gateway_does_not_change_profiles(self):
        engine = self.engine()
        engine._route_choice = lambda: {}
        engine._active_uplinks = lambda: [{"uuid": "local", "name": "Local", "device": "test0", "ipv4_method": "auto"}]
        engine._set_profile_route_settings = lambda *args: self.fail("must not mutate a link without a gateway")
        self.assertFalse(engine._handle_route_choice("use__local")[0])

    def test_route_restore_retains_external_edits_and_recovery_record(self):
        engine = self.engine()
        choice = {"original_settings": {"profile": ["600", "600", "no", "no"]},
                  "applied_settings": {"profile": ["1", "600", "no", "no"]}}
        engine._profile_route_settings = lambda uuid: ("333", "600", "no", "no")
        engine._change_route_settings = lambda *args: self.fail("must not overwrite an external edit")
        self.assertIn("left alone", engine._restore_route_choice(choice))

    def test_status_uses_one_default_route_for_profile_ip_and_gateway(self):
        engine = self.engine()
        engine._devices_cache = [
            {"device": "usb0", "connection": "Android USB"},
            {"device": "wlan0", "connection": "Home Wi-Fi"},
        ]

        def output(args, timeout=5):
            if args[:3] == ["ip", "-j", "-4"]:
                return '[{"dev":"usb0","gateway":"192.168.42.129","metric":101},' \
                       '{"dev":"wlan0","gateway":"192.168.29.1","metric":600}]'
            if args[:4] == ["ip", "-o", "-4", "addr"]:
                return "inet 192.168.42.170/24"
            return ""

        engine._run_cmd = output
        status = engine._enrich_network_status(
            {"router_ping_ms": "1", "internet_ping_ms": "1"},
            {"ssid": "Home Wi-Fi", "device": "wlan0"},
        )
        self.assertEqual((status["iface"], status["ssid"], status["ip"], status["gateway"]),
                         ("usb0", "Android USB", "192.168.42.170", "192.168.42.129"))

    def test_failed_route_switch_restores_profile_settings(self):
        engine = self.engine()
        engine._active_uplinks = lambda: [
            {"name": "Phone", "uuid": "phone", "device": "usb0", "ipv4_method": "auto", "ipv6_method": "disabled", "ipv4_gateway": "192.0.2.1"},
            {"name": "Wi-Fi", "uuid": "wifi", "device": "wlan0", "ipv4_method": "auto", "ipv6_method": "auto"},
        ]
        settings = {"phone": ("-1", "-1", "yes", "no"), "wifi": ("0", "600", "no", "no")}
        engine._profile_route_settings = lambda uuid: settings[uuid]
        engine._active_device_for_uuid = lambda uuid: {"phone": "usb0", "wifi": "wlan0"}[uuid]
        engine._reapply_device = lambda device: SimpleNamespace(returncode=0, stderr="")

        def set_settings(uuid, value):
            if uuid == "wifi" and value[0] == "2":
                return SimpleNamespace(returncode=1, stderr="Rejected")
            settings[uuid] = value
            return SimpleNamespace(returncode=0, stderr="")

        engine._set_profile_route_settings = set_settings
        with tempfile.TemporaryDirectory() as directory, patch.object(nm, "ROUTE_CHOICE_FILE", Path(directory) / "choice.json"):
            result = engine._handle_route_choice("use__phone")
            self.assertFalse(result[0])
            self.assertIn("Rejected", result[1])
            self.assertFalse(nm.ROUTE_CHOICE_FILE.exists())
        self.assertEqual(settings["phone"], ("-1", "-1", "yes", "no"))
        self.assertEqual(settings["wifi"], ("0", "600", "no", "no"))

    def test_timed_out_route_change_restores_prior_profile(self):
        engine = self.engine()
        engine._active_uplinks = lambda: [
            {"name": "Phone", "uuid": "phone", "device": "usb0", "ipv4_method": "auto", "ipv6_method": "disabled", "ipv4_gateway": "192.0.2.1"},
            {"name": "Wi-Fi", "uuid": "wifi", "device": "wlan0", "ipv4_method": "auto", "ipv6_method": "disabled"},
        ]
        settings = {"phone": ("100", "100", "no", "no"), "wifi": ("0", "600", "no", "no")}
        engine._profile_route_settings = lambda uuid: settings[uuid]
        engine._active_device_for_uuid = lambda uuid: {"phone": "usb0", "wifi": "wlan0"}[uuid]
        engine._reapply_device = lambda device: SimpleNamespace(returncode=0, stderr="")

        def change(uuid, value):
            if uuid == "wifi" and value[0] == "2":
                raise nm.subprocess.TimeoutExpired("nmcli", 10)
            settings[uuid] = value
            return SimpleNamespace(returncode=0, stderr="")

        engine._set_profile_route_settings = change
        with tempfile.TemporaryDirectory() as directory, patch.object(nm, "ROUTE_CHOICE_FILE", Path(directory) / "choice.json"):
            result = engine._handle_route_choice("use__phone")
            self.assertFalse(result[0])
            self.assertFalse(nm.ROUTE_CHOICE_FILE.exists())
        self.assertEqual(settings["phone"], ("100", "100", "no", "no"))

    def test_hotspot_uses_shared_profile_and_restores_previous_wifi(self):
        engine = self.engine()
        engine._hotspot_ssid = "OfflineLab"
        engine._hotspot_password = "testpass123"
        engine._hotspot_device = "Auto"
        engine._hotspot_devices = lambda: [{"device": "wlan0", "state": "connected", "connection": "Home", "2.4": "yes", "5": "yes"}]
        engine._prepare_hotspot_firewall = lambda device: ""
        engine._run_cmd = lambda args, timeout=5: (
            "enabled\n" if args[-2:] == ["radio", "wifi"] else
            "home-id:wlan0\n" if "--active" in args else "10.42.0.1/24\n"
        )
        profile = {"saved": False, "active": False}
        engine._hotspot_profile = lambda active_only=False, uuid_filter="": (
            {"uuid": "hotspot-id", "ssid": "OfflineLab", "password": "testpass123", "device": "wlan0"}
            if profile["saved"] and (not active_only or profile["active"]) else None
        )
        remembered = []
        engine._remember_hotspot_previous = lambda device, uuid: remembered.append((device, uuid))
        engine._hotspot_previous = lambda: {"device": "wlan0", "uuid": "home-id"}
        commands = []

        def run(args, **kwargs):
            commands.append(args)
            if args[1:3] == ["connection", "add"]:
                profile["saved"] = True
            elif args[1:3] == ["connection", "up"] and "hotspot-id" in args:
                profile["active"] = True
            elif args[1:3] == ["connection", "down"]:
                profile["active"] = False
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        with patch.object(nm.shutil, "which", return_value="/usr/bin/dnsmasq"), \
             patch.object(nm.subprocess, "run", side_effect=run):
            self.assertTrue(engine._handle_hotspot("start_hotspot_24", "true")[0])
            self.assertTrue(engine._handle_hotspot("stop_hotspot", "true")[0])

        self.assertTrue(any("ipv4.method" in command and "shared" in command for command in commands))
        self.assertIn(["nmcli", "connection", "up", "uuid", "home-id", "ifname", "wlan0"], commands)
        self.assertNotIn(["nmcli", "device", "disconnect", "wlan0"], commands)
        self.assertIn(("wlan0", "home-id"), remembered)

    def test_hotspot_qr_uses_saved_active_credentials_not_unsaved_draft(self):
        engine = self.engine()
        engine._hotspot_ssid = "Unsaved name"
        engine._hotspot_password = "unsavedpass"
        engine._hotspot_profile = lambda active_only=False, uuid_filter="": (
            {"uuid": "hotspot-id", "ssid": "", "password": "", "device": "wlan0"}
            if active_only else
            {"uuid": "hotspot-id", "ssid": "Active name", "password": "activepass", "device": ""}
        )
        engine._trigger_qr_viewer = lambda *args: (True, repr(args), "")
        ok, message, _ = engine._handle_hotspot("qr_hotspot", "true")
        self.assertTrue(ok)
        self.assertIn("Active name", message)
        self.assertIn("activepass", message)
        self.assertNotIn("Unsaved name", message)

    def test_hotspot_activation_timeout_recovers_and_records_previous_first(self):
        engine = self.engine()
        engine._hotspot_ssid, engine._hotspot_password, engine._hotspot_device = "Lab", "testpass123", "Auto"
        engine._hotspot_devices = lambda: [{"device": "wlan0", "state": "connected", "2.4": "yes", "5": "yes"}]
        engine._prepare_hotspot_firewall = lambda device: ""
        engine._run_cmd = lambda args, **kwargs: "enabled\n" if "radio" in args else "home-id:wlan0\n"
        profile = {"saved": False}
        engine._hotspot_profile = lambda active_only=False, uuid_filter="": (
            {"uuid": "hotspot-id", "ssid": "Lab", "password": "testpass123", "device": ""}
            if profile["saved"] and not active_only else None
        )
        events = []
        engine._remember_hotspot_previous = lambda device, uuid: events.append(("remember", uuid))

        def run(args, **kwargs):
            events.append(("command", args))
            if args[1:3] == ["connection", "add"]:
                profile["saved"] = True
            elif args[1:3] == ["connection", "up"] and "hotspot-id" in args:
                raise nm.subprocess.TimeoutExpired(args, 30)
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        with patch.object(nm.shutil, "which", return_value="/usr/bin/dnsmasq"), patch.object(nm.subprocess, "run", side_effect=run):
            ok, message, _ = engine._handle_hotspot("start_hotspot_24", "true")
        self.assertFalse(ok)
        self.assertIn("timed out", message)
        self.assertEqual(events[0], ("remember", "home-id"))
        self.assertIn(("command", ["nmcli", "connection", "up", "uuid", "home-id", "ifname", "wlan0"]), events)
        self.assertEqual(events[-1], ("remember", ""))

    def test_connect_timeout_does_not_display_password_arguments(self):
        engine = self.engine()
        with patch.object(nm.subprocess, "run", side_effect=nm.subprocess.TimeoutExpired(["nmcli", "password", "secret123"], 30)):
            ok, message, _ = engine._async_connect("Example", "secret123")
        self.assertFalse(ok)
        self.assertNotIn("secret123", message)

    def test_qr_export_uses_configured_pictures_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                if args[0] == "xdg-user-dir":
                    return SimpleNamespace(returncode=0, stdout=directory + "\n")
                Path(args[args.index("-o") + 1]).write_bytes(b"png fixture")
                return SimpleNamespace(returncode=0)

            with patch.object(nm.shutil, "which", return_value="/usr/bin/qrencode"), patch.object(nm.subprocess, "run", side_effect=run):
                result = nm.save_qr_image("WIFI:S:Lab;T:nopass;;", "Lab")
            self.assertEqual(Path(result).parent, Path(directory))
            self.assertEqual(calls[0], ["xdg-user-dir", "PICTURES"])

    def test_existing_hotspot_firewall_rules_need_no_polkit(self):
        rules = "\n".join(
            f"-A ufw-user-input -i wlan0 -p {protocol} --dport {port} -j ACCEPT"
            for port, protocol in ((67, "udp"), (53, "udp"), (53, "tcp"))
        )
        with patch.object(nm.shutil, "which", return_value="/usr/bin/ufw"), \
             patch.object(Path, "read_text", return_value=rules), \
             patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(nm.NetworkManagerEngine._prepare_hotspot_firewall("wlan0"), "")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][:2], ["systemctl", "is-active"])

    def test_missing_hotspot_firewall_rules_use_one_polkit_operation(self):
        def which(name):
            return f"/usr/bin/{name}"

        with patch.object(nm.shutil, "which", side_effect=which), \
             patch.object(Path, "read_text", side_effect=OSError("unavailable")), \
             patch.object(nm.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(nm.NetworkManagerEngine._prepare_hotspot_firewall("wlan0"), "")
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args.args[0][:2], ["/usr/bin/pkexec", "/usr/bin/python3"])


if __name__ == "__main__":
    unittest.main()
