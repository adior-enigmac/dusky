#!/usr/bin/env python3
"""Set up an optional WayVNC user service for Hyprland.

Run without arguments once to install and start the user service. Use ``status``
for connection addresses, ``remote`` to set up Tailscale, and ``stop`` to disable
VNC. An offline Wi-Fi network can be started explicitly with ``offline``.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time


HOME = Path.home()
CONFIG_DIR = HOME / ".config" / "wayvnc"
CONFIG = CONFIG_DIR / "arch-ios.conf"
KEY = CONFIG_DIR / "arch-ios-key.pem"
CERT = CONFIG_DIR / "arch-ios-cert.pem"
UNIT_NAME = "dusky_vnc.service"
UNIT = HOME / ".config" / "systemd" / "user" / UNIT_NAME
LEGACY_UNIT_NAME = "arch-ios-vnc.service"
LEGACY_UNIT = UNIT.with_name(LEGACY_UNIT_NAME)
OFFLINE_PROFILE = "arch-ios-offline"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def certificate_valid() -> bool:
    if not KEY.is_file() or not CERT.is_file():
        return False
    if run("openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(CERT), check=False).returncode:
        return False
    key = run("openssl", "pkey", "-in", str(KEY), "-pubout", check=False)
    cert = run("openssl", "x509", "-in", str(CERT), "-pubkey", "-noout", check=False)
    return key.returncode == cert.returncode == 0 and key.stdout == cert.stdout


def write_config() -> bool:
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONFIG_DIR.chmod(0o700)
    changed = False
    if not certificate_valid():
        with tempfile.TemporaryDirectory(dir=CONFIG_DIR) as temp:
            key = Path(temp) / "key.pem"
            cert = Path(temp) / "cert.pem"
            run("openssl", "genrsa", "-traditional", "-out", str(key), "3072")
            run("openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(cert),
                "-days", "3650", "-sha256", "-subj", "/CN=WayVNC")
            key.chmod(0o600)
            cert.chmod(0o600)
            key.replace(KEY)
            cert.replace(CERT)
        changed = True
    KEY.chmod(0o600)
    content = (
        "address=0.0.0.0\nport=5900\nenable_auth=true\nenable_pam=true\n"
        f"rsa_private_key_file={KEY}\nprivate_key_file={KEY}\ncertificate_file={CERT}\n"
    )
    if not CONFIG.exists() or CONFIG.read_text() != content:
        CONFIG.write_text(content)
        changed = True
    CONFIG.chmod(0o600)
    return changed


def install() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("Run setup as the desktop user, without sudo")
    if not Path("/usr/bin/wayvnc").exists():
        print("Installing WayVNC from the distribution repository...")
        subprocess.run(["sudo", "pacman", "-S", "--needed", "--noconfirm", "wayvnc"], check=True)
    if not Path("/etc/pam.d/wayvnc").is_file():
        raise RuntimeError("WayVNC PAM profile is missing; reinstall the wayvnc package")
    instances = run("hyprctl", "instances", "-j", check=False)
    if instances.returncode or not json.loads(instances.stdout):
        raise RuntimeError("Start a Hyprland desktop session before setup")
    config_changed = write_config()
    UNIT.parent.mkdir(parents=True, exist_ok=True)
    start = f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} serve"
    content = (
        "[Unit]\nDescription=WayVNC for the active Hyprland session\n"
        "After=graphical-session.target\nPartOf=graphical-session.target\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\nType=exec\n"
        f"ExecStart={start}\nRestart=always\nRestartSec=2\n"
        "\n"
        "[Install]\nWantedBy=default.target graphical-session.target\n"
    )
    unit_changed = not UNIT.exists() or UNIT.read_text() != content
    if unit_changed:
        UNIT.write_text(content)
    legacy_removed = False
    if LEGACY_UNIT.exists():
        if LEGACY_UNIT.read_text() != content:
            raise RuntimeError(f"Refusing to replace a modified legacy unit: {LEGACY_UNIT}")
        run("systemctl", "--user", "disable", "--now", LEGACY_UNIT_NAME)
        LEGACY_UNIT.unlink()
        legacy_removed = True
    enabled = run("systemctl", "--user", "is-enabled", UNIT_NAME, check=False).stdout.strip() == "enabled"
    if unit_changed and enabled:
        run("systemctl", "--user", "reenable", UNIT_NAME)
    elif not enabled:
        run("systemctl", "--user", "enable", UNIT_NAME)
    elif legacy_removed:
        run("systemctl", "--user", "daemon-reload")
    active = run("systemctl", "--user", "is-active", UNIT_NAME, check=False).stdout.strip() == "active"
    if not active:
        run("systemctl", "--user", "start", UNIT_NAME)
    elif config_changed or unit_changed or not rfb_ready():
        run("systemctl", "--user", "restart", UNIT_NAME)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if rfb_ready():
            break
        time.sleep(0.2)
    status()


def wifi_device() -> str | None:
    result = run("nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status", check=False)
    if result.returncode:
        return None
    for line in result.stdout.splitlines():
        device, _, kind = line.partition(":")
        if kind == "wifi" and run("nmcli", "-g", "WIFI-PROPERTIES.AP", "device", "show", device,
                                   check=False).stdout.strip() == "yes":
            return device
    return None


def offline_credentials() -> tuple[str, str] | None:
    profile = run("nmcli", "-g", "802-11-wireless.ssid", "connection", "show", OFFLINE_PROFILE,
                  check=False)
    if profile.returncode:
        return None
    secret = run("nmcli", "--show-secrets", "-g", "802-11-wireless-security.psk",
                 "connection", "show", OFFLINE_PROFILE, check=False)
    if secret.returncode:
        return None
    return profile.stdout.strip(), secret.stdout.strip()


def setup_offline_wifi() -> None:
    if offline_credentials():
        return
    device = wifi_device()
    if not device:
        print("Offline Wi-Fi: no access point capable adapter detected")
        return
    if not Path("/usr/bin/dnsmasq").exists():
        print("Installing dnsmasq for offline Wi-Fi address assignment...")
        subprocess.run(["sudo", "pacman", "-S", "--needed", "--noconfirm", "dnsmasq"], check=True)
    ssid = f"VNC-{socket.gethostname()[:20]}"
    password = secrets.token_urlsafe(12)
    run("nmcli", "connection", "add", "type", "wifi", "ifname", device,
        "con-name", OFFLINE_PROFILE, "ssid", ssid, "mode", "ap",
        "802-11-wireless-security.key-mgmt", "wpa-psk",
        "802-11-wireless-security.psk", password,
        "ipv4.method", "shared", "ipv6.method", "disabled",
        "connection.autoconnect", "no")
    print(f"Offline Wi-Fi prepared: {ssid} (manual activation only)")


def offline() -> None:
    credentials = offline_credentials()
    if not credentials:
        setup_offline_wifi()
        credentials = offline_credentials()
    if not credentials:
        raise RuntimeError("Offline Wi-Fi profile is unavailable")
    print(f"Connect the iPhone to Wi-Fi {credentials[0]} with password {credentials[1]}")
    print("Switching the laptop from its current Wi-Fi to the offline network now...", flush=True)
    run("nmcli", "connection", "up", OFFLINE_PROFILE)
    status()


def serve() -> None:
    if not CONFIG.is_file():
        raise RuntimeError("Run setup first")
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    while True:
        result = run("hyprctl", "instances", "-j", check=False)
        try:
            sessions = json.loads(result.stdout) if result.returncode == 0 else []
        except ValueError:
            sessions = []
        sessions.sort(key=lambda item: item.get("time", 0), reverse=True)
        for session in sessions:
            name = session.get("wl_socket", "")
            path = runtime / name
            if name and path.exists() and stat.S_ISSOCK(path.stat().st_mode) and path.stat().st_uid == os.getuid():
                env = os.environ.copy()
                env["XDG_RUNTIME_DIR"] = str(runtime)
                env["WAYLAND_DISPLAY"] = name
                env["HYPRLAND_INSTANCE_SIGNATURE"] = session["instance"]
                os.execve("/usr/bin/wayvnc", ["wayvnc", "-C", str(CONFIG)], env)
        time.sleep(2)


def addresses() -> list[tuple[str, str]]:
    result = run("ip", "-j", "-4", "addr", "show", "scope", "global", check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Cannot inspect network addresses")
    found = []
    for link in json.loads(result.stdout):
        if link.get("ifname") == "CloudflareWARP":
            continue
        if "UP" not in link.get("flags", []):
            continue
        for addr in link.get("addr_info", []):
            ip = ipaddress.ip_address(addr["local"])
            if not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified):
                found.append((link["ifname"], str(ip)))
    return found


def rfb_ready() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5900), timeout=2) as conn:
            conn.settimeout(2)
            greeting = bytearray()
            while len(greeting) < 12:
                chunk = conn.recv(12 - len(greeting))
                if not chunk:
                    break
                greeting.extend(chunk)
        return greeting.startswith(b"RFB ") and len(greeting) == 12
    except OSError:
        return False


def status() -> None:
    result = run("systemctl", "--user", "is-active", UNIT_NAME, check=False)
    active = result.stdout.strip() == "active"
    print(f"WayVNC service: {'active' if active else result.stdout.strip() or 'inactive'}")
    ready = rfb_ready()
    print(f"RFB handshake: {'ready' if ready else 'unavailable'}")
    ips = addresses()
    if ips:
        print("VNC connection details:" if active and ready else "Network addresses (VNC unavailable):")
    for iface, ip in ips:
        label = "Tailscale remote" if iface == "tailscale0" else iface
        print(f"{label}: {ip}:5900")
    if not ips:
        print("No active IPv4 network link. Connect a local or Tailscale network and rerun status.")
    if not any(iface == "tailscale0" for iface, _ in ips):
        print("Tailscale remote: unavailable (run 'remote' when online)")
    if active and ready and ips:
        print("Use a VNC viewer and sign in with your Linux username and password.")
    if credentials := offline_credentials():
        print(f"Offline Wi-Fi: {credentials[0]} (run 'offline' to activate now)")
    if not active or not ready:
        print(f"Check: journalctl --user -u {UNIT_NAME} -n 30 --no-pager")
        raise RuntimeError("WayVNC is not ready")


def remote() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("Run setup as the desktop user, without sudo")
    if not Path("/usr/bin/tailscale").exists():
        print("Installing Tailscale from the distribution repository...")
        subprocess.run(["sudo", "pacman", "-S", "--needed", "--noconfirm", "tailscale"], check=True)
    enabled = run("systemctl", "is-enabled", "tailscaled.service", check=False).stdout.strip() == "enabled"
    active = run("systemctl", "is-active", "tailscaled.service", check=False).stdout.strip() == "active"
    if not (enabled and active):
        run("sudo", "systemctl", "enable", "--now", "tailscaled.service")
    ip = run("tailscale", "ip", "-4", check=False)
    if ip.returncode or not ip.stdout.strip():
        print("Complete the Tailscale sign-in shown below to join your tailnet.", flush=True)
        subprocess.run(["sudo", "tailscale", "up"], check=True)
        ip = run("tailscale", "ip", "-4", check=False)
    if ip.returncode or not ip.stdout.strip():
        raise RuntimeError("Tailscale has no IPv4 address yet; finish sign-in and retry")
    print(f"Tailscale address: {ip.stdout.strip()}:5900")
    if rfb_ready():
        print("Connect a VNC viewer on another device signed in to the same tailnet.")
    else:
        print(f"VNC is off; run this script without arguments to start {UNIT_NAME}.")


def stop() -> None:
    run("systemctl", "--user", "disable", "--now", UNIT_NAME)
    print("WayVNC service stopped and disabled")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("setup", "status", "serve", "stop", "offline", "remote"), default="setup")
    action = parser.parse_args().action
    {"setup": install, "status": status, "serve": serve, "stop": stop, "offline": offline, "remote": remote}[action]()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"Error: {exc.stderr.strip() or exc}", file=sys.stderr)
        sys.exit(1)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
