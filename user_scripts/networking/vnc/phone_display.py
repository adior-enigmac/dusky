#!/usr/bin/env python3
"""Use a phone as a separate Hyprland display through WayVNC on port 5901.

Run ``orientation portrait`` or ``orientation landscape`` to switch its shape.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time


HOME = Path.home()
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
CONFIG_DIR = HOME / ".config" / "wayvnc"
CONFIG = CONFIG_DIR / "phone-display.conf"
KEY = CONFIG_DIR / "phone-display-key.pem"
CERT = CONFIG_DIR / "phone-display-cert.pem"
UNIT_NAME = "dusky_phone_display.service"
UNIT = HOME / ".config" / "systemd" / "user" / UNIT_NAME
STATE = RUNTIME / "dusky-phone-display.json"
CONTROL = RUNTIME / "dusky-phone-wayvnc.sock"
OUTPUT = "DUSKY-PHONE"
PORT = 5901
LANDSCAPE_SIZE = (1280, 720)
PREFERENCES = HOME / ".config/dusky/settings/remote/vnc_display.json"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def save_preferences(values: dict) -> None:
    PREFERENCES.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=PREFERENCES.parent) as directory:
        replacement = Path(directory) / PREFERENCES.name
        replacement.write_text(json.dumps(values, indent=2) + "\n")
        replacement.replace(PREFERENCES)


def preferences() -> dict:
    if not PREFERENCES.exists():
        save_preferences({"orientation": "landscape"})
    try:
        values = json.loads(PREFERENCES.read_text())
    except ValueError as error:
        raise RuntimeError(f"Invalid JSON in {PREFERENCES}: {error}") from error
    if not isinstance(values, dict) or values.get("orientation") not in {"landscape", "portrait"}:
        raise RuntimeError(f"Set orientation to landscape or portrait in {PREFERENCES}")
    return values


def display_size(value: str | None = None) -> tuple[int, int]:
    width, height = LANDSCAPE_SIZE
    return (width, height) if (value or preferences()["orientation"]) == "landscape" else (height, width)


def hypr(instance: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("hyprctl", "--instance", instance, *args, check=check)


def monitors(instance: str) -> list[dict]:
    result = hypr(instance, "-j", "monitors")
    return json.loads(result.stdout)


def session() -> dict | None:
    result = run("hyprctl", "instances", "-j", check=False)
    if result.returncode:
        return None
    candidates = sorted(json.loads(result.stdout), key=lambda item: item.get("time", 0), reverse=True)
    for item in candidates:
        name = item.get("wl_socket", "")
        path = RUNTIME / name
        if name and path.exists() and stat.S_ISSOCK(path.stat().st_mode) and path.stat().st_uid == os.getuid():
            return item
    return None


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
        with tempfile.TemporaryDirectory(dir=CONFIG_DIR) as directory:
            key = Path(directory) / "key.pem"
            cert = Path(directory) / "cert.pem"
            run("openssl", "genrsa", "-traditional", "-out", str(key), "3072")
            run("openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(cert),
                "-days", "3650", "-sha256", "-subj", "/CN=Phone Display")
            key.chmod(0o600)
            cert.chmod(0o600)
            key.replace(KEY)
            cert.replace(CERT)
        changed = True
    KEY.chmod(0o600)
    content = (
        f"address=0.0.0.0\nport={PORT}\nenable_auth=true\nenable_pam=true\n"
        f"rsa_private_key_file={KEY}\nprivate_key_file={KEY}\ncertificate_file={CERT}\n"
    )
    if not CONFIG.exists() or CONFIG.read_text() != content:
        CONFIG.write_text(content)
        changed = True
    CONFIG.chmod(0o600)
    return changed


def unit_content() -> str:
    try:
        script = f"%h/{Path(__file__).resolve().relative_to(HOME).as_posix().replace('%', '%%')}"
    except ValueError:
        script = str(Path(__file__).resolve()).replace("%", "%%")
    script = json.dumps(script, ensure_ascii=False)
    python = json.dumps(sys.executable.replace("%", "%%"), ensure_ascii=False)
    return (
        "[Unit]\nDescription=Phone secondary display over WayVNC\n"
        "After=graphical-session.target\nPartOf=graphical-session.target\n"
        "StartLimitIntervalSec=0\n\n"
        "[Service]\nType=exec\n"
        f"ExecStart={python} {script} serve\n"
        f"ExecStopPost={python} {script} cleanup\n"
        "Restart=always\nRestartSec=2\n\n"
        "[Install]\nWantedBy=default.target graphical-session.target\n"
    )


def rfb_ready() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=2) as connection:
            connection.settimeout(2)
            greeting = bytearray()
            while len(greeting) < 12:
                chunk = connection.recv(12 - len(greeting))
                if not chunk:
                    break
                greeting.extend(chunk)
        return greeting == b"RFB 003.008\n"
    except OSError:
        return False


def output_ready() -> bool:
    result = run("wayvncctl", "-S", str(CONTROL), "--json", "output-list", check=False)
    if result.returncode:
        return False
    try:
        return any(item.get("name") == OUTPUT and item.get("captured") for item in json.loads(result.stdout))
    except (TypeError, ValueError):
        return False


def display_ready() -> bool:
    current = session()
    if not current:
        return False
    width, height = display_size()
    return any(item["name"] == OUTPUT and (item["width"], item["height"]) == (width, height)
               for item in monitors(current["instance"]))


def install() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("Run setup as the desktop user, without sudo")
    preferences()
    if not Path("/usr/bin/wayvnc").exists():
        print("Installing WayVNC from the distribution repository...")
        subprocess.run(["sudo", "pacman", "-S", "--needed", "--noconfirm", "wayvnc"], check=True)
    if not Path("/etc/pam.d/wayvnc").is_file():
        raise RuntimeError("WayVNC PAM profile is missing; reinstall the wayvnc package")
    if not session():
        raise RuntimeError("Start a Hyprland desktop session before setup")
    if shutil.which("ufw"):
        subprocess.run(["sudo", "ufw", "allow", f"{PORT}/tcp", "comment", "Dusky phone display"], check=True)
    config_changed = write_config()
    UNIT.parent.mkdir(parents=True, exist_ok=True)
    content = unit_content()
    unit_changed = not UNIT.exists() or UNIT.read_text() != content
    if unit_changed:
        UNIT.write_text(content)
        run("systemctl", "--user", "daemon-reload")
    enabled = run("systemctl", "--user", "is-enabled", UNIT_NAME, check=False).stdout.strip() == "enabled"
    if unit_changed and enabled:
        run("systemctl", "--user", "reenable", UNIT_NAME)
    elif not enabled:
        run("systemctl", "--user", "enable", UNIT_NAME)
    active = run("systemctl", "--user", "is-active", UNIT_NAME, check=False).stdout.strip() == "active"
    if not active:
        run("systemctl", "--user", "start", UNIT_NAME)
    elif config_changed or unit_changed or not (rfb_ready() and output_ready() and display_ready()):
        run("systemctl", "--user", "restart", UNIT_NAME)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if rfb_ready() and output_ready() and display_ready():
            break
        time.sleep(0.2)
    status()


def serve() -> None:
    if not CONFIG.is_file():
        raise RuntimeError("Run setup first")
    width, height = display_size()
    while not (current := session()):
        time.sleep(2)
    instance = current["instance"]
    existing = next((item for item in monitors(instance) if item["name"] == OUTPUT), None)
    if existing:
        previous = json.loads(STATE.read_text()) if STATE.exists() else {}
        if previous.get("instance") != instance:
            raise RuntimeError(f"Output {OUTPUT} already exists and is not owned by this service")
        hypr(instance, "output", "remove", OUTPUT)
    STATE.write_text(json.dumps({"instance": instance}))
    try:
        hypr(instance, "output", "create", "headless", OUTPUT)
        rule = (f'hl.monitor({{ output = "{OUTPUT}", mode = "{width}x{height}@60", '
                'position = "auto-right", scale = 1, disabled = false })')
        hypr(instance, "eval", rule)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            monitor = next((item for item in monitors(instance) if item["name"] == OUTPUT), None)
            if monitor and (monitor["width"], monitor["height"]) == (width, height):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"Hyprland did not configure the {width}x{height} phone output")
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = str(RUNTIME)
        env["WAYLAND_DISPLAY"] = current["wl_socket"]
        env["HYPRLAND_INSTANCE_SIGNATURE"] = instance
        os.execve("/usr/bin/wayvnc", ["wayvnc", "-C", str(CONFIG), "-o", OUTPUT,
                                         "-S", str(CONTROL)], env)
    except Exception:
        cleanup()
        raise


def cleanup() -> None:
    if not STATE.exists():
        return
    try:
        instance = json.loads(STATE.read_text())["instance"]
        result = hypr(instance, "-j", "monitors", check=False)
        if result.returncode == 0 and any(item["name"] == OUTPUT for item in json.loads(result.stdout)):
            hypr(instance, "output", "remove", OUTPUT)
    finally:
        STATE.unlink(missing_ok=True)


def addresses() -> list[str]:
    result = run("ip", "-j", "-4", "addr", "show", "scope", "global")
    found = []
    for link in json.loads(result.stdout):
        if "UP" not in link.get("flags", []) or link.get("ifname") == "CloudflareWARP":
            continue
        for address in link.get("addr_info", []):
            ip = ipaddress.ip_address(address["local"])
            if not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified):
                label = "Tailscale remote" if link["ifname"] == "tailscale0" else link["ifname"]
                found.append(f"{label}: {ip}:{PORT}")
    return found


def status() -> None:
    active = run("systemctl", "--user", "is-active", UNIT_NAME, check=False).stdout.strip() == "active"
    ready = rfb_ready() and output_ready() and display_ready()
    value = preferences()["orientation"]
    width, height = display_size(value)
    print(f"Phone display: {'ready' if active and ready else 'off or starting'}")
    print(f"Orientation: {value} ({width}x{height})")
    for address in addresses():
        print(address)
    if active and ready:
        print(f"Open a VNC viewer at an address above. Sign in with your Linux account; {OUTPUT} is to the right of your main screen.")
    else:
        print(f"Check: journalctl --user -u {UNIT_NAME} -n 30 --no-pager")
        raise RuntimeError("Phone display is not ready")


def stop() -> None:
    run("systemctl", "--user", "disable", "--now", UNIT_NAME)
    print("Phone display stopped; the virtual monitor was removed")


def orientation(value: str | None) -> None:
    current = preferences()
    if value is None:
        print(f"VNC display orientation: {current['orientation']} ({PREFERENCES})")
        return
    changed = value != current["orientation"]
    if changed:
        save_preferences({**current, "orientation": value})
    width, height = display_size(value)
    active = run("systemctl", "--user", "is-active", UNIT_NAME, check=False).stdout.strip() == "active"
    applied = display_ready() if active else False
    if active and (changed or not applied):
        run("systemctl", "--user", "restart", UNIT_NAME)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if rfb_ready() and output_ready() and display_ready():
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"Phone display did not start in {value}; check journalctl --user -u {UNIT_NAME}")
    print(f"VNC display orientation: {value} ({width}x{height})")
    print(f"Saved in {PREFERENCES}" + ("" if active else "; takes effect when the service starts"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("setup", "status", "serve", "cleanup", "stop", "orientation"), default="setup")
    parser.add_argument("value", nargs="?", choices=("landscape", "portrait"), help="Display orientation for the orientation action")
    args = parser.parse_args()
    if args.action == "orientation":
        orientation(args.value)
    elif args.value:
        parser.error("an orientation value requires the orientation action")
    else:
        {"setup": install, "status": status, "serve": serve, "cleanup": cleanup,
         "stop": stop}[args.action]()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"Error: {error.stderr.strip() or error.stdout.strip() or error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
