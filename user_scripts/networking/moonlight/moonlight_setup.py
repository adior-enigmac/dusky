#!/usr/bin/env python3
"""Set up a standalone Hyprland phone display streamed through Sunshine/Moonlight.

Run ``orientation portrait`` or ``orientation landscape`` to switch its shape.
"""

import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen


HOME = Path.home()
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
SCRIPT = Path(__file__).resolve()
UNIT_NAME = "dusky_moonlight_display.service"
UNIT = HOME / ".config/systemd/user" / UNIT_NAME
CONFIG = HOME / ".config/sunshine-moonlight/sunshine.conf"
STATE = RUNTIME / "dusky-moonlight-display.json"
OUTPUT = "DUSKY-MOONLIGHT"
LANDSCAPE_SIZE = (1280, 720)
PREFERENCES = HOME / ".config/dusky/settings/remote/moonlight_display.json"
SUNSHINE_PORT = 47989
REPO_URL = "https://github.com/LizardByte/pacman-repo/releases/latest/download"
FIREWALL_PORTS = ("47984/tcp", "47989/tcp", "48010/tcp", "47998:48000/udp")
IPHONE_USB_PROFILE = "iPhone USB local"


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


def session() -> dict | None:
    result = run("hyprctl", "instances", "-j", check=False)
    if result.returncode:
        return None
    for item in sorted(json.loads(result.stdout), key=lambda value: value.get("time", 0), reverse=True):
        name = item.get("wl_socket", "")
        path = RUNTIME / name
        if name and path.exists() and stat.S_ISSOCK(path.stat().st_mode) and path.stat().st_uid == os.getuid():
            return item
    return None


def monitors(instance: str) -> list[dict]:
    return json.loads(hypr(instance, "-j", "monitors").stdout)


def sunshine_package(package: Path | None) -> None:
    if shutil.which("sunshine"):
        return
    if package:
        if not package.is_file():
            raise RuntimeError(f"Sunshine package not found: {package}")
        subprocess.run(["sudo", "pacman", "-U", "--needed", "--noconfirm", str(package)], check=True)
        return
    try:
        with urlopen(f"{REPO_URL}/lizardbyte.db", timeout=15) as response:
            database = response.read()
        with tarfile.open(fileobj=io.BytesIO(database), mode="r:*") as archive:
            for entry in archive:
                if not entry.name.startswith("sunshine-") or not entry.name.endswith("/desc"):
                    continue
                description = archive.extractfile(entry)
                if description is None:
                    continue
                lines = description.read().decode().splitlines()
                candidate = lines[lines.index("%FILENAME%") + 1]
                if candidate.endswith(f"-{os.uname().machine}.pkg.tar.zst"):
                    filename = candidate
                    digest = lines[lines.index("%SHA256SUM%") + 1]
                    break
            else:
                raise RuntimeError(f"Official Sunshine package is unavailable for {os.uname().machine}; use --package")
        with tempfile.TemporaryDirectory(prefix="dusky-sunshine-") as directory:
            destination = Path(directory) / filename
            with urlopen(f"{REPO_URL}/{filename}", timeout=30) as response, destination.open("wb") as output:
                shutil.copyfileobj(response, output)
            with destination.open("rb") as downloaded:
                actual_digest = hashlib.file_digest(downloaded, "sha256").hexdigest()
            if actual_digest != digest:
                raise RuntimeError("Downloaded Sunshine package checksum does not match the official repository")
            subprocess.run(["sudo", "pacman", "-U", "--needed", "--noconfirm", str(destination)], check=True)
    except (OSError, StopIteration, ValueError, tarfile.TarError) as error:
        raise RuntimeError("Could not download Sunshine. For offline setup, rerun with --package /path/to/sunshine.pkg.tar.zst") from error


def setup_iphone_usb() -> None:
    """Keep iPhone USB tethering local, even when the phone has no internet."""
    if not shutil.which("nmcli"):
        print("iPhone USB routing was not configured: NetworkManager is unavailable", file=sys.stderr)
        return
    settings = (
        "connection.interface-name", "",
        "match.driver", "ipheth",
        "connection.autoconnect", "yes",
        "connection.autoconnect-priority", "999",
        "ipv4.method", "auto",
        "ipv4.never-default", "yes",
        "ipv4.ignore-auto-dns", "yes",
        "ipv6.method", "disabled",
    )
    fields = ("connection.type,connection.interface-name,match.driver,connection.autoconnect,"
              "connection.autoconnect-priority,ipv4.method,ipv4.never-default,"
              "ipv4.ignore-auto-dns,ipv6.method")
    existing = run("nmcli", "-g", fields, "connection", "show", IPHONE_USB_PROFILE, check=False)
    values = existing.stdout.splitlines()
    changed = False
    if existing.returncode:
        run("nmcli", "connection", "add", "type", "ethernet", "ifname", "*",
            "con-name", IPHONE_USB_PROFILE, "autoconnect", "yes", "--", *settings)
        changed = True
    elif not values or values[0] != "802-3-ethernet":
        raise RuntimeError(f"A non-Ethernet profile already uses the name {IPHONE_USB_PROFILE}")
    elif values != ["802-3-ethernet", "", "ipheth", "yes", "999",
                    "auto", "yes", "yes", "disabled"]:
        run("nmcli", "connection", "modify", IPHONE_USB_PROFILE, *settings)
        changed = True
    for device in Path("/sys/class/net").iterdir():
        driver = device / "device/driver"
        if not driver.is_symlink() or driver.resolve().name != "ipheth":
            continue
        if not (device / "carrier").exists() or (device / "carrier").read_text().strip() != "1":
            continue
        active = run("nmcli", "-g", "GENERAL.CONNECTION", "device", "show", device.name).stdout.strip()
        if active != IPHONE_USB_PROFILE or changed:
            run("nmcli", "connection", "up", IPHONE_USB_PROFILE, "ifname", device.name)


def prefer_vaapi() -> bool:
    if not shutil.which("vainfo"):
        return False
    current = session()
    if not current:
        return False
    active = {item["name"] for item in monitors(current["instance"])}
    for connector in Path("/sys/class/drm").glob("card*-*"):
        if not any(connector.name.endswith(f"-{name}") for name in active):
            continue
        if not (connector / "status").is_file() or (connector / "status").read_text().strip() != "connected":
            continue
        card = connector.name.split("-", 1)[0]
        vendor = Path("/sys/class/drm") / card / "device/vendor"
        if vendor.is_file() and vendor.read_text().strip() in {"0x8086", "0x1002"}:
            for render in (vendor.parent / "drm").glob("renderD*"):
                probe = run("vainfo", "--display", "drm", "--device", f"/dev/dri/{render.name}", check=False)
                if probe.returncode == 0 and any(
                    line.strip().startswith("VAProfileH264") and "VAEntrypointEncSlice" in line
                    for line in probe.stdout.splitlines()
                ):
                    return True
    return False


def write_config() -> bool:
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    (CONFIG.parent / "credentials").mkdir(mode=0o700, exist_ok=True)
    apps = CONFIG.parent / "apps.json"
    apps_created = not apps.exists()
    if apps_created:
        apps.write_text(json.dumps({"env": {}, "apps": [{"name": "Desktop", "image-path": "desktop.png"}]}, indent=2) + "\n")
    wanted = {
        "capture": "wlr",
        "output_name": OUTPUT,
        "port": str(SUNSHINE_PORT),
        "system_tray": "disabled",
        "stream_audio": "disabled",
        "file_apps": str(apps),
        "credentials_file": str(CONFIG.parent / "sunshine_state.json"),
        "file_state": str(CONFIG.parent / "sunshine_state.json"),
        "log_path": str(CONFIG.parent / "sunshine.log"),
        "pkey": str(CONFIG.parent / "credentials/cakey.pem"),
        "cert": str(CONFIG.parent / "credentials/cacert.pem"),
    }
    wanted["encoder"] = "vaapi" if prefer_vaapi() else None
    current = CONFIG.read_text().splitlines() if CONFIG.exists() else []
    found = set()
    lines = []
    for line in current:
        key = line.split("=", 1)[0].strip()
        if key in wanted:
            if key in found:
                continue
            found.add(key)
            if wanted[key] is None:
                continue
            line = f"{key} = {wanted[key]}"
        lines.append(line)
    lines.extend(f"{key} = {value}" for key, value in wanted.items() if key not in found and value is not None)
    content = "\n".join(lines) + "\n"
    changed = apps_created or not CONFIG.exists() or CONFIG.read_text() != content
    if changed:
        CONFIG.write_text(content)
    return changed


def unit_content() -> str:
    try:
        script = f"%h/{SCRIPT.relative_to(HOME).as_posix().replace('%', '%%')}"
    except ValueError:
        script = str(SCRIPT).replace("%", "%%")
    script = json.dumps(script, ensure_ascii=False)
    python = json.dumps(sys.executable.replace("%", "%%"), ensure_ascii=False)
    return (
        "[Unit]\nDescription=Phone secondary display over Sunshine/Moonlight\n"
        "After=graphical-session.target\nPartOf=graphical-session.target\n\n"
        "[Service]\nType=exec\n"
        f"ExecStart={python} {script} serve\n"
        f"ExecStopPost={python} {script} cleanup\n"
        "Restart=always\nRestartSec=5\n\n"
        "[Install]\nWantedBy=default.target graphical-session.target\n"
    )


def listening() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", SUNSHINE_PORT), timeout=1):
            return True
    except OSError:
        return False


def ready() -> bool:
    current = session()
    if not current or not listening():
        return False
    width, height = display_size()
    return any(item["name"] == OUTPUT and (item["width"], item["height"]) == (width, height)
               for item in monitors(current["instance"]))


def setup(package: Path | None) -> None:
    if os.geteuid() == 0:
        raise RuntimeError("Run setup as the desktop user, without sudo")
    if not session():
        raise RuntimeError("Start a Hyprland desktop session before setup")
    preferences()
    setup_iphone_usb()
    sunshine_package(package)
    if shutil.which("ufw"):
        for port in FIREWALL_PORTS:
            subprocess.run(["sudo", "ufw", "allow", port, "comment", "Dusky Moonlight display"], check=True)
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
    elif config_changed or unit_changed or not ready():
        run("systemctl", "--user", "restart", UNIT_NAME)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not ready():
        time.sleep(0.25)
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
            raise RuntimeError(f"Hyprland did not configure the {width}x{height} Moonlight output")
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = str(RUNTIME)
        env["WAYLAND_DISPLAY"] = current["wl_socket"]
        env["HYPRLAND_INSTANCE_SIGNATURE"] = instance
        sunshine = shutil.which("sunshine")
        if not sunshine:
            raise RuntimeError("Sunshine executable not found; rerun setup")
        os.execve(sunshine, [sunshine, str(CONFIG)], env)
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
    result = run("ip", "-j", "-d", "-4", "addr", "show", "scope", "global")
    found = []
    for link in json.loads(result.stdout):
        if ("UP" not in link.get("flags", []) or link.get("ifname") == "CloudflareWARP"
                or link.get("linkinfo", {}).get("info_kind") == "bridge"):
            continue
        for address in link.get("addr_info", []):
            ip = ipaddress.ip_address(address["local"])
            if not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified):
                label = "Tailscale" if link["ifname"] == "tailscale0" else link["ifname"]
                driver = Path("/sys/class/net") / link["ifname"] / "device/driver"
                if driver.is_symlink() and driver.resolve().name == "ipheth":
                    label = "iPhone USB (local only)"
                found.append(f"{label}: {ip}")
    return found


def status() -> None:
    active = run("systemctl", "--user", "is-active", UNIT_NAME, check=False).stdout.strip() == "active"
    working = active and ready()
    value = preferences()["orientation"]
    width, height = display_size(value)
    print(f"Moonlight display: {'ready' if working else 'off or starting'}")
    print(f"Orientation: {value} ({width}x{height})")
    for address in addresses():
        print(address)
    if working:
        print("Add one of these IPs in Moonlight. Pair through Sunshine at https://localhost:47990, then stream Desktop.")
        print(f"The {OUTPUT} monitor is to the right of your other displays.")
    else:
        print(f"Check: journalctl --user -u {UNIT_NAME} -n 40 --no-pager")
        raise RuntimeError("Moonlight display is not ready")


def stop() -> None:
    run("systemctl", "--user", "disable", "--now", UNIT_NAME)
    print("Moonlight display stopped; its virtual monitor was removed")


def orientation(value: str | None) -> None:
    current = preferences()
    if value is None:
        print(f"Moonlight display orientation: {current['orientation']} ({PREFERENCES})")
        return
    changed = value != current["orientation"]
    if changed:
        save_preferences({**current, "orientation": value})
    width, height = display_size(value)
    active = run("systemctl", "--user", "is-active", UNIT_NAME, check=False).stdout.strip() == "active"
    applied = ready() if active else False
    if active and (changed or not applied):
        run("systemctl", "--user", "restart", UNIT_NAME)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if ready():
                break
            time.sleep(0.25)
        else:
            raise RuntimeError(f"Moonlight display did not start in {value}; check journalctl --user -u {UNIT_NAME}")
    print(f"Moonlight display orientation: {value} ({width}x{height})")
    print(f"Saved in {PREFERENCES}" + ("" if active else "; takes effect when the service starts"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("setup", "status", "serve", "cleanup", "stop", "orientation"), default="setup")
    parser.add_argument("value", nargs="?", choices=("landscape", "portrait"), help="Display orientation for the orientation action")
    parser.add_argument("--package", type=Path, help="Local Sunshine Arch package for offline setup")
    args = parser.parse_args()
    if args.action == "setup":
        if args.value:
            parser.error("an orientation value requires the orientation action")
        setup(args.package)
    elif args.action == "orientation":
        orientation(args.value)
    else:
        if args.value:
            parser.error("an orientation value requires the orientation action")
        {"status": status, "serve": serve, "cleanup": cleanup, "stop": stop}[args.action]()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"Error: {error.stderr.strip() or error.stdout.strip() or error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
