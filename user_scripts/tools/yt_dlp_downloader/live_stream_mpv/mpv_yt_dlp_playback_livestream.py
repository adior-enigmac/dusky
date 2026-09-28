#!/usr/bin/env python3
"""mpv + yt-dlp live DVR player (YouTube / X / Twitter).

Records a live HLS stream to tmpfs with mpv --stream-record, then plays
the growing file from tmpfs, giving you rewind + 2x on live streams.
Video data never touches disk: startup aborts unless the record dir is tmpfs.

Examples:
  %(prog)s URL                                  # live mode: full timeline + tmpfs record
  %(prog)s URL -F                                # list formats/codecs only
  %(prog)s URL -f 1 --speed 2                    # 2nd listed rendition at 2x
  %(prog)s URL --mode file --buffer full         # growing-file DVR (no server window)
  %(prog)s URL --mode plain                      # play URL, no recording
  %(prog)s URL --cookies ~/cookies.txt            # login-walled / sensitive posts
  %(prog)s --set-global buffer=near speed=2       # persist global defaults
  %(prog)s --history                              # list past streams
  %(prog)s --replay 0                             # replay #0 with stored settings

Preferences: CLI flag > --replay entry > env > config.toml > builtin.
Globals live in ~/.config/dusky/settings/ytdlp_stream/config.toml,
per-stream prefs in history.toml (both 0600; video data stays in tmpfs).

Player keys: } = 2x, ] / [ = faster/slower, Backspace = reset,
Left/Right = seek, Up/Down = seek 1 min.

Cookies are staged as 0600 copies inside tmpfs; the original jar is untouched.

Env overrides: MPV_DVR_FORMAT, MPV_DVR_SPEED, MPV_DVR_TMPDIR, MPV_DVR_BUFFER,
MPV_DVR_CODEC (same as --prefer-codec), MPV_DVR_COOKIES,
MPV_DVR_COOKIES_FROM_BROWSER.
All mpv/yt-dlp flags used were verified against mpv 0.41 + yt-dlp 2026.08.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

PROG = os.path.basename(sys.argv[0]) or "mpv_yt_dlp_playback_livestream.py"
CANDIDATE_TMPFS = ["/mnt/zram1", "/dev/shm", "/tmp"]
MIN_FREE_MB_DEFAULT = 500
START_BYTES = 256 * 1024
# Player RAM window presets (verified mpv 0.41 option names).
# DVR file itself stays fully seekable on tmpfs either way; this only
# controls how much mpv holds in RAM for instant back/forth scrubbing.
BUFFER_PRESETS = {
    "near": [],
    "full": ["--demuxer-max-bytes=1G", "--demuxer-max-back-bytes=1G",
             "--demuxer-readahead-secs=10"],
}

try:
    from rich.console import Console
    from rich.table import Table

    _RICH = True
except Exception:
    _RICH = False


# ---------- config + history (global prefs + per-stream prefs) ----------
# ~/.config/dusky/settings/ytdlp_stream/config.toml   global preferences
# ~/.config/dusky/settings/ytdlp_stream/history.toml  per-URL preferences

def _cfg_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "dusky", "settings", "ytdlp_stream")


CONFIG_FILE = os.path.join(_cfg_dir(), "config.toml")
HISTORY_FILE = os.path.join(_cfg_dir(), "history.toml")
MAX_HISTORY = 100

# key: (type, builtin default)
GLOBAL_SPEC: dict[str, tuple[str, object]] = {
    "format": ("str", ""),
    "prefer_codec": ("str", ""),
    "buffer": ("str", "ask"),
    "speed": ("float", 1.0),
    "tmpdir": ("str", ""),
    "cookies": ("str", ""),
    "cookies_from_browser": ("str", ""),
    "min_free": ("int", MIN_FREE_MB_DEFAULT),
    "timeout": ("float", 30.0),
    "fullscreen": ("bool", False),
    "mute": ("bool", False),
    "low_latency": ("bool", False),
    "keep": ("bool", False),
    "show_recorder": ("bool", False),
    "mode": ("str", "live"),
}


def _tstr(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\u{o:04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _tval(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    return _tstr(str(v))


def _dump_toml(data: dict) -> str:
    """Minimal writer for our schemas: flat scalars + lists of flat dicts."""
    lines = []
    for k, v in data.items():
        if isinstance(v, list):
            for item in v:
                lines.append(f"[[{k}]]")
                for ik, iv in item.items():
                    lines.append(f"{ik} = {_tval(iv)}")
        elif isinstance(v, dict):
            lines.append(f"[{k}]")
            for ik, iv in v.items():
                lines.append(f"{ik} = {_tval(iv)}")
        else:
            lines.append(f"{k} = {_tval(v)}")
    return "\n".join(lines) + "\n"


def _load_toml(path: str) -> dict:
    try:
        import tomllib
    except ImportError:
        return {}
    try:
        with open(path, "rb") as f:
            d = tomllib.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _atomic_write(path: str, text: str) -> None:
    secure_dir(os.path.dirname(path) or ".")
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_config() -> dict:
    d = _load_toml(CONFIG_FILE)
    return d.get("defaults", d) if isinstance(d, dict) else {}


def save_config(values: dict) -> None:
    _atomic_write(CONFIG_FILE, _dump_toml({"defaults": values}))


def parse_global_pair(pair: str) -> tuple[str, object]:
    if "=" not in pair:
        raise SystemExit(f"ERROR: --set-global needs KEY=VALUE, got {pair!r}")
    k, _, raw = pair.partition("=")
    k, raw = k.strip(), raw.strip()
    if k not in GLOBAL_SPEC:
        raise SystemExit(f"ERROR: unknown key {k!r}. Known: {', '.join(sorted(GLOBAL_SPEC))}")
    typ, _ = GLOBAL_SPEC[k]
    if typ == "bool":
        if raw.lower() in ("1", "true", "yes", "on"):
            return k, True
        if raw.lower() in ("0", "false", "no", "off"):
            return k, False
        raise SystemExit(f"ERROR: {k} needs true/false, got {raw!r}")
    if typ == "int":
        try:
            return k, int(raw)
        except ValueError:
            raise SystemExit(f"ERROR: {k} needs an integer, got {raw!r}")
    if typ == "float":
        try:
            return k, float(raw)
        except ValueError:
            raise SystemExit(f"ERROR: {k} needs a number, got {raw!r}")
    return k, raw


def load_history() -> list[dict]:
    d = _load_toml(HISTORY_FILE)
    e = d.get("entries", [])
    return [x for x in e if isinstance(x, dict) and x.get("url")] if isinstance(e, list) else []


def save_history(entries: list[dict]) -> None:
    _atomic_write(HISTORY_FILE, _dump_toml({"entries": entries[:MAX_HISTORY]}))


ENTRY_FIELDS = ("url", "title", "uploader", "live_status", "format", "buffer",
                "speed", "prefer_codec", "fullscreen", "mute", "low_latency",
                "cookies_used", "cookies", "cookies_from_browser", "mode", "start",
                "last_played", "plays")


def parse_start(value: str) -> str:
    """Validate an mpv --start value: seconds, MM:SS, HH:MM:SS, negatives from edge."""
    import re
    if re.fullmatch(r"-?(\d+:){0,2}\d+(\.\d+)?", value.strip()):
        return value.strip()
    raise SystemExit(f"ERROR: bad --start {value!r}. Use seconds (90), MM:SS (1:30), "
                     f"HH:MM:SS, or negative from live edge (-1800).")


def find_entry(spec: str) -> dict:
    """Match a history entry by # index, exact URL, or unique substring."""
    entries = load_history()
    if not entries:
        raise SystemExit("ERROR: history is empty.")
    s = spec.strip()
    if s.isdigit() and int(s) < len(entries):
        return entries[int(s)]
    exact = [e for e in entries if e.get("url") == s]
    if exact:
        return exact[0]
    sub = [e for e in entries if s.lower() in str(e.get("url", "")).lower()
           or s.lower() in str(e.get("title", "")).lower()]
    if len(sub) == 1:
        return sub[0]
    if not sub:
        raise SystemExit(f"ERROR: no history match for {spec!r}. Use --history to list.")
    raise SystemExit("ERROR: ambiguous match:\n" + "\n".join(
        f"  {i}: {e.get('title')} | {e.get('url')}" for i, e in enumerate(entries) if e in sub))


def remember(entry: dict) -> int:
    """Insert/update entry by URL, newest first. Returns its index (0)."""
    entries = [e for e in load_history() if e.get("url") != entry["url"]]
    old = next((e for e in load_history() if e.get("url") == entry["url"]), {})
    entry["plays"] = int(old.get("plays", 0) or 0) + 1
    entries.insert(0, {k: entry.get(k) for k in ENTRY_FIELDS})
    save_history(entries)
    return 0


# ---------- tmpfs enforcement (no disk write amplification) ----------

def _mount_fstype(path: str) -> str | None:
    """Filesystem type of the mount containing path, via /proc/self/mountinfo."""
    path = os.path.realpath(os.path.abspath(path))
    best_fs, best_len = None, -1
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as f:
            for line in f:
                left, sep, right = line.partition(" - ")
                if not sep:
                    continue
                pre = left.split()
                if len(pre) < 5:
                    continue
                mnt = pre[4].replace("\\040", " ")
                if path == mnt or path.startswith(mnt.rstrip("/") + "/"):
                    fields = right.split()
                    if not fields:
                        continue
                    if len(mnt) > best_len:
                        best_len, best_fs = len(mnt), fields[0]
    except FileNotFoundError:
        return None
    return best_fs


def is_tmpfs(path: str) -> bool:
    return _mount_fstype(path) == "tmpfs"


def secure_dir(path: str, mode: int = 0o700) -> str:
    """mkdir 0700, rejecting a leaf symlink and other owners."""
    os.makedirs(path, mode=mode, exist_ok=True)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError(f"Unsafe directory (symlink or other owner): {path}")
    os.chmod(path, mode)
    return path


def secure_subdir(root: str, name: str, mode: int = 0o700) -> str:
    """Create name directly under root, refusing symlink escapes in between."""
    if os.path.realpath(root) != os.path.abspath(root):
        raise ValueError(f"Refusing symlinked pool root: {root}")
    if "/" in name or name in (".", ".."):
        raise ValueError(f"Refusing unsafe pool name: {name!r}")
    pool = os.path.join(root, name)
    os.makedirs(pool, mode=mode, exist_ok=True)
    if os.path.realpath(pool) != os.path.join(os.path.realpath(root), name):
        raise ValueError(f"Refusing path escaping {root}: {pool}")
    return secure_dir(pool, mode)


def pick_tmpfs(user_dir: str | None, allow_disk: bool) -> str:
    cands: list[str] = []
    if user_dir:
        cands.append(user_dir)
    cands += CANDIDATE_TMPFS
    if os.environ.get("XDG_RUNTIME_DIR"):
        cands.append(os.environ["XDG_RUNTIME_DIR"])
    seen = set()
    ordered = [c for c in cands if not (c in seen or seen.add(c))]
    for d in ordered:
        if allow_disk and user_dir and os.path.realpath(d) == os.path.realpath(user_dir):
            try:
                return secure_dir(d)
            except (OSError, ValueError) as e:
                raise SystemExit(f"ERROR: --tmpdir unusable: {e}")
        if _mount_fstype(d) != "tmpfs":
            continue
        pool = secure_subdir(d, f"mpv-dvr-{os.getuid()}")
        try:
            if os.stat(pool).st_dev != os.stat(d).st_dev:
                continue  # nested mount inside pool: refuse
            fd, name = tempfile.mkstemp(prefix=".write-test-", dir=pool)
            os.close(fd)
            os.unlink(name)
        except (OSError, ValueError):
            continue
        if not os.access(pool, os.W_OK):
            continue
        return pool
    raise SystemExit(
        "ERROR: no writable tmpfs found (tried %s). Refusing disk writes.\n"
        "Use --tmpdir /dev/shm (must be tmpfs) or --allow-disk to override."
        % ", ".join(ordered)
    )


# ---------- cookies (login-walled / sensitive broadcasts) ----------

def stage_cookies(src: str | None, browser: str | None, ram_dir: str,
                  ) -> tuple[list[str], str | None, str | None]:
    """Copy the cookie jar into tmpfs; return (yt-dlp flags, mpv raw opt, staged path).

    The original jar is never handed to yt-dlp (it rewrites the file).
    """
    if src and browser:
        raise SystemExit("ERROR: use either --cookies or --cookies-from-browser, not both.")
    if browser:
        return (["--cookies-from-browser", browser], f"cookies-from-browser={browser}", None)
    if not src:
        return ([], None, None)
    if not os.path.isfile(os.path.expanduser(src)):
        raise SystemExit(f"ERROR: not a cookie file: {src}")
    fd, name = tempfile.mkstemp(prefix=".mpv-live-cookies-", dir=ram_dir)
    try:
        with os.fdopen(fd, "wb") as dst, open(os.path.expanduser(src), "rb") as fh:
            shutil.copyfileobj(fh, dst)
        os.chmod(name, 0o600)
    except OSError as e:
        raise SystemExit(f"ERROR: cannot stage cookies in tmpfs: {e}")
    return (["--cookies", name], f"cookies={name}", name)


def check_free(path: str, min_mb: int) -> None:
    try:
        free_mb = shutil.disk_usage(path).free // (1024 * 1024)
    except OSError:
        return
    if free_mb < min_mb:
        raise SystemExit(
            f"ERROR: only {free_mb}MB free on {path} (need {min_mb}MB). "
            "4K live is ~2MB/s. Free tmpfs space or pick lower -f."
        )


# ---------- yt-dlp ----------

def _failure_hint(message: str) -> str:
    m = (message or "").lower()
    if "sign in" in m or "login" in m or "not a bot" in m or "authenticate" in m:
        return "HINT: login needed — pass --cookies ~/cookies.txt or --cookies-from-browser chromium."
    if "429" in m:
        return "HINT: rate-limited, wait and retry."
    if "403" in m:
        return "HINT: access denied — check cookies / link permissions."
    if "unsupported url" in m:
        return "HINT: update with: yt-dlp -U"
    if "requested format" in m:
        return "HINT: codec/height absent — try -f best or a lower cap."
    return ""


def run_yt_dlp_json(url: str, extra_flags: list[str] | None = None) -> dict:
    cmd = ["yt-dlp", "--no-playlist", "--no-cache-dir", "--no-warnings"]
    cmd += extra_flags or []
    cmd += ["-J", "--", url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise SystemExit("ERROR: yt-dlp not found in PATH (need recent yt-dlp for x.com)")
    if p.returncode != 0:
        sys.stderr.write((p.stderr or p.stdout or "yt-dlp failed")[-3000:])
        hint = _failure_hint(p.stderr or p.stdout or "")
        if hint:
            sys.stderr.write("\n" + hint + "\n")
        raise SystemExit(1)
    try:
        info = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise SystemExit("ERROR: could not parse yt-dlp -J output")
    # --no-playlist should prevent this, but stay robust for YT mixes
    if info.get("_type") == "playlist":
        entries = [e for e in (info.get("entries") or []) if e]
        if not entries:
            raise SystemExit("ERROR: playlist returned no entries")
        info = entries[0]
    return info


def codec_fam(vc: str | None) -> str:
    """Short codec family: av1 / vp9 / hevc / avc / none / raw-prefix."""
    v = (vc or "").strip().lower()
    if not v or v in ("?", "none"):
        return v or "?"
    if "av01" in v or v == "av1":
        return "av1"
    if "vp09" in v or v == "vp9":
        return "vp9"
    if v.startswith(("hev1", "hev2", "hvc1", "hevk")) or "hevc" in v or "h265" in v:
        return "hevc"
    if v.startswith("avc") or "h264" in v:
        return "avc"
    return v.split(".")[0][:8] or "?"


CODEC_ALIASES = {
    "av1": "av1", "av01": "av1",
    "vp9": "vp9", "vp09": "vp9",
    "hevc": "hevc", "h265": "hevc", "h.265": "hevc",
    "avc": "avc", "h264": "avc", "h.264": "avc",
}


def fmt_list(info: dict) -> list[dict]:
    fmts = info.get("formats") or []
    if not fmts and info.get("url"):
        fmts = [info]
    out = []
    for f in fmts:
        fid = str(f.get("format_id") or "?")
        w, h = f.get("width"), f.get("height")
        res = f"{w}x{h}" if w and h else (f"{h}p" if h else (f.get("resolution") or "?"))
        vc = f.get("vcodec") or "?"
        out.append({
            "id": fid, "ext": f.get("ext") or "?", "res": res,
            "h": h or 0, "fps": f.get("fps") or 0, "tbr": f.get("tbr") or 0,
            "vcodec": vc[:24], "fam": codec_fam(vc),
            "acodec": (f.get("acodec") or "?")[:16],
            "proto": f.get("protocol") or "?", "note": f.get("format_note") or "",
        })
    out.sort(key=lambda x: (x["h"], x["tbr"] or 0, x["fps"] or 0))
    return out


def print_formats(fmts: list[dict], title: str = "") -> None:
    if title:
        print(title)
    if _RICH and sys.stdout.isatty():
        t = Table(show_header=True, header_style="bold")
        for col in ("#", "ID", "RES", "FPS", "TBR", "CODEC", "VCODEC", "ACODEC", "PROTO"):
            t.add_column(col, justify="right" if col in ("#", "FPS", "TBR") else "left")
        for i, f in enumerate(fmts):
            tag = " ← best" if i == len(fmts) - 1 else (" ← smallest" if i == 0 else "")
            t.add_row(str(i), f["id"], f["res"],
                      str(f["fps"] or "?"), f"{f['tbr']:.0f}k" if f["tbr"] else "?",
                      f["fam"], f["vcodec"], f["acodec"], f["proto"] + tag)
        Console().print(t)
        return
    print(f"{'#':>3}  {'ID':<12} {'RES':<10} {'FPS':>6} {'TBR':>8}  {'CODEC':<6} {'VCODEC':<16} {'ACODEC':<10} PROTO")
    for i, f in enumerate(fmts):
        tag = "  <-- best" if i == len(fmts) - 1 else ""
        print(f"{i:>3}  {f['id']:<12} {f['res']:<10} {str(f['fps'] or '?'):>6} "
              f"{(f'{f['tbr']:.0f}k' if f['tbr'] else '?'):>8}  "
              f"{f['fam']:<6} {f['vcodec']:<16} {f['acodec']:<10} {f['proto']}{tag}")


def _best_of(fmts: list[dict]) -> str:
    return fmts[-1]["id"]


def _pick_codec_best(fmts: list[dict], fam: str) -> str | None:
    m = [f for f in fmts if f["fam"] == fam]
    return m[-1]["id"] if m else None


def resolve_format(fmts: list[dict], want: str | None, prefer_codec: str | None = None,
                   fallback_best: bool = False) -> str:
    """Return an mpv --ytdl-format value.

    Accepts: number from -F, exact format ID, best/worst, a codec family
    (av1/vp9/hevc/avc, with av01/vp09/h264/h265 aliases), or any raw
    yt-dlp format selector (passed through untouched, e.g.
    "bv*[vcodec^=av01]+ba/b"). Interactive prompt loops: typing a codec
    filters the table, anything else unknown is treated as a raw selector.
    With fallback_best (replays), a vanished stored ID degrades to best.
    """
    if not fmts:
        return "best"
    if prefer_codec and want is None:
        fam = CODEC_ALIASES.get(prefer_codec.strip().lower(), prefer_codec.strip().lower())
        hit = _pick_codec_best(fmts, fam)
        if hit is None:
            print(f"WARNING: no {fam} formats, falling back to best.", file=sys.stderr)
            return _best_of(fmts)
        return hit
    if want is not None:
        w = want.strip()
        if prefer_codec:
            print("NOTE: ignoring --prefer-codec (explicit -f given).", file=sys.stderr)
    elif not sys.stdin.isatty():
        return _best_of(fmts)
    else:
        pool = fmts
        while True:
            print_formats(pool)
            try:
                w = input("Pick [# / ID / av1 / vp9 / hevc / avc / raw selector, q=quit, default=best]: ").strip() or "best"
            except (EOFError, KeyboardInterrupt):
                print(file=sys.stderr)
                raise SystemExit(130)
            if w.lower() in ("q", "quit", "exit"):
                raise SystemExit("Aborted.")
            wl = w.lower()
            if wl in ("best", "worst"):
                return pool[-1]["id"] if wl == "best" else pool[0]["id"]
            if w.isdigit() and int(w) < len(pool):
                return pool[int(w)]["id"]
            if w in {f["id"] for f in pool}:
                return w
            if wl in CODEC_ALIASES:
                sub = [f for f in pool if f["fam"] == CODEC_ALIASES[wl]]
                if not sub:
                    print(f"No {wl} in this list, try another.", file=sys.stderr)
                    continue
                if len(sub) == 1:
                    return sub[0]["id"]
                pool = sub  # narrow table, pick again
                continue
            # Unknown input: raw yt-dlp format selector passthrough (future-proof).
            print(f"Passing custom yt-dlp format selector to mpv: {w}", file=sys.stderr)
            return w
    wl = w.lower()
    if wl == "best":
        return _best_of(fmts)
    if wl == "worst":
        return fmts[0]["id"]
    if w.isdigit() and int(w) < len(fmts):
        return fmts[int(w)]["id"]
    if w in {f["id"] for f in fmts}:
        return w
    if wl in CODEC_ALIASES:
        hit = _pick_codec_best(fmts, CODEC_ALIASES[wl])
        if hit is None:
            if fallback_best:
                print(f"WARNING: stored codec {wl} gone, falling back to best.", file=sys.stderr)
                return _best_of(fmts)
            raise SystemExit(f"ERROR: no {wl} formats. Use -F to list.")
        return hit
    if fallback_best and "/" not in w and "[" not in w and "+" not in w and "*" not in w:
        # Plain stored ID that no longer exists (not a raw selector): degrade.
        print(f"WARNING: stored format {w!r} gone, falling back to best.", file=sys.stderr)
        return _best_of(fmts)
    # Raw yt-dlp format selector passthrough (e.g. "bv*[height<=720]+ba/b").
    print(f"Passing custom yt-dlp format selector to mpv: {w}", file=sys.stderr)
    return w


def resolve_buffer(want: str | None, need_player: bool) -> str:
    """full = 1G RAM window for easy back/forth scrub; near = mpv defaults.

    Never forced: ask prompts on a tty, defaults to near when piped or when
    there is no player (--record-only / -F). Direct-live note: full widens
    the in-memory rewind window but can't exceed the server sliding window.
    Global/env/CLI merging happens before this call, so want is already final.
    """
    w = (want or "ask").strip().lower()
    if w not in ("ask", "full", "near"):
        raise SystemExit("ERROR: --buffer must be ask/full/near")
    if not need_player or w in ("full", "near"):
        return w if w in ("full", "near") else "near"
    if not sys.stdin.isatty():
        return "near"
    print("Buffer: [full] keeps a ~1G RAM window for easy back/forth scrubbing "
          "(more RAM); [near] keeps mpv defaults (file stays fully seekable either way).",
          file=sys.stderr)
    try:
        ans = input("Buffer full or near? [near/full, default=near]: ").strip().lower() or "near"
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        raise SystemExit(130)
    if ans in ("full", "near"):
        return ans
    print(f"Unknown {ans!r}, using near.", file=sys.stderr)
    return "near"


def wait_for_file(path: str, proc: subprocess.Popen, timeout: float, min_bytes: int = START_BYTES) -> bool:
    t0 = time.time()
    last_msg = 0.0
    while time.time() - t0 < timeout:
        try:
            have = os.path.getsize(path)
            if have >= min_bytes:
                return True
        except OSError:
            have = 0
        if proc.poll() is not None:  # recorder died: fail fast
            try:
                return os.path.getsize(path) >= min_bytes
            except OSError:
                return False
        if time.time() - last_msg >= 2.0:
            print(f"  recording... {have // 1024}KB / {min_bytes // 1024}KB", file=sys.stderr)
            last_msg = time.time()
        time.sleep(0.5)
    try:
        return os.path.getsize(path) >= min_bytes
    except OSError:
        return False


def join_threshold(fmts: list[dict], choice: str) -> int:
    """Wait ~1.5s of stream data before the player joins a growing file.

    Joining a .ts that only has a fragment of a segment is what causes the
    brief 'PES packet size mismatch / Packet corrupt' burst on player start.
    Scales with the chosen rendition's bitrate so 480p doesn't wait long;
    capped low because mpv tails growing files gracefully anyway, and a slow
    network can deliver far below nominal bitrate (measured ~116KB/s on a
    16Mbps rendition during congestion).
    """
    tbr = next((f["tbr"] for f in fmts if f["id"] == choice), 0) or 0
    return max(START_BYTES, min(int(tbr * 125 * 1.5), 2 * 1024 * 1024))


# ---------- live time-travel (in-player seeks are clamped by ffmpeg HLS) ----------
# Proven: relative/absolute/percent seeks are acked but don't move (deltas ==
# elapsed playback). Only (re)opening at a position works. So travel keys quit
# mpv with a code and the wrapper relaunches at base+delta (absolute --start,
# verified exact to keyframe). Builtin defaults + your input.conf stay intact;
# this fragment only adds four keys.

TRAVEL_CONF = (
    "# added by mpv_yt_dlp_playback_livestream.py (live mode time travel)\n"
    "Ctrl+Left quit 91\n"    # back 60s
    "Ctrl+Right quit 92\n"   # forward 60s (clamped at live edge)
    "Shift+Left quit 93\n"   # back 10min
    "Shift+Right quit 94\n"  # forward 10min (clamped at live edge)
)
TRAVEL_DELTAS = {91: -60, 92: 60, 93: -600, 94: 600}


def _ipc_cmd(sock: str, command: list, timeout: float = 5.0) -> object:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    try:
        s.connect(sock)
        s.sendall((json.dumps({"command": command}) + "\n").encode())
        out = b""
        while b"\n" not in out:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
        return json.loads(out.decode()).get("data")
    finally:
        try:
            s.close()
        except OSError:
            pass


class EdgeTracker(threading.Thread):
    """Poll mpv IPC duration; the max seen approximates the live edge."""

    def __init__(self, sock: str) -> None:
        super().__init__(daemon=True)
        self.sock = sock
        self.edge: float | None = None
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                v = _ipc_cmd(self.sock, ["get_property", "duration"], timeout=4.0)
                if isinstance(v, (int, float)) and v > 0:
                    self.edge = v if self.edge is None else max(self.edge, v)
            except (OSError, ValueError, socket.timeout):
                pass
            self._stop.wait(10.0)

    def halt(self) -> None:
        self._stop.set()


# ---------- CLI ----------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=PROG, description="Watch YouTube/X live in mpv with tmpfs DVR (rewind + 2x).",
        epilog="Precedence: CLI > --replay entry > env > config.toml > builtin. "
               "Player keys: } = 2x, ]/[ = speed, Backspace = reset, Left/Right = seek.",
    )
    ap.add_argument("url", nargs="?",
                    help="youtube.com/watch, youtu.be, x.com/i/broadcasts/..., x.com/.../status/... works for VOD too")
    ap.add_argument("-F", "--list-formats", action="store_true", help="list available resolutions and exit")
    ap.add_argument("-f", "--format", default=None,
                    help="format ID, number from -F, codec (av1/vp9/hevc/avc), best/worst, "
                         "or raw yt-dlp selector (default: prompt, best if piped)")
    ap.add_argument("--prefer-codec", default=None,
                    help="auto-pick best format with this codec: av1/vp9/hevc/avc (ignored if -f given)")
    ap.add_argument("--buffer", default=None,
                    help="player RAM window: ask/full/near (default: ask on tty, near if piped). "
                         "full = 1G back/forth scrub window; file stays seekable either way")
    ap.add_argument("--speed", type=float, default=None, help="initial player speed, 2 = 2x (default: 1.0)")
    ap.add_argument("--tmpdir", default=None, help="tmpfs dir for recording (default: /mnt/zram1, /dev/shm, /tmp)")
    ap.add_argument("--cookies", default=None,
                    help="Netscape cookie file for login-walled broadcasts (copied to tmpfs, original untouched)")
    ap.add_argument("--cookies-from-browser", default=None, metavar="BROWSER",
                    help="e.g. chromium, firefox (passed to yt-dlp and mpv)")
    ap.add_argument("--allow-disk", dest="allow_disk", default=None,
                    action=argparse.BooleanOptionalAction, help="allow non-tmpfs --tmpdir (SSD wear)")
    ap.add_argument("--min-free", type=int, default=None, metavar="MB", help="required free tmpfs MB (default: 500)")
    ap.add_argument("--keep", dest="keep", default=None,
                    action=argparse.BooleanOptionalAction, help="keep tmpfs recording on exit")
    ap.add_argument("--show-recorder", dest="show_recorder", default=None,
                    action=argparse.BooleanOptionalAction,
                    help="also show the live recorder window (default: headless)")
    ap.add_argument("--record-only", action="store_true", help="record to tmpfs without launching the player")
    ap.add_argument("--mode", default=None,
                    help="live = play event URL directly with full server timeline + tmpfs record (default); "
                         "file = two-process growing-file DVR (no server window needed); "
                         "plain = play URL, no recording")
    ap.add_argument("--direct", action="store_true", help="deprecated alias for --mode plain")
    ap.add_argument("--fullscreen", dest="fullscreen", default=None,
                    action=argparse.BooleanOptionalAction, help="start player fullscreen")
    ap.add_argument("--mute", dest="mute", default=None,
                    action=argparse.BooleanOptionalAction, help="start player muted")
    ap.add_argument("--low-latency", dest="low_latency", default=None,
                    action=argparse.BooleanOptionalAction, help="recorder uses mpv --profile=low-latency")
    ap.add_argument("--timeout", type=float, default=None, help="seconds to wait for recording to start (default: 30)")
    ap.add_argument("--start", default=None,
                    help="open at position: seconds (3600), MM:SS, HH:MM:SS, or negative seconds "
                         "from live edge (-1800). In-player clicks cannot seek on live HLS "
                         "(ffmpeg demuxer clamps to edge) — this is the time-travel knob.")
    ap.add_argument("--player-args", default="", help='extra player args, e.g. --player-args="--volume=80"')
    ap.add_argument("--recorder-args", default="", help="extra recorder args (file mode only)")
    ap.add_argument("--print-cmds", action="store_true", help="print mpv commands without running them")
    mg = ap.add_argument_group("config + history",
                               f"stored in {os.path.join(_cfg_dir())} (0600, video stays in tmpfs)")
    mg.add_argument("--set-global", action="append", nargs="+", default=[], metavar="KEY=VALUE",
                    help=f"persist global defaults, e.g. --set-global buffer=near speed=2 "
                         f"({', '.join(sorted(GLOBAL_SPEC))})")
    mg.add_argument("--show-config", action="store_true", help="show global defaults and exit")
    mg.add_argument("--history", action="store_true", help="list previously played streams and exit")
    mg.add_argument("--replay", default=None, metavar="N|URL",
                    help="replay a history entry with its stored settings (index, URL, or title match)")
    mg.add_argument("--forget", default=None, metavar="N|URL", help="drop a history entry and exit")
    mg.add_argument("--clear-history", action="store_true", help="drop all history and exit")
    return ap


OPT_ENV = {
    "format": "MPV_DVR_FORMAT", "prefer_codec": "MPV_DVR_CODEC", "buffer": "MPV_DVR_BUFFER",
    "speed": "MPV_DVR_SPEED", "tmpdir": "MPV_DVR_TMPDIR", "cookies": "MPV_DVR_COOKIES",
    "cookies_from_browser": "MPV_DVR_COOKIES_FROM_BROWSER", "mode": "MPV_DVR_MODE",
    "start": "MPV_DVR_START",
}


def _eff(cli: object, entry: dict, key: str, cfg: dict, builtin: object) -> object:
    """Precedence: CLI > replay entry > env > config.toml > builtin."""
    if cli is not None and cli != "":
        return cli
    if entry.get(key) not in (None, ""):
        return entry[key]
    env = os.environ.get(OPT_ENV[key], "") if key in OPT_ENV else ""
    if env not in (None, ""):
        return env
    if cfg.get(key) not in (None, ""):
        return cfg[key]
    return builtin


def _eff_bool(cli: object | None, entry: dict, key: str, cfg: dict, builtin: bool) -> bool:
    if cli is not None:
        return bool(cli)
    if entry.get(key) is not None:
        return bool(entry[key])
    if cfg.get(key) is not None:
        return bool(cfg[key])
    return builtin


def _eff_float(cli: object | None, entry: dict, key: str, cfg: dict, builtin: float, env_name: str) -> float:
    for src in (cli, entry.get(key), os.environ.get(env_name), cfg.get(key)):
        if src in (None, ""):
            continue
        try:
            return float(src)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            raise SystemExit(f"ERROR: {key} needs a number, got {src!r}")
    return builtin


def show_history() -> None:
    entries = load_history()
    if not entries:
        print("History is empty.")
        return
    if _RICH and sys.stdout.isatty():
        t = Table(show_header=True, header_style="bold")
        for col in ("#", "LAST PLAYED", "TITLE", "FORMAT", "BUF", "SPEED", "PLAYS"):
            t.add_column(col, justify="right" if col in ("#", "SPEED", "PLAYS") else "left")
        for i, e in enumerate(entries):
            ts = time.strftime("%m-%d %H:%M", time.localtime(int(e.get("last_played", 0) or 0)))
            t.add_row(str(i), ts, str(e.get("title") or "?")[:40], str(e.get("format") or "?"),
                      str(e.get("buffer") or "?"), str(e.get("speed") or "?"), str(e.get("plays", 1)))
            t.add_row("", "", f"[dim]{str(e.get('url') or '')[:80]}[/dim]", "", "", "", "")
        Console().print(t)
        return
    for i, e in enumerate(entries):
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(e.get("last_played", 0) or 0)))
        print(f"{i}: [{ts}] {e.get('title')} | f={e.get('format')} buf={e.get('buffer')} "
              f"spd={e.get('speed')} x{e.get('plays', 1)}\n    {e.get('url')}")


def _eff_int(cli: object | None, entry: dict, key: str, cfg: dict, builtin: int) -> int:
    for src in (cli, entry.get(key), cfg.get(key)):
        if src in (None, ""):
            continue
        try:
            return int(src)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            raise SystemExit(f"ERROR: {key} needs an integer, got {src!r}")
    return builtin


def main() -> int:
    args = build_parser().parse_args()
    if shutil.which("mpv") is None:
        raise SystemExit("ERROR: mpv not found in PATH")
    if shutil.which("yt-dlp") is None:
        raise SystemExit("ERROR: yt-dlp not found in PATH")

    # Management commands (no URL needed).
    if args.set_global:
        cfg = load_config()
        for pair in [p for group in args.set_global for p in group]:
            k, v = parse_global_pair(pair)
            cfg[k] = v
        save_config({k: v for k, v in cfg.items() if k in GLOBAL_SPEC})
        print(f"Saved globals to {CONFIG_FILE}")
        return 0
    if args.show_config:
        cfg = load_config()
        print(f"# {CONFIG_FILE}")
        if not cfg:
            print("# (empty — all builtins)")
        for k in sorted(GLOBAL_SPEC):
            if k in cfg:
                print(f"{k} = {_tval(cfg[k])}")
        return 0
    if args.history:
        show_history()
        return 0
    if args.forget is not None:
        victim = find_entry(args.forget)
        entries = [e for e in load_history() if e.get("url") != victim.get("url")]
        save_history(entries)
        print(f"Forgot: {victim.get('title')} | {victim.get('url')}")
        return 0
    if args.clear_history:
        save_history([])
        print("History cleared.")
        return 0

    # Replay supplies URL + per-stream prefs; explicit CLI still wins.
    entry: dict = find_entry(args.replay) if args.replay else {}
    if entry:
        print(f"Replaying #{load_history().index(entry)}: {entry.get('title')} "
              f"(stored f={entry.get('format')} buf={entry.get('buffer')} spd={entry.get('speed')})",
              file=sys.stderr)
    url = args.url or entry.get("url")
    if not url:
        raise SystemExit("ERROR: URL required (or use --replay N).")
    cfg = load_config()
    cli_fmt_given = args.format not in (None, "")

    args.url = url
    args.format = _eff(args.format, entry, "format", cfg, None)
    args.prefer_codec = _eff(args.prefer_codec, entry, "prefer_codec", cfg, None)
    args.buffer = _eff(args.buffer, entry, "buffer", cfg, "ask")
    args.speed = _eff_float(args.speed, entry, "speed", cfg, 1.0, "MPV_DVR_SPEED")
    args.tmpdir = _eff(args.tmpdir, entry, "tmpdir", cfg, None)
    cookie_src = _eff(args.cookies, {"cookies": entry.get("cookies")}, "cookies", cfg, None)
    browser = _eff(args.cookies_from_browser, entry, "cookies_from_browser", cfg, None)
    args.min_free = _eff_int(args.min_free, entry, "min_free", cfg, MIN_FREE_MB_DEFAULT)
    args.timeout = _eff_float(args.timeout, entry, "timeout", cfg, 30.0, "MPV_DVR_TIMEOUT")
    args.fullscreen = _eff_bool(args.fullscreen, entry, "fullscreen", cfg, False)
    args.mute = _eff_bool(args.mute, entry, "mute", cfg, False)
    args.low_latency = _eff_bool(args.low_latency, entry, "low_latency", cfg, False)
    args.keep = _eff_bool(args.keep, entry, "keep", cfg, False)
    args.show_recorder = _eff_bool(args.show_recorder, entry, "show_recorder", cfg, False)
    args.allow_disk = _eff_bool(args.allow_disk, entry, "allow_disk", cfg, False)
    mode = str(_eff(args.mode, entry, "mode", cfg, "live")).strip().lower()
    if args.direct:
        print("NOTE: --direct is deprecated, use --mode plain.", file=sys.stderr)
        if args.mode is None and not entry.get("mode"):
            mode = "plain"
    if mode not in ("live", "file", "plain"):
        raise SystemExit("ERROR: --mode must be live/file/plain")
    start = _eff(args.start, entry, "start", cfg, None)
    start_opt = [f"--start={parse_start(str(start))}"] if start not in (None, "") else []
    if not 0.1 <= args.speed <= 100:
        raise SystemExit("ERROR: --speed must be 0.1..100")
    if args.timeout <= 0 or args.min_free <= 0:
        raise SystemExit("ERROR: --timeout/--min-free must be positive")

    info: dict
    tmpfs = pick_tmpfs(args.tmpdir, args.allow_disk)
    if not is_tmpfs(tmpfs) and not args.allow_disk:
        raise SystemExit(f"ERROR: {tmpfs} is not tmpfs. Aborting to avoid disk writes.")
    check_free(tmpfs, args.min_free)
    watch = secure_subdir(tmpfs, "watch-later")
    yt_cookie_flags, mpv_cookie_opt, staged_cookies = stage_cookies(
        cookie_src, browser, tmpfs)
    raw_opts = ["no-cache-dir="] + ([mpv_cookie_opt] if mpv_cookie_opt else [])

    def _drop(path: str | None) -> None:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    info = run_yt_dlp_json(args.url, yt_cookie_flags)
    fmts = fmt_list(info)
    header = (f"Title: {info.get('title') or '?'} | uploader: {info.get('uploader') or '?'} | "
              f"live: {info.get('live_status') or info.get('is_live') or '?'}")
    print(header, file=sys.stderr)

    if args.list_formats:
        print_formats(fmts)
        _drop(staged_cookies)
        return 0

    choice = resolve_format(fmts, args.format, args.prefer_codec,
                              fallback_best=bool(entry) and not cli_fmt_given)
    print(f"Selected format: {choice}", file=sys.stderr)
    bufmode = resolve_buffer(args.buffer, need_player=not args.record_only)
    buf_flags = BUFFER_PRESETS[bufmode]
    if buf_flags:
        print(f"Buffer mode: {bufmode} ({' '.join(buf_flags)})", file=sys.stderr)
    else:
        print(f"Buffer mode: {bufmode} (mpv defaults)", file=sys.stderr)
    if not args.print_cmds:
        remember({
            "url": url, "title": info.get("title") or "?", "uploader": info.get("uploader") or "?",
            "live_status": str(info.get("live_status") or info.get("is_live") or "?"),
            "format": choice, "buffer": bufmode, "speed": args.speed,
            "prefer_codec": args.prefer_codec or "", "fullscreen": args.fullscreen,
            "mute": args.mute, "low_latency": args.low_latency,
            "cookies_used": bool(cookie_src or browser), "cookies": cookie_src or "",
            "cookies_from_browser": browser or "", "mode": mode,
            "start": start_opt[0].split("=", 1)[1] if start_opt else "",
            "last_played": int(time.time()), "plays": 0,
        })
        print("Saved to history (#0). Replay with: --replay 0", file=sys.stderr)

    extra_player = shlex.split(args.player_args) if args.player_args else []
    extra_rec = shlex.split(args.recorder_args) if args.recorder_args else []
    std_flags = ["--no-save-position-on-quit", "--no-resume-playback"]

    if mode == "plain":
        cmd = ["mpv", f"--ytdl-format={choice}", f"--speed={args.speed}"]
        cmd += [f"--ytdl-raw-options={o}" for o in raw_opts]
        cmd += std_flags + buf_flags + start_opt
        if args.fullscreen:
            cmd.append("--fullscreen")
        if args.mute:
            cmd.append("--mute=yes")
        if args.low_latency:
            cmd.append("--profile=low-latency")
        cmd += extra_player + ["--", args.url]
        print("+ " + " ".join(shlex.quote(c) for c in cmd), file=sys.stderr)
        if args.print_cmds:
            _drop(staged_cookies)
            return 0
        rc = subprocess.call(cmd)
        _drop(staged_cookies)
        return rc

    fd, rec_path = tempfile.mkstemp(prefix="mpv-live-", suffix=".ts", dir=tmpfs)
    os.close(fd)
    try:
        os.unlink(rec_path)  # mpv --stream-record creates it
    except OSError:
        pass
    print(f"Recording to tmpfs: {rec_path}", file=sys.stderr)

    env = dict(os.environ, TMPDIR=tmpfs, XDG_CACHE_HOME=os.path.join(tmpfs, "cache"))
    if mode == "live":
        # One mpv on the event URL: full server timeline + tmpfs archive.
        # In-player seeks are clamped by ffmpeg's HLS demuxer (proven), so
        # travel keys quit mpv with a code and the wrapper relaunches at
        # base+delta via absolute --start (proven exact). Plain arrows keep
        # working for small in-buffer seeks; these keys jump far.
        def _to_secs(v: str) -> int:
            neg = v.startswith("-")
            parts = [float(p) for p in v.lstrip("-").split(":")]
            total = 0.0
            for p in parts:
                total = total * 60 + p
            return int(-total if neg else total)

        base_cmd = ["mpv", f"--ytdl-format={choice}", f"--speed={args.speed}"]
        base_cmd += [f"--ytdl-raw-options={o}" for o in raw_opts]
        base_cmd += std_flags + [f"--watch-later-dir={watch}"] + buf_flags
        if args.fullscreen:
            base_cmd.append("--fullscreen")
        if args.mute:
            base_cmd.append("--mute=yes")
        if args.low_latency:
            base_cmd.append("--profile=low-latency")
        base_cmd += [f"--stream-record={rec_path}"] + extra_player
        sock = os.path.join(tmpfs, "mpv-ipc.sock")
        travel_conf = os.path.join(tmpfs, "travel.conf")
        try:
            with open(travel_conf, "w", encoding="utf-8") as f:
                f.write(TRAVEL_CONF)
            os.chmod(travel_conf, 0o600)
        except OSError as e:
            raise SystemExit(f"ERROR: cannot write travel keys to tmpfs: {e}")

        if start_opt:
            first_start: list[str] = list(start_opt)
            base: int | None = None if start_opt[0].startswith("--start=-") else _to_secs(
                start_opt[0].split("=", 1)[1])
        else:
            first_start = []
            base = None
        tracker = EdgeTracker(sock)
        tracker.start()
        final_base: int | None = base
        print("Travel keys: Ctrl+Left/Right = ∓60s, Shift+Left/Right = ∓10min "
              "(reopens at position; plain arrows = in-buffer seeks).",
              file=sys.stderr)
        if args.print_cmds:
            print("+ " + " ".join(shlex.quote(c) for c in base_cmd + first_start + ["--", args.url]),
                  file=sys.stderr)
            _drop(staged_cookies)
            tracker.halt()
            try:
                os.rmdir(watch)
            except OSError:
                pass
            return 0
        rc_live = 0
        try:
            open_start = first_start
            while True:
                try:
                    os.unlink(sock)
                except OSError:
                    pass
                cmd = list(base_cmd) + open_start + [
                    f"--input-ipc-server={sock}", f"--input-conf={travel_conf}",
                    "--", args.url]
                print("+ " + " ".join(shlex.quote(c) for c in cmd), file=sys.stderr)
                rc_live = subprocess.call(cmd, env=env)
                if rc_live not in TRAVEL_DELTAS:
                    break
                cur = final_base if final_base is not None else tracker.edge
                if cur is None:
                    print("Edge unknown yet — reopening at live edge.", file=sys.stderr)
                    open_start, final_base = [], None
                    continue
                target = int(cur) + TRAVEL_DELTAS[rc_live]
                if tracker.edge is not None and target >= tracker.edge - 5:
                    open_start, final_base = [], None
                    print("Back at live edge.", file=sys.stderr)
                else:
                    target = max(0, target)
                    open_start, final_base = [f"--start={target}"], target
                    print(f"Jumping to {target // 3600}:{(target % 3600) // 60:02d}:{target % 60:02d}...",
                          file=sys.stderr)
            # Remember where playback ended so --replay resumes there.
            try:
                entries = load_history()
                for e in entries:
                    if e.get("url") == url:
                        e["start"] = "" if final_base is None else str(final_base)
                        e["last_played"] = int(time.time())
                save_history(entries)
            except OSError:
                pass
            return rc_live
        except KeyboardInterrupt:
            print("\nStopping...", file=sys.stderr)
            return 130
        finally:
            tracker.halt()
            _drop(staged_cookies)
            try:
                os.unlink(sock)
            except OSError:
                pass
            try:
                os.unlink(travel_conf)
            except OSError:
                pass
            if not args.keep:
                try:
                    os.unlink(rec_path)
                except OSError:
                    pass
            else:
                print(f"Kept (tmpfs): {rec_path}", file=sys.stderr)
    rec_cmd = ["mpv", f"--ytdl-format={choice}", f"--stream-record={rec_path}"]
    rec_cmd += [f"--ytdl-raw-options={o}" for o in raw_opts]
    rec_cmd += std_flags + [f"--watch-later-dir={watch}"]
    if args.low_latency:
        rec_cmd.append("--profile=low-latency")
    if not args.show_recorder:
        rec_cmd += ["--vo=null", "--ao=null"]
    rec_cmd += extra_rec + ["--", args.url]

    play_cmd = ["mpv", f"--speed={args.speed}"] + std_flags + [f"--watch-later-dir={watch}"] + buf_flags + start_opt
    if args.fullscreen:
        play_cmd.append("--fullscreen")
    if args.mute:
        play_cmd.append("--mute=yes")
    play_cmd += extra_player + ["--", rec_path]

    print("+ " + " ".join(shlex.quote(c) for c in rec_cmd), file=sys.stderr)
    print("+ " + " ".join(shlex.quote(c) for c in play_cmd), file=sys.stderr)
    if args.print_cmds:
        _drop(staged_cookies)
        try:
            os.rmdir(watch)
        except OSError:
            pass
        return 0

    rec = subprocess.Popen(rec_cmd, env=env)
    try:
        need = join_threshold(fmts, choice)
        print(f"Waiting for ~{need // 1024}KB before player joins (cleaner start)...", file=sys.stderr)
        if not wait_for_file(rec_path, rec, args.timeout, need):
            if rec.poll() is not None:
                print("ERROR: recorder exited before producing data.", file=sys.stderr)
                return 1
            print("WARNING: recording slower than expected; starting player anyway — "
                  "it follows the growing file.", file=sys.stderr)
        if args.record_only:
            print("Recording... Ctrl-C to stop.", file=sys.stderr)
            rec.wait()
            return 0 if (rec.returncode == 0) else 1
        print("Keys: } = 2x, ]/[ = speed, Backspace = reset, Left/Right = seek", file=sys.stderr)
        subprocess.call(play_cmd, env=env)
        return 0
    except KeyboardInterrupt:
        print("\nStopping...", file=sys.stderr)
        return 130
    finally:
        try:
            if rec.poll() is None:
                rec.terminate()
                try:
                    rec.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    rec.kill()
        except Exception:
            pass
        _drop(staged_cookies)
        if not args.keep:
            try:
                os.unlink(rec_path)
            except OSError:
                pass
        else:
            print(f"Kept (tmpfs): {rec_path}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
