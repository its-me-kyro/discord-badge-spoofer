#!/usr/bin/env python3
"""
Discord Badge Spoofer (modified)

I am against the use of this tool.
I have never used it on any of my accounts and I never will.

This exists only as a technical demonstration and so the original
project does not keep gaining free attention.

Created / modified by @its_me_kyro
https://x.com/its_me_kyro

This tool violates Discord's Terms of Service.
Running it is a good way to get your account suspended.
Profile badges are meaningless.

Requirements:
  - Python 3.10+
  - No third-party packages (stdlib only)

Run:
  python spoofer.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

# paths
ROOT = Path(__file__).resolve().parent
GAMES_FILE = ROOT / "data" / "games.json"
STATE_FILE = ROOT / "science_state.json"

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"

BATCH_SIZE = 50
BATCH_DELAY = 1
AUTH_MAX_AGE = 12 * 3600
DEBUG = False

CLIENT_VERSION = "1.0.9253"
CLIENT_BUILD_NUMBER = 594031
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)


def _user_id_from_token(token: str) -> str:
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""


# PowerShell that generates Discord's executable_fingerprint from PE metadata,
# machine GUID and user id. Used only when the user chooses to set a fingerprint.
_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path -and $ProcessId -gt 0) {
  try { $Path = (Get-Process -Id $ProcessId -ErrorAction Stop).Path } catch { throw "Could not resolve process path." }
}
if (!$Path) { throw "Could not resolve executable path." }

$bytes = [IO.File]::ReadAllBytes($Path)
$fileSize = $bytes.Length
$buf = New-Object byte[] $fileSize
[Array]::Copy($bytes, $buf, $fileSize)

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 60)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$opt = $pe + 24
$magic = [BitConverter]::ToUInt16($buf, $opt)
$isPe32Plus = $magic -eq 0x20B
$optSize = if ($isPe32Plus) { 112 } else { 96 }
$timestamp = [BitConverter]::ToUInt32($buf, $pe + 8)
$sections = [BitConverter]::ToUInt16($buf, $pe + 6)
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    """Run the PowerShell generator and return the base64 executable_fingerprint."""
    if os.name != "nt":
        raise RuntimeError("Fingerprint generation is Windows-only")
    script = Path(tempfile.gettempdir()) / f"disc_fp_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "PowerShell failed")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("No fingerprint returned")
    return out[-1]


class Console:
    """Simple colored console helper."""

    RED = "\x1b[91m"
    ORANGE = "\x1b[38;5;208m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    WHITE = "\x1b[97m"
    GREY = "\x1b[90m"
    RESET = "\x1b[0m"
    RULE = "─" * 48

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        if sys.platform == "win32":
            self._enable_ansi()

    @staticmethod
    def _enable_ansi() -> None:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

    def _stamp(self) -> str:
        return f"{self.GREY}{time.strftime('%H:%M:%S')}{self.RESET}"

    def _line(self, glyph: str, target: str, detail: str, color: str) -> None:
        print(f"  {self._stamp()} {glyph} {self.WHITE}{target}{self.RESET} "
              f"{self.GREY}·{self.RESET} {color}{detail}{self.RESET}")

    def ok(self, target: str, detail: str) -> None:
        self._line(f"{self.GREEN}✓{self.RESET}", target, detail, self.GREEN)

    def sent(self, target: str, detail: str) -> None:
        self._line(f"{self.GREY}·{self.RESET} {self.GREEN}sent{self.RESET}", target, detail, self.GREEN)

    def warn(self, target: str, detail: str) -> None:
        self._line(f"{self.YELLOW}!{self.RESET}", target, detail, self.YELLOW)

    def err(self, target: str, detail: str) -> None:
        self._line(f"{self.RED}✗{self.RESET}", target, detail, self.RED)

    def info(self, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{detail}{self.RESET}")

    def rule(self) -> None:
        print(f"  {self.GREY}{self.RULE}{self.RESET}")

    def clear(self) -> None:
        print("\x1b[2J\x1b[3J\x1b[H", end="")

    def banner(self) -> None:
        self.clear()
        print()
        print(f"  {self.ORANGE}Discord Badge Spoofer{self.RESET}")
        print(f"  {self.GREY}modified by @its_me_kyro{self.RESET}")
        print(f"  {self.GREY}https://x.com/its_me_kyro{self.RESET}")
        print()
        print(f"  {self.RED}I am against using this tool.{self.RESET}")
        print(f"  {self.GREY}Badges are meaningless. This can get you banned.{self.RESET}")
        print()


@dataclass
class State:
    """Persisted local state (token, cookie, fingerprint, stats)."""

    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = None
    total_games_claimed: int = 0
    total_hours_claimed: float = 0.0

    def __post_init__(self) -> None:
        if self.used_games is None:
            self.used_games = []

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore
            filtered = {k: v for k, v in data.items() if k in known}
            state = cls(**{k: filtered.get(k, getattr(cls(), k)) for k in known if k != "used_games"})
            state.used_games = filtered.get("used_games", [])
            return state
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())


def _local_props() -> dict:
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": CLIENT_VERSION,
        "os_version": OS_VERSION,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-GB",
        "has_client_mods": False,
        "browser_user_agent": USER_AGENT,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def build_super_props(launch_signature: str, heartbeat_session: str) -> str:
    try:
        req = urllib.request.Request(
            PROPERTIES_URL,
            method="POST",
            data=b"{}",
            headers={"content-type": "application/json", "user-agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            props = json.loads(response.read().decode("utf-8"))["properties"]
    except Exception:
        props = _local_props()
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _read_analytics_token(auth_token: str, super_props: str) -> str:
    req = urllib.request.Request(ME_URL, headers={
        "authorization": auth_token,
        "user-agent": USER_AGENT,
        "x-super-properties": super_props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Token rejected ({exc.code})") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("No analytics_token in response")
    return token


def ensure_token(state: State, super_props: str) -> None:
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()


@dataclass(frozen=True)
class Session:
    heartbeat_session: str
    launch_signature: str
    super_props: str

    @classmethod
    def new(cls) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(sig, hb))


@dataclass(frozen=True)
class Game:
    id: str
    name: str
    exe: str


def _win_exe(game: dict) -> str:
    for entry in game.get("executables", []):
        if entry.get("os") == "win32" and entry.get("name"):
            return entry["name"]
    return "game.exe"


def _download_games() -> str:
    request = urllib.request.Request(GAMES_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    try:
        GAMES_FILE.parent.mkdir(parents=True, exist_ok=True)
        GAMES_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass
    return raw


def load_games() -> list[Game]:
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8")
    else:
        raw = _download_games()
    data = json.loads(raw)
    games: list[Game] = []
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        games.append(Game(gid, entry.get("name", "Unknown"), _win_exe(entry)))
    return games


def _chunked(items: Sequence[Game], size: int) -> Iterator[Sequence[Game]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


class ScienceClient:
    """Builds and posts launch_game / running_game_heartbeat events."""

    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def build_launch(self, game: Game) -> dict:
        now = int(time.time() * 1000)
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": game.name,
            "game_id": game.id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": game.exe,
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": now,
        }
        if not self.state.fingerprint:
            del props["executable_fingerprint"]
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(
        self,
        game: Game,
        duration_ms: int,
        session_id: str,
        *,
        initial: bool,
        final: bool,
        ts: int | None = None,
    ) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": game.id,
                "game_name": game.name,
                "game_metadata": None,
                "game_executable": game.exe,
                "game_detection_enabled": True,
                "initial_heartbeat": initial,
                "final_heartbeat": final,
                "game_session_id": session_id,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": ts,
            },
        }

    def build_session(self, game: Game, duration_ms: int) -> list[dict]:
        sid = str(uuid.uuid4())
        now = int(time.time() * 1000)
        start = now - duration_ms
        if start < 0:
            start = now
        return [
            self.build_heartbeat(game, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(game),
            self.build_heartbeat(game, duration_ms, sid, initial=False, final=True, ts=now),
        ]

    def post(self, events: Sequence[dict]) -> int:
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB",
            "authorization": self.state.token,
            "content-type": "application/json",
            "cookie": self.state.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_props,
        }
        if DEBUG:
            print("\n" + "=" * 72)
            print(f"POST {SCIENCE_URL} ({len(payload['events'])} events)")
            print("headers:", json.dumps(headers, indent=2))
            print("body:", json.dumps(payload, indent=2))
            print("=" * 72)
        request = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0


class Spoofer:
    def __init__(self, client: ScienceClient, console: Console) -> None:
        self.client = client
        self.console = console

    def run(self, games: Sequence[Game], build_events) -> int:
        total = len(games)
        sent_ok = 0
        for request_no, chunk in enumerate(_chunked(games, BATCH_SIZE), start=1):
            events: list[dict] = []
            for g in chunk:
                events.extend(build_events(g))
            status = self.client.post(events)
            if status == 204:
                sent_ok += len(chunk)
                self.console.sent(f"batch {request_no}", f"{sent_ok}/{total} games")
            elif status in (401, 403):
                self.console.err(f"batch {request_no}",
                                 f"[{status}] auth rejected · refresh auth with a fresh cookie")
                break
            else:
                self.console.warn(f"batch {request_no}", f"[{status}]")
            time.sleep(BATCH_DELAY)
        return sent_ok


class App:
    def __init__(self) -> None:
        self.console = Console()
        self.state = State.load()
        self.session: Session | None = None
        self.client: ScienceClient | None = None
        self.games: list[Game] = []

    def start(self) -> None:
        self.console.banner()
        time.sleep(0.4)

        print()
        self.console.rule()
        self.console.warn("WARNING", "This tool violates Discord's Terms of Service")
        self.console.info("https://discord.com/terms")
        print()
        self.console.info("I (@its_me_kyro) have NEVER used this tool and never will.")
        self.console.info("I am against people using it.")
        self.console.info("Profile badges mean nothing. Even big creators don't care about them.")
        self.console.info("Running this is one of the easiest ways to get your account suspended.")
        self.console.info("If your goal is to get banned, then continue.")
        self.console.rule()
        print()
        answer = input(f"  {self.console.ORANGE}Do you still want to continue? (yes/no):{self.console.RESET} ").strip().lower()
        if answer not in ("yes", "y"):
            self.console.info("Good choice. Aborted.")
            return
        print()
        self.console.warn("risk", "You were warned. Any ban is on you.")
        print()

        # Token
        if not self.state.has_token:
            self._prompt_token()
            if not self.state.has_token:
                self.console.err("token", "required")
                return
        else:
            self.console.ok("token", "loaded from local state")

        # Cookie
        if not self.state.has_cookie:
            self._prompt_cookie()
            if not self.state.has_cookie:
                self.console.err("cookie", "required · use option 3 later to set one")
                return
        else:
            self.console.ok("cookie", "loaded from local state")

        # Games
        try:
            self.games = load_games()
        except Exception as exc:
            self.console.err("games", str(exc))
            return
        self.console.ok("games", f"{len(self.games)} loaded")

        if not self.state.fingerprint:
            self.console.warn("fingerprint", "not set (optional · helps games-played count)")

        # Auth
        self.console.info("validating auth...")
        self._new_session()
        try:
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            self.console.err("token", str(exc))
            return
        self.console.ok("auth", "ready")
        time.sleep(0.4)
        print()
        self.menu()

    def _new_session(self) -> None:
        self.session = Session.new()
        self.client = ScienceClient(self.state, self.session)

    def _prompt_token(self) -> None:
        self.console.info("Paste your Discord account token")
        self.console.info("How to get it: DevTools → Application → Local Storage → discord.com → filter 'token'")
        self.console.info("Copy the value of the key named exactly 'token' (not 'tokens')")
        entered = input(f"  {self.console.GREY}token:{self.console.RESET} ").strip()
        if entered:
            self.state.token = entered
            self.state.save()
            self.console.ok("token", "saved locally (only on your machine)")

    def _prompt_cookie(self) -> None:
        self.console.info("Paste the full cookie header (must include cf_clearance)")
        entered = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
        if entered:
            self.state.cookie = entered
            self.state.save()
            self.console.ok("cookie", "saved locally")

    def _refresh(self) -> None:
        C = self.console
        C.info("Update cookie? (recommended if batches stop working) [y/n]")
        choice = input(f"  {C.GREY}›{C.RESET} ").strip().lower()
        if choice in ("y", "yes"):
            C.info("Paste a fresh full cookie header (must include cf_clearance)")
            entered = input(f"  {C.GREY}cookie:{C.RESET} ").strip()
            if entered:
                self.state.cookie = entered
                C.ok("cookie", "updated")
            else:
                C.info("cookie unchanged")

        C.info("Refreshing analytics token...")
        try:
            self.state.fetched_at = 0
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            C.err("auth", str(exc))
            C.info("Try pasting a fresh cookie and token if this keeps failing")
            return
        self._new_session()
        self.state.save()
        C.ok("auth", "refreshed · ready for new batches")
        time.sleep(1.0)

    def _require_ready(self) -> bool:
        if not self.state.has_cookie:
            self.console.err("cookie", "not set · use option 3 to add one")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state, self.session.super_props)
            except Exception as exc:
                self.console.err("auth", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)

    def claim_games(self) -> None:
        if not self._require_ready():
            return
        C = self.console
        print()
        C.info(f"Loaded {C.GREEN}{len(self.games)}{C.WHITE} games")

        raw_count = input(f"  {C.GREY}How many games? [all]:{C.RESET} ").strip()
        try:
            count = int(raw_count) if raw_count else len(self.games)
        except ValueError:
            C.err("input", "invalid count")
            return
        count = max(1, min(count, len(self.games)))

        raw_hours = input(f"  {C.GREY}Hours per game? [1]:{C.RESET} ").strip()
        try:
            hours = float(raw_hours) if raw_hours else 1.0
        except ValueError:
            C.err("input", "invalid hours")
            return
        if hours <= 0:
            C.err("input", "hours must be positive")
            return

        selected = self._select_games(count)
        if not selected:
            C.err("games", "none selected")
            return

        duration_ms = int(hours * 3600 * 1000)
        total_hours = len(selected) * hours
        print()
        C.info(
            f"Claiming {C.ORANGE}{hours:g}h{C.WHITE} on "
            f"{C.ORANGE}{len(selected)}{C.WHITE} games "
            f"{C.GREY}·{C.WHITE} {total_hours:,.0f}h total"
        )
        C.rule()
        ok = Spoofer(self.client, self.console).run(
            selected,
            lambda g: self.client.build_session(g, duration_ms),
        )
        print()
        C.ok("complete", f"{ok}/{len(selected)} games · {ok * hours:,.0f}h claimed")
        self.state.total_games_claimed += ok
        self.state.total_hours_claimed += ok * hours
        self.state.save()
        C.rule()
        input(f"  {C.ORANGE}›{C.RESET} press enter to continue")

    def add_hours_to_specific(self) -> None:
        if not self._require_ready():
            return
        C = self.console
        print()
        C.info("Search games by name (partial match is fine)")
        query = input(f"  {C.GREY}search:{C.RESET} ").strip().lower()
        if not query:
            C.info("Cancelled")
            return

        matches = [g for g in self.games if query in g.name.lower()]
        if not matches:
            C.err("search", "no games matched")
            return

        shown = matches[:30]
        print()
        C.info(f"Found {len(matches)} match(es) · showing first {len(shown)}")
        C.rule()
        for i, g in enumerate(shown, 1):
            print(f"  {C.ORANGE}{i:2}{C.RESET}  {g.name}")
        if len(matches) > 30:
            C.info(f"... and {len(matches) - 30} more (refine your search)")
        C.rule()

        raw = input(f"  {C.GREY}Select numbers (e.g. 1 3 5) or 'all':{C.RESET} ").strip().lower()
        if not raw:
            C.info("Cancelled")
            return

        if raw == "all":
            selected = shown
        else:
            try:
                idxs = [int(x) for x in raw.replace(",", " ").split()]
                selected = [shown[i - 1] for i in idxs if 1 <= i <= len(shown)]
            except ValueError:
                C.err("input", "invalid selection")
                return

        if not selected:
            C.err("select", "no valid games chosen")
            return

        raw_hours = input(f"  {C.GREY}Hours to add per game? [1]:{C.RESET} ").strip()
        try:
            hours = float(raw_hours) if raw_hours else 1.0
        except ValueError:
            C.err("input", "invalid hours")
            return
        if hours <= 0:
            C.err("input", "hours must be positive")
            return

        duration_ms = int(hours * 3600 * 1000)
        print()
        C.info(
            f"Adding {C.ORANGE}{hours:g}h{C.WHITE} to "
            f"{C.ORANGE}{len(selected)}{C.WHITE} selected game(s)"
        )
        for g in selected:
            C.info(f"  → {g.name}")
        C.rule()

        ok = Spoofer(self.client, self.console).run(
            selected,
            lambda g: self.client.build_session(g, duration_ms),
        )
        print()
        C.ok("complete", f"{ok}/{len(selected)} games · {ok * hours:,.0f}h added")
        self.state.total_games_claimed += ok
        self.state.total_hours_claimed += ok * hours
        self.state.save()
        C.rule()
        input(f"  {C.ORANGE}›{C.RESET} press enter to continue")

    def _select_games(self, count: int) -> list[Game]:
        available_ids = {g.id for g in self.games}
        unused_ids = [g.id for g in self.games if g.id not in self.state.used_games]
        used_ids = [gid for gid in self.state.used_games if gid in available_ids]

        if len(unused_ids) >= count:
            selected_ids = unused_ids[:count]
        else:
            selected_ids = unused_ids
            if used_ids:
                remaining = count - len(selected_ids)
                rotated = used_ids[remaining:] + used_ids[:remaining]
                selected_ids.extend(rotated[:remaining])

        self.state.used_games = [gid for gid in self.state.used_games if gid not in selected_ids] + selected_ids
        id_map = {g.id: g for g in self.games}
        return [id_map[gid] for gid in selected_ids if gid in id_map]

    def set_fingerprint(self) -> None:
        C = self.console
        uid = _user_id_from_token(self.state.token)
        if not uid:
            C.err("fingerprint", "could not parse user id from token · set a valid token first")
            time.sleep(1.5)
            return
        if os.name != "nt":
            C.err("fingerprint", "Windows-only feature")
            time.sleep(1.5)
            return
        C.info("Generate an executable_fingerprint tied to this account + machine")
        C.info(f"Account: {C.ORANGE}{uid}{C.RESET}")
        C.info("Provide a game .exe path or a running process PID")
        entered = input(f"  {C.GREY}exe path or pid:{C.RESET} ").strip().strip('"')
        if not entered:
            C.info("Cancelled")
            time.sleep(1)
            return
        pid = int(entered) if entered.isdigit() else 0
        path = "" if pid else entered
        if path and not Path(path).exists():
            C.err("fingerprint", f"file not found: {path}")
            time.sleep(1.5)
            return
        C.info("Generating...")
        try:
            fp = generate_fingerprint(uid, path=path, pid=pid)
        except Exception as exc:
            C.err("fingerprint", str(exc))
            time.sleep(2)
            return
        self.state.fingerprint = fp
        self.state.save()
        C.ok("fingerprint", f"set ({len(fp)} chars) · saved to {STATE_FILE.name}")
        time.sleep(1.5)

    def menu(self) -> None:
        C = self.console
        while True:
            C.clear()
            C.banner()
            print()
            C.info(f"Loaded {C.ORANGE}{len(self.games)}{C.WHITE} games")
            C.info(
                f"Session stats: {C.ORANGE}{self.state.total_games_claimed}{C.WHITE} games · "
                f"{C.ORANGE}{self.state.total_hours_claimed:,.0f}h{C.WHITE} claimed"
            )
            C.rule()
            C.info(f"{C.ORANGE}1{C.RESET}  Claim playtime (batch / random rotation)")
            C.info(f"{C.ORANGE}2{C.RESET}  Add hours to specific games (search by name)")
            C.info(f"{C.ORANGE}3{C.RESET}  Refresh auth / update cookie")
            C.info(f"{C.ORANGE}4{C.RESET}  Set fingerprint (optional, Windows)")
            C.info(f"{C.ORANGE}5{C.RESET}  Exit")
            C.rule()
            choice = input(f"  {C.ORANGE}›{C.RESET} ").strip()
            print()
            if choice == "1":
                self.claim_games()
            elif choice == "2":
                self.add_hours_to_specific()
            elif choice == "3":
                self._refresh()
            elif choice == "4":
                self.set_fingerprint()
            elif choice in ("5", "q", "quit", "exit", ""):
                break
            else:
                C.warn("input", "invalid option")
                time.sleep(0.8)


def main() -> None:
    try:
        App().start()
    except KeyboardInterrupt:
        print()
        Console().warn("exit", "interrupted")


if __name__ == "__main__":
    main()