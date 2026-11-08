"""Nihil MCP Server — expose Nihil container operations to LLM agents."""

import io
import json
import re
import socket
import struct
import tarfile
import threading
import uuid
import zlib
from base64 import b64encode
from pathlib import Path
from typing import Optional
from urllib.request import urlopen

import docker
from mcp.server.fastmcp import FastMCP

NIHIL_REGISTRY = "thenullpigeons"
AVAILABLE_IMAGES = {
    "full":     "ghcr.io/thenullpigeons/full:latest",
    "ad":       "ghcr.io/thenullpigeons/ad:latest",
    "web":      "ghcr.io/thenullpigeons/web:latest",
    "blueteam": "ghcr.io/thenullpigeons/blueteam:latest",
}
EXEC_TIMEOUT = 60
EXEC_OUTPUT_LIMIT = 32_000
_BROWSER_UI_HOST = "127.0.0.1"
_RFB_PORT = 5901

# Session state is stored inside the container at this path
_SESSION_BASE = "/tmp/.nihil_mcp"

# In-memory session registry: session_id -> container_name
_sessions: dict[str, str] = {}
_sessions_lock = threading.Lock()

# ANSI escape codes (colors, cursor moves, etc.)
_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Per-invocation volatile exports to drop from the persisted session env.
# zsh re-derives these on every `zsh -c`, so carrying them over is noise
# (or actively wrong, e.g. a stale PWD). Everything else is handled by the
# baseline diff below, which is why this stays a tiny list and not a blacklist.
_VOLATILE_ENV = "_|PWD|OLDPWD|SHLVL|RANDOM|SECONDS|LINENO|COLUMNS|LINES|EPOCHSECONDS|EPOCHREALTIME"

# Shell snapshot taken at create_session: the container's pristine exported env,
# sorted so the per-command script can diff against it with `comm`.
_BASELINE_SCRIPT = 'mkdir -p "__SESSION_DIR__" && typeset -xp 2>/dev/null | sort > "__SESSION_DIR__/baseline"'

# Session exec script template — uses __PLACEHOLDER__ to avoid .format() issues.
# Env persistence is an allowlist-by-diff: we keep only exports that are new or
# changed relative to the baseline (i.e. what the user/tools exported, like
# TARGET=...), minus the volatile set. This is robust against zsh's flagged
# exports (`export -T PATH ...`, `export -i10 SHLVL=1`) and against system vars
# that a static blacklist would never anticipate.
_SESSION_SCRIPT = """\
_SD="__SESSION_DIR__"
mkdir -p "$_SD"
[[ -f "$_SD/cwd" ]] && cd "$(< "$_SD/cwd")" 2>/dev/null || cd /workspace
[[ -f "$_SD/env" ]] && source "$_SD/env" 2>/dev/null || true
__COMMAND__
_RC=$?
pwd > "$_SD/cwd"
if [[ -f "$_SD/baseline" ]]; then
  typeset -xp 2>/dev/null | sort | comm -13 "$_SD/baseline" - | grep -vE '^export (-[^ ]+ )?(__VOLATILE__)[=(]' > "$_SD/env" 2>/dev/null || true
fi
exit $_RC
""".replace("__VOLATILE__", _VOLATILE_ENV)


def _clean_output(text: str) -> str:
    """Strip ANSI codes, normalize line endings, collapse blank lines."""
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _run(
    container,
    cmd: str,
    workdir: str = "/workspace",
    timeout: Optional[int] = None,
) -> tuple[int, str]:
    """Execute a zsh command in a container and return (exit_code, cleaned_output).

    When *timeout* is set, the command is wrapped with coreutils ``timeout`` so a
    hanging command (an interactive prompt, a scan that never returns) is killed
    container-side instead of blocking the MCP server indefinitely. ``timeout``
    sends SIGTERM after *timeout* seconds, then SIGKILL 5s later; a killed
    command surfaces exit code 124.
    """
    if timeout is not None:
        exec_cmd = ["/usr/bin/timeout", "-k", "5", str(timeout), "/usr/bin/zsh", "-c", cmd]
    else:
        exec_cmd = ["/usr/bin/zsh", "-c", cmd]
    exit_code, output = container.exec_run(
        cmd=exec_cmd,
        workdir=workdir,
        demux=False,
        stream=False,
        socket=False,
        environment={"TERM": "dumb", "HOME": "/root"},
    )
    raw = output.decode("utf-8", errors="replace") if output else ""
    cleaned = _clean_output(raw)
    if len(cleaned) > EXEC_OUTPUT_LIMIT:
        cleaned = cleaned[:EXEC_OUTPUT_LIMIT] + f"\n... [truncated at {EXEC_OUTPUT_LIMIT} chars]"
    if exit_code == 124:
        cleaned += f"\n... [command timed out after {timeout}s and was killed]"
    return exit_code, cleaned


mcp = FastMCP(
    name="nihil-mcp",
    instructions=(
        "You have access to Nihil pentest containers. "
        "Use these tools to manage containers and execute security tools inside them. "
        "Always work inside a container — never on the host system. "
        "Containers are isolated pre-loaded pentest environments. "
        "Image variants: full (all tools), ad (Active Directory), "
        "web (web hacking), blueteam (DFIR, threat hunting, SOC). "
        "For multi-step operations use create_session + exec_in_session to preserve "
        "working directory and environment variables across commands. "
        "Use exec_command for one-off commands that need no state. "
        "If an image is not installed locally, use pull_image first. "
        "For visual control of a container that has Browser UI enabled, use "
        "browser_ui_screenshot to inspect the desktop, then browser_ui_click and "
        "browser_ui_type to interact; coordinates use the 1280x720 desktop."
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_client() -> docker.DockerClient:
    try:
        client = docker.from_env()
        client.ping()
        return client
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Cannot connect to Docker: {e}")


def _is_nihil_container(container) -> bool:
    image = container.attrs.get("Config", {}).get("Image", "")
    return NIHIL_REGISTRY in image or image.startswith("nihil/")


def _get_nihil_container(client, name: str):
    try:
        container = client.containers.get(name)
    except docker.errors.NotFound:
        raise ValueError(f"Container '{name}' not found")
    if not _is_nihil_container(container):
        raise ValueError(f"'{name}' is not a Nihil container")
    return container


def _container_status(container) -> dict:
    attrs = container.attrs
    image = attrs.get("Config", {}).get("Image", "")
    image_short = image.split("/")[-1] if "/" in image else image
    env_list = attrs.get("Config", {}).get("Env") or []
    env = dict(kv.split("=", 1) for kv in env_list if "=" in kv)
    mounts = [
        {"host": m.get("Source", ""), "container": m.get("Destination", "")}
        for m in attrs.get("Mounts", [])
        if m.get("Source")
    ]
    return {
        "name": container.name,
        "status": container.status,
        "image": image_short,
        "privileged": attrs.get("HostConfig", {}).get("Privileged", False),
        "vpn": env.get("NIHIL_VPN", "0") == "1",
        "browser_ui": env.get("NIHIL_BROWSER_UI", "0") == "1",
        "browser_ui_port": env.get("NIHIL_BROWSER_UI_PORT"),
        "mounts": mounts,
    }


def _browser_ui(container_name: str):
    """Return the authenticated RFB endpoint for the container's Browser UI."""
    client = _get_client()
    container = _get_nihil_container(client, container_name)
    if container.status != "running":
        raise ValueError(f"Container '{container_name}' is not running (status: {container.status})")
    env = dict(kv.split("=", 1) for kv in container.attrs.get("Config", {}).get("Env", []) if "=" in kv)
    if env.get("NIHIL_BROWSER_UI") != "1":
        raise ValueError(f"Browser UI is not enabled for container '{container_name}'")
    port = int(env.get("NIHIL_BROWSER_UI_PORT", "6901"))
    url = f"http://{_BROWSER_UI_HOST}:{port}/"
    try:
        with urlopen(url, timeout=3) as response:
            if response.status != 200:
                raise RuntimeError(f"Browser UI returned HTTP {response.status}")
    except Exception as e:
        raise RuntimeError(f"Browser UI on '{container_name}' is not reachable at {url}: {e}") from e
    if not env.get("NIHIL_BROWSER_UI_PASSWORD"):
        raise RuntimeError("Browser UI password is missing from the container configuration")
    return env["NIHIL_BROWSER_UI_PASSWORD"]


class _RFB:
    """Small RFB 3.8 client for authenticated screenshots and input events."""

    def __init__(self, password: str):
        self.sock = socket.create_connection((_BROWSER_UI_HOST, _RFB_PORT), timeout=5)
        self.sock.settimeout(10)
        self._read(12)
        self.sock.sendall(b"RFB 003.008\n")
        count = self._read(1)[0]
        security_types = self._read(count)
        if 2 not in security_types:
            raise RuntimeError("VNC server does not offer password authentication")
        self.sock.sendall(b"\x02")
        challenge = self._read(16)
        key = password.encode()[:8].ljust(8, b"\0")
        key = bytes(int(f"{byte:08b}"[::-1], 2) for byte in key)
        try:
            from Crypto.Cipher import DES
            response = DES.new(key, DES.MODE_ECB).encrypt(challenge)
        except ImportError as e:
            raise RuntimeError("VNC authentication requires pycryptodome") from e
        self.sock.sendall(response)
        if struct.unpack(">I", self._read(4))[0] != 0:
            raise RuntimeError("VNC authentication failed")
        self.sock.sendall(b"\x01")  # shared session
        server_init = self._read(24)
        self.width, self.height = struct.unpack(">HH", server_init[:4])
        name_len = struct.unpack(">I", server_init[20:24])[0]
        self._read(name_len)
        # Request 32-bit little-endian RGBX, then raw rectangles.
        pixel_format = b"\x20\x18\x00\x01" + struct.pack(">HHH", 255, 255, 255) + b"\x10\x08\x00\x00\x00\x00"
        self.sock.sendall(b"\x00" + b"\x00" * 3 + pixel_format)
        self.sock.sendall(b"\x02\x00\x00\x01\x00\x00\x00\x00")

    def _read(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError("VNC connection closed unexpectedly")
            data.extend(chunk)
        return bytes(data)

    def screenshot(self) -> bytes:
        self.sock.sendall(b"\x03\x00" + struct.pack(">HHHH", 0, 0, self.width, self.height))
        pixels = bytearray(self.width * self.height * 4)
        while True:
            header = self._read(4)
            if header[0] != 0:
                raise RuntimeError(f"Unsupported VNC server message: {header[0]}")
            rect_count = struct.unpack(">H", header[2:])[0]
            for _ in range(rect_count):
                x, y, width, height, encoding = struct.unpack(">HHHHi", self._read(12))
                if encoding == -223:
                    self.width, self.height = width, height
                    pixels = bytearray(width * height * 4)
                elif encoding == 0:
                    for row in range(height):
                        raw = bytearray(self._read(width * 4))
                        for i in range(0, len(raw), 4):
                            raw[i], raw[i + 2] = raw[i + 2], raw[i]
                        pixels[((y + row) * self.width + x) * 4:((y + row) * self.width + x + width) * 4] = raw
                elif encoding == 1:
                    src_x, src_y = struct.unpack(">HH", self._read(4))
                    row_bytes = width * 4
                    for row in range(height):
                        src = ((src_y + row) * self.width + src_x) * 4
                        dst = ((y + row) * self.width + x) * 4
                        pixels[dst:dst + row_bytes] = pixels[src:src + row_bytes]
                else:
                    raise RuntimeError(f"Unsupported VNC encoding: {encoding}")
            if rect_count:
                break
        # Emit a PNG using stdlib zlib.
        rows = bytearray()
        for y in range(self.height):
            rows.append(0)
            for x in range(self.width):
                i = (y * self.width + x) * 4
                rows.extend((pixels[i], pixels[i + 1], pixels[i + 2]))
        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
        return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.width, self.height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")

    def pointer(self, x: int, y: int, mask: int = 0) -> None:
        self.sock.sendall(b"\x05" + bytes([mask]) + struct.pack(">HH", x, y))

    def key(self, keysym: int, down: bool) -> None:
        self.sock.sendall(b"\x04" + bytes([int(down)]) + b"\0\0" + struct.pack(">I", keysym))

    def close(self) -> None:
        self.sock.close()


# ---------------------------------------------------------------------------
# Container management
# ---------------------------------------------------------------------------

@mcp.tool()
def list_containers() -> list[dict]:
    """List all Nihil pentest containers with their status (running, exited, etc.)."""
    client = _get_client()
    containers = [c for c in client.containers.list(all=True) if _is_nihil_container(c)]
    return [_container_status(c) for c in containers]


@mcp.tool()
def get_container_info(name: str) -> dict:
    """Get detailed information about a specific Nihil container.

    Args:
        name: Container name
    """
    client = _get_client()
    return _container_status(_get_nihil_container(client, name))


@mcp.tool()
def start_container(
    name: str,
    image: str = "full",
    workspace: Optional[str] = None,
    network: str = "host",
    privileged: bool = False,
) -> dict:
    """Create and start a new Nihil pentest container.

    Args:
        name: Container name (e.g. "pentest-htb")
        image: Image variant — full, ad, web, blueteam (default: full)
        workspace: Host path to mount as /workspace. Auto-created at
                   ~/.nihil/workspaces/<name> if not specified.
        network: Network mode — host, bridge, none (default: host)
        privileged: Privileged mode (needed for nmap raw sockets, etc.)
    """
    if image not in AVAILABLE_IMAGES:
        raise ValueError(f"Unknown image '{image}'. Choose from: {', '.join(AVAILABLE_IMAGES)}")
    if network not in ("host", "bridge", "none"):
        raise ValueError(f"Unknown network mode '{network}'. Choose from: host, bridge, none")

    client = _get_client()

    try:
        client.containers.get(name)
        raise ValueError(f"Container '{name}' already exists")
    except docker.errors.NotFound:
        pass

    image_tag = AVAILABLE_IMAGES[image]
    try:
        client.images.get(image_tag)
    except docker.errors.ImageNotFound:
        raise RuntimeError(
            f"Image '{image_tag}' not found locally. Pull it first with pull_image('{image}')"
        )

    if workspace is None:
        default_ws = Path.home() / ".nihil" / "workspaces" / name
        default_ws.mkdir(parents=True, exist_ok=True)
        workspace = str(default_ws)

    ws_path = Path(workspace).expanduser().resolve()
    if not ws_path.exists():
        raise ValueError(f"Workspace path does not exist: {workspace}")

    container = client.containers.create(
        name=name,
        image=image_tag,
        detach=True,
        tty=True,
        stdin_open=True,
        network_mode=network,
        privileged=privileged,
        volumes={str(ws_path): {"bind": "/workspace", "mode": "rw"}},
    )
    container.start()
    container.reload()
    return {
        "created": True,
        "name": container.name,
        "status": container.status,
        "image": image,
        "workspace": workspace,
        "privileged": privileged,
    }


@mcp.tool()
def stop_container(name: str) -> dict:
    """Stop a running Nihil container.

    Args:
        name: Container name
    """
    client = _get_client()
    _get_nihil_container(client, name).stop()
    return {"stopped": True, "name": name}


@mcp.tool()
def remove_container(name: str, force: bool = False) -> dict:
    """Remove a Nihil container (must be stopped unless force=True).

    Args:
        name: Container name
        force: Force removal even if running (default: False)
    """
    client = _get_client()
    _get_nihil_container(client, name).remove(force=force)
    with _sessions_lock:
        dead = [sid for sid, cname in _sessions.items() if cname == name]
        for sid in dead:
            del _sessions[sid]
    return {"removed": True, "name": name}


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

@mcp.tool()
def exec_command(
    name: str,
    command: str,
    workdir: str = "/workspace",
    timeout: int = EXEC_TIMEOUT,
) -> dict:
    """Execute a one-off command in a running Nihil container.

    Output is cleaned (ANSI codes stripped, blank lines collapsed) and
    capped at 32 000 characters. Use exec_in_session instead when you need
    to preserve working directory or environment variables across calls.

    Args:
        name: Container name
        command: Shell command to run (executed in zsh)
        workdir: Working directory inside the container (default: /workspace)
        timeout: Timeout in seconds (default: 60, max: 300)
    """
    if timeout > 300:
        timeout = 300

    client = _get_client()
    container = _get_nihil_container(client, name)
    if container.status != "running":
        raise ValueError(f"Container '{name}' is not running (status: {container.status})")

    exit_code, cleaned = _run(container, command, workdir=workdir, timeout=timeout)
    return {
        "exit_code": exit_code,
        "output": cleaned,
        "command": command,
        "container": name,
    }


# ---------------------------------------------------------------------------
# Sessions — persistent shell state across calls
# ---------------------------------------------------------------------------

@mcp.tool()
def create_session(name: str) -> dict:
    """Create a persistent shell session inside a Nihil container.

    A session preserves working directory and exported environment variables
    across calls. Use exec_in_session with the returned session_id instead of
    exec_command when running multi-step operations (e.g. set TARGET=..., then
    run nmap, then run gobuster — all sharing the same env).

    Args:
        name: Container name (must be running)
    """
    client = _get_client()
    container = _get_nihil_container(client, name)
    if container.status != "running":
        raise ValueError(f"Container '{name}' is not running (status: {container.status})")

    session_id = uuid.uuid4().hex[:12]
    session_dir = f"{_SESSION_BASE}/{session_id}"

    # Init session dir and snapshot the pristine env as the diff baseline
    _run(container, _BASELINE_SCRIPT.replace("__SESSION_DIR__", session_dir), workdir="/root")

    with _sessions_lock:
        _sessions[session_id] = name

    return {
        "session_id": session_id,
        "container": name,
        "hint": "Use exec_in_session(session_id, command) to run commands in this session.",
    }


@mcp.tool()
def exec_in_session(session_id: str, command: str, timeout: int = EXEC_TIMEOUT) -> dict:
    """Execute a command in a persistent session, preserving cwd and env vars.

    The session restores the working directory and any variables exported in
    previous calls (e.g. export TARGET=10.10.10.1), then runs your command,
    then saves the new state.

    Args:
        session_id: Session ID returned by create_session
        command: Shell command to run
        timeout: Timeout in seconds (default: 60, max: 300)
    """
    if timeout > 300:
        timeout = 300

    with _sessions_lock:
        container_name = _sessions.get(session_id)
    if container_name is None:
        raise ValueError(f"Session '{session_id}' not found. Create one with create_session.")

    client = _get_client()
    container = _get_nihil_container(client, container_name)
    if container.status != "running":
        raise ValueError(f"Container '{container_name}' is not running.")

    session_dir = f"{_SESSION_BASE}/{session_id}"
    script = (
        _SESSION_SCRIPT
        .replace("__SESSION_DIR__", session_dir)
        .replace("__COMMAND__", command)
    )

    exit_code, cleaned = _run(container, script, workdir="/root", timeout=timeout)
    return {
        "exit_code": exit_code,
        "output": cleaned,
        "command": command,
        "session_id": session_id,
        "container": container_name,
    }


# ---------------------------------------------------------------------------
# Browser UI — visual interaction with noVNC desktops
# ---------------------------------------------------------------------------

@mcp.tool()
def browser_ui_screenshot(name: str) -> dict:
    """Capture the visible desktop in a running container with Browser UI enabled.

    Returns a base64 PNG screenshot for visual inspection.
    Args:
        name: Nihil container name
    """
    password = _browser_ui(name)
    rfb = _RFB(password)
    try:
        return {"container": name, "image": b64encode(rfb.screenshot()).decode("ascii"), "mime_type": "image/png", "width": rfb.width, "height": rfb.height}
    finally:
        rfb.close()


@mcp.tool()
def browser_ui_click(name: str, x: int, y: int, button: str = "left") -> dict:
    """Click a point on the remote desktop (coordinates use screenshot pixels).

    Args:
        name: Nihil container name
        x: Horizontal coordinate, 0–1279
        y: Vertical coordinate, 0–719
        button: Mouse button: left, middle, or right
    """
    if button not in ("left", "middle", "right"):
        raise ValueError("button must be left, middle, or right")
    password = _browser_ui(name)
    rfb = _RFB(password)
    try:
        if not (0 <= x < rfb.width and 0 <= y < rfb.height):
            raise ValueError(f"Coordinates must be within the {rfb.width}x{rfb.height} desktop")
        mask = {"left": 1, "middle": 2, "right": 4}[button]
        rfb.pointer(x, y, mask)
        rfb.pointer(x, y, 0)
        return {"clicked": True, "container": name, "x": x, "y": y, "button": button}
    finally:
        rfb.close()


@mcp.tool()
def browser_ui_type(name: str, text: str) -> dict:
    """Type literal text into the currently focused control in the Browser UI.

    Args:
        name: Nihil container name
        text: Text to type (maximum 2000 characters)
    """
    if len(text) > 2000:
        raise ValueError("text must be at most 2000 characters")
    password = _browser_ui(name)
    rfb = _RFB(password)
    try:
        for char in text:
            keysym = ord(char)
            if char == "\n":
                keysym = 0xff0d
            elif char == "\t":
                keysym = 0xff09
            elif char == "\b":
                keysym = 0xff08
            if keysym > 0xffff:
                keysym = 0x01000000 | keysym
            rfb.key(keysym, True)
            rfb.key(keysym, False)
        return {"typed": len(text), "container": name}
    finally:
        rfb.close()


@mcp.tool()
def list_sessions() -> list[dict]:
    """List all active persistent sessions and which container they belong to."""
    with _sessions_lock:
        return [
            {"session_id": sid, "container": cname}
            for sid, cname in _sessions.items()
        ]


@mcp.tool()
def close_session(session_id: str) -> dict:
    """Close a persistent session and clean up its state inside the container.

    Args:
        session_id: Session ID to close
    """
    with _sessions_lock:
        container_name = _sessions.pop(session_id, None)
    if container_name is None:
        raise ValueError(f"Session '{session_id}' not found.")

    try:
        client = _get_client()
        container = client.containers.get(container_name)
        if container.status == "running":
            session_dir = f"{_SESSION_BASE}/{session_id}"
            _run(container, f"rm -rf {session_dir}", workdir="/root")
    except Exception:
        pass

    return {"closed": True, "session_id": session_id, "container": container_name}


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

@mcp.tool()
def list_images() -> list[dict]:
    """List Nihil image variants and whether they are installed locally."""
    client = _get_client()
    result = []
    for variant, tag in AVAILABLE_IMAGES.items():
        installed = False
        size_mb = None
        try:
            img = client.images.get(tag)
            installed = True
            size_mb = round(img.attrs.get("Size", 0) / 1024 / 1024)
        except docker.errors.ImageNotFound:
            pass
        result.append({"variant": variant, "tag": tag, "installed": installed, "size_mb": size_mb})
    return result


@mcp.tool()
def pull_image(image: str) -> dict:
    """Pull a Nihil image from the registry (ghcr.io/thenullpigeons).

    Use before start_container if the image is not installed locally.
    This may take several minutes depending on image size.

    Args:
        image: Image variant — full, ad, web, blueteam
    """
    if image not in AVAILABLE_IMAGES:
        raise ValueError(f"Unknown image '{image}'. Choose from: {', '.join(AVAILABLE_IMAGES)}")

    client = _get_client()
    tag = AVAILABLE_IMAGES[image]
    client.images.pull(tag)
    img = client.images.get(tag)
    return {
        "pulled": True,
        "variant": image,
        "tag": tag,
        "size_mb": round(img.attrs.get("Size", 0) / 1024 / 1024),
    }


@mcp.tool()
def list_tools(image: str = "full", category: Optional[str] = None) -> dict:
    """List pentest tools available in a Nihil image.

    Reads the tools.json manifest embedded in the image.

    Args:
        image: Image variant — full, ad, web, blueteam (default: full)
        category: Filter by category (e.g. "network", "web", "mod_hunt", "mod_dfir")
    """
    if image not in AVAILABLE_IMAGES:
        raise ValueError(f"Unknown image '{image}'. Choose from: {', '.join(AVAILABLE_IMAGES)}")

    client = _get_client()
    tag = AVAILABLE_IMAGES[image]
    try:
        client.images.get(tag)
    except docker.errors.ImageNotFound:
        raise RuntimeError(f"Image '{tag}' not installed. Run: pull_image('{image}')")

    try:
        tmp = client.containers.create(image=tag, command="true")
        try:
            bits, _ = tmp.get_archive("/opt/nihil/tools.json")
            buf = io.BytesIO(b"".join(bits))
            with tarfile.open(fileobj=buf) as tar:
                content = tar.extractfile(tar.getmember("tools.json")).read()
            manifest = json.loads(content)
        finally:
            tmp.remove(force=True)
    except Exception as e:
        return {"error": f"Could not read tools manifest: {e}", "image": image}

    if category:
        cat_lower = category.lower()
        manifest = {k: v for k, v in manifest.items() if cat_lower in k.lower()}
        return {"image": image, "category_filter": category, "tools": manifest}

    return {"image": image, "tools": manifest}


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
