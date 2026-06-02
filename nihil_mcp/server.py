"""Nihil MCP Server — expose Nihil container operations to LLM agents."""

import io
import json
import re
import tarfile
import threading
import uuid
from pathlib import Path
from typing import Optional

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

# Session state is stored inside the container at this path
_SESSION_BASE = "/tmp/.nihil_mcp"

# In-memory session registry: session_id -> container_name
_sessions: dict[str, str] = {}
_sessions_lock = threading.Lock()

# System env vars that should not be persisted across session commands
_ENV_BLACKLIST_RE = re.compile(
    r"^typeset -x ("
    r"HOME|PATH|TERM|SHELL|SHLVL|OLDPWD|PWD|_|LOGNAME|USER|MAIL|"
    r"LANG|LC_ALL|LC_[A-Z]+|LS_COLORS|COLORTERM|TMPDIR|TEMP|TMP|"
    r"HISTFILE|HISTSIZE|SAVEHIST|ZDOTDIR|ZSH|NVM_DIR|PYENV_ROOT|"
    r"GOPATH|GOBIN|JAVA_HOME|NIHIL_BUILD|NIHIL_AUDIT"
    r")="
)

# ANSI escape codes (colors, cursor moves, etc.)
_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Session exec script template — uses __PLACEHOLDER__ to avoid .format() issues
_SESSION_SCRIPT = """\
_SD="__SESSION_DIR__"
mkdir -p "$_SD"
[[ -f "$_SD/cwd" ]] && cd "$(< "$_SD/cwd")" 2>/dev/null || cd /workspace
[[ -f "$_SD/env" ]] && source "$_SD/env" 2>/dev/null || true
__COMMAND__
_RC=$?
pwd > "$_SD/cwd"
typeset -xp 2>/dev/null | grep -vE \
  '^typeset -x (HOME|PATH|TERM|SHELL|SHLVL|OLDPWD|PWD|_|LOGNAME|USER|MAIL|LANG|LC_[A-Z]*|LS_COLORS|COLORTERM|TMPDIR|TEMP|TMP|HISTFILE|HISTSIZE|SAVEHIST|ZDOTDIR|ZSH|NVM_DIR|PYENV_ROOT|GOPATH|GOBIN|JAVA_HOME|NIHIL_BUILD|NIHIL_AUDIT)=' \
  > "$_SD/env" 2>/dev/null || true
exit $_RC
"""


def _clean_output(text: str) -> str:
    """Strip ANSI codes, normalize line endings, collapse blank lines."""
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _run(container, cmd: str, workdir: str = "/workspace") -> tuple[int, str]:
    """Execute a zsh command in a container and return (exit_code, cleaned_output)."""
    exit_code, output = container.exec_run(
        cmd=["/usr/bin/zsh", "-c", cmd],
        workdir=workdir,
        demux=False,
        stream=False,
        socket=False,
        environment={"TERM": "dumb", "HOME": "/root"},
    )
    raw = output.decode("utf-8", errors="replace") if output else ""
    cleaned = _clean_output(raw)
    truncated = len(cleaned) > EXEC_OUTPUT_LIMIT
    if truncated:
        cleaned = cleaned[:EXEC_OUTPUT_LIMIT] + f"\n... [truncated at {EXEC_OUTPUT_LIMIT} chars]"
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
        "If an image is not installed locally, use pull_image first."
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

    exit_code, cleaned = _run(container, command, workdir=workdir)
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

    # Init session dir inside the container
    _run(container, f"mkdir -p {session_dir}", workdir="/root")

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

    exit_code, cleaned = _run(container, script, workdir="/root")
    return {
        "exit_code": exit_code,
        "output": cleaned,
        "command": command,
        "session_id": session_id,
        "container": container_name,
    }


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
