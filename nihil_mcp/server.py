"""Nihil MCP Server — expose Nihil container operations to LLM agents."""

import sys
from typing import Optional

import docker
from mcp.server.fastmcp import FastMCP

NIHIL_REGISTRY = "thenullpigeons"
AVAILABLE_IMAGES = {
    "full": "ghcr.io/thenullpigeons/full:latest",
    "ad": "ghcr.io/thenullpigeons/ad:latest",
    "web": "ghcr.io/thenullpigeons/web:latest",
    "ctf": "ghcr.io/thenullpigeons/ctf:latest",
}
EXEC_TIMEOUT = 60
EXEC_OUTPUT_LIMIT = 32_000

mcp = FastMCP(
    name="nihil-mcp",
    instructions=(
        "You have access to Nihil pentest containers. "
        "Use these tools to manage containers and execute security tools inside them. "
        "Always work inside a container — never on the host system. "
        "Containers are isolated environments pre-loaded with pentest tools."
    ),
)


def _get_client() -> docker.DockerClient:
    try:
        client = docker.from_env()
        client.ping()
        return client
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Cannot connect to Docker: {e}")


def _is_nihil_container(container) -> bool:
    image = container.attrs.get("Config", {}).get("Image", "")
    return NIHIL_REGISTRY in image


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
        "vpn": env.get("NIHIL_VPN", "0") == "1",
        "browser_ui": env.get("NIHIL_BROWSER_UI", "0") == "1",
        "browser_ui_port": env.get("NIHIL_BROWSER_UI_PORT"),
        "mounts": mounts,
    }


@mcp.tool()
def list_containers() -> list[dict]:
    """List all Nihil pentest containers with their status (running, exited, etc.)."""
    client = _get_client()
    containers = [c for c in client.containers.list(all=True) if _is_nihil_container(c)]
    if not containers:
        return []
    return [_container_status(c) for c in containers]


@mcp.tool()
def get_container_info(name: str) -> dict:
    """Get detailed information about a specific Nihil container.

    Args:
        name: Container name
    """
    client = _get_client()
    try:
        container = client.containers.get(name)
    except docker.errors.NotFound:
        raise ValueError(f"Container '{name}' not found")
    if not _is_nihil_container(container):
        raise ValueError(f"'{name}' is not a Nihil container")
    return _container_status(container)


@mcp.tool()
def start_container(
    name: str,
    image: str = "full",
    workspace: Optional[str] = None,
    network: str = "host",
) -> dict:
    """Create and start a new Nihil pentest container.

    Args:
        name: Container name (e.g. "pentest-htb")
        image: Image variant — full, ad, web, ctf (default: full)
        workspace: Host path to mount as /workspace inside the container (optional)
        network: Network mode — host, bridge, none (default: host)
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
            f"Image '{image_tag}' not found locally. Pull it first with: nihil install {image}"
        )

    volumes = {}
    if workspace:
        from pathlib import Path
        ws_path = Path(workspace).expanduser().resolve()
        if not ws_path.exists():
            raise ValueError(f"Workspace path does not exist: {workspace}")
        volumes[str(ws_path)] = {"bind": "/workspace", "mode": "rw"}

    config: dict = {
        "name": name,
        "image": image_tag,
        "detach": True,
        "tty": True,
        "stdin_open": True,
        "network_mode": network,
        "volumes": volumes,
    }

    container = client.containers.create(**config)
    container.start()
    container.reload()
    return {
        "created": True,
        "name": container.name,
        "status": container.status,
        "image": image,
    }


@mcp.tool()
def stop_container(name: str) -> dict:
    """Stop a running Nihil container.

    Args:
        name: Container name
    """
    client = _get_client()
    try:
        container = client.containers.get(name)
    except docker.errors.NotFound:
        raise ValueError(f"Container '{name}' not found")
    if not _is_nihil_container(container):
        raise ValueError(f"'{name}' is not a Nihil container")
    container.stop()
    return {"stopped": True, "name": name}


@mcp.tool()
def exec_command(
    name: str,
    command: str,
    workdir: str = "/workspace",
    timeout: int = EXEC_TIMEOUT,
) -> dict:
    """Execute a command inside a running Nihil container and return its output.

    Use this to run pentest tools, enumerate targets, or inspect results.
    The container must be running. Output is capped at 32 000 characters.

    Args:
        name: Container name
        command: Shell command to run (executed via /bin/sh -c)
        workdir: Working directory inside the container (default: /workspace)
        timeout: Timeout in seconds (default: 60, max: 300)
    """
    if timeout > 300:
        timeout = 300

    client = _get_client()
    try:
        container = client.containers.get(name)
    except docker.errors.NotFound:
        raise ValueError(f"Container '{name}' not found")
    if not _is_nihil_container(container):
        raise ValueError(f"'{name}' is not a Nihil container")
    if container.status != "running":
        raise ValueError(f"Container '{name}' is not running (status: {container.status})")

    exit_code, output = container.exec_run(
        cmd=["/bin/sh", "-c", command],
        workdir=workdir,
        demux=False,
        stream=False,
        socket=False,
        environment={"TERM": "dumb"},
    )

    raw = output.decode("utf-8", errors="replace") if output else ""
    truncated = len(raw) > EXEC_OUTPUT_LIMIT
    if truncated:
        raw = raw[:EXEC_OUTPUT_LIMIT] + f"\n... [truncated at {EXEC_OUTPUT_LIMIT} chars]"

    return {
        "exit_code": exit_code,
        "output": raw,
        "truncated": truncated,
        "command": command,
        "container": name,
    }


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
        result.append({
            "variant": variant,
            "tag": tag,
            "installed": installed,
            "size_mb": size_mb,
        })
    return result


@mcp.tool()
def list_tools(image: str = "full", category: Optional[str] = None) -> dict:
    """List pentest tools available in a Nihil image.

    Reads the tools.json manifest embedded in the image. Optionally filter by category.

    Args:
        image: Image variant — full, ad, web, ctf (default: full)
        category: Filter by category name (optional, e.g. "network", "web", "ad")
    """
    if image not in AVAILABLE_IMAGES:
        raise ValueError(f"Unknown image '{image}'. Choose from: {', '.join(AVAILABLE_IMAGES)}")

    client = _get_client()
    tag = AVAILABLE_IMAGES[image]
    try:
        img = client.images.get(tag)
    except docker.errors.ImageNotFound:
        raise RuntimeError(f"Image '{tag}' not installed. Run: nihil install {image}")

    import io
    import json
    import tarfile

    try:
        tmp = client.containers.create(image=tag, command="true")
        try:
            bits, _ = tmp.get_archive("/opt/nihil/tools.json")
            buf = io.BytesIO(b"".join(bits))
            with tarfile.open(fileobj=buf) as tar:
                member = tar.getmember("tools.json")
                content = tar.extractfile(member).read()
            manifest = json.loads(content)
        finally:
            tmp.remove(force=True)
    except Exception as e:
        return {"error": f"Could not read tools manifest: {e}", "image": image}

    if category:
        category_lower = category.lower()
        filtered = {
            cat: tools
            for cat, tools in manifest.items()
            if category_lower in cat.lower()
        }
        return {"image": image, "category_filter": category, "tools": filtered}

    return {"image": image, "tools": manifest}


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
