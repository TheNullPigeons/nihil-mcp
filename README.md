# nihil-mcp

MCP server for Nihil — lets Claude manage and use pentest containers directly.

## Install

```bash
cd nihil-mcp
pip install -e .
```

## Register with Claude Code

```bash
claude mcp add nihil -- nihil-mcp
```

## Verify

```bash
claude mcp list
```

## Usage

Start a new Claude Code session — the tools are loaded automatically.

You can then ask Claude to manage containers and run tools:

> "Start a nihil web container, mount ~/htb as workspace, then scan 10.10.10.1 with nmap"

## Available tools

**Containers**

| Tool | Description |
|---|---|
| `list_containers` | List all Nihil containers with their status |
| `get_container_info` | Detailed info on a specific container |
| `start_container` | Create and start a container (image, workspace, network, privileged) |
| `stop_container` | Stop a running container |
| `remove_container` | Remove a container (`force` to remove a running one) |

**Command execution**

| Tool | Description |
|---|---|
| `exec_command` | Run a one-off command in a container |
| `create_session` | Open a persistent shell session (preserves cwd + env) |
| `exec_in_session` | Run a command in a session, keeping cwd and exported vars |
| `list_sessions` | List active sessions and their containers |
| `close_session` | Close a session and clean up its state |

**Images**

| Tool | Description |
|---|---|
| `list_images` | List image variants and whether they are installed locally |
| `pull_image` | Pull an image from `ghcr.io/thenullpigeons` |
| `list_tools` | List tools available in an image (optionally by category) |

`exec_command` and `exec_in_session` accept a `timeout` (default 60s, max 300s);
a command that exceeds it is killed inside the container and reported with
exit code 124.

## Security

This server gives an LLM the ability to run **arbitrary commands inside Nihil
containers**. Understand the trust boundaries before using it.

- **Not a host sandbox.** The model is instructed to work only inside
  containers, but that is guidance, not isolation. `start_container` defaults to
  `network="host"`, so the container shares the host's network stack — commands
  can reach the host's loopback services, the LAN, and anything the host routes
  to. For stronger isolation, start containers with `network="bridge"` (or
  `"none"`) and only use `host` when a task genuinely needs it.
- **`privileged=True` breaks containment.** It grants added capabilities and
  device access and should be treated as near-host access. Enable it only for
  the specific task that needs it (e.g. raw sockets for certain scans), never as
  a default.
- **Tool output is untrusted input.** Scan results, HTTP responses, and file
  contents returned to the model can carry prompt-injection payloads that try to
  steer it into running attacker-controlled commands. Review the actions the
  model takes; do not run it fully unattended against untrusted targets.
- **No built-in scope enforcement.** Nothing here restricts which targets can be
  attacked. Only point it at systems you are explicitly authorized to test. The
  operator is responsible for staying in scope and within the law.
