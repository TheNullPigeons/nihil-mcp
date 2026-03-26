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

| Tool | Description |
|---|---|
| `list_containers` | List all Nihil containers |
| `get_container_info` | Info on a specific container |
| `start_container` | Create and start a container |
| `stop_container` | Stop a container |
| `exec_command` | Run a command inside a container |
| `list_images` | List installed image variants |
| `list_tools` | List tools available in an image |
