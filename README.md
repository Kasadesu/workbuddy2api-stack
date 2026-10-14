# Kasa2API Stack

Integration stack and bridge services for the Kasa2API gateway.

## Features

- **Responses Bridge (`responses-bridge.py`)**: Translates `POST /v1/responses` to upstream `/v1/chat/completions`, supporting SSE streaming, image input, namespace/custom tool mapping, web search/fetch adapters, and token accounting.
- **Admin Dashboard (`wb2api-admin.py`)**: Web UI for account management, multi-tenant API keys, usage metrics, token statistics, and automated tasks.
- **Task Automation (`workbuddy_automation.py`)**: Scheduled check-ins and growth tasks.
- **Production Setup**: Caddy reverse proxy templates with auth and systemd service configurations.

## Project Structure

| Path | Description |
| --- | --- |
| `responses-bridge.py` | Responses API to Chat Completions translation bridge |
| `wb2api-admin.py` | Local admin service and management API |
| `workbuddy_automation.py` | Optional task automation sidecar |
| `Caddyfile.example` | Reverse-proxy and multi-key authentication configuration |
| `deploy/` | systemd service unit templates |
| `tools/` | Deployment helpers and offline test suite |
| `docs/` | Architecture and deployment documentation |

## Quick Start

1. Start the upstream gateway on `127.0.0.1:7863`.
2. Configure gateway settings using `workbuddy2api-config.example.json`.
3. Set environment variables (see [docs/CONFIGURATION.md](docs/CONFIGURATION.md)):
   ```sh
   export PUBLIC_HOST=api.example.com
   export PUBLIC_BASE_URL=https://api.example.com/v1
   export WB2A_BASE=/opt/workbuddy2api
   export BRIDGE_LOG_DIR=/var/log/responses-bridge
   export CADDY_FILE=/etc/caddy/Caddyfile
   ```
4. Configure Caddy using `Caddyfile.example` and reload:
   ```sh
   caddy validate --config /etc/caddy/Caddyfile
   systemctl reload caddy
   ```
5. Enable and start systemd services (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

## References

- Upstream gateway: [Sliverkiss/workbuddy2api](https://github.com/Sliverkiss/workbuddy2api)
- Automation reference: [linguo2625469/workbuddy2api-panel](https://github.com/linguo2625469/workbuddy2api-panel)

## License

[MIT](NOTICE.md)
