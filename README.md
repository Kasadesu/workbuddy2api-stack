# WorkBuddy2API Stack

Self-hosted integration glue for a WorkBuddy-compatible gateway:

- a standard-library Responses-to-Chat bridge for clients that send `POST /v1/responses`;
- a small admin site for accounts, API keys, usage, token statistics, and automation;
- Caddy and systemd examples for a single VPS;
- an opt-in WorkBuddy task sidecar;
- offline smoke tests for translation, image input, caching/session behavior, and admin hardening.

This repository does **not** include upstream gateway source code, account files, API keys, cookies, VPS state, or production logs. Install the upstream gateway separately and connect it to these components.

## Layout

| Path | Purpose |
| --- | --- |
| `responses-bridge.py` | Responses API to Chat Completions translation, SSE conversion, tool adapters, web fetch/search adapters, image input, and token accounting |
| `wb2api-admin.py` | Local admin HTTP service; Caddy exposes it under `/admin` |
| `workbuddy_automation.py` | Optional check-in and growth-task sidecar |
| `Caddyfile.example` | Generic reverse-proxy and authentication example |
| `deploy/` | systemd units |
| `tools/` | Deployment helpers and offline tests |
| `docs/` | Architecture, deployment, and configuration notes |

## Quick start

1. Install the upstream WorkBuddy-compatible gateway and make its Chat Completions endpoint available on `127.0.0.1:7863`.
2. Copy `workbuddy2api-config.example.json` to the gateway config location and set a private upstream `api_key`.
3. Copy `responses-bridge.py`, `wb2api-admin.py`, and `workbuddy_automation.py` to the directories used by the systemd units.
4. Set `PUBLIC_HOST`, `PUBLIC_BASE_URL`, `WB2A_BASE`, `CADDY_FILE`, and `BRIDGE_LOG_DIR` for the host.
5. Replace every placeholder in `Caddyfile.example`, validate it with `caddy validate`, then reload Caddy.
6. Run the systemd units as a dedicated non-root account with permission to access Docker and the application directories.

The deployment helpers intentionally refuse to run unless `DEPLOY_HOST` and `DEPLOY_SSH_KEY` are set. They contain no target host or private-key path.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for a full example and [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for environment variables.

## Security model

Keep the upstream key, account OAuth files, admin password, Caddy bcrypt hash, and search-provider keys outside Git. Public API keys should be generated with the `sk-` prefix by the admin page and rotated when access changes. Bind the bridge and admin services to loopback; let Caddy handle TLS and public routing.

The automation sidecar is disabled for task execution by default. Review the task list and permissions before enabling it.

## License and upstream attribution

The integration code in this repository is released under the MIT License. The upstream WorkBuddy-compatible gateway is a separate project with its own license and terms; this repository does not relicense or redistribute that upstream code.
