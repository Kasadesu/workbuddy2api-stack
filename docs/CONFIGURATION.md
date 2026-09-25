# Configuration

## Environment variables

| Variable | Default | Used by |
| --- | --- | --- |
| `PUBLIC_HOST` | `api.example.com` | admin Caddy migration and route utility |
| `PUBLIC_BASE_URL` | `https://api.example.com/v1` | admin page API base URL |
| `WB2A_BASE` | `/opt/workbuddy2api` | admin and automation state |
| `WB2A_CONTAINER` | `workbuddy2api` | Docker exec operations |
| `BRIDGE_LOG_DIR` | `/var/log/responses-bridge` | bridge and token statistics |
| `TOKEN_STATS_FILE` | `<BRIDGE_LOG_DIR>/token-usage.json` | admin token totals |
| `CADDY_FILE` | `/etc/caddy/Caddyfile` | admin and route utility |
| `DEPLOY_HOST` | unset | remote deployment helpers |
| `DEPLOY_SSH_KEY` | unset | remote deployment helpers |
| `REMOTE_BRIDGE_DIR` | `/opt/responses-bridge` | bridge deployment helper |

Unset deployment variables are intentional: the helper exits instead of guessing a host or key.

## Gateway config

Start from `workbuddy2api-config.example.json`. Keep `api_key`, OAuth credentials, device tokens, and provider keys in files outside the repository. The example enables the upstream check-in/travel schedule but leaves optional task automation to the sidecar's explicit configuration.

## API keys

The admin page generates public keys in the conventional `sk-...` format. Store only hashes or protected files where possible, rotate keys when a client is removed, and never paste production keys into issue reports or logs.
