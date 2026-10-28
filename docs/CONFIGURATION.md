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

Deployment helpers require DEPLOY_HOST and DEPLOY_SSH_KEY to be set explicitly.

## Gateway config

Start from `workbuddy2api-config.example.json`. Keep `api_key`, OAuth credentials, device tokens, and provider keys in files outside the repository. The example enables the upstream check-in/travel schedule but leaves optional task automation to the sidecar's explicit configuration.

## Upstream Device Token and Channel Verification (渠道校验)

Tencent upstream enforces client device fingerprint checks. If requests lack a valid `X-Device-Token`, the upstream API rejects requests with error code `11128: 这次调用没通过渠道校验` (Channel verification failed).

### Obtaining your device token
1. Launch your WorkBuddy desktop client or open the browser web client.
2. Inspect outgoing HTTP request headers (via browser DevTools Network tab, Fiddler, Charles, or mitmproxy).
3. Copy the value of the `X-Device-Token` header (typically a 32–36 character hex identifier).

### Configuring your device token
You can configure the device token using any of the following approaches (in order of priority):
- **Web Admin Dashboard (Recommended)**: Navigate to **Gateway & Key** in the Admin UI (`wb2api-admin.py`), paste your device token into the **Device Token** section, and click save. The gateway restarts automatically.
- **Shared Token File**: Write your token string to `./data/device_token` (`/app/data/device_token` inside the container) with file mode `644`. All accounts under the gateway share this token.
- **Gateway Config**: In `config.json`, set `"device_token": "YOUR_DEVICE_TOKEN"` or `"device_token_file": "./data/device_token"` under the `"upstream"` section.
- **Environment Variable**: Export `WB2A_DEVICE_TOKEN="YOUR_DEVICE_TOKEN"` or `WB2A_DEVICE_TOKEN_FILE="/app/data/device_token"` before starting the container.
- **Per-Account Override**: In `auths/workbuddy-<uid>.json`, add `"deviceToken": "YOUR_DEVICE_TOKEN"`.

## API keys

The admin page generates public keys in the conventional `sk-...` format. Store only hashes or protected files where possible, rotate keys when a client is removed, and never paste production keys into issue reports or logs.
