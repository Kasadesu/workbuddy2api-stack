# Deployment

The commands below are a template. Replace example values and review every path before running them.

## Host preparation

Use a dedicated Linux account, install Python 3.11+, Caddy, Docker, and the upstream gateway. Create application directories such as:

```sh
sudo install -d -o workbuddy -g workbuddy /opt/workbuddy2api/admin
sudo install -d -o workbuddy -g workbuddy /opt/responses-bridge
sudo install -d -o workbuddy -g workbuddy /var/log/responses-bridge
```

The upstream gateway must listen on `127.0.0.1:7863`; the admin service listens on `127.0.0.1:7864`; the bridge listens on `127.0.0.1:7866`.

## Install files

Copy the Python files and `deploy/*.service` into the directories referenced by the units. Adjust `User=`, `WorkingDirectory=`, and the Python paths if your layout differs. Install the upstream gateway's account files with restrictive permissions.

Set these environment variables for the admin process and bridge where appropriate:

```sh
export PUBLIC_HOST=api.example.com
export PUBLIC_BASE_URL=https://api.example.com/v1
export WB2A_BASE=/opt/workbuddy2api
export BRIDGE_LOG_DIR=/var/log/responses-bridge
export CADDY_FILE=/etc/caddy/Caddyfile
```

## Caddy

Copy `Caddyfile.example` to the Caddy configuration path, replace the site name and all key/hash placeholders, then validate before reloading:

```sh
sudo caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

The `tools/caddy-route.py` helper can insert or remove the managed Responses route. It reads the public key allow-list and internal upstream key from the selected site block and never accepts keys as command-line arguments.

## systemd

```sh
sudo install -m 644 deploy/responses-bridge.service /etc/systemd/system/
sudo install -m 644 deploy/workbuddy-automation.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now responses-bridge
sudo systemctl enable --now workbuddy-automation
```

Leave the automation unit stopped until its configuration has been reviewed. The bridge health endpoint is local: `curl http://127.0.0.1:7866/healthz`.

## Optional remote helper

From a trusted workstation, set `DEPLOY_HOST` to an SSH destination and `DEPLOY_SSH_KEY` to a local key path before running `tools/deploy-bridge.py` or `tools/deploy-automation.py`. The scripts do not contain a default host and cannot deploy accidentally to the original environment.
