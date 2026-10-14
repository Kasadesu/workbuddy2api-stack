# References and Attribution

This project references and integrates with the following open-source projects:

- **[Sliverkiss/workbuddy2api](https://github.com/Sliverkiss/workbuddy2api)**: Upstream gateway framework handling the account pool, Chat Completions endpoint, model routing, and core scheduler.
- **[linguo2625469/workbuddy2api-panel](https://github.com/linguo2625469/workbuddy2api-panel)**: Reference for check-in and task automation workflows in `workbuddy_automation.py`.

### Repository Components

- `responses-bridge.py`: Responses-to-Chat translation, streaming conversion, hosted tool adapters, and token accounting.
- `wb2api-admin.py`: Local admin dashboard and API key management.
- `workbuddy_automation.py`: Task automation sidecar.
- `Caddyfile.example`, `deploy/`, `tools/`: Reverse-proxy config, systemd units, and tests.
