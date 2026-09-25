# References and Attribution

This project combines original integration code with ideas and runtime conventions from the following public projects. The references are called out here so users can distinguish upstream dependencies from code maintained in this repository.

## Upstream gateway

**[Sliverkiss/workbuddy2api](https://github.com/Sliverkiss/workbuddy2api)**

The gateway is the upstream 2API framework that this stack is designed to sit beside. The account pool, Chat Completions endpoint, gateway configuration shape, account files, model routing, and native check-in/travel scheduler belong to that project. This repository does not include or relicense its source code; install it separately and follow its current license and terms.

## Automation reference

**[linguo2625469/workbuddy2api-panel](https://github.com/linguo2625469/workbuddy2api-panel)**

The check-in, travel, activity, and growth-task workflow in `workbuddy_automation.py` was designed with this project as a reference for task concepts, scheduling, and account selection. The sidecar in this repository is an independent Python implementation that invokes the installed gateway through Docker; it is not presented as a copy of the upstream panel.

## This repository's own code

The following pieces were written as integration code for this stack:

- `responses-bridge.py`: Responses-to-Chat translation, streaming conversion, image input, hosted-tool adapters, cache/session key forwarding, and token accounting.
- `wb2api-admin.py`: the local admin service, API-key management, usage views, and configuration UI.
- `Caddyfile.example`, `deploy/`, and `tools/`: generic reverse-proxy, systemd, deployment, and offline-test scaffolding.

When redistributing or modifying this repository, keep this attribution file and comply with the upstream projects' current licenses and service terms.
