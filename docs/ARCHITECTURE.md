# Architecture

```text
OpenAI-compatible client
        |
        v
      Caddy  (TLS, public-key allow-list, admin routing)
        |\
        | \-- /admin* ------> admin service :7864
        |
        \---- /v1/responses -> responses-bridge :7866
                                  |
                                  \-> gateway /v1/chat/completions :7863
                                           |
                                           \-> WorkBuddy-compatible upstream
```

The bridge is intentionally a single Python standard-library process. It converts Responses input items into Chat messages, preserves tool-call history, adapts hosted web tools, forwards remote or data-URL images, and converts streaming Chat chunks back into Responses events. Request summaries and token aggregates are written beneath the configured bridge log directory.

The admin service runs on loopback and uses Docker exec for account operations. Caddy protects its JSON API with Basic Auth while the page itself presents an application login form. The automation sidecar only runs explicitly selected tasks and can be left disabled.
