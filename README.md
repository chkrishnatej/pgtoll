# pgtoll

> Wire-level PostgreSQL proxy for per-tenant and per-AI-agent query cost attribution

![Status](https://img.shields.io/badge/status-WIP-yellow)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Go](https://img.shields.io/badge/go-1.22+-00ADD8)

## What it does

`pgtoll` sits between your application and PostgreSQL, intercepts queries at the wire protocol level, and attributes query costs to tenants or AI agents using [sqlcommenter](https://google.github.io/sqlcommenter/) metadata — without any changes to your application code.

```
App / AI Agent
      │
      ▼
  [ pgtoll ]   ← parses wire protocol, extracts sqlcommenter metadata
      │         ← attributes cost per tenant / per agent
      │         ← emits metrics to Prometheus
      ▼
  PostgreSQL
```

## Status

Work in progress. Not production ready.

- [x] TCP pass-through proxy
- [x] SSL termination
- [ ] Protocol message parsing (RowDescription, Query, DataRow)
- [ ] sqlcommenter metadata extraction
- [ ] Per-tenant cost attribution
- [ ] Prometheus metrics export

## License

Apache 2.0
