# opencti-mcp

MCP backend for OpenCTI threat intelligence queries. Provides
`lookup_ioc`, `search_entity`, and related tools through the
Valhuntir gateway.

## OpenCTI version compatibility

**You must align `pycti`'s major version to your OpenCTI server's
major version.** `opencti-mcp` declares only a floor (`pycti>=6.0`)
and does not ceiling-pin, because the correct major depends on which
OpenCTI server you are connecting to — and that is
environment-specific, not a package-wide default.

A major mismatch causes `GRAPHQL_VALIDATION_FAILED: Unknown type
"..."` errors on every IOC query because each major adds new schema
types the older server doesn't know about (e.g., pycti 7.x's
`AIPrompt` fragment against a 6.x server; or older pycti missing
types a newer server requires).

Install the pycti major that matches your server:

| OpenCTI server   | Install pycti                                   |
|------------------|-------------------------------------------------|
| 5.x (legacy)     | `uv pip install 'pycti>=5.0,<6.0'`              |
| 6.x              | `uv pip install 'pycti>=6.0,<7.0'`              |
| 7.x              | `uv pip install 'pycti>=7.0,<8.0'`              |

If pycti's major doesn't match the server's major at startup,
`opencti-mcp` fails init with a clear `VersionMismatchError`
including the exact pin instruction for your server's version. It
will NOT start the backend and begin emitting per-IOC GraphQL
errors.

### Checking your server version

```bash
curl -H "Authorization: Bearer <token>" \
     -d '{"query":"{ about { version } }"}' \
     https://<opencti-host>/graphql
```

Returns `{"data":{"about":{"version":"6.9.10"}}}` — the major digit
is the `pycti` major you need.

### Future

A future release will detect the server version and install the
matching pycti automatically. Until then, this is a manual step
after setting up a new operator environment or upgrading
`opencti-mcp`.
