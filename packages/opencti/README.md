# opencti-mcp

MCP backend for OpenCTI threat intelligence queries. Provides
`lookup_ioc`, `search_entity`, and related tools through the
Valhuntir gateway.

## Threat-intel providers

`lookup_ioc` asks every configured platform for the records it holds on exactly
the IOC, and returns each platform's answer under `providers.<name>`: the
records as the platform holds them, with `outcome` MATCH, NO_MATCH or
UNAVAILABLE (the platform couldn't be asked, which is not a not-found). No
verdict is computed. The top-level `outcome` is MATCH when any platform matched.

The platforms are set in the backend's `env` block in `gateway.yaml`:

| Setting | Meaning |
|---|---|
| `THREATINTEL_PROVIDERS` | Comma-separated platforms to ask: `opencti`, `misp`. Unset means `opencti`. |
| `OPENCTI_URL`, `OPENCTI_TOKEN` | OpenCTI's address and API token (the token can also be in `~/.config/opencti-mcp/token`, mode 600). |
| `OPENCTI_SSL_VERIFY`, `OPENCTI_TIMEOUT` | TLS verification (default `true`) and request timeout in seconds. |
| `MISP_URL`, `MISP_KEY` | MISP's address and an API key of an API-enabled user. |
| `MISP_SSL_VERIFY` | `true` (default), `false`, or the path of a CA bundle that signs MISP's certificate. |
| `MISP_TIMEOUT` | Request timeout in seconds (default 30). |

Each lookup waits at most 12 seconds for each platform. A platform that is
listed but can't be used (a missing setting, a bad key, a server that is down)
is reported UNAVAILABLE with the reason on every lookup, and never hides
another platform's answer. When OpenCTI isn't listed, the other OpenCTI tools
answer `opencti_not_configured`.

**To add MISP, edit the existing threat-intel backend's `env` block**; don't add
a second backend entry, which would put two copies of every tool behind the
gateway. Then restart the gateway (`systemctl --user restart vhir-gateway`, or
however you start it):

```yaml
  opencti-mcp:
    env:
      THREATINTEL_PROVIDERS: "opencti,misp"
      OPENCTI_URL: "https://opencti.example.org"
      OPENCTI_TOKEN: "..."
      MISP_URL: "https://misp.example.org"
      MISP_KEY: "..."
```

For MISP, each lookup is one attribute search and one warninglist check. The
search never filters on `to_ids`, publication, decay or warninglists; each
record carries `to_ids`, its event's `threat_level_id`, `analysis` and
`published`, and `decay_score` where MISP computes one. `warninglist_hits`
names the warninglists that list the value, and `warninglists_enabled` and
`decaying_models_enabled` say how many are switched on (both are disabled in a
new MISP).

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
