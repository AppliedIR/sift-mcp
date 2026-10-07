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

**To add MISP, edit the existing threat-intel backend's `env` block**
(`threatintel-mcp`, or `opencti-mcp` in configurations from before); don't add
a second backend entry, which would put two copies of every tool behind the
gateway. Then restart the gateway (`systemctl --user restart vhir-gateway`, or
however you start it):

```yaml
  threatintel-mcp:
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

## OpenCTI versions

`opencti-mcp` talks to OpenCTI's GraphQL API directly, with no client
library, so one install works with OpenCTI 6.9 and 7. Every query uses fields
that both versions have; `lookup_ioc` records the server's version with each
answer.

An install from an earlier release may still have OpenCTI's old client,
pycti. Nothing uses it any more; the installers and `vhir update` leave it in
place and print the command that removes it:

```bash
uv pip uninstall --python ~/.vhir/venv/bin/python pycti
```

The standalone `opencti_query.py` script still uses pycti. To run it, install
the pycti major that matches your server's, in an environment of its own.

### Checking your server version

```bash
curl -H "Authorization: Bearer <token>" \
     -d '{"query":"{ about { version } }"}' \
     https://<opencti-host>/graphql
```
