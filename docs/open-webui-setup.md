# Open WebUI Setup

Open WebUI is an MCP-only client for Valhuntir: it reaches the case only
through the gateway's MCP tools, so it gets the server-side controls (the
gateway audit, the case records' rules and signed approvals) and no shell.
It needs a locked configuration, because Open WebUI can run code on its own
server.

## What setup writes

```
vhir setup client --client=open-webui
```

In the folder it runs from:

- `openwebui-vhir.env`: the lock profile (below).
- `openwebui-system-prompt.md`: the forensic discipline prefix, then the
  instructions each Valhuntir backend sends at initialize. Open WebUI drops
  those instructions, so without this prompt the model never sees them,
  including the rule that evidence content is data, never instructions.

It then prints the steps to add each backend. The bearer token is never
printed; it is the gateway's token (`api_keys` in `~/.vhir/gateway.yaml` on
the SIFT workstation).

A backend that doesn't answer at setup is named, and its instructions are
missing from the prompt. Re-run setup once it runs.

## The lock profile

Start Open WebUI with the env file, e.g.
`docker run --env-file openwebui-vhir.env ... ghcr.io/open-webui/open-webui`.

| Setting | Value | Why |
|---|---|---|
| `ENABLE_PLUGINS` | `False` | Python Tools and Functions run on the Open WebUI server, which is equivalent to giving them a shell. This stops them running. It doesn't stop an admin creating them. |
| `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS` | `False` | Users can't add workspace tools. |
| `ENABLE_DIRECT_INTEGRATIONS` | `False` | Users can't connect their own tool servers from the browser. |
| `ENABLE_CODE_INTERPRETER` | `False` | No code interpreter. |
| `CODE_INTERPRETER_ENGINE`, `CODE_EXECUTION_ENGINE` | `pyodide` | If an admin turns code execution on, it runs in the browser, not on a server. Never point either at Jupyter or Open Terminal. |

Open WebUI keeps some settings in its database after the first start, and
there the Admin Panel value wins over the environment. On an existing
instance, check each setting in the Admin Panel as well.

## Adding the backends

As an admin: **Admin Panel > Settings > External Tools**. Add each backend
setup printed as **MCP (Streamable HTTP)**, auth **Bearer**, with the
gateway's token. MCP servers can only be added by administrators.

Then paste `openwebui-system-prompt.md` into the model's system prompt
(**Admin Panel > Settings > Models**, or the workspace model you use).

## Small local models

Open WebUI sends every tool's schema with every request. All of Valhuntir's
backends together have more tools than a small local model's context holds.

- Add only the backends the investigation needs, each by its own URL
  (`http://<sift>:4508/mcp/<backend>`), not the aggregate endpoint.
- Use the connection's **Function Name Filter List** to keep only the tools
  you use.

## Limits

- Open WebUI's per-call tool approval is experimental, off by default, and
  chosen by the user. Valhuntir's approval of findings stays on the SIFT
  workstation (`vhir approve` or the Examiner Portal).
- The lock profile stops tool code running; an Open WebUI admin is trusted.
- Setup's printed steps follow the Open WebUI documentation; they were not
  run against every Open WebUI version.
