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
| `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS` | `False` | Users can't add workspace tools. With `ENABLE_PLUGINS=False` no tool code can load anyway. |
| `ENABLE_DIRECT_INTEGRATIONS` | `False` | Users don't see the Integrations tab, where they'd add their own tool and terminal connections. Hiding it doesn't disable connections they already have. |
| `ENABLE_DIRECT_CONNECTIONS` | `False` | Users can't connect their own OpenAI-compatible API endpoints. |
| `USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS` | `False` | Users can't connect their own tool servers, unless a group they're in allows it (see below). Admins always can. |
| `ENABLE_CODE_INTERPRETER` | `False` | No code interpreter. |
| `CODE_INTERPRETER_ENGINE`, `CODE_EXECUTION_ENGINE` | `pyodide` | If an admin turns code execution on, it runs in the browser, not on a server. Never point either at Jupyter or Open Terminal. |

**On an existing instance, the env file sets only `ENABLE_PLUGINS`.** At its
first start Open WebUI writes the other seven into its database, and from then
on the database value is used, whatever the environment says. No Admin Panel
save is needed for that to happen. On an instance that has started before,
set the seven as below (checked on Open WebUI 0.11.4); Tools Access needs nothing while
plugins stay disabled:

| Setting | Where in the Admin Panel |
|---|---|
| `USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS` | Nothing to set: with plugins disabled (as this profile sets), the **Tools Access** switch isn't shown and no tool code can load |
| `ENABLE_DIRECT_INTEGRATIONS` | **Settings > Integrations**, User Connections: turn **Direct Integrations** off |
| `ENABLE_DIRECT_CONNECTIONS` | **Settings > Connections**, User Connections: turn **Direct Connections** off |
| `USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS` | **Users > Groups > Default permissions > Edit**, and **each group's Edit > Permissions**; Features Permissions: turn **Direct Tool Servers** off |
| `ENABLE_CODE_INTERPRETER` | **Settings > Code Execution**, Code Interpreter: turn **Enable Code Interpreter** off |
| `CODE_INTERPRETER_ENGINE` | **Settings > Code Execution**, Code Interpreter: **Code Interpreter Engine** Pyodide |
| `CODE_EXECUTION_ENGINE` | **Settings > Code Execution**: **Code Execution Engine** Pyodide |

A fresh instance started with the env file takes all eight.

**`USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS` is a default only.** Open WebUI
gives a user a permission when the defaults or any group they're in allows it,
so a group that allows Direct Tool Servers gives it to its members whatever
the defaults say. Turn it off in every group (**Users > Groups >** the group
**> Edit > Permissions**, Features Permissions), on a fresh instance too, and
in each group you add later.

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
