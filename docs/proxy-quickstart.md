# SecretVault Proxy Integration Quick Guide

Use this guide when an application or coding tool needs an API, but you want
the real provider key to remain stored in SecretVault. The application sends a
SecretVault client key to the proxy; SecretVault replaces it with the mapped
provider credential on the server.

## The URL rule

When you have a provider endpoint, split it into the profile target and the
client-facing proxy route:

```text
Provider endpoint:       https://api.z.ai/api/coding/paas/v4
Service profile target:  https://api.z.ai
Client proxy URL:        https://vault.example.com/proxy/zai/api/coding/paas/v4
```

The service profile stores the provider origin and the name of the SecretVault
secret. The path after the origin is appended to the client-facing proxy URL.
The Services page shows this conversion while you create a profile and lets
you copy the resulting proxy URL.

## Create the service profile

1. Store the real provider key as a SecretVault secret. For this example, the
   secret name is `zai_api_key`.
2. Open **Services** → **Create Profile**.
3. Enter `zai` as the service name.
4. Paste `https://api.z.ai/api/coding/paas/v4` into **Target Upstream URL**.
   The form saves `https://api.z.ai` as the profile target.
5. Choose **Bearer Token** and select `zai_api_key` as the credential secret.
6. Create a client application with the `proxy:zai` capability (or
   `proxy:*` if the client needs several proxy services).

The client-facing base URL for this example is:

```text
https://vault.example.com/proxy/zai/api/coding/paas/v4
```

Clients authenticate to SecretVault with the client linking key. They do not
need, and should never receive, the real Z.AI key.

## MiniMax Code CLI (`mcode`)

For the Z.AI coding-plan endpoint, use MCode's OpenAI Completions format and
the SecretVault proxy URL. Run this once on each machine where MCode is
installed:

```bash
ZAI_API_KEY="$(
  node --input-type=module -e '
    import { readFileSync } from "node:fs";
    const p = `${process.env.HOME}/.secretvault/credential.json`;
    const c = JSON.parse(readFileSync(p, "utf8"));
    process.stdout.write(c.clientKey ?? c.client_key ?? "");
  '
)" \
  mcode provider add \
    --name zai \
    --base-url "https://vault.example.com/proxy/zai/api/coding/paas/v4" \
    --api-format openai-completions \
    --model glm-5.3-flash \
    --model glm-5.3 \
    --api-key-env ZAI_API_KEY \
    --use
```

There must not be a space between `$` and `(` in the first line. The exact
shell form is:

```bash
ZAI_API_KEY="$(node --input-type=module -e '...')" mcode provider add ...
```

The command reads the SecretVault client key from
`~/.secretvault/credential.json` into a temporary shell assignment. It does
not export a provider key or put a real Z.AI key in the command line or shell
history. MCode may save the value supplied through `--api-key-env` in its own
configuration; in this setup that value is only the SecretVault client key.

`glm-5.3-flash` is listed first and is selected by `--use`. Keep both models
registered, then choose the other model from MCode's provider/model selector or
for a one-off execution with the model option supported by your MCode version.

Useful checks:

```bash
mcode provider list
mcode
```

For this proxy profile, keep `--api-format openai-completions` and the
`/api/coding/paas/v4` path. The current SecretVault bearer flow expects the
client's SecretVault authorization header and injects the provider bearer
credential upstream; an Anthropic Messages client mode that sends a different
credential header is not interchangeable with this setup.

## Rotate the provider key

Rotate the `zai_api_key` secret in SecretVault's Web UI or with the SecretVault
secret manager. Do not change the MCode provider on each computer. New proxy
requests use the rotated value because the proxy resolves the mapped secret at
request time.

## Avoid the easy but wrong setup for this goal

`secretvault run --secret zai_api_key -- mcode ...` can place the real provider
key in the child process environment, but a CLI that persists its API-key
environment value can then write that real key to its local configuration. Use
the proxy setup above when centralized rotation is the priority.

For the broader proxy model and SDK examples, see the
[Web UI guide](webui.md) and [SDK guide](sdk.md).
