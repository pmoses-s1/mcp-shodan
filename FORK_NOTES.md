# pmoses-s1/mcp-shodan: fork notes

Fork of [w0h1v/mcp-shodan](https://github.com/w0h1v/mcp-shodan) at upstream
`08bf8ee` (v1.0.34), used by the `sentinelone/secops-mcps` Docker image as its
optional `shodan-mcp` server. The image installs this repo with `git` alone, so
this fork commits its compiled `build/` and production `node_modules/`.

## Changes from upstream

| Change | Why |
|---|---|
| `build/` and production `node_modules/` committed, `prepare` script added | Upstream publishes only to npm (`prepublishOnly`, no `prepare`), so a git install has no `build/` and cannot start. The image has no npm. |
| `page` capped at 10 on `shodan_search` and `domain_info` (`MAX_PAGE` in `src/helpers.ts`) | Every page past the first costs a query credit; an agent loop could drain a paid plan. |
| `maxRedirects: 0` on every HTTP call | The key travels in the query string; a followed redirect would resend it elsewhere. Shodan's API does not redirect. |
| `redact()` on Shodan error text | Scrubs `key=` and the literal key from anything that reaches a log line or a tool result. |
| `dotenv` removed | Credentials come from the environment only, never from a `.env` file in the working directory. |
| Dead code stripped from the vendored tree (`vendor-strip.txt`) | `mcp-proxy`'s CLI pulls in `pipenet`, a tunnel to the public internet, plus a Koa server: 26 packages the stdio server never loads. |

The image entrypoint also forces stdio (it unsets `MCP_TRANSPORT`, `MCP_HOST`,
`MCP_PORT`, `MCP_ENDPOINT`), so upstream's unauthenticated HTTP transport cannot
be switched on inside the container.

## Verification at vendoring time (2026-10-13, Node v24.21.0, npm 11.19.0)

- `npm test`: pass.
- `npm audit` (all and `--omit=dev`): 0 vulnerabilities.
- `osv-scanner v2.2.3` on `package-lock.json`: 192 packages, no issues.
- `gitleaks v8.30.1` over full history: no leaks.
- stdio probe: 11 tools; key absent from stderr and from every tool result; `page: 11` and a path-shaped `ip` are rejected by schema validation.

## Refresh against upstream

    git remote add upstream https://github.com/w0h1v/mcp-shodan.git
    git fetch upstream && git merge upstream/main   # resolve, keep the patches above
    <s1-secops-skills>/scripts/vendor-node-fork.sh "$PWD"
    git push origin main && git rev-parse HEAD      # -> SHODAN_MCP_REF
