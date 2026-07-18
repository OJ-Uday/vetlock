# Vetlock MCP Admission Server

`@vetlock/mcp` is a local stdio MCP server for AI coding agents and developer
tools. It provides dependency-admission analysis before an agent requests an
install. It is **advisory**: actual enforcement stays in `vetlock add` and the
Vetlock guard, because an agent can otherwise bypass MCP by invoking a package
manager directly.

## Start

Build the workspace, then configure an MCP client with:

```json
{
  "mcpServers": {
    "vetlock": {
      "command": "node",
      "args": ["/absolute/path/to/vetlock/packages/mcp/dist/server.js"]
    }
  }
}
```

The server uses stdio. Do not write logs to stdout: stdout is reserved for MCP
protocol messages.

## Tools

| Tool | Purpose |
| --- | --- |
| `analyze_lockfile_change` | Scan two absolute lockfile paths through Vetlock's normal diff engine. |
| `analyze_package_install` | Fetch and statically analyze one npm package spec before installation. |
| `evaluate_policy` | Turn findings into `allow`, `review`, or `block`. |
| `issue_admission_receipt` | Bind an admission decision to package/artifact/project/policy/finding hashes. |
| `verify_admission_receipt` | Verify a receipt's deterministic integrity hash. |
| `explain_finding` | Return detector evidence for a package/finding. |

## Security model

- Analysis fetches tarball bytes and extracts them with Vetlock's existing
  never-execute path. It does not run `npm`, `pnpm`, `yarn`, lifecycle scripts,
  imports, or subprocesses from analyzed packages.
- `analyze_package_install` uses the same safe fetch/analyze/detect sequence as
  the Wave 8 `vetlock add` gate, but omits its final package-manager shellout.
- Lockfile paths must be absolute regular files and are capped at 5 MiB.
- MCP is not an enforcement boundary. Pair it with `vetlock add`/guard, a
  package-manager wrapper, or registry policy that rejects installs without a
  valid receipt.
- Receipts are `sha256-deterministic-unsigned`. They protect against accidental
  or obvious tampering but **do not authenticate an issuer**. Signing support is
  intentionally deferred until a user-controlled key-storage/key-rotation model
  is supplied; never treat these receipts as authorization tokens.
- The project hash is a local context hash, not a source-code attestation. An
  enforcement integration must compare the receipt's artifact and project hash
  to the exact install request.

## Receipt workflow

1. Call `analyze_package_install`.
2. Call `evaluate_policy` with its findings.
3. Call `issue_admission_receipt` using the returned artifact/project hashes,
   exact resolved package version, policy and findings.
4. Before an enforced install, call `verify_admission_receipt` and independently
   compare its bound values to the artifact and project being installed.
