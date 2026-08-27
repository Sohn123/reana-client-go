# REANA-Client-Go

[![image](https://github.com/reanahub/reana-client-go/workflows/CI/badge.svg)](https://github.com/reanahub/reana-client-go/actions)
[![image](https://codecov.io/gh/reanahub/reana-client-go/branch/master/graph/badge.svg)](https://codecov.io/gh/reanahub/reana-client-go)
[![image](https://img.shields.io/badge/discourse-forum-blue.svg)](https://forum.reana.io)
[![image](https://img.shields.io/github/license/reanahub/reana.svg)](https://github.com/reanahub/reana-client-go/blob/master/LICENSE)

## About

REANA-Client-Go is a component of the [REANA](https://www.reana.io/) reusable
and reproducible research data analysis platform. It provides a command-line
tool that allows researchers to submit, run, and manage their computational
workflows.

- seed workspace with input code and data
- run computational workflows on remote compute clouds
- list submitted workflows and enquire about their statuses
- download results of finished workflows

## Usage

The detailed information on how to install and use REANA can be found in
[docs.reana.io](https://docs.reana.io).

### Bundling additional workflow source files

The `create` and `validate` commands upload a scoped specification bundle for
server-side workflow loading. Declare every imported source explicitly under
`workflow.files` or `workflow.directories` so it is available to the loader.

For example, given this Snakemake project:

```text
analysis/
├── reana.yaml
├── Snakefile
└── rules/
    └── common.smk
```

where `Snakefile` contains `include: "rules/common.smk"`, declare the included
source in `reana.yaml`:

```yaml
version: 0.9.0
workflow:
  type: snakemake
  file: Snakefile
  directories:
    - rules
```

Paths are relative to the directory containing the selected specification.
Absolute paths, paths that escape through `..`, and symbolic links are rejected.
Use `workflow.files` only for workflow definitions and configuration needed
while loading the workflow; input datasets belong under `inputs.files` or
`inputs.directories`.

Validation snapshots accept at most 1,000 files, 2,000 directories, 100 MiB of
file content, and 64 relative path components. Symbolic links are not followed.

`reana-client-go validate --environments` performs offline image-reference
checks and reports effective runtime identities. Add `--pull` to verify
availability and inspect those images with your local container runtime and
registry credentials; the REANA server does not contact image registries.

### Authentication

Authenticate against a REANA deployment using the browser-based OIDC flow:

```console
$ reana-client-go login --server-url https://reana.example.org
```

On a remote or browserless machine, use the interactive device flow instead:

```console
$ reana-client-go login --headless --server-url https://reana.example.org
```

Browser login normally uses an OS-assigned loopback port. If the identity
provider requires an exact redirect URI, set
`REANA_CLIENT_LOGIN_LOOPBACK_PORT=<port>` and register
`http://127.0.0.1:<port>/callback`. Login fails with an actionable error if the
configured port is invalid or already occupied.

The client stores renewable OIDC credentials in the shared REANA client
configuration at `~/.config/reana/reana-client.json`, or at the path selected by
`REANA_CLIENT_CONFIG`. The file is permission-restricted to `0600`. Use
`reana-client-go logout` to revoke and remove the credentials. The
`--access-token` option remains available as an explicit per-command override.

For CI, obtain credentials once with an interactive browser or headless login,
store the JSON as a protected secret, and restore it to a unique private file:

```console
$ credential_file="$(mktemp)"
$ trap 'rm -f "$credential_file"' EXIT
$ chmod 600 "$credential_file"
$ printf '%s' "$REANA_CREDENTIALS_SECRET" > "$credential_file"
$ export REANA_CLIENT_CONFIG="$credential_file"
```

This immutable-secret pattern is safe only when the issuer permits reuse of the
stored refresh token. If refresh-token rotation invalidates the previous token,
the client writes the replacement only to the current job's local file; later or
concurrent jobs restoring the original secret will fail. Such deployments need a
mutable, serialised secret store or an issuer-supported non-rotating service
credential.

TLS certificate verification is enabled by default. Private deployments can set
`REANA_SERVER_CA_CERTS` to a PEM CA bundle. `REANA_INSECURE=true` disables
verification only when no CA bundle is configured and should be limited to local
testing.

## Shell completion

The `reana-client-go` supports shell completion for Bash and Zsh. To enable the
auto-completion of commands and options, add the following to your shell
configuration file:

**Bash** (add to `~/.bashrc`):

```bash
source <(reana-client-go completion bash)
```

**Zsh** (add to `~/.zshrc`):

```bash
source <(reana-client-go completion zsh)
compdef _reana-client-go reana-client-go
```

## Useful links

- [REANA project home page](http://www.reana.io/)
- [REANA user documentation](https://docs.reana.io)
- [REANA user support forum](https://forum.reana.io)
- [REANA-Client-Go known issues](https://github.com/reanahub/reana-client-go/issues)
- [REANA-Client-Go source code](https://github.com/reanahub/reana-client-go)
