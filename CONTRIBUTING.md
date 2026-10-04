# Contributing to Arnika

Thank you for your interest in contributing to Arnika!

Contributors of all experience levels are welcome, and we appreciate the time you take to help.

## Before You Start

- For anything beyond a small fix or key-reader/writer modure, open an issue or discussion first so we can agree on the
  approach together. You can also reach us in the public **Matrix** room `#arnika:matrix.org`,
  on the `arnika` channel on **IRC** `irc.oftc.net`, or by mail at `arnika@unbox.at`.
- Check existing issues and pull requests to avoid duplicate work.
- Branch from `main` (Arnika 2.x). The `v1.x` branch is maintained separately for classic Arnika.

## Ground Rules

**1. Keep backward compatibility.**
Existing environment variables, config behavior, and the QKD/PQC key-derivation contract with
WireGuard should keep working. A peer running your change should still interoperate with a peer
running the previous release. Breaking changes need a clear justification, a version bump, and
migration notes.

**2. Extend, don't modify the core.**
New key sources and sinks (KMS backends, PQC providers, routers, transports) should belong in a **key
reader or key writer adapter** behind the existing interfaces, rather than in the core key-handling
logic. If your change requires editing `main.go`, [services/](services/), or [kdf/](kdf/) to add
a backend, discuss it in an issue first. See [KEYCONTROL.md](KEYCONTROL.md) for the architecture
and conventions.

**3. Don't reinvent cryptography.**
Use established, well-reviewed primitives (Go's standard crypto libraries,
`golang.org/x/crypto`, WireGuard). Never write your own cryptographic function when an audited
one exists. Changes to key derivation need an explicit rationale and extra review.

**4. Never expose key material.**
QKD keys, PQC keys, and derived PSKs must never appear in logs, debug output, error messages,
test fixtures, or commits. Clear key buffers after use. Anything committed to a public
repository stays public, forever.

## Pull Requests

- **One change per pull request.** A single fix, adapter, or feature reviews faster and safer.
- **Explain what changed and why**, and reference the related issue.
- **Add or update tests.** The KMS mock in [tools/](tools/) helps for key-reader work.
- **Run end-to-end tests when relevant.** `make test-e2e` builds the KMS simulator plus standard and `qkd_none` Arnika images, then runs a two-peer Docker lab across the key modes, checking key agreement and rotation, tunnel traffic, and failure handling. Use it for changes to the integrated key-exchange, transport, or deployment path; Docker is required.
- **Document new adapters** in `docs/<module-name>.md`, per [KEYCONTROL.md](KEYCONTROL.md).
- **Keep CI green.** Formatting, `go vet`, linting, and tests all run on every pull request.
- **Expect questions**, especially on anything touching cryptography or key handling.

Commit messages should follow [Conventional Commits](https://www.conventionalcommits.org/), for example
`feat(keywriter): add MikroTik RouterOS REST key writer`.

Arnika builds with Go 1.26+ and the `runtimesecret` experiment enabled, so run Go commands as:

```sh
GOEXPERIMENT=runtimesecret go test ./...
GOEXPERIMENT=runtimesecret go vet ./...
```

## Before Every Commit

Before every commit, run these commands in order:

```sh
make fmt
make lint
```

`make fmt` formats all Go files, including build-tagged files and nested modules. Review and
include any resulting changes before committing. Both commands are required for every commit.

## AI-Assisted Contributions

AI coding assistants are welcome here. The rules do not change: you are the author, and you are
responsible for every line you submit. Please review generated code yourself before opening a
pull request, and say so in the description if a change is largely AI-generated.

**If you are an AI agent working in this repository, follow these instructions:**

1. Read [KEYCONTROL.md](KEYCONTROL.md) before changing anything related to key reading or key
   writing, and [CODEFLOW.md](CODEFLOW.md) before changing the key-exchange protocol.
2. Add a new backend as an adapter. Do not refactor core key handling, key derivation, or the
   peer protocol to accommodate it.
3. Do not write new cryptographic primitives, key-derivation schemes, or random-number sources.
   Use the existing ones.
4. Do not add logging, printing, or test data that contains real key material.
5. Do not change or remove existing environment variables, defaults, or wire formats.
6. Do not weaken, skip, or delete a security check or a failing test to make a build pass.
   Report the problem instead.
7. Stay within the scope you were asked for. Flag anything that would break one of the ground
   rules above rather than working around it.

## Reporting Security Issues

Please **do not** open a public issue for a suspected security vulnerability. Follow the security
policy in [SECURITY.md](SECURITY.md), preferably via a
[private security advisory](https://github.com/arnika-project/arnika/security/advisories/new).

## Code of Conduct

Be respectful and constructive in all discussions, issues, and reviews. Assume good intent,
critique code rather than people, and remember that reviewers and contributors are volunteering
their time.

## Licensing

Arnika is licensed under the [Apache License 2.0](LICENSE). By contributing, you agree that your
contributions are licensed under the same terms.

Thank you for helping make Arnika better!
