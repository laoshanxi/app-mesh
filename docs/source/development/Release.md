# Release Process

This document describes the release pipelines: what each one produces, when it runs, and how the version is set. Build-from-source instructions live in [Build](Build.md).

## 1. Version and triggers

- The version is pinned per workflow in the `APPMESH_VERSION` environment variable (for example `3.0.1`). A release raises the value in every release workflow together.
- Every release workflow runs in two modes: on push to `main` when its source paths change (`src/**`, `script/**`, and the workflow file itself), and manually through `workflow_dispatch`.
- Package workflows attach their artifacts to the GitHub release tagged with `APPMESH_VERSION`.

## 2. Pipelines

| Workflow | Artifacts | Notes |
| --- | --- | --- |
| `release-linux` | `.deb` and `.rpm` per Ubuntu platform, plus `.bundle` offline bundles | Builds on `linux/amd64` and `linux/arm64`; installs the deb in a container and smoke-tests the daemon, token minting, and `appm ls`; signs RPMs with GPG; produces SLSA attestations for every package |
| `release-macos` | macOS package | Build, test, publish, with installer verification |
| `release-windows` | Windows installer | Build and test |
| `release-image` | `laoshanxi/appmesh` container image | Builds per-platform images, merges and pushes a multi-arch manifest |
| `release-image-agent` | `laoshanxi/appmesh_agent` container image | Same merge-and-push flow for the agent image |
| `release-sdk-python` | Python SDK on PyPI | Uploads the `appmesh` package |
| `release-sdk-js` | JavaScript SDK on npm | OIDC trusted publishing |
| `release-sdk-java` | Java SDK to GitHub Packages; Maven Central when configured | The Maven Central publish requires the `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` secrets; without them it is skipped |
| `release-sdk-rust` | Rust crate | Build and release |

## 3. Verification

A release round is green when:

1. every release workflow succeeds for the pinned version;
2. the GitHub release with tag `APPMESH_VERSION` carries the expected packages;
3. the SDK registries list the new version (the JavaScript SDK version follows `src/sdk/javascript/package.json`; the release must carry the matching bump).

## 4. Related

- [Build](Build.md) — building from source and inside Docker
- [Coverity](Coverity.md) — static analysis
- [Port Specification](../deploy/Ports.md) — the listeners the packages configure
