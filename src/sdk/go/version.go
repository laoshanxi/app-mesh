package appmesh

// SDKVersion is the Go SDK version. It is the artifact the release convention
// bumps whenever the SDK changes, mirroring the version constants of the
// sibling SDKs (setup.py, Cargo.toml, package.json, pom.xml).
// 3.0.24 adds the UploadOptions overwrite flag on every transport's upload:
// it sends X-File-Overwrite so the engine replaces an existing file instead of
// answering 409. The default stays no-overwrite. It also adds the Workflow
// secret broker calls (ProtectWorkflowSecretsContext and
// UnprotectWorkflowSecretsContext) used by the bundled engine.
const SDKVersion = "3.0.24"
