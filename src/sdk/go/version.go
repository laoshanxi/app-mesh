package appmesh

// SDKVersion is the Go SDK version. It is the artifact the release convention
// bumps whenever the SDK changes, mirroring the version constants of the
// sibling SDKs (setup.py, Cargo.toml, package.json, pom.xml).
// 3.0.24 adds the UploadOptions overwrite flag on every transport's upload:
// it sends X-File-Overwrite so the engine replaces an existing file instead of
// answering 409. The default stays no-overwrite. It also adds the Workflow
// secret broker calls (ProtectWorkflowSecretsContext and
// UnprotectWorkflowSecretsContext) used by the bundled engine.
// 3.0.25 completes a sync run past the first reply page: RunAppSync and
// RunAppSyncChecked page the rest of a truncated run. RunAppSyncWithContext
// and RunAppSyncCheckedContext add a context and SyncRunOptions.MaxOutputBytes
// (error instead of a truncated result). Existing signatures are unchanged.
// 3.0.26 makes Application.Enabled a *bool: an unset value is omitted from the
// registration body, so the daemon keeps its enabled default like the other
// SDKs (a zero-value false registered every app as disabled).
const SDKVersion = "3.0.26"
