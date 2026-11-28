# File Management

This document specifies the file transfer behavior of the App Mesh file API: the transferable area, upload, download, and delete semantics, and the attribute rules shared by the CLI and every SDK. The endpoint list lives in [REST API](../interfaces/RESTAPI.md); the directory layout and file life time live in [Work Directory Specification](../deploy/WorkDir.md).

## 1. Transferable area

- With the packaged defaults, only `work/share` and `work/workspaces` are exchangeable; every other path under the work directory is refused.
- The daemon's own installation tree (the directory that holds `bin/`, `ssl/`, `config/`, `script/`, and `work/`) is refused in both directions regardless of configuration; symbolic links into it are resolved before the check.
- Pseudo filesystems (`/proc`, `/sys`, `/dev`) are refused on every transfer: their files stat as empty regular files and would download as empty bodies.
- An unset `REST.FileAllowedBaseDir` jails transfers to the work directory tree. Set it to an absolute path to open another tree: the whole external tree becomes exchangeable and the work directory does not.
- `share/` is world-writable with the sticky bit: every execution user can create files, and each user can delete only their own files. Do not store secrets in it.

## 2. Addressing and modes

| Header | Rule |
| --- | --- |
| `X-File-Path` | Absolute path; percent-encoded UTF-8. The daemon and the agent are the only decode points |
| `X-File-Mode` | Decimal file mode (for example `493` for `0755`), matching the `st_mode` convention used by the SDKs. A value outside `0..511` (for example the octal digits `"755"`) is ignored on every transport — the file keeps its default mode; it is never masked |
| `X-File-Overwrite` | `true` to replace an existing destination |

## 3. Upload and download

- Uploads never overwrite by default: an existing destination returns `409`. Send `X-File-Overwrite: true` to replace it; the new content is published atomically.
- Applying or sending POSIX mode, owner, and group metadata is opt-in because identities commonly differ between machines and containers:

| Surface | Opt-in form |
| --- | --- |
| Python, JavaScript | optional permission/attribute argument, default `false` |
| Go | explicit boolean argument |
| Rust | explicit boolean argument |
| Java | explicit boolean argument |
| CLI | `--apply-permissions` |

- Overwrite is opted in per surface as well: Python, JavaScript, and Java take an `overwrite` flag on the upload method, Rust exposes `upload_file_with`, Go takes `UploadOptions{Overwrite: true}`, and the CLI uses `--overwrite`. The wire form is `X-File-Overwrite: true` on every transport.

## 4. Delete

`DELETE /appmesh/file/delete` removes one regular file named by `X-File-Path`:

- it is guarded by the dedicated `file-delete` permission, independent of `file-upload`;
- a missing file returns `404`;
- a directory or anything other than a regular file is refused.

## 5. Signatures

The five file routes (`/appmesh/file/download`, `/appmesh/file/upload`, `/appmesh/file/delete`, and the two `/ws` data-channel variants) are exempt from the request-signature body hash: they sign the empty string in place of the body, and the signed path is the file route without the trailing `/ws`. See [Security](../security/Security.md#signature-format).

## 6. Related

- [Work Directory Specification](../deploy/WorkDir.md) — layout, life time, and the exchange rules behind this API
- [REST API](../interfaces/RESTAPI.md) — endpoint reference
- [Secure REST file server](../success/secure_REST_file_server.md) — a worked recipe
