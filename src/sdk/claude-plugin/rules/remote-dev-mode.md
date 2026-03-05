## Remote Dev Mode Rules

When `APPMESH_WORKSPACE` is set, remote execution mode is active.

### Local (Claude native tools)
- Read / Edit / Write / Grep / Glob → local files
- Git → local git

### Remote (via remote.py)
- Build / Test → `remote.py sync-exec "<cmd>"`
- System commands → `remote.py exec "<cmd>"`
- Run a script file → `remote.py run-script <file>`
- Deploy → `remote.py deploy <name> "<cmd>"`

### Environment Variables
- `APPMESH_HOST` — server URL (default: `https://127.0.0.1:6060`)
- `APPMESH_WORKSPACE` — remote working directory (required)
- `APPMESH_PASSWORD` — password (default: `admin123`)
- `APPMESH_SSL_VERIFY` — SSL verification (default: `false`)
- `APPMESH_SYNC_EXCLUDE` — extra sync excludes, comma-separated (optional)
