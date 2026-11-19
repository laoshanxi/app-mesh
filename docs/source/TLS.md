# TLS and certificates

App Mesh uses TLS on every listener by default. Plaintext is an explicit choice
for a trusted network behind a TLS-terminating gateway.

## Listener configuration

The `REST.SSL` section of `config.yaml` controls the daemon listeners. The Go
agent reads the same file and the same environment overrides. A relative
certificate path resolves against the App Mesh home directory: `/opt/appmesh`
on Linux and macOS, `C:\local\appmesh` on Windows.

| Key | Packaged default | Description |
| --- | --- | --- |
| `SSLEnabled` | `true` | `false` makes every listener accept plaintext and ignores the certificate paths. An absent key keeps TLS on. |
| `SSLCaPath` | `ssl/ca.pem` | CA bundle used to verify peers. The value can be a file or a directory of PEM files. |
| `SSLCertificateFile` | `ssl/server.pem` | Server certificate chain. |
| `SSLCertificateKeyFile` | `ssl/server-key.pem` | Server private key. |
| `SSLClientCertificateFile` | `ssl/client.pem` | Client certificate presented to peers. |
| `SSLClientCertificateKeyFile` | `ssl/client-key.pem` | Client private key. |
| `VerifyClient` | `false` | `true` requires a valid client certificate on incoming connections (mTLS). |
| `VerifyServer` | `false` | `true` verifies the peer certificate on outgoing connections. The packaged value is `false` because the generated certificates are self-signed. |

Override a key with `APPMESH_REST_SSL_<Key>`, for example
`APPMESH_REST_SSL_VerifyServer=true`.

Listeners: `6058` serves HTTPS REST and WSS, `6059` the TCP frame API over TLS,
and `6060` the Go agent entry (same `REST.SSL` settings; the daemon does not
bind this port). A missing or unreadable certificate stops a TLS listener; App
Mesh never degrades it to plaintext.

The authentication service is outside `REST.SSL`: the issuer listens over plain
HTTP on `6062`, health on `6063`, the `dexuser` administration UI on `6064` on
loopback, and the Dex gRPC administration listener on `5557` on loopback with
mutual TLS when the administration UI is enabled. See
[Authentication](Authentication.md).

## Certificates

`APPMESH_SSL_SOURCE` selects the certificate source: `file` (default) gives
each node a self-signed set; `vault` signs every node's leaves from one cluster
CA in the Vault PKI engine. A plaintext deployment uses no certificate
material, and the container entry point skips certificate preparation in that
mode.

With the file source, the installation creates the set when `ssl/server.pem` is
absent, and the container entry point stops when the set is incomplete. The
generator `script/ssl/generate_ssl_cert.sh` (`.ps1` on Windows) uses ECDSA
prime256v1, leaves valid for 825 days (the Apple TLS limit), CA valid for 10
years. The server certificate covers `localhost`, `127.0.0.1`, the host name,
and the local IP addresses. Add peer names with `APPMESH_SSL_EXTRA_SAN`;
reuse an existing CA with `APPMESH_SSL_CA_CERT` and `APPMESH_SSL_CA_KEY`.

| File | Use |
| --- | --- |
| `ca.pem` | CA certificate. |
| `ca-key.pem` | CA private key. File source only. Keep it private. |
| `server.pem`, `server-key.pem` | Server certificate and key. |
| `client.pem`, `client-key.pem` | Client certificate and key for mTLS. |

### Vault PKI source

With `APPMESH_SSL_SOURCE=vault`, `appmesh-auth.sh bootstrap` requests the five
daemon files: `ca.pem`, `server.pem`, `server-key.pem`, `client.pem`, and
`client-key.pem`. There is no `ca-key.pem`: the CA private key stays in Vault.
Set the source in the installer environment, so the bootstrap issues the files
before the installer checks them.

| Setting | Default | Use |
| --- | --- | --- |
| `APPMESH_SSL_VAULT_ADDR` | The replication Vault address | Vault API address. |
| `APPMESH_SSL_VAULT_TOKEN_FILE` | The replication token file | One line for a service token, two lines for an AppRole pair. |
| `APPMESH_SSL_VAULT_PKI_ROLE` | `appmesh-node` | Issuing role. |

The role issues leaves with the same name coverage as the file source;
`generate_ssl_cert.sh --san-list` prints that list for an external issuer. The
compose overlay `script/docker/docker-compose.vault.yaml` selects this source
for every node. The bootstrap is idempotent by trust: material that does not
chain to the current Vault CA is re-issued. Renew with
`appmesh-auth.sh tls-renew`, then restart the node, because the daemon loads
certificates only at start. A Vault outage fails closed.

Vault drops DNS names with underscores: use a hyphenated peer name in
`APPMESH_SSL_EXTRA_SAN` and in the issuer URL. The root certificate must carry
a subject; the packaged sidecar sets `common_name="AppMesh Root CA"`. Both
sources write `ca.pem` to the same `ssl` directory, so the client default trust
does not change with the source.

## Client settings

A client verifies the server certificate by default. No interface disables
verification implicitly. Each interface gives an explicit way to pin a CA, to
disable verification, or to select plaintext.

| Interface | Verify peer | Pin a CA | Client certificate (mTLS) | Plaintext |
| --- | --- | --- | --- | --- |
| CLI | Local Engine configuration; `--no-verify` for any endpoint | `--ca-cert PATH` | Local Engine configuration only | `-H ws://host:6058` or `-H http://host:6058` |
| Python SDK | `ssl_verify=None` (auto), `True`, `False` | `ssl_verify="<path>"` | `ssl_client_cert` | `plain_transport=True` (framed); a REST base URL can use `http://` |
| Rust SDK | Default; `danger_accept_invalid_certs(true)` | `ssl_ca_cert(path)` | `ssl_client_auth(cert, key)` | `plain_transport(true)` |
| Go SDK | Default; `Option{InsecureSkipVerify: true}` | `Option{SSLTrustedCA: &path}` | `Option{SSLClientCertificateFile, SSLClientCertificateKeyFile}` | `TCPConnection.ConnectPlain`, `ws://` URL |
| Java SDK | Default; `Builder.disableSSLVerify()` | `Builder.caCert(path)` | `Builder.clientCert(cert, key)` | Framed transports are TLS-only; a REST base URL can use `http://` |
| JavaScript SDK | `sslConfig.rejectUnauthorized`; `sslConfig: false` disables | `sslConfig.ca` | `sslConfig.cert`, `sslConfig.key` | Framed transports are TLS-only; a REST base URL can use `http://` |

The automatic default uses the App Mesh CA bundle if it is installed, and the
system CAs if it is absent. A configured CA path that does not exist is a hard
error. In the Python, Rust, and Go SDKs, an empty CA path is the legacy
explicit disable form.

### CLI endpoint memory

The CLI records the endpoint it last reached with the transport settings that
reached it: TLS or plaintext, the CA path, and whether the server certificate
is verified. A later command reuses those settings.

- The local Engine address comes from its `config.yaml`, which stays
  authoritative on every command. `--no-verify` or `--ca-cert` applies to that
  command only.
- A remote endpoint never inherits the local Engine's verification setting or
  client key material.
- `--ca-cert` is stored as an absolute path. A relative path works for the
  current command. A symlink stays unresolved, so a certificate rotation behind
  the link keeps working.
- `--no-verify` is an explicit insecure choice and conflicts with `--ca-cert`.
- A plaintext endpoint (`ws://` or `http://`) is remembered with its scheme.
- A configuration file from an older CLI is upgraded on the first read. If a
  remembered CA path is relative or missing, the CLI discards the remembered
  endpoint, prints one warning, and falls back to the local Engine. A file from
  a newer CLI is used as-is.

Cluster trust patterns — one CA per target client, a shared CA directory, or a
Vault-issued cluster — and their tested procedures are in
[Cluster authentication design](cluster/ClusterAuthDesign.md#cluster-tls-trust).

## Plaintext deployments

Set `REST.SSL.SSLEnabled: false` only when a trusted gateway terminates TLS:
every listener accepts plaintext and the certificate paths are ignored. Keep
the listeners on the trusted network segment, and enable request signatures.
See [Security](Security.md#deployment-behind-a-tls-terminating-gateway).
