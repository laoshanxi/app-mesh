#!/usr/bin/python3
# pylint: disable=line-too-long
"""Provision OAuth2 (Keycloak) on a running App Mesh daemon — entirely through the SDK.

Use this when the daemon runs where you cannot edit files directly (e.g. inside a
container): it uploads ``work/config/oauth2.yaml`` and persists
``REST.JWT.SecurityInterface: oauth2`` over the TCP API. The security backend is chosen
at daemon startup, so restart the daemon afterwards to activate it.

The Keycloak URL is embedded in every token as the issuer, and the daemon only accepts
tokens whose issuer matches its own ``auth_server_url``. Therefore the URL must be
reachable — as the SAME string — from BOTH the daemon and your test clients.
Two workable choices when the daemon is in a local container:

  1. ``http://<LAN-IP>:8080`` (this script's default, auto-detected): needs no host
     setup, but the IP changes when you switch networks — re-run this script then.
  2. ``http://host.docker.internal:8080`` (pass via --keycloak-url): stable forever on
     one machine, but requires a one-time host-side line so the HOST can resolve it too:
         sudo sh -c 'echo "127.0.0.1 host.docker.internal" >> /etc/hosts'

Usage:
    export APPMESH_Keycloak_client_secret=...   # from keycloak-init.sh; never commit
    python3 setup_oauth2_daemon.py                          # auto-detect LAN IP
    python3 setup_oauth2_daemon.py --keycloak-url http://192.168.1.10:8080

    # then restart the daemon (e.g. docker restart <container>) and verify:
    KEYCLOAK_URL=http://<same-url> python3 smoke_oauth2.py

Environment:
    APPMESH_ADMIN_USER / APPMESH_ADMIN_PWD  daemon admin for provisioning (default admin/admin123)
    APPMESH_Keycloak_client_secret          Keycloak client secret (empty = public client)
"""

import argparse
import os
import socket
import sys
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))  # -> src/sdk/python
from appmesh import AppMeshClientTCP


def detect_lan_ip() -> str:
    """Return this host's outbound LAN IP (no traffic is actually sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def main() -> None:
    """Provision oauth2.yaml + SecurityInterface on the daemon via the TCP SDK."""
    parser = argparse.ArgumentParser(description="Provision OAuth2 (Keycloak) on an App Mesh daemon via the SDK")
    parser.add_argument("--keycloak-url", default=None, help="Keycloak base URL reachable from daemon AND clients (default: http://<LAN-IP>:8080)")
    parser.add_argument("--realm", default="appmesh-realm", help="Keycloak realm (default: appmesh-realm)")
    parser.add_argument("--client-id", default="appmesh-client", help="Keycloak client ID (default: appmesh-client)")
    parser.add_argument("--tcp-host", default="127.0.0.1", help="daemon TCP host (default: 127.0.0.1)")
    parser.add_argument("--tcp-port", type=int, default=6059, help="daemon TCP port (default: 6059)")
    args = parser.parse_args()

    keycloak_url = args.keycloak_url or f"http://{detect_lan_ip()}:8080"
    secret = os.environ.get("APPMESH_Keycloak_client_secret", "")
    if not secret:
        print("WARNING: APPMESH_Keycloak_client_secret is empty — assuming a public Keycloak client")

    client = AppMeshClientTCP(tcp_address=(args.tcp_host, args.tcp_port), ssl_verify=False)
    # Local-mode daemon → admin user; daemon already in oauth2 mode → Keycloak user.
    candidates = [
        (os.environ.get("APPMESH_ADMIN_USER", "admin"), os.environ.get("APPMESH_ADMIN_PWD", "admin123")),
        (os.environ.get("TEST_USER", "mesh"), os.environ.get("TEST_PWD", "mesh123")),
    ]
    last_error = None
    for user, pwd in candidates:
        try:
            client.login(user, pwd)
            print(f"provisioning as '{user}'")
            break
        except Exception as exc:  # pylint: disable=broad-exception-caught
            last_error = exc
    else:
        client.close()
        sys.exit(f"ABORT: could not login with any candidate user: {last_error}")

    # 1) The daemon must be able to reach Keycloak at this URL (JWKS, login proxy).
    probe = f"python3 -c 'import urllib.request; print(urllib.request.urlopen(\"{keycloak_url}/realms/{args.realm}\", timeout=5).status)'"
    code, out = client.run_app_sync(probe, max_time=30, lifecycle=60)
    if code != 0 or "200" not in out:
        client.close()
        sys.exit(f"ABORT: daemon cannot reach {keycloak_url} (exit={code}): {out.strip()[:200]}")
    print(f"daemon can reach Keycloak at {keycloak_url}: OK")

    # 2) Upload oauth2.yaml to the preferred read location work/config/.
    oauth2_yaml = (
        "---\n"
        "Keycloak:\n"
        f"  auth_server_url: {keycloak_url}\n"
        f"  realm: {args.realm}\n"
        f"  client_id: {args.client_id}\n"
        f'  client_secret: "{secret}"\n'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
        tmp.write(oauth2_yaml)
        tmp_path = tmp.name
    os.chmod(tmp_path, 0o600)
    try:
        # The upload API refuses to overwrite; drop any previous provisioning first.
        client.run_app_sync("rm -f /opt/appmesh/work/config/oauth2.yaml", max_time=30, lifecycle=60)
        client.upload_file(local_file=tmp_path, remote_file="/opt/appmesh/work/config/oauth2.yaml")
    finally:
        os.unlink(tmp_path)
    print("uploaded /opt/appmesh/work/config/oauth2.yaml")

    # 3) Persist the backend switch (takes effect on next daemon start).
    result = client.set_config({"REST": {"JWT": {"SecurityInterface": "oauth2"}}})
    print("SecurityInterface:", result.get("REST", {}).get("JWT", {}).get("SecurityInterface"))
    client.close()

    print("\nDONE — restart the daemon to activate, then verify with:")
    print(f"  KEYCLOAK_URL={keycloak_url} python3 smoke_oauth2.py")
    print(f"  KEYCLOAK_URL={keycloak_url} python3 smoke_oauth2.py --device")


if __name__ == "__main__":
    main()
