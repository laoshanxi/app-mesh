"""Test Python SDK"""

import sys
import os
import stat
import json
import unittest
import tempfile
from http.cookiejar import Cookie
from unittest import TestCase
from pyotp import TOTP

# For source code env:
current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_directory))

# For wheel package
# python3 -m pip install --upgrade appmesh pyotp
from appmesh import AppMeshClient, AppMeshClientTCP, App

# python3 -m unittest test_appmesh_client.TestAppMeshClient.test_user


def get_test_paths():
    """return platform specific paths"""
    tmpdir = tempfile.gettempdir()
    if sys.platform == "win32":
        return {
            "server_log": r"C:\local\appmesh\work\server.log",
            "tmp_file": os.path.join(tmpdir, "2.log"),
            "tmp_file2": os.path.join(tmpdir, "3.log"),
            "etc_file": r"C:\Windows\System32\drivers\etc\hosts",
            "etc_copy": os.path.join(tmpdir, "hosts-copy"),
        }
    elif sys.platform.startswith("darwin"):
        # macOS: use /etc/hosts for etc_file, and a temp copy place
        return {
            "server_log": "/opt/appmesh/work/server.log",
            "tmp_file": os.path.join(tmpdir, "2.log"),
            "tmp_file2": os.path.join(tmpdir, "3.log"),
            "etc_file": "/etc/hosts",
            "etc_copy": os.path.join(tmpdir, "hosts-copy"),
        }
    else:
        # Linux or other
        return {
            "server_log": "/opt/appmesh/work/server.log",
            "tmp_file": "/tmp/2.log",
            "tmp_file2": "/tmp/3.log",
            "etc_file": "/etc/os-release",
            "etc_copy": "/tmp/os-release-1",
        }


def get_ping_command():
    """return platform specific ping command"""
    if sys.platform == "win32":
        return "ping cloudflare.com -n 5 -w 2000"
    elif sys.platform.startswith("darwin"):
        # On macOS, -c count, -W wait (in ms) is not supported, use -c and maybe -t TTL
        # Use `ping -c 5 github.com`
        return "ping cloudflare.com -c 5"
    else:
        # Linux
        return "ping cloudflare.com -w 5"


class TestAppMeshClient(TestCase):
    """
    unit test for AppMeshClient
    """

    DEFAULT_PASSWORD = "admin123"

    def test_09_app_run(self):
        """test app run"""
        client = AppMeshClient()
        client.login("admin", self.DEFAULT_PASSWORD)
        client.forward_to = "127.0.0.1"
        metadata = {"subject": "subject", "message": "msg"}

        app_data = {"name": "ping", "metadata": json.dumps(metadata)}
        app = App(app_data)
        app.behavior.set_exit_behavior(App.Behavior.Action.REMOVE)
        self.assertEqual(
            9,
            client.run_app_sync(app=app, max_time_seconds=3, life_cycle_seconds=4)[0],
        )

        app_data = {"name": "whoami", "command": "whoami", "metadata": json.dumps(metadata)}
        self.assertEqual(
            0,
            client.run_app_sync(app=App(app_data), max_time_seconds=5, life_cycle_seconds=6)[0],
        )

        self.assertEqual(9, client.run_app_sync(App({"command": get_ping_command(), "shell": True}), max_time_seconds=4)[0])
        run = client.run_app_async(App({"command": get_ping_command(), "shell": True}), max_time_seconds=6)
        run.wait()

    def test_08_file(self):
        """test file"""
        paths = get_test_paths()
        client = AppMeshClientTCP()
        client.login("admin", self.DEFAULT_PASSWORD)
        # client.forward_to = "127.0.0.1:6059" # only for REST client, not for TCP client
        if os.path.exists("1.log"):
            os.remove("1.log")
        self.assertIsNone(client.download_file(paths["server_log"], "1.log"))
        self.assertTrue(os.path.exists("1.log"))

        # remove file if exists
        metadata = f"import os; [os.remove(r'{paths['tmp_file']}') if os.path.exists(r'{paths['tmp_file']}') else None]"
        self.assertEqual(0, client.run_app_sync(App({"name": "pyexec", "metadata": metadata}))[0])

        self.assertIsNone(client.upload_file(local_file="1.log", remote_file=paths["tmp_file"]))
        self.assertIsNone(client.download_file(remote_file=paths["tmp_file"], local_file=paths["tmp_file2"]))
        self.assertTrue(os.path.exists(paths["tmp_file2"]))
        os.remove("1.log")

        # copy etc file
        metadata = f"import shutil;shutil.copy(r'{paths['etc_file']}', r'{paths['etc_copy']}')"
        self.assertEqual(0, client.run_app_sync(App({"name": "pyexec", "metadata": metadata}))[0])

        self.assertIsNone(client.download_file(paths["etc_file"], "etc-local"))
        with open(paths["etc_copy"], "r", encoding="utf-8") as etc:
            with open("etc-local", "r", encoding="utf-8") as local:
                self.assertEqual(etc.read(), local.read())
        os.remove("etc-local")

    def test_04_config(self):
        """test config"""
        client = AppMeshClientTCP()
        client.login("admin", self.DEFAULT_PASSWORD)
        self.assertIn("cpu_cores", client.get_host_resources())
        self.assertIn("appmesh_prom_scrape_count", client.get_metrics())
        self.assertEqual(client.set_log_level("DEBUG"), "DEBUG")
        self.assertEqual(client.set_log_level("INFO"), "INFO")
        self.assertEqual(client.set_config({"REST": {"SSL": {"VerifyServer": True}}})["REST"]["SSL"]["VerifyServer"], True)

    def test_05_tag(self):
        """test tag"""
        client = AppMeshClient()
        client.login("admin", self.DEFAULT_PASSWORD)
        self.assertIsNone(client.add_label("MyTag", "TagValue"))
        self.assertIn("MyTag", client.list_labels())
        self.assertIsNone(client.delete_label("MyTag"))
        self.assertNotIn("MyTag", client.list_labels())

    def test_06_app(self):
        """test application"""
        client = AppMeshClient()
        client.login("admin", self.DEFAULT_PASSWORD)
        self.assertEqual(client.get_app("ping").name, "ping")
        for app in client.list_apps():
            self.assertTrue(hasattr(app, "name"))
            self.assertTrue(hasattr(app, "shell"))
            self.assertTrue(hasattr(app, "session_login"))
        self.assertEqual(client.check_app_health("ping"), True)
        client.get_app_output("ping")

    def test_07_app_mgt(self):
        """test application management"""
        client = AppMeshClient()
        client.login("admin", self.DEFAULT_PASSWORD)
        app = client.add_app(App({"command": "ping cloudflare.com -w 5", "name": "SDK"}))
        self.assertTrue(hasattr(app, "name"))

        self.assertTrue(client.delete_app("SDK"))
        self.assertFalse(client.delete_app("SDK"))
        self.assertIsNone(client.disable_app("ping"))
        self.assertIsNone(client.enable_app("ping"))

    def test_01_auth(self):
        """test authentication"""
        client = AppMeshClient()
        with self.assertRaises(Exception):
            client.login("admin", self.DEFAULT_PASSWORD, audience="appmesh-service-na")
        client.login("admin", self.DEFAULT_PASSWORD, audience="your-service-api")
        token = client._get_access_token()
        self.assertFalse(client.authenticate(token)[0])
        self.assertTrue(client.authenticate(token, audience="your-service-api")[0])

        client.login("admin", self.DEFAULT_PASSWORD, audience="appmesh-service")
        token = client._get_access_token()
        self.assertTrue(client.authenticate(token, audience="appmesh-service")[0])
        self.assertFalse(client.authenticate(token, audience="appmesh-service-na")[0])

        self.assertIsNotNone(client._get_access_token())

        client.renew_token(100)
        token2 = client._get_access_token()
        self.assertNotEqual(token, token2)

        self.assertFalse(client.authentication(token)[0])
        self.assertTrue(client.authenticate(token2)[0])

        self.assertTrue(client.logout())
        with self.assertRaises(Exception):
            client.list_apps()
        self.assertIsNone(client.login("admin", self.DEFAULT_PASSWORD))
        self.assertIsNotNone(client.list_apps())

    def test_02_user(self):
        """test user"""
        client = AppMeshClient()
        self.assertIsNone(client.login("admin", self.DEFAULT_PASSWORD))

        # Test password change - use password that meets complexity requirements
        # (works whether PasswordComplexityEnabled is true or false)
        temp_password = "Admin@456"
        try:
            self.assertIsNone(client.update_password(self.DEFAULT_PASSWORD, temp_password))
            # Login should fail with old password
            with self.assertRaises(Exception):
                client.login("admin", self.DEFAULT_PASSWORD)
            # Login should succeed with new password
            self.assertIsNone(client.login("admin", temp_password))
            # Change back to default
            self.assertIsNone(client.update_password(temp_password, self.DEFAULT_PASSWORD))
        finally:
            # Ensure password is restored even if test fails
            try:
                client.login("admin", temp_password)
                client.update_password(temp_password, self.DEFAULT_PASSWORD)
            except Exception:
                pass

        self.assertIsNone(client.login("admin", self.DEFAULT_PASSWORD))

        self.assertIn("permission-list", client.list_permissions())
        self.assertIn("permission-list", client.get_user_permissions())
        self.assertTrue(client.authenticate(client._get_access_token(), "app-view")[0])
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate("", "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate(client._get_access_token(), "app-view2"))

        self.assertIsNone(client.lock_user("mesh"))
        self.assertIsNone(client.unlock_user("mesh"))

        self.assertIsNone(client.update_role("manage", ["app-control", "app-delete", "app-reg", "config-set", "file-download", "file-upload", "label-delete", "label-set"]))

        self.assertIn("manage", client.list_roles())
        self.assertIn("admin", client.list_groups())
        self.assertIn("mesh", client.list_users())
        self.assertEqual(client.get_current_user()["email"], "admin@appmesh.com")

    def test_03_totp(self):
        """test TOTP"""
        client = AppMeshClient()
        client.login("admin", self.DEFAULT_PASSWORD)
        token = client._get_access_token()
        self.assertIsNotNone(token)
        # get totp secret
        totp_secret = client.get_totp_secret()
        # print(f"TOTP Secret: {totp_secret!r}")
        self.assertIsNotNone(totp_secret)
        # generate totp code
        totp = TOTP(totp_secret)
        totp_code = totp.now()
        print(totp_code)
        # setup totp
        self.assertIsNone(client.enable_totp(totp_code))

        # use totp code to login
        totp_code = totp.now()
        print(totp_code)
        self.assertIsNone(client.login("admin", self.DEFAULT_PASSWORD, totp_code))

        # use totp with 2 step login
        challange = client.login("admin", self.DEFAULT_PASSWORD)
        self.assertIsNotNone(challange)
        self.assertIsNone(client.validate_totp("admin", challange, totp_code))

        # disable totp
        self.assertIsNone(client.disable_totp())
        print("TOTP disabled")

    def read_file_content(self, file_path):
        """read file content"""
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    def test_11_cookies(self):
        """Test cookie creation, persistence, and reuse"""

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cookie_path = tmp.name

        try:
            # init empty cookie file
            os.remove(cookie_path) if os.path.exists(cookie_path) else None
            client = AppMeshClient(rest_cookie_file=cookie_path)
            # Cookie file is NOT created until first token write (lazy creation)
            self.assertFalse(os.path.exists(cookie_path))

            # cookie set (file created on login)
            client.login("admin", self.DEFAULT_PASSWORD)
            self.assertTrue(os.path.exists(cookie_path))

            # permission check (Unix only)
            if os.name == "posix":
                mode = stat.S_IMODE(os.stat(cookie_path).st_mode)
                self.assertEqual(mode, 0o600)
            content = self.read_file_content(cookie_path)
            self.assertIn("appmesh_auth_token", content)
            self.assertIn("appmesh_csrf_token", content)

            # cookie cleared on logoff
            client.logout()
            content_after = self.read_file_content(cookie_path)
            self.assertNotIn("appmesh_auth_token", content_after)
            self.assertNotIn("appmesh_csrf_token", content_after)

            # re-use cookie: should require login again
            client = AppMeshClient(rest_cookie_file=cookie_path)
            with self.assertRaises(Exception):
                client.list_apps()

            # re-login and verify user info
            client.login("admin", self.DEFAULT_PASSWORD)
            token = client._get_access_token()
            client = AppMeshClient(rest_cookie_file=cookie_path)
            user_info = client.get_current_user()
            self.assertIn("name", user_info)
            self.assertEqual(user_info["name"], "admin")

            # TOTP setup should update cookie file
            content_before_totp = self.read_file_content(cookie_path)

            # get totp secret
            totp_secret = client.get_totp_secret()
            # generate totp code
            totp = TOTP(totp_secret)
            totp_code = totp.now()
            # setup totp
            self.assertIsNone(client.enable_totp(totp_code))
            self.assertNotEqual(token, client._get_access_token())

            content_after_totp = self.read_file_content(cookie_path)

            self.assertIn("appmesh_auth_token", content_after_totp)
            self.assertIn("appmesh_csrf_token", content_after_totp)
            self.assertNotEqual(content_before_totp, content_after_totp)

            # Use totp code to login
            content_before_totp = self.read_file_content(cookie_path)

            client = AppMeshClient(rest_cookie_file=cookie_path)
            self.assertTrue(client.logout())
            totp_code = totp.now()
            print(totp_code)
            self.assertIsNone(client.login("admin", self.DEFAULT_PASSWORD, totp_code))
            self.assertIn("appmesh_auth_token", content_after_totp)
            self.assertIn("appmesh_csrf_token", content_after_totp)

            content_after_totp = self.read_file_content(cookie_path)

            self.assertIn("appmesh_auth_token", content_after_totp)
            self.assertIn("appmesh_csrf_token", content_after_totp)
            self.assertNotEqual(content_before_totp, content_after_totp)

            self.assertIsNone(client.disable_totp())

        finally:
            try:
                client = AppMeshClient(rest_cookie_file=cookie_path)
                client.disable_totp()
            except Exception:
                pass
            os.remove(cookie_path) if os.path.exists(cookie_path) else None

    def test_12_set_token(self):
        """Test set_token, jwt_token constructor, with and without cookie file"""

        # 1. set_token without cookie file (in-memory)
        client = AppMeshClient()
        client.login("admin", self.DEFAULT_PASSWORD)
        token = client._get_access_token()
        self.assertIsNotNone(token)

        client2 = AppMeshClient()
        client2.set_token(token)
        apps = client2.list_apps()
        self.assertGreater(len(apps), 0)

        # 2. jwt_token constructor without cookie file
        client3 = AppMeshClient(jwt_token=token)
        apps3 = client3.list_apps()
        self.assertEqual(len(apps3), len(apps))

        # 3. set_token with cookie file (file-backed + persist + reload)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cookie_path = tmp.name
        try:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None

            client4 = AppMeshClient(rest_cookie_file=cookie_path)
            # No file created yet
            self.assertFalse(os.path.exists(cookie_path))
            client4.set_token(token)
            # File created on set_token
            self.assertTrue(os.path.exists(cookie_path))
            self.assertIn("appmesh_auth_token", self.read_file_content(cookie_path))

            # Reload from file
            client5 = AppMeshClient(rest_cookie_file=cookie_path)
            self.assertEqual(client5._get_access_token(), token)
            apps5 = client5.list_apps()
            self.assertEqual(len(apps5), len(apps))

            # 4. jwt_token constructor + cookie file
            os.remove(cookie_path)
            client6 = AppMeshClient(jwt_token=token, rest_cookie_file=cookie_path)
            self.assertTrue(os.path.exists(cookie_path))
            apps6 = client6.list_apps()
            self.assertEqual(len(apps6), len(apps))

            # Reload
            client7 = AppMeshClient(rest_cookie_file=cookie_path)
            self.assertEqual(client7._get_access_token(), token)
        finally:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None

    def test_13_authenticate_apply_semantics(self):
        """authenticate(apply=False) must not mutate state; apply=True must."""

        class FakeResponse:
            def __init__(self, payload):
                self.status_code = 200
                self._payload = payload
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cookie_path = tmp.name
        try:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None

            client = AppMeshClient(rest_url="https://127.0.0.1:6060", ssl_verify=False, rest_cookie_file=cookie_path)
            client.set_token("existing-token")
            before = self.read_file_content(cookie_path)

            seen_auth = []
            seen_set_cookie = []

            def fake_request(method, path, query=None, header=None, body=None, raise_on_fail=True):
                self.assertEqual("/appmesh/auth", path)
                seen_auth.append(header.get("Authorization"))
                seen_set_cookie.append(header.get("X-Set-Cookie"))
                old_token = client._get_access_token()
                if header.get("X-Set-Cookie") == "true":
                    client.session.cookies.set_cookie(
                        Cookie(
                            version=0,
                            name=client._COOKIE_TOKEN,
                            value="verified-token",
                            port=None,
                            port_specified=False,
                            domain="",
                            domain_specified=False,
                            domain_initial_dot=False,
                            path="/",
                            path_specified=True,
                            secure=False,
                            expires=None,
                            discard=False,
                            comment=None,
                            comment_url=None,
                            rest={},
                            rfc2109=False,
                        )
                    )
                # Simulate _request_http before/after token detection
                new_token = client._get_access_token()
                if new_token != old_token:
                    client._on_token_changed(new_token)
                return FakeResponse({"access_token": "verified-token", "expires_in": 3600})

            client._request_http = fake_request

            ok, _ = client.authenticate("provided-token", apply=False)
            self.assertTrue(ok)
            self.assertEqual("Bearer provided-token", seen_auth[-1])
            self.assertIsNone(seen_set_cookie[-1])
            self.assertEqual("existing-token", client._get_access_token())
            self.assertEqual(before, self.read_file_content(cookie_path))

            ok, _ = client.authenticate("provided-token", apply=True)
            self.assertTrue(ok)
            self.assertEqual("true", seen_set_cookie[-1])
            self.assertEqual("verified-token", client._get_access_token())
            self.assertIn("verified-token", self.read_file_content(cookie_path))
        finally:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None


    def test_14_transport_token_sync(self):
        """Test _sync_transport_token for TCP/WSS path-based token extraction."""
        from appmesh.transport_mixin import (
            TransportClientMixin,
            _AUTH_SET_COOKIE_PATHS,
            _AUTH_RENEW_PATHS,
            _LOGOFF_PATH,
        )

        class FakeTransportResponse:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload

            def json(self):
                return self._payload

        class FakeTransportClient(TransportClientMixin, AppMeshClient):
            """Minimal fake to test _sync_transport_token in isolation."""
            pass

        client = AppMeshClient(rest_url="https://127.0.0.1:6060", ssl_verify=False)
        # Use a standalone mixin instance to call _sync_transport_token
        mixin = TransportClientMixin()
        mixin._token = None
        mixin._auto_refresh_token = False
        # Provide a minimal cookie_file=None and session to satisfy _on_token_changed
        mixin.cookie_file = None

        def on_token_changed(token):
            mixin._token = token

        mixin._on_token_changed = on_token_changed

        # 1. Login with X-Set-Cookie: true → token applied
        resp = FakeTransportResponse(200, {"access_token": "login-token"})
        mixin._sync_transport_token(resp, "/appmesh/login", {"X-Set-Cookie": "true"})
        self.assertEqual("login-token", mixin._token)

        # 2. Login without X-Set-Cookie → token NOT applied
        mixin._token = "old"
        resp = FakeTransportResponse(200, {"access_token": "should-not-apply"})
        mixin._sync_transport_token(resp, "/appmesh/login", {})
        self.assertEqual("old", mixin._token)

        # 3. Login with X-Set-Cookie but non-200 → token NOT applied
        mixin._token = "old"
        resp = FakeTransportResponse(401, {"access_token": "should-not-apply"})
        mixin._sync_transport_token(resp, "/appmesh/login", {"X-Set-Cookie": "true"})
        self.assertEqual("old", mixin._token)

        # 4. Renew → always applied (no X-Set-Cookie check)
        mixin._token = "old"
        resp = FakeTransportResponse(200, {"access_token": "renewed-token"})
        mixin._sync_transport_token(resp, "/appmesh/token/renew", {})
        self.assertEqual("renewed-token", mixin._token)

        # 5. TOTP setup → always applied
        mixin._token = "old"
        resp = FakeTransportResponse(200, {"access_token": "totp-token"})
        mixin._sync_transport_token(resp, "/appmesh/totp/setup", {})
        self.assertEqual("totp-token", mixin._token)

        # 6. Logoff → token cleared
        mixin._token = "has-token"
        resp = FakeTransportResponse(200, {})
        mixin._sync_transport_token(resp, "/appmesh/self/logoff", {})
        self.assertIsNone(mixin._token)

        # 7. Logoff with non-200 → token NOT cleared
        mixin._token = "has-token"
        resp = FakeTransportResponse(500, {})
        mixin._sync_transport_token(resp, "/appmesh/self/logoff", {})
        self.assertEqual("has-token", mixin._token)

        # 8. Non-auth path → token NOT changed
        mixin._token = "old"
        resp = FakeTransportResponse(200, {"access_token": "should-not-apply"})
        mixin._sync_transport_token(resp, "/appmesh/applications", {})
        self.assertEqual("old", mixin._token)

        # 9. Auth path with apply=False (no X-Set-Cookie) → token NOT changed
        mixin._token = "old"
        resp = FakeTransportResponse(200, {"access_token": "should-not-apply"})
        mixin._sync_transport_token(resp, "/appmesh/auth", {"Authorization": "Bearer test"})
        self.assertEqual("old", mixin._token)

        # 10. Auth path with apply=True (X-Set-Cookie: true) → token applied
        mixin._token = "old"
        resp = FakeTransportResponse(200, {"access_token": "auth-token"})
        mixin._sync_transport_token(resp, "/appmesh/auth", {"X-Set-Cookie": "true"})
        self.assertEqual("auth-token", mixin._token)


if __name__ == "__main__":
    unittest.main()
