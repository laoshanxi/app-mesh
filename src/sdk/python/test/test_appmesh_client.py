"""Test Python SDK"""

import sys
import os
import stat
import json
import unittest
import tempfile
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
        return "ping github.com -n 5 -w 2000"
    elif sys.platform.startswith("darwin"):
        # On macOS, -c count, -W wait (in ms) is not supported, use -c and maybe -t TTL
        # Use `ping -c 5 github.com`
        return "ping github.com -c 5"
    else:
        # Linux
        return "ping github.com -w 5"


class TestAppMeshClient(TestCase):
    """
    unit test for AppMeshClient
    """

    def test_09_app_run(self):
        """test app run"""
        client = AppMeshClient()
        client.login("admin", "admin123")
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
        client.login("admin", "admin123")
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
        client.login("admin", "admin123")
        self.assertIn("cpu_cores", client.view_host_resources())
        self.assertIn("appmesh_prom_scrape_count", client.get_metrics())
        self.assertEqual(client.set_log_level("DEBUG"), "DEBUG")
        self.assertEqual(client.set_log_level("INFO"), "INFO")
        self.assertEqual(client.set_config({"REST": {"SSL": {"VerifyServer": True}}})["REST"]["SSL"]["VerifyServer"], True)

    def test_05_tag(self):
        """test tag"""
        client = AppMeshClient()
        client.login("admin", "admin123")
        self.assertIsNone(client.add_tag("MyTag", "TagValue"))
        self.assertIn("MyTag", client.view_tags())
        self.assertIsNone(client.delete_tag("MyTag"))
        self.assertNotIn("MyTag", client.view_tags())

    def test_06_app(self):
        """test application"""
        client = AppMeshClient()
        client.login("admin", "admin123")
        self.assertEqual(client.view_app("ping").name, "ping")
        for app in client.view_all_apps():
            self.assertTrue(hasattr(app, "name"))
            self.assertTrue(hasattr(app, "shell"))
            self.assertTrue(hasattr(app, "session_login"))
        self.assertEqual(client.check_app_health("ping"), True)
        client.get_app_output("ping")

    def test_07_app_mgt(self):
        """test application management"""
        client = AppMeshClient()
        client.login("admin", "admin123")
        app = client.add_app(App({"command": "ping github.com -w 5", "name": "SDK"}))
        self.assertTrue(hasattr(app, "name"))

        self.assertTrue(client.delete_app("SDK"))
        self.assertFalse(client.delete_app("SDK"))
        self.assertIsNone(client.disable_app("ping"))
        self.assertIsNone(client.enable_app("ping"))

    def test_01_auth(self):
        """test authentication"""
        client = AppMeshClient()
        with self.assertRaises(Exception):
            client.login("admin", "admin123", audience="appmesh-service-na")
        token = client.login("admin", "admin123", audience="your-service-api")
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate(token))
        self.assertTrue(client.authenticate(token, audience="your-service-api"))

        token = client.login("admin", "admin123", audience="appmesh-service")
        self.assertTrue(client.authenticate(token, audience="appmesh-service"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate(token, audience="appmesh-service-na"))

        token2 = client.renew_token(100)
        self.assertNotEqual(token, token2)

        with self.assertRaises(Exception):
            self.assertFalse(client.authentication(token))
        self.assertTrue(client.authenticate(token2))

        self.assertTrue(client.logoff())
        with self.assertRaises(Exception):
            client.view_all_apps()
        self.assertIsNotNone(client.login("admin", "admin123"))
        self.assertIsNotNone(client.view_all_apps())

    def test_02_user(self):
        """test user"""
        client = AppMeshClient()
        self.assertIsNotNone(client.login("admin", "admin123"))
        with self.assertRaises(Exception):
            client.update_user_password("admin123", "admin")
        with self.assertRaises(Exception):
            client.update_user_password("admin", "admin123")
        self.assertIsNone(client.update_user_password("admin123", "admin1234"))

        with self.assertRaises(Exception):
            self.assertIsNone(client.login("admin", "admin123"))
        self.assertIsNotNone(client.login("admin", "admin1234"))
        self.assertIsNone(client.update_user_password("admin1234", "admin123"))

        self.assertIn("permission-list", client.view_permissions())
        self.assertIn("permission-list", client.view_user_permissions())
        self.assertTrue(client.authenticate(client.jwt_token, "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate("", "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate(client.jwt_token, "app-view2"))

        self.assertIsNone(client.lock_user("mesh"))
        self.assertIsNone(client.unlock_user("mesh"))

        self.assertIsNone(client.update_role("manage", ["app-control", "app-delete", "app-reg", "config-set", "file-download", "file-upload", "label-delete", "label-set"]))

        self.assertIn("manage", client.view_roles())
        self.assertIn("admin", client.view_groups())
        self.assertIn("mesh", client.view_users())
        self.assertEqual(client.view_self()["email"], "admin@appmesh.com")

    def test_03_totp(self):
        """test TOTP"""
        client = AppMeshClient()
        token = client.login("admin", "admin123")
        self.assertIsNotNone(token)
        self.assertEqual(token, client.jwt_token)
        # get totp secret
        totp_secret = client.get_totp_secret()
        # print(f"TOTP Secret: {totp_secret!r}")
        self.assertIsNotNone(totp_secret)
        # generate totp code
        totp = TOTP(totp_secret)
        totp_code = totp.now()
        print(totp_code)
        # setup totp
        self.assertTrue(client.setup_totp(totp_code))

        # use totp code to login
        totp_code = totp.now()
        print(totp_code)
        self.assertIsNotNone(client.login("admin", "admin123", totp_code))
        self.assertIsNone(client.disable_totp())

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
            self.assertTrue(os.path.exists(cookie_path))

            # permission check (Unix only)
            if os.name == "posix":
                mode = stat.S_IMODE(os.stat(cookie_path).st_mode)
                self.assertEqual(mode, 0o600)

            # cookie set
            client.login("admin", "admin123")
            content = self.read_file_content(cookie_path)
            self.assertIn("appmesh_auth_token", content)
            self.assertIn("appmesh_csrf_token", content)

            # cookie cleared on logoff
            client.logoff()
            content_after = self.read_file_content(cookie_path)
            self.assertNotIn("appmesh_auth_token", content_after)
            self.assertNotIn("appmesh_csrf_token", content_after)

            # re-use cookie: should require login again
            client = AppMeshClient(rest_cookie_file=cookie_path)
            with self.assertRaises(Exception):
                client.view_all_apps()

            # re-login and verify user info
            token = client.login("admin", "admin123")
            client = AppMeshClient(rest_cookie_file=cookie_path)
            user_info = client.view_self()
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
            self.assertNotEqual(token, client.setup_totp(totp_code))

            content_after_totp = self.read_file_content(cookie_path)

            self.assertIn("appmesh_auth_token", content_after_totp)
            self.assertIn("appmesh_csrf_token", content_after_totp)
            self.assertNotEqual(content_before_totp, content_after_totp)

            # Use totp code to login
            content_before_totp = self.read_file_content(cookie_path)

            client = AppMeshClient(rest_cookie_file=cookie_path)
            self.assertTrue(client.logoff())
            totp_code = totp.now()
            print(totp_code)
            self.assertIsNotNone(client.login("admin", "admin123", totp_code))
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


if __name__ == "__main__":
    unittest.main()
