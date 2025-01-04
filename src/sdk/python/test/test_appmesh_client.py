#!/usr/bin/python3
"""Test Python SDK"""
import sys
import os
import json
import unittest
from unittest import TestCase
from pyotp import TOTP

# For source code env:
current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_directory))

# For wheel package
# python3 -m pip install --upgrade appmesh pyotp
from appmesh import AppMeshClient, AppMeshClientTCP, App

# python3 -m unittest test_appmesh_client.TestAppMeshClient.test_user


class TestAppMeshClient(TestCase):
    """
    unit test for AppMeshClient
    """

    def test_app_run(self):
        """test app run"""
        client = AppMeshClient()
        client.login("admin", "admin123")
        client.forward_to = "localhost"
        metadata = {
            "subject": "subject",
            "message": "msg",
        }
        app_data = {"name": "ping", "metadata": json.dumps(metadata)}
        app = App(app_data)
        app.behavior.set_exit_behavior(App.Behavior.Action.REMOVE)
        self.assertEqual(9, client.run_app_sync(app=app, max_time_seconds=3, life_cycle_seconds=4)[0])

        app_data = {"name": "whoami", "command": "whoami", "metadata": json.dumps(metadata)}
        self.assertEqual(0, client.run_app_sync(app=App(app_data), max_time_seconds=5, life_cycle_seconds=6)[0])

        self.assertEqual(9, client.run_app_sync(App({"command": "ping github.com -w 5", "shell": True}), max_time_seconds=4)[0])
        run = client.run_app_async(App({"command": "ping github.com -w 4", "shell": True}), max_time_seconds=6)
        run.wait()

    def test_file(self):
        """test file"""
        client = AppMeshClientTCP()
        client.login("admin", "admin123")
        # client.forward_to = "127.0.0.1:6059" # only for REST client, not for TCP client
        if os.path.exists("1.log"):
            os.remove("1.log")
        self.assertIsNone(client.download_file("/opt/appmesh/work/server.log", "1.log"))
        self.assertTrue(os.path.exists("1.log"))

        self.assertEqual(
            0,
            client.run_app_sync(
                App(
                    {
                        "name": "pyrun",
                        "metadata": "import os; [os.remove('/tmp/2.log') if os.path.exists('/tmp/2.log') else None]",
                    }
                )
            )[0],
        )
        self.assertIsNone(client.upload_file(local_file="1.log", remote_file="/tmp/2.log"))
        self.assertIsNone(client.download_file(remote_file="/tmp/2.log", local_file="/tmp/3.log"))
        self.assertTrue(os.path.exists("/tmp/3.log"))
        os.remove("1.log")

        self.assertEqual(
            0,
            client.run_app_sync(
                App(
                    {
                        "name": "pyrun",
                        "metadata": "import shutil;shutil.copy('/etc/os-release', '/tmp/os-release')",
                    }
                )
            )[0],
        )
        self.assertIsNone(client.download_file("/tmp/os-release", "os-release"))
        if os.path.exists("/tmp/os-release-1"):
            os.remove("/tmp/os-release-1")
        self.assertIsNone(client.download_file("/tmp/os-release", "/tmp/os-release-1"))
        with open("/tmp/os-release-1", "r", encoding="utf-8") as etc:
            with open("os-release", "r", encoding="utf-8") as local:
                self.assertEqual(etc.read(), local.read())
        os.remove("os-release")

    def test_config(self):
        """test config"""
        client = AppMeshClientTCP()
        client.login("admin", "admin123")
        self.assertIn("cpu_cores", client.view_host_resources())
        self.assertIn("appmesh_prom_scrape_count", client.get_metrics())
        self.assertEqual(client.set_log_level("DEBUG"), "DEBUG")
        self.assertEqual(client.set_log_level("INFO"), "INFO")
        self.assertEqual(client.set_config({"REST": {"SSL": {"VerifyServer": True}}})["REST"]["SSL"]["VerifyServer"], True)

    def test_tag(self):
        """test tag"""
        client = AppMeshClient()
        client.login("admin", "admin123")
        self.assertTrue(client.add_tag("MyTag", "TagValue"))
        self.assertIn("MyTag", client.view_tags())
        self.assertTrue(client.delete_tag("MyTag"))
        self.assertNotIn("MyTag", client.view_tags())

    def test_app(self):
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

    def test_app_mgt(self):
        """test application management"""
        client = AppMeshClient()
        client.login("admin", "admin123")
        app = client.add_app(App({"command": "ping github.com -w 5", "name": "SDK"}))
        self.assertTrue(hasattr(app, "name"))

        self.assertTrue(client.delete_app("SDK"))
        self.assertFalse(client.delete_app("SDK"))
        self.assertTrue(client.disable_app("ping"))
        self.assertTrue(client.enable_app("ping"))

    def test_auth(self):
        """test authentication"""
        client = AppMeshClient()
        token = client.login("admin", "admin123")
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

    def test_user(self):
        """test user"""
        client = AppMeshClient()
        self.assertIsNotNone(client.login("admin", "admin123"))
        with self.assertRaises(Exception):
            client.update_user_password("admin")
        self.assertTrue(client.update_user_password("admin1234"))

        with self.assertRaises(Exception):
            self.assertIsNone(client.login("admin", "admin123"))
        self.assertIsNotNone(client.login("admin", "admin1234"))
        self.assertTrue(client.update_user_password("admin123"))

        self.assertIn("permission-list", client.view_permissions())
        self.assertIn("permission-list", client.view_user_permissions())
        self.assertTrue(client.authenticate(client.jwt_token, "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate("", "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authenticate(client.jwt_token, "app-view2"))

        self.assertTrue(client.lock_user("mesh"))
        self.assertTrue(client.unlock_user("mesh"))

        self.assertTrue(
            client.update_role("manage", ["app-control", "app-delete", "app-reg", "config-set", "file-download", "file-upload", "label-delete", "label-set"])
        )

        self.assertIn("manage", client.view_roles())
        self.assertIn("admin", client.view_groups())
        self.assertIn("mesh", client.view_users())
        self.assertEqual(client.view_self()["email"], "admin@appmesh.com")

    def test_totp(self):
        """test TOTP"""
        client = AppMeshClient()
        token = client.login("admin", "admin123")
        self.assertIsNotNone(token)
        self.assertEqual(token, client.jwt_token)
        # get totp secret
        totp_secret = client.get_totp_secret()
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
        self.assertTrue(client.disable_totp())


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAppMeshClient)

    runner = unittest.TextTestRunner()
    runner.run(suite)
