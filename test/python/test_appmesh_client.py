import json
import shutil
import unittest
from unittest import TestCase
from pyotp import TOTP
import sys
import os

# For source code env:
current_directory = os.path.dirname(os.path.abspath(__file__))
source_code_root_dir = os.path.dirname(os.path.dirname(current_directory))
sys.path.append(os.path.join(source_code_root_dir, "src/sdk/python/appmesh"))
# import appmesh_client

# For wheel package
# python3 -m pip install --upgrade appmesh
from appmesh import appmesh_client

# python3 -m unittest test_appmesh_client.TestAppMeshClient.test_user


class TestAppMeshClient(TestCase):
    """
    unit test for AppMeshClient
    """

    def test_cloud(self):
        """test cloud"""
        client = appmesh_client.AppMeshClient()
        client.login("admin", "admin123")
        if "Url" in client.config_view()["Consul"] and client.config_view()["Consul"]["Url"] != "":
            self.assertIsNotNone(client.cloud_app_view_all())
            self.assertIsNotNone(
                client.cloud_app_add(
                    {
                        "condition": {"arch": "x86_64", "os_version": "centos7.6"},
                        "content": {
                            "command": "sleep 30",
                            "metadata": "cloud-sdk-app",
                            "name": "cloud",
                            "shell": True,
                        },
                        "port": 6667,
                        "priority": 0,
                        "replication": 1,
                        "memoryMB": 1024,
                    }
                )
            )
            self.assertEqual(client.cloud_app("cloud")["name"], "cloud")
            self.assertTrue(client.cloud_app_delete("cloud"))
            self.assertIsNotNone(client.cloud_nodes())

    def test_app_run(self):
        """test app run"""
        client = appmesh_client.AppMeshClient()
        client.login("admin", "admin123")
        metadata = {
            "subject": "subject",
            "message": "msg",
        }
        app_data = {"name": "ping", "metadata": json.dumps(metadata)}
        app = appmesh_client.App(app_data)
        app.behavior.set_exit_behavior(appmesh_client.App.Behavior.Action.REMOVE)
        self.assertEqual(9, client.run_sync(app=app, max_time_seconds=3, life_cycle_seconds=4))

        app_data = {"name": "whoami", "command": "whoami", "metadata": json.dumps(metadata)}
        self.assertEqual(0, client.run_sync(app=appmesh_client.App(app_data), max_time_seconds=5, life_cycle_seconds=6))

        self.assertEqual(9, client.run_sync(appmesh_client.App({"command": "ping github.com -w 5", "shell": True}), max_time_seconds=4))
        run = client.run_async(appmesh_client.App({"command": "ping github.com -w 4", "shell": True}), max_time_seconds=6)
        run.wait()

    def test_file(self):
        """test file"""
        client = appmesh_client.AppMeshClient()
        client.login("admin", "admin123")
        if os.path.exists("1.log"):
            os.remove("1.log")
        self.assertTrue(client.file_download("/opt/appmesh/log/server.log", "1.log"))
        self.assertTrue(os.path.exists("1.log"))

        self.assertEqual(
            0,
            client.run_sync(
                appmesh_client.App(
                    {
                        "name": "pyrun",
                        "metadata": "import os;os.remove('/tmp/2.log')",
                    }
                )
            ),
        )
        self.assertTrue(client.file_upload(local_file="1.log", file_path="/tmp/2.log"))
        self.assertTrue(client.file_download(file_path="/tmp/2.log", local_file="/tmp/3.log"))
        self.assertTrue(os.path.exists("/tmp/3.log"))

        self.assertEqual(
            0,
            client.run_sync(
                appmesh_client.App(
                    {
                        "name": "pyrun",
                        "metadata": "import shutil;shutil.copy('/etc/os-release', '/tmp/os-release')",
                    }
                )
            ),
        )
        self.assertTrue(client.file_download("/tmp/os-release", "os-release"))
        self.assertTrue(client.file_download("/tmp/os-release", "/tmp/os-release"))
        with open("/tmp/os-release", "r", encoding="utf-8") as etc:
            with open("os-release", "r", encoding="utf-8") as local:
                self.assertEqual(etc.read(), local.read())
        os.remove("os-release")

    def test_config(self):
        """test config"""
        client = appmesh_client.AppMeshClientTCP()
        client.login("admin", "admin123")
        self.assertIn("cpu_cores", client.host_resource())
        self.assertIn("appmesh_prom_scrape_count", client.metrics())
        self.assertEqual(client.log_level_set("DEBUG"), "DEBUG")
        self.assertEqual(client.log_level_set("INFO"), "INFO")
        self.assertEqual(client.config_set({"REST": {"SSL": {"VerifyServer": True}}})["REST"]["SSL"]["VerifyServer"], True)

    def test_tag(self):
        """test tag"""
        client = appmesh_client.AppMeshClient()
        client.login("admin", "admin123")
        self.assertTrue(client.tag_add("MyTag", "TagValue"))
        self.assertIn("MyTag", client.tag_view())
        self.assertTrue(client.tag_delete("MyTag"))
        self.assertNotIn("MyTag", client.tag_view())

    def test_app(self):
        """test application"""
        client = appmesh_client.AppMeshClient()
        client.login("admin", "admin123")
        self.assertEqual(client.app_view("ping").name, "ping")
        for app in client.app_view_all():
            self.assertTrue(hasattr(app, "name"))
            self.assertTrue(hasattr(app, "shell"))
            self.assertTrue(hasattr(app, "session_login"))
        self.assertEqual(client.app_health("ping"), 0)
        client.app_output("ping")

    def test_app_mgt(self):
        """test application management"""
        client = appmesh_client.AppMeshClient()
        client.login("admin", "admin123")
        app = client.app_add(appmesh_client.App({"command": "ping github.com -w 5", "name": "SDK"}))
        self.assertTrue(hasattr(app, "name"))

        self.assertTrue(client.app_delete("SDK"))
        self.assertFalse(client.app_delete("SDK"))
        self.assertTrue(client.app_disable("ping"))
        self.assertTrue(client.app_enable("ping"))

    def test_auth(self):
        """test authentication"""
        client = appmesh_client.AppMeshClient()
        token = client.login("admin", "admin123")
        token2 = client.renew(100)
        self.assertNotEqual(token, token2)

        with self.assertRaises(Exception):
            self.assertFalse(client.authentication(token))
        self.assertTrue(client.authentication(token2))

        self.assertTrue(client.logoff())
        with self.assertRaises(Exception):
            client.app_view_all()
        self.assertIsNotNone(client.login("admin", "admin123"))
        self.assertIsNotNone(client.app_view_all())

    def test_user(self):
        """test user"""
        client = appmesh_client.AppMeshClient()
        self.assertIsNotNone(client.login("admin", "admin123"))
        with self.assertRaises(Exception):
            client.user_passwd_update("admin")
        self.assertTrue(client.user_passwd_update("admin1234"))

        with self.assertRaises(Exception):
            self.assertIsNone(client.login("admin", "admin123"))
        self.assertIsNotNone(client.login("admin", "admin1234"))
        self.assertTrue(client.user_passwd_update("admin123"))

        self.assertIn("permission-list", client.permissions_view())
        self.assertIn("permission-list", client.permissions_for_user())
        self.assertTrue(client.authentication(client.jwt_token, "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authentication("", "app-view"))
        with self.assertRaises(Exception):
            self.assertFalse(client.authentication(client.jwt_token, "app-view2"))

        self.assertTrue(client.user_lock("mesh"))
        self.assertTrue(client.user_unlock("mesh"))

        self.assertTrue(
            client.role_update("manage", ["app-control", "app-delete", "cloud-app-reg", "cloud-app-delete", "app-reg", "config-set", "file-download", "file-upload", "label-delete", "label-set"])
        )

        self.assertIn("manage", client.roles_view())
        self.assertIn("admin", client.groups_view())
        self.assertIn("mesh", client.users_view())
        self.assertEqual(client.user_self()["email"], "admin@appmesh.com")

    def test_totp(self):
        """test TOTP"""
        client = appmesh_client.AppMeshClient()
        token = client.login("admin", "admin123")
        self.assertIsNotNone(token)
        self.assertEqual(token, client.jwt_token)
        # get totp secret
        totp_secret = client.totp_secret()
        self.assertIsNotNone(totp_secret)
        # generate totp code
        totp = TOTP(totp_secret)
        totp_code = totp.now()
        print(totp_code)
        # setup totp
        self.assertTrue(client.totp_setup(totp_code))

        # use totp code to login
        totp_code = totp.now()
        print(totp_code)
        self.assertIsNotNone(client.login("admin", "admin123", totp_code))
        self.assertTrue(client.totp_disable())


if __name__ == "__main__":
    unittest.main()
