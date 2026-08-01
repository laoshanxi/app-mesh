"""Shared daemon settings for the tests: login credential, base URL, ports."""
import os

# Login user for the daemon under test (env: APPMESH_TEST_USER).
USER = os.environ.get("APPMESH_TEST_USER", "admin")

# Password for USER (env: APPMESH_TEST_CRED).
CRED = os.environ.get("APPMESH_TEST_CRED", "admin123")

# Daemon base URL; None lets the SDK use its default (https://127.0.0.1:6060).
BASE_URL = os.environ.get("APPMESH_TEST_URL")

# REST-over-WSS port used by the WSSRest transport tests.
WSS_REST_PORT = 6058
