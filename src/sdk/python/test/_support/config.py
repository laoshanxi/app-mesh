"""Shared daemon settings for tests against a Dex-protected App Mesh daemon."""
import os

ACCESS_TOKEN_ENV = "APPMESH_TEST_ACCESS_TOKEN"


def attach_test_bearer(client, env_name=ACCESS_TOKEN_ENV):
    """Attach a pre-acquired Dex access token without logging or persisting it."""
    token = os.environ.get(env_name)
    if not token:
        raise RuntimeError("{} must contain a Dex access token".format(env_name))
    client.set_bearer_token(token)
    return client

# Daemon base URL; None lets the SDK use its default (https://127.0.0.1:6060).
BASE_URL = os.environ.get("APPMESH_TEST_URL")

# REST-over-WSS port used by the WSSRest transport tests.
WSS_REST_PORT = 6058
