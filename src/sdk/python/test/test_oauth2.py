#!/usr/bin/python3
"""
App Mesh Client Authentication Example

This example demonstrates how to use the App Mesh client for Keycloak authentication
and verification of the obtained access token.

Setup:
1. Start Keycloak:
    docker run --restart=always -d -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin --name keycloak2 quay.io/keycloak/keycloak:latest start-dev

2. Configure Keycloak:
    - Create realm: appmesh-realm, select this realm
    - In "Authentication" menu, disable all Required actions
    - Create user 'mesh' with password 'mesh123' and disable temporary password
    - In Realm roles > create role: manage/view
    - In Clients > create client: appmesh-client with client secret V87QbGeDJ4RCtzL8VNG4DTzsavZZENAx
    - In Users > User details, assign role: appmesh-client manage/view
"""

import os
import sys
import json
import time
import requests
import jwt
from jwt.algorithms import RSAAlgorithm

# For source code env:
current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_directory))
from appmesh import AppMeshClientOAuth


class KeycloakTokenVerifier:
    """
    Keycloak Token Verifier

    Used to verify JWT access tokens obtained from Keycloak
    """

    def __init__(self, auth_server_url, realm):
        """
        Initialize Keycloak token verifier

        Args:
            auth_server_url (str): Keycloak server URL
            realm (str): Keycloak realm name
        """
        self.auth_server_url = auth_server_url
        self.realm = realm
        self.jwks_uri = f"{self.auth_server_url}/realms/{self.realm}/protocol/openid-connect/certs"
        self.public_keys = {}
        self.fetch_public_keys()

    def fetch_public_keys(self):
        """Fetch public keys from Keycloak's JWKS endpoint"""
        try:
            response = requests.get(self.jwks_uri)
            response.raise_for_status()
            jwks = response.json()

            # Extract and store keys by kid (key ID)
            for key_data in jwks.get("keys", []):
                kid = key_data.get("kid")
                if kid and key_data.get("alg") == "RS256":
                    self.public_keys[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))

        except Exception as e:
            print(f"Error fetching public keys: {e}")
            raise

    def verify_token(self, access_token):
        """
        Verify the signature and claims of a Keycloak access token

        Args:
            access_token (str): JWT token to verify

        Returns:
            tuple: (is_valid, result_info/decoded_token)
        """
        try:
            # Get the header without verification
            header = jwt.get_unverified_header(access_token)
            kid = header.get("kid")

            if not kid or kid not in self.public_keys:
                print(f"Key ID {kid} not found, refreshing keys...")
                self.fetch_public_keys()
                if kid not in self.public_keys:
                    raise ValueError(f"Unable to find public key for kid: {kid}")

            # Verify the token with the appropriate public key
            # Note: You may need to adjust the audience parameter based on your Keycloak configuration
            decoded_token = jwt.decode(access_token, key=self.public_keys[kid], algorithms=["RS256"], audience="account", options={"verify_exp": True})

            return True, decoded_token

        except jwt.ExpiredSignatureError:
            return False, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, f"Invalid token: {str(e)}"
        except Exception as e:
            return False, f"Verification error: {str(e)}"


def main():
    """
    Main example function - demonstrates login and token verification
    """
    # Keycloak configuration
    keycloak_config = {
        "auth_server_url": "http://localhost:8080",
        "realm": "appmesh-realm",
        "client_id": "appmesh-client",
        "client_secret": "V87QbGeDJ4RCtzL8VNG4DTzsavZZENAx",  # For confidential clients
    }

    # Create App Mesh client
    client = AppMeshClientOAuth(rest_ssl_verify=False, oauth2=keycloak_config, auto_refresh_token=True)

    # Try to login and verify the token
    # Make sure "Required Actions" is disabled in "appmesh-realm" Authentication
    try:
        # Login to get token
        print("Attempting to login...")
        token = client.login("mesh", "mesh123")
        print("Login successful!")

        # Verify token
        print("Verifying token...")
        verifier = KeycloakTokenVerifier(keycloak_config["auth_server_url"], keycloak_config["realm"])
        is_valid, result = verifier.verify_token(token.get("access_token"))

        if is_valid:
            print("Token verification successful!")
            print("Token contains the following claims:")
            for key, value in result.items():
                print(f"  - {key}: {value}")
        else:
            print(f"Token verification failed: {result}")

        # Make sure permission configured resource_access: {'appmesh-client': {'roles': ['view', 'uma_protection', 'manage']}}
        print(client.view_app("ping"))

    except Exception as e:
        print(f"Operation failed: {str(e)}")


if __name__ == "__main__":
    main()
