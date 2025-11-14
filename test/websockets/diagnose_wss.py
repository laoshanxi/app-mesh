#!/usr/bin/env python3
"""Diagnostic tool to test WSS connection with C++ server."""

import asyncio
import logging
import ssl
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_raw_websocket():
    """Test raw websocket connection without SDK."""
    try:
        import websockets
    except ImportError:
        print("ERROR: websockets library not found. Install with: pip install websockets")
        return False
    
    host = "127.0.0.1"
    port = 6058
    uri = f"wss://{host}:{port}/"
    
    logger.info(f"Attempting connection to {uri}")
    
    try:
        # Test with SSL disabled first
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Try connection
        logger.info("Sending WebSocket handshake request...")
        async with websockets.connect(
            uri,
            ssl=ssl_context,
            max_size=100*1024*1024,
            compression=None,
            ping_interval=None,
            ping_timeout=None,
            close_timeout=10,
            subprotocols=[],
        ) as websocket:
            logger.info(f"✓ Connection successful!")
            logger.info(f"  Subprotocol: {websocket.subprotocol}")
            logger.info(f"  Local address: {websocket.local_address}")
            logger.info(f"  Remote address: {websocket.remote_address}")
            
            # Try sending a simple message
            logger.info("Sending test message...")
            await asyncio.sleep(0.5)
            
            return True
            
    except asyncio.TimeoutError as e:
        logger.error(f"Connection timeout: {e}")
        return False
    except ConnectionRefusedError as e:
        logger.error(f"Connection refused: {e}")
        logger.error("  Server is not listening on this port")
        return False
    except ssl.SSLError as e:
        logger.error(f"SSL error: {e}")
        return False
    except Exception as e:
        logger.error(f"Connection error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Run diagnostics."""
    print("\n" + "="*60)
    print("WSS Connection Diagnostics")
    print("="*60)
    
    # Check if server is reachable
    print("\n[Step 1] Checking server connectivity...")
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("127.0.0.1", 6058))
    sock.close()
    
    if result == 0:
        print("✓ Server port 6058 is open")
    else:
        print("✗ Server port 6058 is NOT open (connection refused)")
        print("  Troubleshooting:")
        print("  1. Check if AppMesh server is running: ps aux | grep appmesh")
        print("  2. Check server logs for errors")
        print("  3. Verify WSS service is enabled in AppMesh config")
        return False
    
    print("\n[Step 2] Testing raw WebSocket connection...")
    success = await test_raw_websocket()
    
    if success:
        print("\n[SUCCESS] WebSocket connection test passed!")
        print("The server is ready for WSS connections.")
    else:
        print("\n[FAILURE] WebSocket connection test failed!")
        print("See logs above for details.")
    
    return success

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
