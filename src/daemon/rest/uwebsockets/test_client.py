import asyncio
import json
import ssl
import websockets
import requests
import time

# --- Configuration ---
HOST = "localhost"
PORT = 9001
WSS_URL = f"wss://{HOST}:{PORT}"
HTTPS_URL = f"https://{HOST}:{PORT}"

# NOTE: Since the C++ server uses SSL, you MUST provide the path to your server's certificate 
# (the one referenced in main.cpp: /opt/appmesh/ssl/server.pem)
# If you are using a self-signed cert, create an SSL context and pass it to websockets.
# Replace 'path/to/server.pem' with the actual path to your server certificate for testing.
CERT_PATH = "/opt/appmesh/ssl/ca.pem" # Change this if running locally!

# Create an SSL Context for the WebSocket client
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
try:
    ssl_context.load_verify_locations(CERT_PATH)
except FileNotFoundError:
    print(f"WARNING: Certificate file '{CERT_PATH}' not found. Skipping SSL verification for testing.")
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

# Global variable to store the connection ID for HTTP testing
CLIENT_ID = None

# --- WebSocket Test Functions ---

async def connect_and_test_ws():
    global CLIENT_ID
    
    print(f"\n--- 1. Connecting to WSS ({WSS_URL}) ---")
    try:
        async with websockets.connect(WSS_URL, ssl=ssl_context, subprotocols=["appmesh-ws", "admin-protocol"],) as websocket:
            print(f"Connected. Sub-protocol negotiated: {websocket.subprotocol}")

            # 1. Receive Welcome Message and store Client ID
            welcome_msg = json.loads(await websocket.recv())
            CLIENT_ID = welcome_msg['id']
            print(f"Welcome message received. Client ID: {CLIENT_ID}")
            
            # Use two tasks to handle sending/receiving concurrently
            send_task = asyncio.create_task(send_ws_messages(websocket))
            receive_task = asyncio.create_task(receive_ws_messages(websocket))
            
            # Wait for 15 seconds to allow async task and periodic broadcasts
            await asyncio.sleep(15) 
            
            # Cancel tasks to clean up
            send_task.cancel()
            receive_task.cancel()

    except Exception as e:
        print(f"WebSocket connection failed: {e}")
        
async def send_ws_messages(websocket):
    messages = [
        {"action": "ping"}, # One-way message
        {"action": "echo", "data": "Hello World from Python"}, # Request/Response
        {"action": "task", "taskId": "T-1234"}, # Async task
        {"action": "broadcast", "message": "Global announcement from the test client!"}, # Broadcast test
    ]
    
    for i, msg in enumerate(messages):
        await asyncio.sleep(1.0)
        print(f"\n[SEND] ({i+1}/{len(messages)}): {msg['action']}")
        await websocket.send(json.dumps(msg))

async def receive_ws_messages(websocket):
    while True:
        try:
            message = await websocket.recv()
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'timer_broadcast':
                print(f"[RECV: Broadcast] {data['message']} (Timestamp: {data['timestamp']})")
            elif msg_type == 'echo_response':
                print(f"[RECV: Echo] Data: '{data['data']}' | Protocol: {data['protocol']}")
            elif msg_type == 'pong':
                print(f"[RECV: Pong] Timestamp: {data['timestamp']}")
            elif data.get('action') == 'task':
                print(f"[RECV: Task Update] ID: {data['taskId']}, Status: {data['status']}, Progress: {data['progress']}%")
            elif msg_type == 'direct_message':
                 print(f"[RECV: Direct Message] {data['message']}")
            else:
                print(f"[RECV: Other] {data}")
                
        except websockets.exceptions.ConnectionClosedOK:
            print("[RECV] Connection closed normally.")
            break
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[RECV Error] {e}")
            break

# --- HTTP Test Functions ---

def test_http_api():
    print("\n--- 2. Testing HTTPS API Endpoints ---")
    
    # Disable SSL warnings for self-signed certificates
    requests.packages.urllib3.disable_warnings()
    
    # 2.1. Test /api/status (GET)
    status_url = f"{HTTPS_URL}/api/status"
    try:
        print(f"\n[HTTP GET] {status_url}")
        response = requests.get(status_url, verify=False)
        response.raise_for_status()
        print(f"  Status: {response.status_code} | Body: {response.json()}")
    except Exception as e:
        print(f"  [Error] GET /api/status failed: {e}")

    # 2.2. Test /api/task (POST - Async Reply)
    task_url = f"{HTTPS_URL}/api/task"
    task_payload = json.dumps({"taskId": "HTTP-T-123", "data": "start_async"})
    try:
        print(f"\n[HTTP POST] {task_url} (Async)")
        
        # Requests.post must handle the stream to receive all chunks of the async reply
        response = requests.post(task_url, data=task_payload, headers={'Content-Type': 'application/json'}, verify=False, stream=True)
        response.raise_for_status()
        
        # Read the async chunks and print them
        full_response = ""
        print("  Async Task Chunks:")
        for chunk in response.iter_content(chunk_size=None):
            if chunk:
                chunk_str = chunk.decode('utf-8')
                full_response += chunk_str
                print(f"    {chunk_str}")
                
        print(f"  [Done] Full Task Response: {full_response}")

    except Exception as e:
        print(f"  [Error] POST /api/task failed: {e}")
        
    # 2.3. Test /api/notify (POST - Direct message to WS Client)
    if CLIENT_ID:
        notify_url = f"{HTTPS_URL}/api/notify"
        notify_payload = json.dumps({"clientId": CLIENT_ID, "message": "Hello from the HTTP API!"})
        try:
            print(f"\n[HTTP POST] {notify_url} (Target: {CLIENT_ID})")
            response = requests.post(notify_url, data=notify_payload, headers={'Content-Type': 'application/json'}, verify=False)
            response.raise_for_status()
            print(f"  Status: {response.status_code} | Body: {response.json()}")
        except Exception as e:
            print(f"  [Error] POST /api/notify failed: {e}")
    else:
        print("\n[SKIP] Skipping /api/notify test: No Client ID obtained from WS connection.")


# --- Main Execution ---

if __name__ == "__main__":
    # Run the WebSocket tests
    asyncio.run(connect_and_test_ws())
    
    # Run the HTTP tests (synchronous)
    test_http_api()