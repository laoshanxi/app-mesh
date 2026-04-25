# Event Subscription

App Mesh supports real-time event subscription over persistent connections (TCP and WebSocket). Clients can subscribe to specific application events and receive server-push notifications without polling.

## Event Types

| Event | Description | Data Fields |
|---|---|---|
| `process_start` | Process spawned | `pid`, `process_uuid` |
| `process_exit` | Process exited | `pid`, `exit_code`, `last_error` |
| `stdout` | Stdout output available | `output`, `position`, `finished` |
| `health_change` | Health status changed | `health` (0=healthy, 1=unhealthy), `previous_health` |
| `status_change` | App enabled/disabled | `status`, `previous_status` |
| `app_removed` | App deleted | (empty) |

## REST API

### Subscribe (per-app)

```
POST /appmesh/app/{app_name}/subscribe?events=process_start,process_exit,stdout
Authorization: Bearer <JWT>
```

**Response:**
```json
{
  "subscription_id": "cqk8g7l4d",
  "app_name": "myapp",
  "events": ["process_start", "process_exit", "stdout"]
}
```

### Subscribe (all apps)

```
POST /appmesh/subscribe?events=process_start,process_exit
```

### Unsubscribe

```
DELETE /appmesh/app/{app_name}/subscribe?subscription_id=cqk8g7l4d
```

### Subscribe at Registration

Register an app and subscribe atomically (no events missed):

```
PUT /appmesh/app/{app_name}?subscribe_events=process_start,process_exit,stdout
Content-Type: application/json

{ "name": "myapp", "command": "python3 server.py" }
```

The response includes `subscription_id` alongside the normal app JSON when subscription is active.

> **Note:** Subscribe requires a persistent connection (TCP or WebSocket). REST/HTTP returns `405 Method Not Allowed`.

## Event Push Message Format

Events are delivered as standard `Response` messages with `request_uri = "/appmesh/event"`. Clients identify pushes by this sentinel URI and the absence of a matching pending request UUID.

```
Response {
  uuid:         "<event-uuid>"
  request_uri:  "/appmesh/event"
  http_status:  200
  body: {
    "subscription_id": "cqk8g7l4d",
    "event_type": "process_exit",
    "app_name": "myapp",
    "timestamp": 1714000000,
    "sequence": 42,
    "data": { "pid": 12345, "exit_code": 1 }
  }
  headers: {
    "X-Subscription-Id": "cqk8g7l4d",
    "X-Event-Type": "process_exit",
    "X-App-Name": "myapp"
  }
}
```

## Architecture

```
                        ┌──────────────────┐
                        │  EventDispatcher │  (singleton)
                        │                  │
  Application hooks ──▶ │  dispatch()      │──▶ DeliveryCallback(TCP)
  - onTimerSpawn        │                  │──▶ DeliveryCallback(WSS)
  - onExitUpdate        │  subscribe()     │
  - health(bool)        │  unsubscribe()   │
  - enable/disable      │  removeByConn()  │
  - Configuration::     │  removeByApp()   │
    removeApp           └──────────────────┘
                               │
                    ┌──────────┼──────────┐
                    │ StdoutWatcher (1s)  │
                    │ per-app timer poll  │
                    └─────────────────────┘
```

### Thread Safety

- `EventDispatcher` uses `std::recursive_mutex` for all operations
- `dispatch()` delivers events and cleans dead subscriptions in a single lock scope (no TOCTOU)
- `StdoutWatcher` timer callback uses `weak_ptr` capture to prevent use-after-free
- Connection cleanup (`removeByConnection`) is called from `SocketServer::onClose` and `WebSocketService::destroySession` after releasing transport-specific locks

### Ownership Enforcement

- `unsubscribe()` verifies the requesting user matches the subscription owner
- Connection disconnect auto-removes all subscriptions for that connection
- App deletion dispatches `APP_REMOVED` event then purges all subscriptions

## SDK Usage

> **Note:** Event subscription requires a persistent connection (TCP or WebSocket). The C++ SDK (`ClientHttp`) is HTTP-only and does not support subscriptions.

### Go

```go
// Subscribe to events
client, _ := appmesh.NewTCPClient(appmesh.Option{})
client.Login("admin", "admin123", "", 0, "")

result, _ := client.Subscribe(appmesh.SubscribeOption{
    AppName: "myapp",
    Events:  []string{"process_start", "process_exit"},
}, func(event appmesh.AppEvent) {
    fmt.Printf("Event: %s app=%s\n", event.EventType, event.AppName)
})

// Register app with atomic subscribe
app, _ := client.AddApp(appmesh.Application{
    Name:    "myapp",
    Command: ptr("ping github.com"),
}, "process_start", "process_exit", "stdout")
fmt.Println("subscription_id:", app.SubscriptionID)

// Unsubscribe
client.Unsubscribe(result.SubscriptionID)
```

### Python

```python
from appmesh import AppMeshClientTCP, App

client = AppMeshClientTCP()
client.login("admin", "admin123")

# Subscribe to events
def on_event(event):
    print(f"Event: {event.event_type} app={event.app_name}")

result = client.subscribe("myapp", ["process_start", "process_exit"], on_event)

# Register app with atomic subscribe
app = client.add_app(
    App({"name": "myapp", "command": "ping github.com"}),
    subscribe_events=["process_start", "process_exit", "stdout"]
)

# Unsubscribe
client.unsubscribe(result.subscription_id)
```

### JavaScript

```javascript
import { AppMeshClientTCP } from 'appmesh'

const client = new AppMeshClientTCP()
await client.login('admin', 'admin123')

// Subscribe
const result = await client.subscribe('myapp', ['process_start', 'process_exit'], (event) => {
  console.log(`Event: ${event.event_type} app=${event.app_name}`)
})

// Unsubscribe
await client.unsubscribe(result.subscription_id)
```

### Java

```java
AppMeshClientTCP client = new AppMeshClientTCP.Builder().disableSSLVerify().build();
client.login("admin", "admin123");

// Subscribe to events
JSONObject result = client.subscribe("myapp", "process_start", "process_exit");
String subId = result.getString("subscription_id");

// Register app with atomic subscribe
JSONObject app = new JSONObject().put("name", "myapp").put("command", "ping github.com");
JSONObject appResult = client.addApp("myapp", app, "process_start", "process_exit", "stdout");
// appResult has "subscription_id" when active

// Unsubscribe
client.unsubscribe(subId);
```

### Rust

```rust
let client = ClientBuilderTCP::new().danger_accept_invalid_certs(true).build()?;
client.login("admin", "admin123", None, None, None).await?;

// Subscribe to events
let result = client.subscribe("myapp", Some(&["process_start", "process_exit"])).await?;

// Register app with atomic subscribe
let app = Application::builder("myapp").command("ping github.com").build();
let created = client.add_app(&app, Some(&["process_start", "stdout"])).await?;
println!("subscription_id: {:?}", created.subscription_id);

// Unsubscribe
client.unsubscribe(&result.subscription_id).await?;
```

## Limitations

- **REST/HTTP** does not support subscriptions (no persistent connection). Use TCP or WebSocket.
- **Wildcard stdout** (`/appmesh/subscribe?events=stdout`) is not supported — stdout polling requires a specific app name.
- **Server restart** clears all subscriptions (in-memory only). Clients must re-subscribe after reconnecting.
- **Event ordering** is guaranteed per-subscription via a monotonic `sequence` counter. Cross-subscription ordering is not guaranteed.
