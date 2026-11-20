package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"

	"github.com/laoshanxi/app-mesh/src/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

const (
	// Liveness-marker cadence; the daemon's staleness window covers three misses.
	containerEventSyncInterval = 30 * time.Second
	containerEventPath         = "/appmesh/internal/container-event"
)

// StartContainerEventsPush subscribes to docker events (App Mesh labeled
// containers only) and pushes die events plus a liveness marker to the daemon,
// each signed with the boot PSK. Noop without Docker.
func StartContainerEventsPush(ctx context.Context) {
	if !dockerEndpointConfigured() {
		return
	}
	go func() {
		// Reconnect loop; each (re)subscribe sends a fresh liveness marker.
		for {
			if ctx.Err() != nil {
				return
			}
			runEventsSubscription(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

// dockerEndpointConfigured mirrors RegisterContainerRoutes' gates: the
// Docker.Enable switch, then a configured endpoint.
func dockerEndpointConfigured() bool {
	if !config.ConfigData.Docker.Enable {
		return false
	}
	return os.Getenv("DOCKER_HOST") != "" || appmesh.IsFileExist(DockerSocketFilePath)
}

func runEventsSubscription(ctx context.Context) {
	cli, err := engineClient()
	if err != nil {
		logger.Warnf("Container events: %v", err)
		return
	}
	eventFilter := filters.NewArgs(
		filters.Arg("type", "container"),
		filters.Arg("label", labelManaged+"=true"),
	)
	eventsCh, errCh := cli.Events(ctx, events.ListOptions{Filters: eventFilter})
	logger.Info("Container events subscription established")
	defer logger.Info("Container events subscription ended")

	pushContainerEvent(containerEvent{Type: "sync"})
	ticker := time.NewTicker(containerEventSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pushContainerEvent(containerEvent{Type: "sync"})
		case msg, ok := <-eventsCh:
			if !ok {
				return
			}
			if msg.Type != events.ContainerEventType || msg.Action != events.ActionDie {
				continue
			}
			pushContainerEvent(containerEvent{
				Type:        "die",
				App:         msg.Actor.Attributes[labelApp],
				ContainerId: msg.Actor.ID,
			})
		case err := <-errCh:
			logger.Warnf("Container events stream error: %v", err)
			return
		}
	}
}

// containerEvent is the push wire format; App carries the appmesh.app label.
type containerEvent struct {
	Type        string `json:"type"`
	App         string `json:"app,omitempty"`
	ContainerId string `json:"containerId,omitempty"`
}

// pushContainerEvent signs with the boot PSK like the daemon's internal
// routes; failures are logged and dropped (the poll fallback covers a loss).
func pushContainerEvent(event containerEvent) {
	if cloud.AgentToCPPHMAC == nil {
		return
	}
	request := &Request{appmesh.NewRequest()}
	request.HTTPMethod = http.MethodPost
	request.RequestURI = containerEventPath
	request.ClientAddress = "agent-container-events"
	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	request.Body = body
	request.Headers[cloud.HeaderHMAC] = cloud.AgentToCPPHMAC.GenerateHMAC(request.UUID)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	conn, err := getLocalConnection()
	if err != nil {
		logger.Warnf("Container event <%s> not delivered: %v", event.Type, err)
		return
	}
	response, err := conn.sendRequestDataWithContext(ctx, request)
	if err != nil {
		logger.Warnf("Container event <%s> not delivered: %v", event.Type, err)
		return
	}
	if response.HTTPStatus >= http.StatusBadRequest {
		logger.Warnf("Container event <%s> rejected: %d %s", event.Type, response.HTTPStatus, string(response.Body))
	}
}
