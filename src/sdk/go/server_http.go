package appmesh

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// AppMeshServerHttpContext interacts with the App Mesh REST service over HTTPS for server-side applications.
// Requires environment variables: APP_MESH_PROCESS_KEY and APP_MESH_APPLICATION_NAME.
type AppMeshServerHttpContext struct {
	client *AppMeshClient
}

// NewHTTPContext creates a new AppMeshServer instance for interacting with the local App Mesh service.
// Uses default HTTPS endpoint and SSL settings unless overridden via Option.
func NewHTTPContext(options Option) (*AppMeshServerHttpContext, error) {
	httpClient, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &AppMeshServerHttpContext{client: httpClient}, nil
}
func newHTTPContextWithRequester(options Option, r Requester) (*AppMeshServerHttpContext, error) {
	httpClient, err := newHTTPClientWithRequester(options, r)
	if err != nil {
		return nil, err
	}
	return &AppMeshServerHttpContext{client: httpClient}, nil
}

// getRuntimeEnv reads and validates required runtime environment variables.
func (r *AppMeshServerHttpContext) getRuntimeEnv() (key, appName string, err error) {
	key = os.Getenv("APP_MESH_PROCESS_KEY")
	appName = os.Getenv("APP_MESH_APPLICATION_NAME")

	if key == "" {
		return "", "", errors.New("missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service")
	}
	if appName == "" {
		return "", "", errors.New("missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service")
	}
	return key, appName, nil
}

// TaskFetch fetches task data (payload) from the App Mesh service for the current running application process.
// Uses context for cancellation support with exponential backoff on retries.
// Returns the payload string provided by the client.
func (r *AppMeshServerHttpContext) TaskFetch() (string, error) {
	return r.TaskFetchWithContext(context.Background())
}

// TaskFetchWithContext fetches task data with context support for cancellation and timeout.
//
// Retries with exponential backoff (100ms → 10s cap). Pass a context with timeout/cancel
// to limit the retry duration.
func (r *AppMeshServerHttpContext) TaskFetchWithContext(ctx context.Context) (string, error) {
	key, appName, err := r.getRuntimeEnv()
	if err != nil {
		return "", err
	}

	path := "/appmesh/app/" + appName + "/task"
	query := url.Values{}
	query.Set("process_key", key)

	const (
		initialDelay = 100 * time.Millisecond
		maxDelay     = 10 * time.Second
	)
	delay := initialDelay

	for {
		status, body, _, err := r.client.get(path, query, nil)
		if err != nil {
			log.Printf("task_fetch request failed: %v, retrying...", err)
		} else if status == http.StatusOK {
			return string(body), nil
		} else {
			log.Printf("task_fetch failed with status %d: %s, retrying...", status, string(body))
		}

		// Wait with context cancellation support
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("task_fetch cancelled: %w", ctx.Err())
		case <-timer.C:
		}

		// Exponential backoff with cap
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}
}

// TaskReturn sends the result of a processed task back to the original invoking client via App Mesh service.
// Returns error if the PUT request fails.
func (r *AppMeshServerHttpContext) TaskReturn(result string) error {
	processKey, appName, err := r.getRuntimeEnv()
	if err != nil {
		return err
	}

	path := "/appmesh/app/" + appName + "/task"
	query := url.Values{}
	query.Set("process_key", processKey)
	headers := map[string]string{"Content-Type": "text/plain"}

	status, body, err := r.client.put(path, query, headers, []byte(result))
	if err != nil {
		return err
	}

	if status != http.StatusOK {
		return errors.New("task_return failed with status " + http.StatusText(status) + ": " + string(body))
	}

	return nil
}
