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

// NewHTTPContext creates a server-side task context backed by the HTTP client.
// Uses default HTTPS endpoint and TLS settings unless overridden via Option.
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

// TaskFetch fetches task data (payload) for the current application process.
// It retries with a short fixed delay until success or caller cancellation.
func (r *AppMeshServerHttpContext) TaskFetch() (string, error) {
	return r.TaskFetchWithContext(context.Background())
}

// TaskFetchWithContext fetches task data with context support for cancellation and timeout.
//
// Retries with a fixed 100ms delay on failure. Pass a context with timeout/cancel
// to limit the retry duration.
func (r *AppMeshServerHttpContext) TaskFetchWithContext(ctx context.Context) (string, error) {
	key, appName, err := r.getRuntimeEnv()
	if err != nil {
		return "", err
	}

	path := "/appmesh/app/" + appName + "/task"
	query := url.Values{}
	query.Set("process_key", key)

	const retryDelay = 100 * time.Millisecond

	for {
		attemptStart := time.Now()
		status, body, _, err := r.client.get(path, query, nil)
		if err != nil {
			log.Printf("task_fetch request failed: %v, retrying...", err)
		} else if status == http.StatusOK {
			return string(body), nil
		} else {
			log.Printf("task_fetch failed with status %d: %s, retrying...", status, string(body))
		}

		if remaining := retryDelay - time.Since(attemptStart); remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", fmt.Errorf("task_fetch cancelled: %w", ctx.Err())
			case <-timer.C:
			}
		} else {
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("task_fetch cancelled: %w", ctx.Err())
			default:
			}
		}
	}
}

// TaskReturn sends the processed result bytes back to the original invoking client via App Mesh.
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
