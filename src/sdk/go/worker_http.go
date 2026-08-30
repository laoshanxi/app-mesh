package appmesh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// ErrProcessSuperseded indicates the server rejected the process key (HTTP 412):
// this process instance has been superseded by another and should stop fetching tasks.
var ErrProcessSuperseded = errors.New("process superseded: process key mismatch")

// ErrWorkerRejected indicates a permanent worker request error (HTTP 400).
// Retrying the same request cannot recover; the worker entry point should exit.
var ErrWorkerRejected = errors.New("worker task request permanently rejected")

// WorkerHTTPContext runs a worker-side task loop (fetch task, send result) against
// the App Mesh REST service over HTTPS.
// Requires environment variables: APP_MESH_PROCESS_KEY and APP_MESH_APPLICATION_NAME.
type WorkerHTTPContext struct {
	client *AppMeshClient
}

// NewHTTPContext creates a server-side task context over HTTP. Server endpoints
// authenticate via APP_MESH_PROCESS_KEY; the worker is not an OAuth client.
func NewHTTPContext(options Option) (*WorkerHTTPContext, error) {
	httpClient, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &WorkerHTTPContext{client: httpClient}, nil
}
func newHTTPContextWithRequester(options Option, r Requester) (*WorkerHTTPContext, error) {
	httpClient, err := newHTTPClientWithRequester(options, r)
	if err != nil {
		return nil, err
	}
	return &WorkerHTTPContext{client: httpClient}, nil
}

// getRuntimeEnv reads and validates required runtime environment variables.
func (r *WorkerHTTPContext) getRuntimeEnv() (key, appName string, err error) {
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

// FetchTask fetches task data (payload) for the current application process.
// It retries transient failures until success with a fixed 100ms floor per attempt
// (SDKContract.md).
// It returns ErrProcessSuperseded when the server responds 412 (this process
// instance has been replaced), and ErrWorkerRejected for a permanent HTTP 400.
func (r *WorkerHTTPContext) FetchTask() (string, error) {
	return r.FetchTaskContext(context.Background())
}

// FetchTaskContext is FetchTask with a caller-supplied context controlling cancellation:
// the retry loop stops with ctx.Err() once the context is done.
func (r *WorkerHTTPContext) FetchTaskContext(ctx context.Context) (string, error) {
	key, appName, err := r.getRuntimeEnv()
	if err != nil {
		return "", err
	}

	path := "/appmesh/app/" + appName + "/task"
	headers := map[string]string{"X-AppMesh-Process-Key": key}

	// Fixed 100ms floor per attempt: sleep only the remainder if the attempt
	// finished early; otherwise retry immediately. No backoff (SDKContract.md).
	const retryFloor = 100 * time.Millisecond

	for {
		attemptStart := time.Now()
		status, body, _, err := r.client.req.SendContext(ctx, http.MethodGet, path, nil, headers, nil)
		if err != nil {
			if ctx.Err() != nil {
				return "", fmt.Errorf("fetch_task canceled: %w", ctx.Err())
			}
			logf("fetch_task request failed: %v, retrying...", err)
		} else if status == http.StatusOK {
			return string(body), nil
		} else if status == http.StatusPreconditionFailed {
			return "", ErrProcessSuperseded
		} else if status == http.StatusBadRequest {
			return "", fmt.Errorf("%w: status %d: %s", ErrWorkerRejected, status, string(body))
		} else {
			logf("fetch_task failed with status %d: %s, retrying...", status, string(body))
		}

		if remaining := retryFloor - time.Since(attemptStart); remaining > 0 {
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("fetch_task canceled: %w", ctx.Err())
			case <-time.After(remaining):
			}
		}
	}
}

// SendTaskResult sends the processed result bytes back to the original invoking client via App Mesh.
func (r *WorkerHTTPContext) SendTaskResult(result string) error {
	processKey, appName, err := r.getRuntimeEnv()
	if err != nil {
		return err
	}

	path := "/appmesh/app/" + appName + "/task"
	headers := map[string]string{
		"Content-Type":          "text/plain",
		"X-AppMesh-Process-Key": processKey,
	}

	status, body, err := r.client.put(path, nil, headers, []byte(result))
	if err != nil {
		return err
	}

	if status != http.StatusOK {
		return errors.New("send_task_result failed with status " + http.StatusText(status) + ": " + string(body))
	}

	return nil
}
