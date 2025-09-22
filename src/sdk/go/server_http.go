package appmesh

import (
	"errors"
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

// NewHttpContext creates a new AppMeshServer instance for interacting with the local App Mesh service.
// Uses default HTTPS endpoint and SSL settings unless overridden via Option.
func NewHttpContext(options Option) *AppMeshServerHttpContext {
	return &AppMeshServerHttpContext{client: NewHttpClient(options)}
}

// getRuntimeEnv reads and validates required runtime environment variables.
func (r *AppMeshServerHttpContext) getRuntimeEnv() (processID, appName string, err error) {
	processID = os.Getenv("APP_MESH_PROCESS_KEY")
	appName = os.Getenv("APP_MESH_APPLICATION_NAME")

	if processID == "" {
		return "", "", errors.New("missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service")
	}
	if appName == "" {
		return "", "", errors.New("missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service")
	}
	return processID, appName, nil
}

// TaskFetch fetches task data (payload) from the App Mesh service for the current running application process.
// Retries indefinitely with 100ms backoff until successful.
// Returns the payload string provided by the client.
func (r *AppMeshServerHttpContext) TaskFetch() (string, error) {
	processID, appName, err := r.getRuntimeEnv()
	if err != nil {
		return "", err
	}

	path := "/appmesh/app/" + appName + "/task"
	query := url.Values{}
	query.Set("process_uuid", processID)

	for {
		status, body, _, err := r.client.get(path, query, nil)
		if err != nil {
			log.Printf("task_fetch request failed: %v, retrying...", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if status != http.StatusOK {
			log.Printf("task_fetch failed with status %d: %s, retrying...", status, string(body))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return string(body), nil
	}
}

// TaskReturn sends the result of a processed task back to the original invoking client via App Mesh service.
// Returns error if the PUT request fails.
func (r *AppMeshServerHttpContext) TaskReturn(result string) error {
	processID, appName, err := r.getRuntimeEnv()
	if err != nil {
		return err
	}

	path := "/appmesh/app/" + appName + "/task"
	query := url.Values{}
	query.Set("process_uuid", processID)
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
