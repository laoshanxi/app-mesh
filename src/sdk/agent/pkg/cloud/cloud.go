package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
)

type Cloud struct {
	appmesh *AppMesh
}

var logManager = NewLogManager(1 * time.Hour)

const (
	hostResourceSessionTTL = "90s"
	hostResourceReportRate = 30 * time.Second
)

var (
	errHostResourceKeyNotAcquired = errors.New("host-resource key not acquired")
	errHostResourceSessionExpired = errors.New("host-resource session expired")
)

func NewCloud() (*Cloud, error) {
	client, err := NewAppMeshClient()
	if err != nil {
		return nil, err
	}
	return &Cloud{appmesh: client}, nil
}

func (r *Cloud) getLeader() (string, error) {
	consul := getConsul()
	if consul == nil {
		return "", fmt.Errorf("consul not initialized")
	}

	leader, err := consulClient.Status().Leader()
	if err != nil {
		return "", fmt.Errorf("failed to get Consul leader: %v", err)
	}

	return leader, nil
}

func (r *Cloud) registerHttpService() error {
	consul := getConsul()
	if consul == nil {
		return fmt.Errorf("consul not initialized")
	}

	// Define the service details
	serviceName := "APPMESH-HTTP"
	serviceAddress, err := os.Hostname() // Service address
	if err != nil {
		return fmt.Errorf("failed to get hostname: %v", err)
	}
	servicePort := config.ConfigData.REST.RestListenPort // Service port for HTTPS
	serviceID := serviceName + "-" + serviceAddress      // Unique service ID

	// Construct the URL using the net/url package
	uri := url.URL{Scheme: "https", Host: fmt.Sprintf("%s:%d", serviceAddress, servicePort)}

	reg := &api.AgentServiceRegistration{
		ID:      serviceID,
		Name:    serviceName,
		Port:    servicePort,
		Address: serviceAddress,
		Check: &api.AgentServiceCheck{
			HTTP:                           uri.String(),
			Interval:                       "10s",
			Timeout:                        "5s",
			TLSSkipVerify:                  true,
			DeregisterCriticalServiceAfter: "30s", // Deregister if critical for 0.5 minute
		},
	}

	if err := consul.Agent().ServiceRegister(reg); err != nil {
		return fmt.Errorf("failed to register service: %v", err)
	}
	return nil
}

func (r *Cloud) ReportHostMetricsPeriodically(ctx context.Context) error {
	hostname, err := os.Hostname()
	if err != nil {
		logManager.Log(fmt.Sprintf("failed to get hostname: %v", err))
		return err
	}

	kvPath := fmt.Sprintf("appmesh/nodes/%s/resources", hostname)
	sessionID := ""
	defer func() {
		if sessionID == "" {
			return
		}
		consul := getConsul()
		if consul == nil {
			return
		}
		destroyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := consul.Session().Destroy(sessionID, (&api.WriteOptions{}).WithContext(destroyCtx)); err != nil {
			logManager.Log(fmt.Sprintf("Failed to destroy host-resource session: %v", err))
		}
	}()

	// Initial report
	if err := r.updateHostResourcesInConsul(ctx, hostname, kvPath, &sessionID); err != nil {
		logManager.Log(err.Error())
	}

	ticker := time.NewTicker(hostResourceReportRate)
	defer ticker.Stop() // Ensure ticker is cleaned up when the function exits

	for {
		select {
		case <-ctx.Done():
			logManager.Log(fmt.Sprintf("context canceled: %v", ctx.Err()))
			return ctx.Err()
		case <-ticker.C:
			if err := r.updateHostResourcesInConsul(ctx, hostname, kvPath, &sessionID); err != nil {
				logManager.Log(err.Error())
			}
		}
	}
}

func ensureHostResourceSession(ctx context.Context, consul *api.Client, hostname string, sessionID *string) error {
	if *sessionID != "" {
		return nil
	}

	created, _, err := consul.Session().CreateNoChecks(&api.SessionEntry{
		Name:     fmt.Sprintf("appmesh-host-resources-%s", hostname),
		Behavior: api.SessionBehaviorDelete,
		TTL:      hostResourceSessionTTL,
	}, (&api.WriteOptions{}).WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to create host-resource session: %w", err)
	}
	if created == "" {
		return fmt.Errorf("failed to create host-resource session: empty session ID")
	}
	*sessionID = created
	return nil
}

func renewHostResourceSession(ctx context.Context, consul *api.Client, sessionID string) error {
	entry, _, err := consul.Session().Renew(sessionID, (&api.WriteOptions{}).WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to renew host-resource session: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("%w: failed to renew host-resource session", errHostResourceSessionExpired)
	}
	return nil
}

func acquireHostResource(ctx context.Context, consul *api.Client, kvPath, sessionID string, data []byte) error {
	acquired, _, err := consul.KV().Acquire(&api.KVPair{
		Key:     kvPath,
		Value:   data,
		Session: sessionID,
	}, (&api.WriteOptions{}).WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to report resources: %w", err)
	}
	if !acquired {
		return fmt.Errorf("%w: key is owned by another live host session", errHostResourceKeyNotAcquired)
	}
	return nil
}

func publishHostResource(ctx context.Context, consul *api.Client, hostname, kvPath string, sessionID *string, data []byte) error {
	if err := ensureHostResourceSession(ctx, consul, hostname, sessionID); err != nil {
		return err
	}
	if err := acquireHostResource(ctx, consul, kvPath, *sessionID, data); err != nil {
		if !errors.Is(err, errHostResourceKeyNotAcquired) {
			return err
		}
		// The session may have expired before Acquire. Inspecting it does not extend
		// its TTL; recreate and retry only when it is actually gone.
		entry, _, infoErr := consul.Session().Info(*sessionID, (&api.QueryOptions{}).WithContext(ctx))
		if infoErr != nil {
			return fmt.Errorf("failed to inspect host-resource session after acquire rejection: %w", infoErr)
		}
		if entry != nil {
			return err
		}
		*sessionID = ""
		if createErr := ensureHostResourceSession(ctx, consul, hostname, sessionID); createErr != nil {
			return createErr
		}
		if retryErr := acquireHostResource(ctx, consul, kvPath, *sessionID, data); retryErr != nil {
			return retryErr
		}
	}
	if err := renewHostResourceSession(ctx, consul, *sessionID); err != nil {
		// A transport/HTTP failure is ambiguous: Consul may have renewed the
		// session before the response was lost. Forget it only on confirmed expiry.
		if errors.Is(err, errHostResourceSessionExpired) {
			*sessionID = ""
		}
		return err
	}
	return nil
}

func (r *Cloud) updateHostResourcesInConsul(ctx context.Context, hostname, kvPath string, sessionID *string) error {
	consul := getConsul()
	if consul == nil {
		return fmt.Errorf("consul not initialized")
	}

	// Register HTTP service
	if err := r.registerHttpService(); err != nil {
		return fmt.Errorf("failed to register HTTP service: %w", err)
	}

	// Fetch resources and report to Consul
	resources, err := r.appmesh.GetHostResources(ctx)
	if err != nil {
		return fmt.Errorf("failed to get host resources: %w", err)
	}

	if len(resources) == 0 {
		return fmt.Errorf("no resources to report")
	}

	// Serialize resources to JSON
	data, err := json.Marshal(resources)
	if err != nil {
		return fmt.Errorf("failed to marshal resources: %w", err)
	}

	// Renew only freshly published data. Failed collection or publication lets
	// the old session and KV expire.
	if err := publishHostResource(ctx, consul, hostname, kvPath, sessionID, data); err != nil {
		return err
	}
	logManager.Log("Successfully reported resources")
	return nil
}
