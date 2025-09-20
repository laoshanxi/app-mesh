package cloud

import (
	"context"
	"encoding/json"
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

func NewCloud() *Cloud {
	return &Cloud{
		appmesh: NewAppMeshClient(),
	}
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

	// Initial report
	r.updateHostResourcesInConsul(kvPath)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop() // Ensure ticker is cleaned up when the function exits

	for {
		select {
		case <-ctx.Done():
			logManager.Log(fmt.Sprintf("context canceled: %v", ctx.Err()))
			return ctx.Err()
		case <-ticker.C:
			r.updateHostResourcesInConsul(kvPath)
		}
	}
}

func (r *Cloud) updateHostResourcesInConsul(kvPath string) {
	consul := getConsul()
	if consul == nil {
		logManager.Log("consul not initialized")
		return
	}

	// Register HTTP service
	if err := r.registerHttpService(); err != nil {
		logManager.Log(fmt.Sprintf("Failed to register HTTP service: %v", err))
		return
	}

	// Fetch resources and report to Consul
	resources, err := r.appmesh.GetHostResources()
	if err != nil {
		logManager.Log(fmt.Sprintf("Failed to get cloud resources: %v", err))
		return
	}

	if len(resources) == 0 {
		logManager.Log("No resources to report")
		return
	}

	// Serialize resources to JSON
	data, err := json.Marshal(resources)
	if err != nil {
		logManager.Log(fmt.Sprintf("Failed to marshal resources: %v", err))
		return
	}

	kvPair := &api.KVPair{Key: kvPath, Value: data}
	if _, err := consul.KV().Put(kvPair, nil); err != nil {
		logManager.Log(fmt.Sprintf("Failed to report resources: %v", err))
	} else {
		logManager.Log("Successfully reported resources")
	}
}
