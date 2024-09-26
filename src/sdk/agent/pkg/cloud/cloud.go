package cloud

import (
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

	return consulClient.Status().Leader()
}

func (r *Cloud) registerHttpService() error {
	consul := getConsul()
	if consul == nil {
		return fmt.Errorf("consul not initialized")
	}

	// Define the service details
	serviceName := "APPMESH-HTTP"                        // Service name
	serviceAddress, _ := os.Hostname()                   // Service address
	servicePort := config.ConfigData.REST.RestListenPort // Service port for HTTPS
	serviceID := serviceName + "-" + serviceAddress      // Unique service ID
	// Construct the URL using the net/url package
	uri := url.URL{Scheme: "https", Host: fmt.Sprintf("%s:%d", "serviceAddress", servicePort)}

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

	return consul.Agent().ServiceRegister(reg)
}

func (r *Cloud) ReportHostResource() {

	hostname, _ := os.Hostname()
	kvPath := fmt.Sprintf("appmesh/nodes/%s/resources", hostname)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	r.doReport(kvPath)
	for range ticker.C {
		r.doReport(kvPath)
	}

}

func (r *Cloud) doReport(kvPath string) {
	consul := getConsul()
	if consul == nil {
		logManager.Log("consul not initialized")
	} else {
		// Register HTTP service
		if err := r.registerHttpService(); err != nil {
			logManager.Log(fmt.Sprintf("Failed to register http service: %v", err))
		}
		// Fetch resources and report to Consul
		resources, err := r.appmesh.GetCloudResource()
		if err != nil {
			logManager.Log(fmt.Sprintf("Failed to get cloud resources: %v", err))
			return
		}

		if len(resources) == 0 {
			logManager.Log("No resources to report")
			return
		}

		kvPair := &api.KVPair{Key: kvPath, Value: []byte(resources)}
		if _, err := consul.KV().Put(kvPair, nil); err != nil {
			logManager.Log(fmt.Sprintf("Failed to report resources: %v", err))
		} else {
			logManager.Log("Successfully reported resources")
		}
	}
}
