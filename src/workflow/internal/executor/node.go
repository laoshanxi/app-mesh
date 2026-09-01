package executor

import (
	"fmt"
	"strings"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/tlsconf"
)

// ResolveTargetNode finds a cluster node matching the given label selector.
//
// The local node is checked first. Remote probes carry only the caller's Dex
// bearer, which the destination independently verifies against the shared Dex.
func ResolveTargetNode(localClient *appmesh.AppMeshClient, serverURI string, nodeLabel map[string]string, clusterNodes []string, forwardToken string) (string, error) {
	if len(nodeLabel) == 0 {
		return "", nil
	}

	if host, ok := nodeLabel["host"]; ok {
		if forwardToken == "" {
			return "", fmt.Errorf("remote workflow host %q requires a transient caller Dex bearer", host)
		}
		return host, nil
	}

	if localClient != nil {
		if labels, err := localClient.ListLabels(); err == nil && labelsMatch(labels, nodeLabel) {
			return "", nil
		}
	}

	if forwardToken == "" {
		return "", fmt.Errorf("no local node matches label selector %s and remote probing requires a transient caller Dex bearer", formatLabels(nodeLabel))
	}
	for _, node := range clusterNodes {
		probeOption := appmesh.Option{
			AppMeshUri: serverURI,
			ForwardTo:  node,
			JwtToken:   forwardToken,
		}
		tlsconf.Apply(&probeOption)
		probe, err := appmesh.NewTCPClient(probeOption)
		if err != nil {
			continue
		}
		remoteLabels, err := probe.ListLabels()
		probe.CloseConnection()
		if err != nil {
			continue
		}
		if labelsMatch(remoteLabels, nodeLabel) {
			return node, nil
		}
	}

	return "", fmt.Errorf("no node matches label selector: %s", formatLabels(nodeLabel))
}

func labelsMatch(nodeLabels, selector map[string]string) bool {
	for k, v := range selector {
		if nodeLabels[k] != v {
			return false
		}
	}
	return true
}

func formatLabels(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}
