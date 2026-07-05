package executor

import (
	"fmt"
	"strings"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// ResolveTargetNode finds a cluster node matching the given label selector.
//
// If nodeLabel contains a special key "host", its value is used directly.
// Otherwise, queries the local client first then each node in clusterNodes
// (via X-Target-Host forwarding) to find a label match.
//
// Returns the target host string or empty string for local execution.
func ResolveTargetNode(localClient *appmesh.AppMeshClient, serverURI string, nodeLabel map[string]string, clusterNodes []string) (string, error) {
	if len(nodeLabel) == 0 {
		return "", nil
	}

	if host, ok := nodeLabel["host"]; ok {
		return host, nil
	}

	if localClient != nil {
		if labels, err := localClient.ListLabels(); err == nil && labelsMatch(labels, nodeLabel) {
			return "", nil
		}
	}

	token := ""
	if localClient != nil {
		token = localClient.GetToken()
	}
	for _, node := range clusterNodes {
		probe, err := appmesh.NewTCPClient(appmesh.Option{
			AppMeshUri:         serverURI,
			ForwardTo:          node,
			JwtToken:           token,
			InsecureSkipVerify: true,
		})
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
