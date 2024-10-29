package cloud

import (
	"os"
	"testing"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestLeader(t *testing.T) {
	consul := NewCloud()
	logger.Info(consul.getLeader())
}

func TestRegisterSelf(t *testing.T) {
	consul := NewCloud()
	logger.Info(consul.registerHttpService())
}

func TestReportResource(t *testing.T) {
	os.Setenv("APPMESH_CONSUL_ENABLE", "true")
	os.Setenv("APPMESH_CONSUL_ADDRESS", "192.168.1.1:8500")
	cfg, _ := readConsulConfig()
	require.NotNil(t, cfg)
	require.Equal(t, cfg.Address, "192.168.1.1:8500")

	require.False(t, config.IsAgentProdEnv())
	//consul := NewCloud()
	//consul.ReportHostResource()
}
