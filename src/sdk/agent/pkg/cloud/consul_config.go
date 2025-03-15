package cloud

import (
	"fmt"
	"path/filepath"
	"sync"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/spf13/viper"
)

type Config struct {
	Consul struct {
		Enable     bool   `mapstructure:"enable"`
		Address    string `mapstructure:"address"`
		Scheme     string `mapstructure:"scheme"`
		Datacenter string `mapstructure:"datacenter"`
		TLS        struct {
			Enable             bool   `mapstructure:"enable"`
			InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
			CAFile             string `mapstructure:"ca_file"`
			CertFile           string `mapstructure:"cert_file"`
			KeyFile            string `mapstructure:"key_file"`
		} `mapstructure:"tls"`
		Token string `mapstructure:"token"`
	} `mapstructure:"consul"`
}

var (
	consulClient *consulapi.Client
	consulMutex  sync.Mutex // Mutex to protect the consul client
)

func init() {
	if err := newConsulClient(); err != nil {
		logger.Warnf("failed to create Consul client: %v", err)
	}
}

func newConsulClient() error {
	cfg, err := readConsulConfig()
	if err != nil {
		return fmt.Errorf("failed to read Consul config: %v", err)
	}

	client, err := consulapi.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %v", err)
	}

	setConsul(client)
	logger.Infof("Consul client initialized successfully")
	return nil
}

func getConsul() *consulapi.Client {
	consulMutex.Lock()
	defer consulMutex.Unlock()
	return consulClient
}

func setConsul(client *consulapi.Client) {
	consulMutex.Lock()
	defer consulMutex.Unlock()
	consulClient = client
}

func readConsulConfig() (*consulapi.Config, error) {
	viperConfig := viper.New()
	viperConfig.SetConfigName("consul") // Name of the config file (without extension)
	viperConfig.SetConfigType("yaml")   // Config file type

	if !config.IsAgentProdEnv() {
		viperConfig.AddConfigPath(".") // Path to look for the config file in, for debug test
	}
	viperConfig.AddConfigPath(filepath.Join(config.GetAppMeshHomeDir(), "work/config/")) // Path to look for the config file in
	viperConfig.AddConfigPath(config.GetAppMeshHomeDir())                                // Path to look for the config file in

	// Read YAML file
	if err := viperConfig.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Override config with environment variables
	config.OverrideConfigWithEnv(viperConfig)

	// Unmarshal into struct
	var consulConfig Config
	if err := viperConfig.Unmarshal(&consulConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if consulConfig.Consul.Enable {
		config := consulapi.DefaultConfig()
		config.Address = consulConfig.Consul.Address
		config.Scheme = consulConfig.Consul.Scheme
		config.Datacenter = consulConfig.Consul.Datacenter
		config.Token = consulConfig.Consul.Token
		if consulConfig.Consul.TLS.Enable {
			config.TLSConfig = consulapi.TLSConfig{
				CAFile:             consulConfig.Consul.TLS.CAFile,
				CertFile:           consulConfig.Consul.TLS.CertFile,
				KeyFile:            consulConfig.Consul.TLS.KeyFile,
				InsecureSkipVerify: consulConfig.Consul.TLS.InsecureSkipVerify,
			}
		}
		return config, nil
	} else {
		return nil, fmt.Errorf("consul not enable in consul.yaml")
	}
}
