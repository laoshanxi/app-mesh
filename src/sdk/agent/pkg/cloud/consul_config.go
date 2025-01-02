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
	viperWatch   = viper.New()
)

func init() {
	initConfig()
}

func initConfig() {
	viperWatch.SetConfigName("consul-api-config") // Name of the config file (without extension)
	viperWatch.SetConfigType("yaml")              // Config file type

	if !config.IsAgentProdEnv() {
		viperWatch.AddConfigPath(".") // Path to look for the config file in, for debug test
	}
	viperWatch.AddConfigPath(filepath.Join(config.GetAppMeshHomeDir(), "work/config/")) // Path to look for the config file in
	viperWatch.AddConfigPath(config.GetAppMeshHomeDir())                                // Path to look for the config file in

	if err := viperWatch.ReadInConfig(); err != nil {
		logger.Warnf("failed to read consul-api-config.yaml: %v", err)
	} else {
		/*
			// Watch for changes to the config file
			viperWatch.WatchConfig()
			// Define what happens when the config changes
			viperWatch.OnConfigChange(func(e fsnotify.Event) {
				logger.Infof("Config file changed: %s", e.Name)
				// Here you can handle what to do with the new configuration
				if err := newConsulClient(); err != nil {
					logger.Warnf("failed to reload Consul client after config change: %v", err)
					setConsul(nil)
				}
			})
		*/
		if err := newConsulClient(); err != nil {
			logger.Warnf("failed to create Consul client: %v", err)
		}
	}
}

func newConsulClient() error {
	cfg, err := readConsulConfig()
	if err != nil {
		return fmt.Errorf("failed to read Consul config: %v", err)
	}

	config.ApplyEnvConfig(cfg)

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
	var consulConfig Config
	// Unmarshal YAML and ENV into consulConfig struct
	if err := viperWatch.Unmarshal(&consulConfig); err != nil {
		return nil, fmt.Errorf("unable to decode into config struct: %v", err)
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
		return nil, fmt.Errorf("consul not enable in consul-api-config.yaml")
	}
}
