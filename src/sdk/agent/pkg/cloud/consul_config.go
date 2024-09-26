package cloud

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
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
	initConfig()
}

func initConfig() {
	viper.SetConfigName("consul-api-config") // Name of the config file (without extension)
	viper.SetConfigType("yaml")              // Config file type

	viper.AutomaticEnv()                                   // Config ENV setting
	viper.SetEnvPrefix("APPMESH")                          // Config ENV pre-fix
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Config ENV use _ instead of .

	if config.IsAgentProdEnv() {
		viper.AddConfigPath(filepath.Join(config.GetAppMeshHomeDir(), "work/config/")) // Path to look for the config file in
	} else {
		viper.AddConfigPath(".") // Path to look for the config file in, for debug test
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("failed to read consul-api-config.yaml: %v", err)
	} else {
		// Watch for changes to the config file
		viper.WatchConfig()
		// Define what happens when the config changes
		viper.OnConfigChange(func(e fsnotify.Event) {
			log.Printf("Config file changed: %s", e.Name)
			// Here you can handle what to do with the new configuration
			if err := newConsulClient(); err != nil {
				log.Printf("failed to reload Consul client after config change: %v", err)
				setConsul(nil)
			}
		})
		if err := newConsulClient(); err != nil {
			log.Printf("failed to create Consul client: %v", err)
		}
	}
}

func newConsulClient() error {
	config, err := readConsulConfig()
	if err != nil {
		return fmt.Errorf("failed to read Consul config: %v", err)
	}

	client, err := consulapi.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %v", err)
	}

	setConsul(client)
	log.Println("Consul client initialized successfully")
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
	if err := viper.Unmarshal(&consulConfig); err != nil {
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
