package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	"gopkg.in/yaml.v2"
)

var configData = make(map[string]interface{})

func convertMap(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[fmt.Sprint(k)] = convertMap(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertMap(v)
		}
	}
	return i
}

func init() {
	yamlFile, err := os.ReadFile(filepath.Join(GetAppMeshHomeDir(), "config.yaml"))
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	// Create a map to hold the parsed YAML data
	data := make(map[interface{}]interface{})

	// Parse the YAML data into the map
	err = yaml.Unmarshal(yamlFile, &data)
	if err != nil {
		log.Fatalf("Error unmarshalling YAML: %v", err)
	}

	// Convert the map to map[string]interface{}
	configData = convertMap(data).(map[string]interface{})
}

func GetAppMeshHomeDir() string {
	return utils.GetParentDir(utils.GetCurrentAbPath())
}

func GetAppMeshConfig3(level1 string, level2 string, level3 string) (interface{}, error) {
	// Access data from the map
	// Read level 3 value in one line
	if value, ok := configData[level1].(map[string]interface{})[level2].(map[string]interface{})[level3]; ok {
		log.Printf("Value of %s = %v", level3, value)
		return value, nil
	} else {
		log.Printf("failed to retrieve yaml value for: %s", level3)
		return false, errors.New("failed to retrieve yaml value")
	}
}

func GetAppMeshConfig2(level1 string, level2 string) (interface{}, error) {
	// Access data from the map
	// Read level 3 value in one line
	if value, ok := configData[level1].(map[string]interface{})[level2]; ok {
		log.Printf("Value of %s = %v", level2, value)
		return value, nil
	} else {
		log.Printf("failed to retrieve yaml value for: %s", level2)
		return false, errors.New("failed to retrieve yaml value")
	}
}
