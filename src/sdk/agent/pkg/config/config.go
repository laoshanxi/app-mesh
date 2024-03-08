package config

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
)

var configJsonData map[string]interface{}

func init() {
	data, err := os.ReadFile(filepath.Join(GetAppMeshHomeDir(), "config.json"))
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	// Unmarshal the JSON data into the map
	err = json.Unmarshal(data, &configJsonData)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}
}

func GetAppMeshHomeDir() string {
	return utils.GetParentDir(utils.GetCurrentAbPath())
}

func GetAppMeshConfig3(level1 string, level2 string, level3 string) (interface{}, error) {
	// Access data from the map
	// Read level 3 value in one line
	if value, ok := configJsonData[level1].(map[string]interface{})[level2].(map[string]interface{})[level3]; ok {
		log.Printf("Value of %s = %v", level3, value)
		return value, nil
	} else {
		log.Printf("failed to retrieve json value for: %s", level3)
		return false, errors.New("failed to retrieve json value")
	}
}

func GetAppMeshConfig2(level1 string, level2 string) (interface{}, error) {
	// Access data from the map
	// Read level 3 value in one line
	if value, ok := configJsonData[level1].(map[string]interface{})[level2]; ok {
		log.Printf("Value of %s = %v", level2, value)
		return value, nil
	} else {
		log.Printf("failed to retrieve json value for: %s", level2)
		return false, errors.New("failed to retrieve json value")
	}
}
