package config_loader

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/naoina/toml"
)

func LoadConfig(file io.Reader, filename string, cfg interface{}) error {
	ext := strings.ToLower(filepath.Ext(filename))

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("JSON parse error: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("YAML parse error: %w", err)
		}
	default:
		if err := toml.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("TOML parse error: %w", err)
		}
	}

	return nil
}
