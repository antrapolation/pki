package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the agent configuration loaded from YAML.
type Config struct {
	PKCS11 struct {
		Library string `yaml:"library"`
		Slot    uint   `yaml:"slot"`
		Pin     string `yaml:"pin"`
	} `yaml:"pkcs11"`

	Backend struct {
		URL string `yaml:"url"`
		TLS struct {
			MinVersion string `yaml:"min_version"`
			ClientCert string `yaml:"client_cert"`
			ClientKey  string `yaml:"client_key"`
			CACert     string `yaml:"ca_cert"`
		} `yaml:"tls"`
	} `yaml:"backend"`

	Agent struct {
		ID                string `yaml:"id"`
		TenantID          string `yaml:"tenant_id"`
		HeartbeatInterval string `yaml:"heartbeat_interval"`
	} `yaml:"agent"`
}

// LoadConfig reads and parses the YAML configuration file.
// Environment variables in the form ${VAR_NAME} are expanded for the PIN field.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Expand environment variables in PIN
	if strings.HasPrefix(config.PKCS11.Pin, "${") && strings.HasSuffix(config.PKCS11.Pin, "}") {
		envVar := config.PKCS11.Pin[2 : len(config.PKCS11.Pin)-1]
		config.PKCS11.Pin = os.Getenv(envVar)
		if config.PKCS11.Pin == "" {
			return nil, fmt.Errorf("environment variable %s not set", envVar)
		}
	}

	return &config, nil
}
