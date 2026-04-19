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
		AuthToken         string `yaml:"auth_token"`
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

	// Expand ${VAR} in sensitive fields so secrets don't live in config files.
	config.PKCS11.Pin, err = expandEnvVar(config.PKCS11.Pin, "pkcs11.pin")
	if err != nil {
		return nil, err
	}

	config.Agent.AuthToken, err = expandEnvVar(config.Agent.AuthToken, "agent.auth_token")
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// expandEnvVar replaces a ${VAR} literal with os.Getenv(VAR). Pass-through
// for non-placeholder values. Returns an error if the envvar is unset.
func expandEnvVar(value, field string) (string, error) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return value, nil
	}
	envVar := value[2 : len(value)-1]
	v := os.Getenv(envVar)
	if v == "" {
		return "", fmt.Errorf("environment variable %s (referenced by %s) is not set", envVar, field)
	}
	return v, nil
}
