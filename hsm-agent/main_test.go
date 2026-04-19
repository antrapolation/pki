package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `
pkcs11:
  library: "/usr/lib/softhsm/libsofthsm2.so"
  slot: 0
  pin: "1234"
backend:
  url: "wss://localhost:9010/hsm/connect"
  tls:
    min_version: "1.3"
    client_cert: "/etc/pki/agent-cert.pem"
    client_key: "/etc/pki/agent-key.pem"
    ca_cert: "/etc/pki/ca-chain.pem"
agent:
  id: "test-agent"
  tenant_id: "test-tenant"
  heartbeat_interval: "10s"
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.PKCS11.Library != "/usr/lib/softhsm/libsofthsm2.so" {
		t.Errorf("Library = %q, want /usr/lib/softhsm/libsofthsm2.so", config.PKCS11.Library)
	}
	if config.PKCS11.Slot != 0 {
		t.Errorf("Slot = %d, want 0", config.PKCS11.Slot)
	}
	if config.PKCS11.Pin != "1234" {
		t.Errorf("Pin = %q, want 1234", config.PKCS11.Pin)
	}
	if config.Backend.URL != "wss://localhost:9010/hsm/connect" {
		t.Errorf("Backend.URL = %q, want wss://localhost:9010/hsm/connect", config.Backend.URL)
	}
	if config.Agent.ID != "test-agent" {
		t.Errorf("Agent.ID = %q, want test-agent", config.Agent.ID)
	}
	if config.Agent.TenantID != "test-tenant" {
		t.Errorf("Agent.TenantID = %q, want test-tenant", config.Agent.TenantID)
	}
	if config.Agent.HeartbeatInterval != "10s" {
		t.Errorf("HeartbeatInterval = %q, want 10s", config.Agent.HeartbeatInterval)
	}
}

func TestLoadConfigEnvExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configData := `
pkcs11:
  library: "/usr/lib/softhsm/libsofthsm2.so"
  slot: 0
  pin: "${TEST_HSM_PIN}"
backend:
  url: "wss://localhost:9010/hsm/connect"
  tls:
    min_version: "1.3"
    client_cert: ""
    client_key: ""
    ca_cert: ""
agent:
  id: "test"
  tenant_id: "test"
  heartbeat_interval: "5s"
`
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Without env var set, should fail
	os.Unsetenv("TEST_HSM_PIN")
	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error when env var not set")
	}

	// With env var set, should succeed
	t.Setenv("TEST_HSM_PIN", "secret-pin")

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if config.PKCS11.Pin != "secret-pin" {
		t.Errorf("Pin = %q, want secret-pin", config.PKCS11.Pin)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for missing config file")
	}
}

func TestRegisterMsgSerialization(t *testing.T) {
	msg := RegisterMsg{
		Type:          "register",
		TenantID:      "tenant-001",
		AgentID:       "agent-01",
		AvailableKeys: []string{"key-a", "key-b"},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded RegisterMsg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Type != "register" {
		t.Errorf("Type = %q, want register", decoded.Type)
	}
	if decoded.TenantID != "tenant-001" {
		t.Errorf("TenantID = %q, want tenant-001", decoded.TenantID)
	}
	if decoded.AgentID != "agent-01" {
		t.Errorf("AgentID = %q, want agent-01", decoded.AgentID)
	}
	if len(decoded.AvailableKeys) != 2 {
		t.Errorf("AvailableKeys length = %d, want 2", len(decoded.AvailableKeys))
	}
}

func TestSignRequestDeserialization(t *testing.T) {
	raw := `{
		"type": "sign_request",
		"request_id": "req-123",
		"key_label": "my-key",
		"tbs_data": "aGVsbG8gd29ybGQ=",
		"algorithm": "ECC-P256"
	}`

	var req SignRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if req.Type != "sign_request" {
		t.Errorf("Type = %q, want sign_request", req.Type)
	}
	if req.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want req-123", req.RequestID)
	}
	if req.KeyLabel != "my-key" {
		t.Errorf("KeyLabel = %q, want my-key", req.KeyLabel)
	}
	if req.TbsData != "aGVsbG8gd29ybGQ=" {
		t.Errorf("TbsData = %q, want aGVsbG8gd29ybGQ=", req.TbsData)
	}
	if req.Algorithm != "ECC-P256" {
		t.Errorf("Algorithm = %q, want ECC-P256", req.Algorithm)
	}
}

func TestSignResponseSerialization(t *testing.T) {
	// Success response
	resp := SignResponse{
		Type:      "sign_response",
		RequestID: "req-123",
		Signature: "c2lnbmF0dXJl",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SignResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Signature != "c2lnbmF0dXJl" {
		t.Errorf("Signature = %q, want c2lnbmF0dXJl", decoded.Signature)
	}
	if decoded.Error != "" {
		t.Errorf("Error = %q, want empty", decoded.Error)
	}

	// Error response
	errResp := SignResponse{
		Type:      "sign_response",
		RequestID: "req-456",
		Error:     "key not found",
	}

	data, err = json.Marshal(errResp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decodedErr SignResponse
	if err := json.Unmarshal(data, &decodedErr); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decodedErr.Error != "key not found" {
		t.Errorf("Error = %q, want 'key not found'", decodedErr.Error)
	}
	if decodedErr.Signature != "" {
		t.Errorf("Signature = %q, want empty", decodedErr.Signature)
	}
}

func TestSignResponseOmitsEmptyError(t *testing.T) {
	resp := SignResponse{
		Type:      "sign_response",
		RequestID: "req-789",
		Signature: "c2ln",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// The "error" field should be omitted when empty (omitempty tag)
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if _, exists := raw["error"]; exists {
		t.Error("Expected 'error' field to be omitted when empty")
	}
}

func TestEnvelopeDecoding(t *testing.T) {
	raw := `{"type": "heartbeat_ack", "timestamp": 1234567890}`

	var env Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if env.Type != "heartbeat_ack" {
		t.Errorf("Type = %q, want heartbeat_ack", env.Type)
	}
}
