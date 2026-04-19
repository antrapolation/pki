package main

// RegisterMsg is sent by the agent to register with the backend.
// AuthToken is required — the backend checks it against its configured
// agent allowlist. Without a valid token the registration is rejected.
type RegisterMsg struct {
	Type          string   `json:"type"`
	TenantID      string   `json:"tenant_id"`
	AgentID       string   `json:"agent_id"`
	AuthToken     string   `json:"auth_token"`
	AvailableKeys []string `json:"available_key_labels"`
}

// RegisterResponse is received from the backend after registration.
type RegisterResponse struct {
	Type     string `json:"type"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// SignRequest is received from the backend asking the agent to sign data.
type SignRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	KeyLabel  string `json:"key_label"`
	TbsData   string `json:"tbs_data"`
	Algorithm string `json:"algorithm"`
}

// SignResponse is sent back to the backend with the signature or error.
type SignResponse struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Heartbeat is sent periodically to keep the connection alive.
type Heartbeat struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// HeartbeatAck is received from the backend acknowledging a heartbeat.
type HeartbeatAck struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// Envelope is used to decode the "type" field before full deserialization.
type Envelope struct {
	Type string `json:"type"`
}
