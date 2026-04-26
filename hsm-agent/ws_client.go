package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// signWorkerCount is the number of concurrent PKCS#11 sign operations allowed.
// One worker is correct: PKCS#11 sessions are not thread-safe even with HsmClient.mu,
// because FindObjectsInit/FindObjectsFinal must be balanced on the same session handle
// without interleaving. A single worker makes this a hard guarantee.
const signWorkerCount = 1

// WsClient handles the WebSocket connection to the backend.
type WsClient struct {
	config    *Config
	hsm       *HsmClient
	conn      *websocket.Conn
	mu        sync.Mutex
	connected bool
	signCh    chan SignRequest
}

// NewWsClient creates a new WebSocket client.
func NewWsClient(config *Config, hsm *HsmClient) *WsClient {
	return &WsClient{
		config: config,
		hsm:    hsm,
		signCh: make(chan SignRequest, 64),
	}
}

// Connect establishes the WebSocket connection with mTLS.
//
// mTLS is REQUIRED. If TLS config is missing or invalid, Connect returns an
// error. We never fall back to plaintext — the agent holds HSM signing
// authority, and a rogue backend that can impersonate the gateway can make
// the agent sign arbitrary data with production CA keys.
func (w *WsClient) Connect(ctx context.Context) error {
	tlsConfig, err := w.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("mTLS config required but not loadable: %w", err)
	}

	dialer := websocket.Dialer{TLSClientConfig: tlsConfig}

	conn, _, err := dialer.DialContext(ctx, w.config.Backend.URL, nil)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	w.mu.Lock()
	w.conn = conn
	w.connected = true
	w.mu.Unlock()

	return nil
}

// Register sends the register message to the backend and waits for response.
func (w *WsClient) Register() error {
	if w.config.Agent.AuthToken == "" {
		return fmt.Errorf("agent.auth_token is required — set it in the config or the HSM_AGENT_AUTH_TOKEN env var")
	}
	msg := RegisterMsg{
		Type:          "register",
		TenantID:      w.config.Agent.TenantID,
		AgentID:       w.config.Agent.ID,
		AuthToken:     w.config.Agent.AuthToken,
		AvailableKeys: w.hsm.AvailableKeyLabels(),
	}

	w.mu.Lock()
	err := w.conn.WriteJSON(msg)
	w.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send register failed: %w", err)
	}

	// Wait for RegisterResponse
	var resp RegisterResponse
	if err := w.conn.ReadJSON(&resp); err != nil {
		return fmt.Errorf("recv register response failed: %w", err)
	}

	if resp.Type != "register_response" {
		return fmt.Errorf("unexpected response type: %s", resp.Type)
	}
	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Error)
	}

	log.Printf("Registered with backend: agent=%s, keys=%v", w.config.Agent.ID, w.hsm.AvailableKeyLabels())
	return nil
}

// RunLoop handles the message loop: reads server messages, dispatches sign requests, sends heartbeats.
func (w *WsClient) RunLoop(ctx context.Context) error {
	heartbeatInterval, err := time.ParseDuration(w.config.Agent.HeartbeatInterval)
	if err != nil {
		heartbeatInterval = 10 * time.Second
	}

	// Start heartbeat goroutine
	go w.heartbeatLoop(ctx, heartbeatInterval)

	// Start bounded sign workers. signWorkerCount=1 serializes PKCS#11 access.
	for i := 0; i < signWorkerCount; i++ {
		go w.signWorker(ctx)
	}

	// Read loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, rawMsg, err := w.conn.ReadMessage()
			if err != nil {
				return fmt.Errorf("read failed: %w", err)
			}

			var env Envelope
			if err := json.Unmarshal(rawMsg, &env); err != nil {
				log.Printf("Failed to decode message envelope: %v", err)
				continue
			}

			switch env.Type {
			case "sign_request":
				var req SignRequest
				if err := json.Unmarshal(rawMsg, &req); err != nil {
					log.Printf("Failed to decode sign_request: %v", err)
					continue
				}
				select {
				case w.signCh <- req:
				default:
					log.Printf("Sign queue full, rejecting request %s", req.RequestID)
					w.sendSignResponse(req.RequestID, nil, fmt.Errorf("server busy"))
				}
			case "heartbeat_ack":
				// Server is alive
			default:
				log.Printf("Unknown message type: %s", env.Type)
			}
		}
	}
}

// signWorker drains signCh and processes each request serially.
func (w *WsClient) signWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-w.signCh:
			w.handleSignRequest(req)
		}
	}
}

// handleSignRequest processes a sign request from the backend.
func (w *WsClient) handleSignRequest(req SignRequest) {
	log.Printf("Sign request: id=%s, key=%s, algo=%s", req.RequestID, req.KeyLabel, req.Algorithm)

	tbsData, err := base64.StdEncoding.DecodeString(req.TbsData)
	if err != nil {
		w.sendSignResponse(req.RequestID, nil, fmt.Errorf("invalid tbs_data base64: %w", err))
		return
	}

	mechanism, ok := MechanismForAlgorithm(req.Algorithm)
	if !ok {
		w.sendSignResponse(req.RequestID, nil, fmt.Errorf("unsupported algorithm: %s", req.Algorithm))
		return
	}

	signature, err := w.hsm.Sign(req.KeyLabel, tbsData, mechanism)
	w.sendSignResponse(req.RequestID, signature, err)
}

// sendSignResponse sends a sign response back to the backend.
func (w *WsClient) sendSignResponse(requestID string, signature []byte, signErr error) {
	resp := SignResponse{
		Type:      "sign_response",
		RequestID: requestID,
	}

	if signErr != nil {
		log.Printf("Sign failed for %s: %v", requestID, signErr)
		resp.Error = signErr.Error()
	} else {
		resp.Signature = base64.StdEncoding.EncodeToString(signature)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.WriteJSON(resp); err != nil {
		log.Printf("Failed to send sign response: %v", err)
	}
}

// SendHeartbeat sends a single heartbeat message.
func (w *WsClient) SendHeartbeat() error {
	msg := Heartbeat{
		Type:      "heartbeat",
		Timestamp: time.Now().Unix(),
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.WriteJSON(msg)
}

func (w *WsClient) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.SendHeartbeat(); err != nil {
				log.Printf("Heartbeat send failed: %v", err)
				return
			}
		}
	}
}

func (w *WsClient) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := w.config.Backend.TLS

	if tlsCfg.ClientCert == "" || tlsCfg.ClientKey == "" {
		return nil, fmt.Errorf("backend.tls.client_cert and client_key are required")
	}
	if tlsCfg.CACert == "" {
		return nil, fmt.Errorf("backend.tls.ca_cert is required: agent must pin the backend CA")
	}

	cert, err := tls.LoadX509KeyPair(tlsCfg.ClientCert, tlsCfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert failed: %w", err)
	}

	caCert, err := os.ReadFile(tlsCfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert failed: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Close shuts down the WebSocket connection.
func (w *WsClient) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		w.conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		w.conn.Close()
	}
	w.connected = false
}
