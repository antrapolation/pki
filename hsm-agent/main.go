package main

import (
	"context"
	"flag"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("HSM Agent starting...")

	// Load config
	config, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Config loaded: agent=%s, tenant=%s, backend=%s",
		config.Agent.ID, config.Agent.TenantID, config.Backend.URL)

	// Initialize PKCS#11
	hsm, err := NewHsmClient(config.PKCS11.Library, config.PKCS11.Slot, config.PKCS11.Pin)
	if err != nil {
		log.Fatalf("Failed to initialize HSM: %v", err)
	}
	defer hsm.Close()
	log.Printf("HSM initialized: %d keys available: %v", len(hsm.AvailableKeyLabels()), hsm.AvailableKeyLabels())

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Connect with exponential backoff
	wsClient := NewWsClient(config, hsm)
	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			wsClient.Close()
			return
		default:
		}

		log.Printf("Connecting to backend: %s", config.Backend.URL)
		if err := wsClient.Connect(ctx); err != nil {
			log.Printf("Connection failed: %v (retry in %v)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
			continue
		}

		// Register
		if err := wsClient.Register(); err != nil {
			log.Printf("Registration failed: %v (retry in %v)", err, backoff)
			wsClient.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
			continue
		}

		// Reset backoff on successful connection
		backoff = 1 * time.Second

		// Run the message loop
		if err := wsClient.RunLoop(ctx); err != nil {
			log.Printf("Stream error: %v (reconnecting in %v)", err, backoff)
			wsClient.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
		}
	}
}
