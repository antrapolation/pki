package main

import (
	"os"
	"testing"
)

func TestMechanismForAlgorithm(t *testing.T) {
	tests := []struct {
		algo     string
		expected uint
	}{
		{"ECC-P256", 0x00001041}, // CKM_ECDSA
		{"ECC-P384", 0x00001041},
		{"RSA-2048", 0x00000001}, // CKM_RSA_PKCS
		{"RSA-4096", 0x00000001},
		{"unknown", 0x00001041}, // defaults to ECDSA
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			got := MechanismForAlgorithm(tt.algo)
			if got != tt.expected {
				t.Errorf("MechanismForAlgorithm(%s) = %x, want %x", tt.algo, got, tt.expected)
			}
		})
	}
}

func TestSoftHSMListKeys(t *testing.T) {
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		t.Skip("SOFTHSM2_LIB not set, skipping SoftHSM test")
	}

	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		pin = "1234"
	}

	hsm, err := NewHsmClient(lib, 0, pin)
	if err != nil {
		t.Fatalf("NewHsmClient failed: %v", err)
	}
	defer hsm.Close()

	labels := hsm.AvailableKeyLabels()
	t.Logf("Found %d key labels: %v", len(labels), labels)
}

func TestSoftHSMSign(t *testing.T) {
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		t.Skip("SOFTHSM2_LIB not set, skipping SoftHSM test")
	}

	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		pin = "1234"
	}

	hsm, err := NewHsmClient(lib, 0, pin)
	if err != nil {
		t.Fatalf("NewHsmClient failed: %v", err)
	}
	defer hsm.Close()

	labels := hsm.AvailableKeyLabels()
	if len(labels) == 0 {
		t.Skip("No keys found in SoftHSM2")
	}

	data := []byte("test data to sign with HSM")
	sig, err := hsm.Sign(labels[0], data, MechanismForAlgorithm("ECC-P256"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Signature is empty")
	}
	t.Logf("Signature length: %d bytes", len(sig))
}
