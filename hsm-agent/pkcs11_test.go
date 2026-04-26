package main

import (
	"os"
	"testing"
)

func TestMechanismForAlgorithm(t *testing.T) {
	known := []struct {
		algo     string
		expected uint
	}{
		{"ECC-P256", 0x00001041}, // CKM_ECDSA
		{"ECC-P384", 0x00001041},
		{"RSA-2048", 0x00000001}, // CKM_RSA_PKCS
		{"RSA-4096", 0x00000001},
	}
	for _, tt := range known {
		t.Run(tt.algo, func(t *testing.T) {
			got, ok := MechanismForAlgorithm(tt.algo)
			if !ok {
				t.Fatalf("MechanismForAlgorithm(%s) returned ok=false, want true", tt.algo)
			}
			if got != tt.expected {
				t.Errorf("MechanismForAlgorithm(%s) = %x, want %x", tt.algo, got, tt.expected)
			}
		})
	}

	// Unknown algorithms must return ok=false — not silently fall back to ECDSA.
	for _, algo := range []string{"unknown", "ML-DSA-65", "KAZ-SIGN-192"} {
		t.Run("unknown_"+algo, func(t *testing.T) {
			_, ok := MechanismForAlgorithm(algo)
			if ok {
				t.Errorf("MechanismForAlgorithm(%s) returned ok=true, want false", algo)
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
	mech, ok := MechanismForAlgorithm("ECC-P256")
	if !ok {
		t.Fatal("MechanismForAlgorithm returned ok=false for ECC-P256")
	}
	sig, err := hsm.Sign(labels[0], data, mech)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Signature is empty")
	}
	t.Logf("Signature length: %d bytes", len(sig))
}
