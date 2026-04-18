package main

import (
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

// HsmClient wraps PKCS#11 operations.
type HsmClient struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	labels  []string
}

// NewHsmClient loads the PKCS#11 library, opens a session, and logs in.
func NewHsmClient(libraryPath string, slotID uint, pin string) (*HsmClient, error) {
	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", libraryPath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("C_Initialize failed: %w", err)
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("C_OpenSession failed: %w", err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("C_Login failed: %w", err)
	}

	client := &HsmClient{
		ctx:     ctx,
		session: session,
	}

	// Discover available key labels
	labels, err := client.ListKeyLabels()
	if err != nil {
		log.Printf("Warning: could not list key labels: %v", err)
	}
	client.labels = labels

	return client, nil
}

// ListKeyLabels finds all private keys and returns their labels.
func (h *HsmClient) ListKeyLabels() ([]string, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}
	defer h.ctx.FindObjectsFinal(h.session)

	var labels []string
	for {
		objs, _, err := h.ctx.FindObjects(h.session, 10)
		if err != nil {
			return nil, fmt.Errorf("C_FindObjects failed: %w", err)
		}
		if len(objs) == 0 {
			break
		}

		for _, obj := range objs {
			attrs, err := h.ctx.GetAttributeValue(h.session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			})
			if err != nil {
				continue
			}
			for _, attr := range attrs {
				if attr.Type == pkcs11.CKA_LABEL {
					labels = append(labels, string(attr.Value))
				}
			}
		}
	}

	return labels, nil
}

// Sign finds a private key by label and signs the data.
func (h *HsmClient) Sign(keyLabel string, data []byte, mechanism uint) ([]byte, error) {
	// Find the private key by label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}

	objs, _, err := h.ctx.FindObjects(h.session, 1)
	if err != nil {
		h.ctx.FindObjectsFinal(h.session)
		return nil, fmt.Errorf("C_FindObjects failed: %w", err)
	}
	h.ctx.FindObjectsFinal(h.session)

	if len(objs) == 0 {
		return nil, fmt.Errorf("key not found: %s", keyLabel)
	}

	// Sign
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
	if err := h.ctx.SignInit(h.session, mech, objs[0]); err != nil {
		return nil, fmt.Errorf("C_SignInit failed: %w", err)
	}

	signature, err := h.ctx.Sign(h.session, data)
	if err != nil {
		return nil, fmt.Errorf("C_Sign failed: %w", err)
	}

	return signature, nil
}

// Close cleans up the PKCS#11 session.
func (h *HsmClient) Close() {
	if h.ctx != nil {
		h.ctx.Logout(h.session)
		h.ctx.CloseSession(h.session)
		h.ctx.Finalize()
	}
}

// AvailableKeyLabels returns the discovered key labels.
func (h *HsmClient) AvailableKeyLabels() []string {
	return h.labels
}

// MechanismForAlgorithm maps algorithm string to PKCS#11 mechanism.
func MechanismForAlgorithm(algorithm string) uint {
	switch algorithm {
	case "ECC-P256", "ECC-P384":
		return pkcs11.CKM_ECDSA
	case "RSA-2048", "RSA-4096":
		return pkcs11.CKM_RSA_PKCS
	default:
		// For PQC algorithms, use vendor-specific mechanisms
		// or CKM_VENDOR_DEFINED
		return pkcs11.CKM_ECDSA
	}
}
